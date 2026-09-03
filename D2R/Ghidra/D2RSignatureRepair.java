// D2RSignatureRepair.java
//
// Repairs stale d2.re D2R signature entries against the currently opened D2R.exe.
//
// Strategy:
//   1. Exact-search every existing functions.json / variables.json signature.
//   2. For missing signatures, use multiple exact anchor fragments from the old pattern.
//   3. Score candidate starts by masked byte similarity.
//   4. Accept only high-confidence, uniquely-best candidates.
//   5. Build a repaired pattern by wildcarding changed bytes and extending it if needed
//      until it is unique in the current program.
//   6. Resolve the signature's target using absolute / operand / other semantics.
//   7. Apply the symbol/function name in the current Ghidra program.
//   8. Merge repaired entries into data/_functions.json and data/_variables.json,
//      backing up any existing override files first.
//
// IMPORTANT:
// This is intentionally conservative. If a relocation is ambiguous, it is NOT written.
// A name plus an old byte signature is not enough information to safely identify every
// heavily changed function across arbitrary game/compiler revisions.
//
//@category D2R
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class D2RSignatureRepair extends GhidraScript {

    // Conservative defaults. Lowering these increases false-positive risk.
    private static final double MIN_SIMILARITY = 0.72;
    private static final double MIN_MARGIN = 0.08;
    private static final int MIN_EXACT_BYTES = 8;
    private static final int ANCHOR_LEN = 4;
    private static final int MAX_ANCHORS = 8;
    private static final int MAX_ANCHOR_HITS = 2000;
    private static final int MAX_EXTENSION_BYTES = 32;

    private static class PatternBytes {
        final byte[] bytes;
        final byte[] mask;

        PatternBytes(byte[] bytes, byte[] mask) {
            this.bytes = bytes;
            this.mask = mask;
        }
    }

    private static class Anchor {
        final int offset;
        final byte[] bytes;

        Anchor(int offset, byte[] bytes) {
            this.offset = offset;
            this.bytes = bytes;
        }
    }

    private static class Candidate {
        final Address start;
        final double similarity;
        final int equalExact;
        final int exactCount;

        Candidate(Address start, double similarity, int equalExact, int exactCount) {
            this.start = start;
            this.similarity = similarity;
            this.equalExact = equalExact;
            this.exactCount = exactCount;
        }
    }

    private static class Relocation {
        final Address matchAddress;
        final String repairedPattern;
        final double similarity;
        final boolean exact;

        Relocation(Address matchAddress, String repairedPattern, double similarity, boolean exact) {
            this.matchAddress = matchAddress;
            this.repairedPattern = repairedPattern;
            this.similarity = similarity;
            this.exact = exact;
        }
    }

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private File d2rDirectory;
    private File dataDirectory;

    private int exactMatches;
    private int repairedMatches;
    private int unresolved;
    private int ambiguous;
    private int appliedFunctions;
    private int appliedVariables;
    private int resolutionFailures;

    @Override
    protected void run() throws Exception {
        println("=== D2R signature repair ===");
        println("Program: " + currentProgram.getName());
        println("Image base: " + currentProgram.getImageBase());

        if (!runScannerSelfTest()) {
            printerr("Scanner self-test failed. Aborting without changing JSON.");
            return;
        }

        d2rDirectory = askDirectory("Select the d2.re D2R directory", "Select");
        dataDirectory = new File(d2rDirectory, "data");

        if (!dataDirectory.isDirectory()) {
            printerr("Missing data directory: " + dataDirectory.getAbsolutePath());
            return;
        }

        JsonArray baseFunctions = readArray(new File(dataDirectory, "functions.json"));
        JsonArray baseVariables = readArray(new File(dataDirectory, "variables.json"));

        LinkedHashMap<String, JsonObject> functionOverrides =
            loadOverrides(new File(dataDirectory, "_functions.json"));
        LinkedHashMap<String, JsonObject> variableOverrides =
            loadOverrides(new File(dataDirectory, "_variables.json"));

        println("Base functions: " + baseFunctions.size());
        println("Base variables: " + baseVariables.size());
        println("");

        processArray(baseFunctions, true, functionOverrides);
        processArray(baseVariables, false, variableOverrides);

        if (monitor.isCancelled()) {
            println("Cancelled. No override JSON files were written.");
            return;
        }

        backupIfExists(new File(dataDirectory, "_functions.json"));
        backupIfExists(new File(dataDirectory, "_variables.json"));

        writeOverrides(new File(dataDirectory, "_functions.json"), functionOverrides);
        writeOverrides(new File(dataDirectory, "_variables.json"), variableOverrides);

        println("");
        println("=== Repair summary ===");
        println("Exact signatures already valid: " + exactMatches);
        println("Stale signatures repaired: " + repairedMatches);
        println("Ambiguous relocations skipped: " + ambiguous);
        println("Unresolved signatures skipped: " + unresolved);
        println("Target resolution failures: " + resolutionFailures);
        println("Applied function names: " + appliedFunctions);
        println("Applied variable names: " + appliedVariables);
        println("Wrote: " + new File(dataDirectory, "_functions.json").getAbsolutePath());
        println("Wrote: " + new File(dataDirectory, "_variables.json").getAbsolutePath());
        println("Done.");
    }

    // ---------------------------------------------------------------------
    // Main processing
    // ---------------------------------------------------------------------

    private void processArray(
        JsonArray items,
        boolean isFunction,
        LinkedHashMap<String, JsonObject> overrides
    ) throws Exception {

        String kind = isFunction ? "FUNC" : "VAR ";

        for (JsonElement element : items) {
            if (monitor.isCancelled()) {
                return;
            }
            if (element == null || !element.isJsonObject()) {
                continue;
            }

            JsonObject item = element.getAsJsonObject();
            String name = getString(item, "name", "<unnamed>");
            String oldPattern = getString(item, "pattern", null);

            if (oldPattern == null || oldPattern.trim().isEmpty()) {
                unresolved++;
                println("[" + kind + " UNRESOLVED] " + name + " - no pattern");
                continue;
            }

            Relocation relocation = relocateSignature(oldPattern, isFunction);

            if (relocation == null) {
                unresolved++;
                println("[" + kind + " UNRESOLVED] " + name);
                continue;
            }

            if (relocation.exact) {
                exactMatches++;
            }
            else {
                repairedMatches++;

                JsonObject repaired = item.deepCopy();
                repaired.addProperty("pattern", relocation.repairedPattern);
                repaired.addProperty(
                    "repair_note",
                    String.format(
                        "Auto-repaired by Ghidra against %s; similarity %.3f",
                        currentProgram.getName(),
                        relocation.similarity
                    )
                );
                overrides.put(name, repaired);
            }

            Address target = resolveTarget(item, relocation.matchAddress);

            if (target == null) {
                resolutionFailures++;
                println(
                    "[" + kind + " MATCH/RESOLVE-FAIL] " + name +
                    " match=" + relocation.matchAddress +
                    " similarity=" + String.format("%.3f", relocation.similarity)
                );
                continue;
            }

            if (isFunction) {
                if (applyFunction(target, item)) {
                    appliedFunctions++;
                }
            }
            else {
                if (applyVariable(target, item)) {
                    appliedVariables++;
                }
            }

            println(
                "[" + kind + (relocation.exact ? " EXACT] " : " REPAIRED] ") +
                name +
                " match=" + relocation.matchAddress +
                " target=" + target +
                " similarity=" + String.format("%.3f", relocation.similarity)
            );
        }
    }

    // ---------------------------------------------------------------------
    // Relocation
    // ---------------------------------------------------------------------

    private Relocation relocateSignature(String pattern, boolean executableOnly)
        throws Exception {

        Address exact = findPattern(pattern, executableOnly, null);
        if (exact != null) {
            return new Relocation(exact, pattern, 1.0, true);
        }

        PatternBytes old = parsePattern(pattern);
        int exactCount = countExact(old.mask);

        if (exactCount < MIN_EXACT_BYTES) {
            return null;
        }

        List<Anchor> anchors = buildAnchors(old);
        if (anchors.isEmpty()) {
            return null;
        }

        Map<String, Candidate> candidates = new HashMap<>();

        for (Anchor anchor : anchors) {
            if (monitor.isCancelled()) {
                return null;
            }

            int hits = 0;

            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                if (!eligibleBlock(block, executableOnly)) {
                    continue;
                }

                Address search = block.getStart();

                while (search.compareTo(block.getEnd()) <= 0) {
                    Address hit = currentProgram.getMemory().findBytes(
                        search,
                        block.getEnd(),
                        anchor.bytes,
                        null,
                        true,
                        monitor
                    );

                    if (hit == null) {
                        break;
                    }

                    hits++;
                    if (hits > MAX_ANCHOR_HITS) {
                        break;
                    }

                    Address candidateStart;
                    try {
                        candidateStart = hit.subtract(anchor.offset);
                    }
                    catch (Exception e) {
                        candidateStart = null;
                    }

                    if (
                        candidateStart != null &&
                        block.contains(candidateStart) &&
                        candidateFitsBlock(candidateStart, old.bytes.length, block)
                    ) {
                        Candidate candidate = scoreCandidate(candidateStart, old);

                        if (
                            candidate != null &&
                            candidate.similarity >= MIN_SIMILARITY
                        ) {
                            String key = candidate.start.toString();
                            Candidate prior = candidates.get(key);

                            if (prior == null || candidate.similarity > prior.similarity) {
                                candidates.put(key, candidate);
                            }
                        }
                    }

                    if (hit.equals(block.getEnd())) {
                        break;
                    }

                    search = hit.add(1);
                }
            }
        }

        if (candidates.isEmpty()) {
            return null;
        }

        Candidate best = null;
        Candidate second = null;

        for (Candidate candidate : candidates.values()) {
            if (best == null || candidate.similarity > best.similarity) {
                second = best;
                best = candidate;
            }
            else if (second == null || candidate.similarity > second.similarity) {
                second = candidate;
            }
        }

        if (best == null) {
            return null;
        }

        if (second != null && (best.similarity - second.similarity) < MIN_MARGIN) {
            ambiguous++;
            return null;
        }

        String repaired = buildUniqueRepairedPattern(best.start, old, executableOnly);

        if (repaired == null) {
            ambiguous++;
            return null;
        }

        return new Relocation(best.start, repaired, best.similarity, false);
    }

    private Candidate scoreCandidate(Address start, PatternBytes old) {
        try {
            byte[] current = new byte[old.bytes.length];
            int read = currentProgram.getMemory().getBytes(start, current);

            if (read != current.length) {
                return null;
            }

            int exact = 0;
            int equal = 0;

            for (int i = 0; i < old.bytes.length; i++) {
                if ((old.mask[i] & 0xff) != 0xff) {
                    continue;
                }

                exact++;
                if (current[i] == old.bytes[i]) {
                    equal++;
                }
            }

            if (exact == 0) {
                return null;
            }

            return new Candidate(
                start,
                ((double) equal) / ((double) exact),
                equal,
                exact
            );
        }
        catch (Exception e) {
            return null;
        }
    }

    private List<Anchor> buildAnchors(PatternBytes pattern) {
        List<Anchor> result = new ArrayList<>();
        Set<Integer> usedOffsets = new HashSet<>();

        // Prefer evenly distributed exact 4-byte windows.
        for (int pass = 0; pass < 2 && result.size() < MAX_ANCHORS; pass++) {
            int step = pass == 0 ? Math.max(1, pattern.bytes.length / MAX_ANCHORS) : 1;

            for (
                int i = 0;
                i <= pattern.bytes.length - ANCHOR_LEN && result.size() < MAX_ANCHORS;
                i += step
            ) {
                if (usedOffsets.contains(i)) {
                    continue;
                }

                boolean allExact = true;
                for (int j = 0; j < ANCHOR_LEN; j++) {
                    if ((pattern.mask[i + j] & 0xff) != 0xff) {
                        allExact = false;
                        break;
                    }
                }

                if (!allExact) {
                    continue;
                }

                byte[] anchorBytes = new byte[ANCHOR_LEN];
                System.arraycopy(pattern.bytes, i, anchorBytes, 0, ANCHOR_LEN);
                result.add(new Anchor(i, anchorBytes));
                usedOffsets.add(i);
            }
        }

        return result;
    }

    private String buildUniqueRepairedPattern(
        Address candidateStart,
        PatternBytes old,
        boolean executableOnly
    ) throws Exception {

        byte[] current = new byte[old.bytes.length];
        int read = currentProgram.getMemory().getBytes(candidateStart, current);

        if (read != current.length) {
            return null;
        }

        List<Byte> outBytes = new ArrayList<>();
        List<Boolean> exact = new ArrayList<>();

        for (int i = 0; i < old.bytes.length; i++) {
            outBytes.add(current[i]);

            boolean keepExact =
                ((old.mask[i] & 0xff) == 0xff) &&
                current[i] == old.bytes[i];

            exact.add(keepExact);
        }

        // A repaired signature needs enough fixed bytes to be meaningful.
        if (countTrue(exact) < MIN_EXACT_BYTES) {
            return null;
        }

        for (int extension = 0; extension <= MAX_EXTENSION_BYTES; extension += 4) {
            List<Byte> testBytes = new ArrayList<>(outBytes);
            List<Boolean> testExact = new ArrayList<>(exact);

            if (extension > 0) {
                Address extensionStart = candidateStart.add(old.bytes.length);
                byte[] extra = new byte[extension];

                try {
                    int got = currentProgram.getMemory().getBytes(extensionStart, extra);
                    if (got != extension) {
                        continue;
                    }
                }
                catch (Exception e) {
                    continue;
                }

                for (byte b : extra) {
                    testBytes.add(b);
                    testExact.add(true);
                }
            }

            String pattern = formatPattern(testBytes, testExact);
            int matches = countPatternMatches(pattern, executableOnly, 2);

            if (matches == 1) {
                Address verify = findPattern(pattern, executableOnly, null);
                if (candidateStart.equals(verify)) {
                    return pattern;
                }
            }
        }

        return null;
    }

    // ---------------------------------------------------------------------
    // Pattern scanning
    // ---------------------------------------------------------------------

    private PatternBytes parsePattern(String pattern) {
        String[] tokens = pattern.trim().split("\\s+");
        byte[] bytes = new byte[tokens.length];
        byte[] mask = new byte[tokens.length];

        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];

            if ("?".equals(token) || "??".equals(token)) {
                bytes[i] = 0;
                mask[i] = 0;
            }
            else {
                if (token.length() != 2) {
                    throw new IllegalArgumentException(
                        "Unsupported token '" + token + "' in pattern: " + pattern
                    );
                }

                bytes[i] = (byte) Integer.parseInt(token, 16);
                mask[i] = (byte) 0xff;
            }
        }

        return new PatternBytes(bytes, mask);
    }

    private Address findPattern(
        String pattern,
        boolean executableOnly,
        Address startAfter
    ) throws Exception {

        PatternBytes parsed = parsePattern(pattern);
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!eligibleBlock(block, executableOnly)) {
                continue;
            }

            Address start = block.getStart();

            if (startAfter != null) {
                if (startAfter.compareTo(block.getEnd()) >= 0) {
                    continue;
                }

                if (
                    startAfter.compareTo(block.getStart()) >= 0 &&
                    startAfter.compareTo(block.getEnd()) < 0
                ) {
                    start = startAfter.add(1);
                }
            }

            Address result = memory.findBytes(
                start,
                block.getEnd(),
                parsed.bytes,
                parsed.mask,
                true,
                monitor
            );

            if (result != null) {
                return result;
            }
        }

        return null;
    }

    private int countPatternMatches(
        String pattern,
        boolean executableOnly,
        int stopAfter
    ) throws Exception {

        PatternBytes parsed = parsePattern(pattern);
        Memory memory = currentProgram.getMemory();
        int count = 0;

        for (MemoryBlock block : memory.getBlocks()) {
            if (!eligibleBlock(block, executableOnly)) {
                continue;
            }

            Address cursor = block.getStart();

            while (cursor.compareTo(block.getEnd()) <= 0) {
                Address hit = memory.findBytes(
                    cursor,
                    block.getEnd(),
                    parsed.bytes,
                    parsed.mask,
                    true,
                    monitor
                );

                if (hit == null) {
                    break;
                }

                count++;
                if (count >= stopAfter) {
                    return count;
                }

                if (hit.equals(block.getEnd())) {
                    break;
                }

                cursor = hit.add(1);
            }
        }

        return count;
    }

    private boolean eligibleBlock(MemoryBlock block, boolean executableOnly) {
        return block.isInitialized() && (!executableOnly || block.isExecute());
    }

    private boolean candidateFitsBlock(Address start, int length, MemoryBlock block) {
        try {
            return start.add(length - 1).compareTo(block.getEnd()) <= 0;
        }
        catch (Exception e) {
            return false;
        }
    }

    // ---------------------------------------------------------------------
    // Target resolution (mirrors D2R/update.py semantics as closely as Ghidra allows)
    // ---------------------------------------------------------------------

    private Address resolveTarget(JsonObject item, Address match) throws Exception {
        String type = getString(item, "type", "absolute");

        if ("absolute".equalsIgnoreCase(type)) {
            return match;
        }

        int operandIndex = getInt(item, "operand", 0);
        Instruction instruction = currentProgram.getListing().getInstructionAt(match);

        if (instruction == null) {
            return null;
        }

        if (operandIndex < 0 || operandIndex >= instruction.getNumOperands()) {
            return null;
        }

        if ("other".equalsIgnoreCase(type)) {
            Scalar scalar = getOperandScalar(instruction, operandIndex);
            if (scalar != null) {
                try {
                    return currentProgram.getImageBase().add(scalar.getSignedValue());
                }
                catch (Exception ignored) {
                }
            }
        }

        Reference[] refs = instruction.getOperandReferences(operandIndex);

        if (refs != null) {
            for (Reference ref : refs) {
                Address target = ref.getToAddress();
                if (target != null && target.isMemoryAddress()) {
                    return target;
                }
            }
        }

        Scalar scalar = getOperandScalar(instruction, operandIndex);
        if (scalar == null) {
            return null;
        }

        String mnemonic = instruction.getMnemonicString().toUpperCase();

        if (mnemonic.startsWith("CALL") || mnemonic.startsWith("J")) {
            try {
                return instruction.getMaxAddress().add(1).add(scalar.getSignedValue());
            }
            catch (Exception ignored) {
            }
        }

        try {
            AddressSpace space =
                currentProgram.getAddressFactory().getDefaultAddressSpace();

            Address target = space.getAddress(scalar.getUnsignedValue());

            if (currentProgram.getMemory().contains(target)) {
                return target;
            }
        }
        catch (Exception ignored) {
        }

        return null;
    }

    private Scalar getOperandScalar(Instruction instruction, int operandIndex) {
        Object[] objects = instruction.getOpObjects(operandIndex);

        if (objects == null) {
            return null;
        }

        for (Object object : objects) {
            if (object instanceof Scalar) {
                return (Scalar) object;
            }
        }

        return null;
    }

    // ---------------------------------------------------------------------
    // Apply symbols
    // ---------------------------------------------------------------------

    private boolean applyFunction(Address address, JsonObject item) {
        String name = getString(item, "name", "<unnamed>");

        try {
            Function function =
                currentProgram.getFunctionManager().getFunctionAt(address);

            if (function == null) {
                function = createFunction(address, name);
            }

            if (function == null) {
                return false;
            }

            function.setName(name, SourceType.USER_DEFINED);

            String summary = getString(item, "summary", null);
            if (summary != null && !summary.trim().isEmpty()) {
                function.setComment(summary);
                currentProgram.getListing().setComment(
                    address,
                    CodeUnit.PLATE_COMMENT,
                    summary
                );
            }

            return true;
        }
        catch (Exception e) {
            println("[FUNCTION APPLY FAILED] " + name + ": " + e.getMessage());
            return false;
        }
    }

    private boolean applyVariable(Address address, JsonObject item) {
        String name = getString(item, "name", "<unnamed>");

        try {
            Symbol existing = currentProgram.getSymbolTable().getPrimarySymbol(address);

            if (existing != null && existing.getSource() == SourceType.DEFAULT) {
                existing.setName(name, SourceType.USER_DEFINED);
            }
            else {
                List<Symbol> globals = currentProgram.getSymbolTable().getGlobalSymbols(name);
                boolean alreadyThere = false;

                if (globals != null) {
                    for (Symbol symbol : globals) {
                        if (address.equals(symbol.getAddress())) {
                            alreadyThere = true;
                            if (!symbol.isPrimary()) {
                                symbol.setPrimary();
                            }
                            break;
                        }
                    }
                }

                if (!alreadyThere) {
                    Symbol created = currentProgram.getSymbolTable().createLabel(
                        address,
                        name,
                        SourceType.USER_DEFINED
                    );

                    if (created != null && !created.isPrimary()) {
                        created.setPrimary();
                    }
                }
            }

            String summary = getString(item, "summary", null);
            if (summary != null && !summary.trim().isEmpty()) {
                currentProgram.getListing().setComment(
                    address,
                    CodeUnit.PLATE_COMMENT,
                    summary
                );
            }

            return true;
        }
        catch (Exception e) {
            println("[VARIABLE APPLY FAILED] " + name + ": " + e.getMessage());
            return false;
        }
    }

    // ---------------------------------------------------------------------
    // JSON override handling
    // ---------------------------------------------------------------------

    private JsonArray readArray(File file) throws Exception {
        if (!file.isFile()) {
            throw new IllegalStateException("Missing required file: " + file.getAbsolutePath());
        }

        try (FileReader reader = new FileReader(file)) {
            JsonElement root = JsonParser.parseReader(reader);

            if (!root.isJsonArray()) {
                throw new IllegalStateException("Expected JSON array: " + file.getAbsolutePath());
            }

            return root.getAsJsonArray();
        }
    }

    private LinkedHashMap<String, JsonObject> loadOverrides(File file) throws Exception {
        LinkedHashMap<String, JsonObject> result = new LinkedHashMap<>();

        if (!file.isFile()) {
            return result;
        }

        JsonArray array = readArray(file);

        for (JsonElement element : array) {
            if (!element.isJsonObject()) {
                continue;
            }

            JsonObject object = element.getAsJsonObject();
            String name = getString(object, "name", null);

            if (name != null) {
                result.put(name, object.deepCopy());
            }
        }

        return result;
    }

    private void writeOverrides(
        File file,
        LinkedHashMap<String, JsonObject> overrides
    ) throws Exception {

        JsonArray array = new JsonArray();

        for (JsonObject object : overrides.values()) {
            array.add(object);
        }

        try (FileWriter writer = new FileWriter(file)) {
            gson.toJson(array, writer);
        }
    }

    private void backupIfExists(File file) throws Exception {
        if (!file.isFile()) {
            return;
        }

        String timestamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
        File backup = new File(file.getParentFile(), file.getName() + "." + timestamp + ".bak");

        Files.copy(
            file.toPath(),
            backup.toPath(),
            StandardCopyOption.REPLACE_EXISTING
        );

        println("Backup: " + backup.getAbsolutePath());
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private boolean runScannerSelfTest() throws Exception {
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute() || block.getSize() < 8) {
                continue;
            }

            byte[] bytes = new byte[8];
            int read = memory.getBytes(block.getStart(), bytes);

            if (read != bytes.length) {
                continue;
            }

            Address result = memory.findBytes(
                block.getStart(),
                block.getEnd(),
                bytes,
                null,
                true,
                monitor
            );

            println(
                "Scanner self-test: expected=" + block.getStart() +
                " result=" + result
            );

            return block.getStart().equals(result);
        }

        return false;
    }

    private int countExact(byte[] mask) {
        int count = 0;

        for (byte b : mask) {
            if ((b & 0xff) == 0xff) {
                count++;
            }
        }

        return count;
    }

    private int countTrue(List<Boolean> values) {
        int count = 0;

        for (Boolean value : values) {
            if (Boolean.TRUE.equals(value)) {
                count++;
            }
        }

        return count;
    }

    private String formatPattern(List<Byte> bytes, List<Boolean> exact) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < bytes.size(); i++) {
            if (i != 0) {
                sb.append(' ');
            }

            if (exact.get(i)) {
                sb.append(String.format("%02X", bytes.get(i) & 0xff));
            }
            else {
                sb.append("??");
            }
        }

        return sb.toString();
    }

    private String getString(JsonObject item, String key, String defaultValue) {
        if (item == null || !item.has(key) || item.get(key).isJsonNull()) {
            return defaultValue;
        }

        return item.get(key).getAsString();
    }

    private int getInt(JsonObject item, String key, int defaultValue) {
        if (item == null || !item.has(key) || item.get(key).isJsonNull()) {
            return defaultValue;
        }

        return item.get(key).getAsInt();
    }
}
