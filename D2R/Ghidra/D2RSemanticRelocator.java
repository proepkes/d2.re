// D2RSemanticRelocator.java
//
// Second-pass relocation assistant for stale d2.re D2R signatures.
//
// Purpose:
//   When byte signatures no longer survive a new D2R build, this script ranks
//   candidate functions using structural evidence from the OLD signature entry
//   and the CURRENT Ghidra program.
//
// This script is deliberately read-mostly and conservative:
//   - It does NOT automatically rename unresolved functions.
//   - It writes a ranked JSON report to D2R/data/_semantic_candidates.json.
//   - Exact byte matches, if any, are reported as certainty=exact.
//   - For stale entries, candidates are scored using:
//       * old-pattern byte similarity at function entry
//       * function size similarity to the old-pattern length
//       * number of basic blocks
//       * number of callees
//       * number of callers
//       * referenced string count
//       * referenced global/data count
//       * immediate-constant overlap
//   - The top candidates can then be reviewed manually or promoted by a later
//     script once enough anchors are known.
//
// Limitations:
//   The d2.re JSON does not preserve old call graphs, strings, function sizes,
//   or semantic metadata. Therefore this script cannot "know" the historical
//   BITMANIP_Read body from the signature entry alone. It can only use the old
//   bytes plus current structural characteristics to build a useful ranked set.
//
//@category D2R
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class D2RSemanticRelocator extends GhidraScript {

    private static final int TOP_N = 12;
    private static final int MAX_ENTRY_COMPARE = 96;
    private static final int MAX_FUNCTIONS = 200000;

    private static class PatternBytes {
        final byte[] bytes;
        final byte[] mask;

        PatternBytes(byte[] bytes, byte[] mask) {
            this.bytes = bytes;
            this.mask = mask;
        }
    }

    private static class FunctionFeatures {
        Function function;
        long size;
        int basicBlocks;
        int callers;
        int callees;
        int referencedStrings;
        int referencedData;
        Set<Long> immediates = new HashSet<>();
    }

    private static class Candidate {
        FunctionFeatures features;
        double score;
        double entrySimilarity;
        double sizeScore;
        double complexityScore;
    }

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private File d2rDirectory;
    private File dataDirectory;

    @Override
    protected void run() throws Exception {
        println("=== D2R semantic relocator ===");
        println("Program: " + currentProgram.getName());

        d2rDirectory = askDirectory("Select the d2.re D2R directory", "Select");
        dataDirectory = new File(d2rDirectory, "data");

        if (!dataDirectory.isDirectory()) {
            printerr("Missing data directory: " + dataDirectory.getAbsolutePath());
            return;
        }

        JsonArray functionsJson = readArray(new File(dataDirectory, "functions.json"));

        List<FunctionFeatures> currentFunctions = collectCurrentFunctionFeatures();

        println("Indexed current functions: " + currentFunctions.size());
        println("Old function entries: " + functionsJson.size());

        JsonArray report = new JsonArray();

        int processed = 0;
        int exact = 0;
        int ranked = 0;

        for (JsonElement element : functionsJson) {
            if (monitor.isCancelled()) {
                break;
            }

            if (element == null || !element.isJsonObject()) {
                continue;
            }

            JsonObject item = element.getAsJsonObject();
            String name = getString(item, "name", "<unnamed>");
            String pattern = getString(item, "pattern", null);

            if (pattern == null || pattern.trim().isEmpty()) {
                continue;
            }

            JsonObject out = new JsonObject();
            out.addProperty("name", name);
            out.addProperty("old_pattern", pattern);

            Address exactMatch = findPattern(pattern);

            if (exactMatch != null) {
                out.addProperty("status", "exact");
                out.addProperty("address", exactMatch.toString());
                out.addProperty("confidence", 1.0);
                exact++;
                report.add(out);
                processed++;
                continue;
            }

            PatternBytes old = parsePattern(pattern);
            List<Long> oldConstants = extractOldPatternConstants(old);

            List<Candidate> candidates = rankCandidates(old, oldConstants, currentFunctions);

            out.addProperty("status", "ranked");
            JsonArray candidateArray = new JsonArray();

            for (int i = 0; i < Math.min(TOP_N, candidates.size()); i++) {
                Candidate c = candidates.get(i);
                Function f = c.features.function;

                JsonObject co = new JsonObject();
                co.addProperty("rank", i + 1);
                co.addProperty("address", f.getEntryPoint().toString());
                co.addProperty("current_name", f.getName());
                co.addProperty("score", c.score);
                co.addProperty("entry_similarity", c.entrySimilarity);
                co.addProperty("size_score", c.sizeScore);
                co.addProperty("complexity_score", c.complexityScore);
                co.addProperty("size", c.features.size);
                co.addProperty("basic_blocks", c.features.basicBlocks);
                co.addProperty("callers", c.features.callers);
                co.addProperty("callees", c.features.callees);
                co.addProperty("referenced_strings", c.features.referencedStrings);
                co.addProperty("referenced_data", c.features.referencedData);

                candidateArray.add(co);
            }

            out.add("candidates", candidateArray);
            report.add(out);

            ranked++;
            processed++;

            if ((processed % 25) == 0) {
                println("Processed " + processed + " / " + functionsJson.size());
            }
        }

        File outFile = new File(dataDirectory, "_semantic_candidates.json");

        try (FileWriter writer = new FileWriter(outFile)) {
            gson.toJson(report, writer);
        }

        println("");
        println("=== Semantic relocation summary ===");
        println("Processed: " + processed);
        println("Exact: " + exact);
        println("Ranked unresolved: " + ranked);
        println("Report: " + outFile.getAbsolutePath());
        println("Done.");
    }

    // ---------------------------------------------------------------------
    // Candidate ranking
    // ---------------------------------------------------------------------

    private List<Candidate> rankCandidates(
        PatternBytes old,
        List<Long> oldConstants,
        List<FunctionFeatures> currentFunctions
    ) {

        List<Candidate> result = new ArrayList<>();

        for (FunctionFeatures ff : currentFunctions) {
            if (monitor.isCancelled()) {
                break;
            }

            Candidate c = new Candidate();
            c.features = ff;
            c.entrySimilarity = entrySimilarity(old, ff.function.getEntryPoint());
            c.sizeScore = sizeCompatibility(old.bytes.length, ff.size);
            c.complexityScore = complexityScore(ff, oldConstants);

            // Heavily weight surviving entry bytes, but still allow structure to
            // pull plausible candidates upward when the compiler changed prologues.
            c.score =
                0.60 * c.entrySimilarity +
                0.15 * c.sizeScore +
                0.25 * c.complexityScore;

            if (c.score > 0.05) {
                result.add(c);
            }
        }

        Collections.sort(
            result,
            new Comparator<Candidate>() {
                @Override
                public int compare(Candidate a, Candidate b) {
                    return Double.compare(b.score, a.score);
                }
            }
        );

        return result;
    }

    private double entrySimilarity(PatternBytes old, Address entry) {
        try {
            int compareLen = Math.min(old.bytes.length, MAX_ENTRY_COMPARE);
            byte[] current = new byte[compareLen];

            int got = currentProgram.getMemory().getBytes(entry, current);
            if (got <= 0) {
                return 0.0;
            }

            int exact = 0;
            int equal = 0;

            for (int i = 0; i < Math.min(got, compareLen); i++) {
                if ((old.mask[i] & 0xff) != 0xff) {
                    continue;
                }

                exact++;

                if (current[i] == old.bytes[i]) {
                    equal++;
                }
            }

            if (exact == 0) {
                return 0.0;
            }

            return ((double) equal) / ((double) exact);
        }
        catch (Exception e) {
            return 0.0;
        }
    }

    private double sizeCompatibility(int oldPatternLength, long functionSize) {
        // Old pattern length is only a lower-bound-ish hint, not historical size.
        // Reward functions large enough to plausibly contain it without strongly
        // preferring huge functions.
        if (functionSize <= 0) {
            return 0.0;
        }

        if (functionSize < oldPatternLength) {
            return Math.max(0.0, ((double) functionSize) / oldPatternLength * 0.5);
        }

        double ratio = ((double) oldPatternLength) / ((double) functionSize);

        if (ratio > 1.0) {
            ratio = 1.0;
        }

        return 0.5 + 0.5 * Math.sqrt(ratio);
    }

    private double complexityScore(FunctionFeatures ff, List<Long> oldConstants) {
        double score = 0.0;

        // Mild preference for nontrivial functions.
        if (ff.basicBlocks >= 2) {
            score += 0.10;
        }
        if (ff.basicBlocks >= 5) {
            score += 0.05;
        }

        if (ff.callees > 0) {
            score += 0.05;
        }
        if (ff.callers > 0) {
            score += 0.05;
        }
        if (ff.referencedStrings > 0) {
            score += 0.05;
        }
        if (ff.referencedData > 0) {
            score += 0.05;
        }

        if (!oldConstants.isEmpty()) {
            int matched = 0;

            for (Long value : oldConstants) {
                if (ff.immediates.contains(value)) {
                    matched++;
                }
            }

            double overlap = ((double) matched) / ((double) oldConstants.size());
            score += Math.min(0.60, overlap * 0.60);
        }

        if (score > 1.0) {
            score = 1.0;
        }

        return score;
    }

    // ---------------------------------------------------------------------
    // Current-program feature extraction
    // ---------------------------------------------------------------------

    private List<FunctionFeatures> collectCurrentFunctionFeatures() throws Exception {
        List<FunctionFeatures> result = new ArrayList<>();

        ReferenceManager refManager = currentProgram.getReferenceManager();
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

        FunctionIterator functions =
            currentProgram.getFunctionManager().getFunctions(true);

        int count = 0;

        while (functions.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }

            if (count >= MAX_FUNCTIONS) {
                break;
            }

            Function f = functions.next();
            FunctionFeatures ff = new FunctionFeatures();
            ff.function = f;
            ff.size = f.getBody().getNumAddresses();
            ff.basicBlocks = countBasicBlocks(blockModel, f);
            ff.callers = countCallers(refManager, f);
            ff.callees = f.getCalledFunctions(monitor).size();

            collectInstructionFeatures(f, ff);

            result.add(ff);
            count++;

            if ((count % 5000) == 0) {
                println("Indexed " + count + " current functions...");
            }
        }

        return result;
    }

    private int countBasicBlocks(BasicBlockModel model, Function f) {
        int count = 0;

        try {
            CodeBlockIterator blocks = model.getCodeBlocksContaining(f.getBody(), monitor);

            while (blocks.hasNext()) {
                blocks.next();
                count++;
            }
        }
        catch (Exception ignored) {
        }

        return count;
    }

    private int countCallers(ReferenceManager refManager, Function f) {
        Set<Address> callers = new HashSet<>();

        ReferenceIterator refs =
            refManager.getReferencesTo(f.getEntryPoint());

        while (refs.hasNext()) {
            Reference ref = refs.next();

            if (!ref.getReferenceType().isCall()) {
                continue;
            }

            Function caller =
                currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());

            if (caller != null) {
                callers.add(caller.getEntryPoint());
            }
        }

        return callers.size();
    }

    private void collectInstructionFeatures(Function f, FunctionFeatures ff) {
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(f.getBody(), true);

        Set<Address> stringAddresses = new HashSet<>();
        Set<Address> dataAddresses = new HashSet<>();

        while (instructions.hasNext()) {
            Instruction ins = instructions.next();

            for (int op = 0; op < ins.getNumOperands(); op++) {
                Object[] objects = ins.getOpObjects(op);

                if (objects != null) {
                    for (Object object : objects) {
                        if (object instanceof Scalar) {
                            Scalar scalar = (Scalar) object;
                            long value = scalar.getUnsignedValue();

                            // Ignore tiny values which are usually register masks,
                            // stack offsets, or mundane loop constants.
                            if (value >= 0x10) {
                                ff.immediates.add(value);
                            }
                        }
                    }
                }

                Reference[] refs = ins.getOperandReferences(op);

                if (refs == null) {
                    continue;
                }

                for (Reference ref : refs) {
                    Address to = ref.getToAddress();

                    if (to == null || !to.isMemoryAddress()) {
                        continue;
                    }

                    CodeUnit cu = currentProgram.getListing().getCodeUnitAt(to);

                    if (cu != null && cu.toString().startsWith("\"")) {
                        stringAddresses.add(to);
                        continue;
                    }

                    Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(to);

                    if (
                        symbol != null &&
                        symbol.getSymbolType() != SymbolType.FUNCTION
                    ) {
                        dataAddresses.add(to);
                    }
                }
            }
        }

        ff.referencedStrings = stringAddresses.size();
        ff.referencedData = dataAddresses.size();
    }

    // ---------------------------------------------------------------------
    // Old-pattern metadata extraction
    // ---------------------------------------------------------------------

    private List<Long> extractOldPatternConstants(PatternBytes old) {
        LinkedHashSet<Long> constants = new LinkedHashSet<>();

        // Pull fixed 32-bit little-endian windows from the old signature.
        // This is crude but occasionally preserves meaningful immediates.
        for (int i = 0; i <= old.bytes.length - 4; i++) {
            boolean allExact = true;

            for (int j = 0; j < 4; j++) {
                if ((old.mask[i + j] & 0xff) != 0xff) {
                    allExact = false;
                    break;
                }
            }

            if (!allExact) {
                continue;
            }

            long value =
                ((long) old.bytes[i] & 0xffL) |
                (((long) old.bytes[i + 1] & 0xffL) << 8) |
                (((long) old.bytes[i + 2] & 0xffL) << 16) |
                (((long) old.bytes[i + 3] & 0xffL) << 24);

            if (value >= 0x1000L) {
                constants.add(value);
            }
        }

        return new ArrayList<>(constants);
    }

    // ---------------------------------------------------------------------
    // Pattern handling
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
                        "Unsupported token '" + token + "' in: " + pattern
                    );
                }

                bytes[i] = (byte) Integer.parseInt(token, 16);
                mask[i] = (byte) 0xff;
            }
        }

        return new PatternBytes(bytes, mask);
    }

    private Address findPattern(String pattern) throws Exception {
        PatternBytes parsed = parsePattern(pattern);
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }

            Address found = memory.findBytes(
                block.getStart(),
                block.getEnd(),
                parsed.bytes,
                parsed.mask,
                true,
                monitor
            );

            if (found != null) {
                return found;
            }
        }

        return null;
    }

    // ---------------------------------------------------------------------
    // JSON helpers
    // ---------------------------------------------------------------------

    private JsonArray readArray(File file) throws Exception {
        if (!file.isFile()) {
            throw new IllegalStateException(
                "Missing required file: " + file.getAbsolutePath()
            );
        }

        try (FileReader reader = new FileReader(file)) {
            JsonElement root = JsonParser.parseReader(reader);

            if (!root.isJsonArray()) {
                throw new IllegalStateException(
                    "Expected JSON array: " + file.getAbsolutePath()
                );
            }

            return root.getAsJsonArray();
        }
    }

    private String getString(
        JsonObject item,
        String key,
        String defaultValue
    ) {
        if (item == null || !item.has(key) || item.get(key).isJsonNull()) {
            return defaultValue;
        }

        return item.get(key).getAsString();
    }
}
