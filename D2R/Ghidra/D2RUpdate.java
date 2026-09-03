// D2RUpdate.java
// Ghidra port of D2R/update.py
//
// Run from Ghidra Script Manager after importing/analyzing D2R.exe.
// When prompted, select the repository's D2R directory, e.g.
// D:\Projects\RE\d2.re\D2R
//
// This version includes a corrected masked byte-pattern scanner and
// startup diagnostics to distinguish scanner failures from stale signatures.

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
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class D2RUpdate extends GhidraScript {

    private static class PatternBytes {
        final byte[] bytes;
        final byte[] mask;

        PatternBytes(byte[] bytes, byte[] mask) {
            this.bytes = bytes;
            this.mask = mask;
        }
    }

    private final Gson gson = new Gson();

    private File d2rDirectory;
    private File dataDirectory;

    private List<JsonObject> functions = new ArrayList<>();
    private List<JsonObject> variables = new ArrayList<>();

    private int renamedFunctions = 0;
    private int renamedVariables = 0;
    private int brokenSignatures = 0;
    private int resolutionFailures = 0;
    private int typeApplicationsSkippedOrFailed = 0;

    @Override
    protected void run() throws Exception {
        println("=== D2R Ghidra importer ===");
        println("Program: " + currentProgram.getName());
        println("Image base: " + currentProgram.getImageBase());

        printMemoryDiagnostics();
        runExactScannerSelfTest();

        d2rDirectory = askDirectory(
            "Select the d2.re D2R directory",
            "Select"
        );

        dataDirectory = new File(d2rDirectory, "data");

        if (!dataDirectory.isDirectory()) {
            printerr(
                "Missing data directory: " +
                dataDirectory.getAbsolutePath()
            );
            return;
        }

        functions = loadJsonItems(
            "functions.json",
            "_functions.json"
        );

        variables = loadJsonItems(
            "variables.json",
            "_variables.json"
        );

        println("Loaded functions: " + functions.size());
        println("Loaded variables: " + variables.size());

        runRepositorySignatureSelfTest();

        println("");
        println("=== Processing functions ===");

        for (JsonObject item : functions) {
            if (monitor.isCancelled()) {
                break;
            }

            processFunction(item);
        }

        println("");
        println("=== Processing variables ===");

        for (JsonObject item : variables) {
            if (monitor.isCancelled()) {
                break;
            }

            processVariable(item);
        }

        println("");
        println("=== Expanding known D2R function tables ===");

        expandKnownFunctionTables();

        println("");
        println(
            "Renamed/created " +
            renamedFunctions +
            " functions and " +
            renamedVariables +
            " variables."
        );

        println(
            "Broken signatures: " +
            brokenSignatures
        );

        println(
            "Address/operand resolution failures: " +
            resolutionFailures
        );

        println(
            "Type/signature applications skipped or failed: " +
            typeApplicationsSkippedOrFailed
        );

        println("Done.");
    }

    // ================================================================
    // Diagnostics
    // ================================================================

    private void printMemoryDiagnostics() {
        println("");
        println("=== Memory map ===");

        for (MemoryBlock block :
            currentProgram.getMemory().getBlocks()) {

            println(
                "Memory block: " +
                block.getName() +
                " " +
                block.getStart() +
                " - " +
                block.getEnd() +
                " initialized=" +
                block.isInitialized() +
                " execute=" +
                block.isExecute()
            );
        }
    }

    /*
     * Take bytes directly from Ghidra's first executable block
     * and search for them again.
     *
     * This must find the same address. If it does not, the
     * underlying scanner itself is not functioning correctly.
     */
    private void runExactScannerSelfTest()
        throws Exception {

        println("");
        println("=== Exact scanner self-test ===");

        Memory memory =
            currentProgram.getMemory();

        MemoryBlock executable = null;

        for (MemoryBlock block :
            memory.getBlocks()) {

            if (
                block.isInitialized() &&
                block.isExecute() &&
                block.getSize() > 0
            ) {
                executable = block;
                break;
            }
        }

        if (executable == null) {
            println(
                "Exact scanner self-test: SKIPPED " +
                "(no initialized executable block)"
            );
            return;
        }

        int testLength =
            (int)Math.min(
                8L,
                executable.getSize()
            );

        byte[] testBytes =
            new byte[testLength];

        int read =
            memory.getBytes(
                executable.getStart(),
                testBytes
            );

        if (read != testLength) {
            println(
                "Exact scanner self-test: FAILED " +
                "(could not read initial executable bytes)"
            );
            return;
        }

        StringBuilder sb =
            new StringBuilder();

        for (byte b : testBytes) {
            sb.append(
                String.format(
                    "%02X ",
                    b & 0xff
                )
            );
        }

        println(
            "Executable block: " +
            executable.getName()
        );

        println(
            "First executable bytes: " +
            sb.toString().trim()
        );

        Address selfMatch =
            memory.findBytes(
                executable.getStart(),
                executable.getEnd(),
                testBytes,
                null,
                true,
                monitor
            );

        println(
            "Exact scanner self-test result: " +
            (
                selfMatch == null
                    ? "NOT FOUND"
                    : selfMatch.toString()
            )
        );

        if (
            selfMatch == null ||
            !selfMatch.equals(
                executable.getStart()
            )
        ) {
            println(
                "WARNING: scanner self-test did not " +
                "return the expected address."
            );
        }
    }

    private void runRepositorySignatureSelfTest()
        throws Exception {

        println("");
        println(
            "=== Repository signature scanner test ==="
        );

        JsonObject first = null;

        if (!functions.isEmpty()) {
            first = functions.get(0);
        }
        else if (!variables.isEmpty()) {
            first = variables.get(0);
        }

        if (first == null) {
            println(
                "Repository scanner test: SKIPPED " +
                "(no signatures loaded)"
            );
            return;
        }

        String name =
            getString(
                first,
                "name",
                "<unnamed>"
            );

        String pattern =
            getString(
                first,
                "pattern",
                null
            );

        if (
            pattern == null ||
            pattern.trim().isEmpty()
        ) {
            println(
                "Repository scanner test: SKIPPED " +
                "(first item has no pattern)"
            );
            return;
        }

        println(
            "Scanner test name: " +
            name
        );

        println(
            "Scanner test pattern: " +
            pattern
        );

        PatternBytes parsed =
            parsePattern(pattern);

        int exact =
            countExactMaskBytes(
                parsed.mask
            );

        println(
            "Scanner test bytes: " +
            parsed.bytes.length
        );

        println(
            "Scanner test exact bytes: " +
            exact
        );

        println(
            "Scanner test wildcard bytes: " +
            (
                parsed.mask.length -
                exact
            )
        );

        Address result =
            findPattern(pattern);

        println(
            "Scanner test result: " +
            (
                result == null
                    ? "NOT FOUND"
                    : "FOUND at " + result
            )
        );
    }

    private int countExactMaskBytes(
        byte[] mask
    ) {
        int count = 0;

        for (byte b : mask) {
            if (
                (b & 0xff) ==
                0xff
            ) {
                count++;
            }
        }

        return count;
    }

    // ================================================================
    // JSON loading
    // ================================================================

    private List<JsonObject> loadJsonItems(
        String requiredName,
        String optionalName
    ) throws Exception {

        List<JsonObject> result =
            new ArrayList<>();

        File required =
            new File(
                dataDirectory,
                requiredName
            );

        if (!required.isFile()) {
            throw new IllegalStateException(
                "Missing required file: " +
                required.getAbsolutePath()
            );
        }

        result.addAll(
            readJsonArray(required)
        );

        File optional =
            new File(
                dataDirectory,
                optionalName
            );

        if (optional.isFile()) {
            result.addAll(
                readJsonArray(optional)
            );
        }

        return result;
    }

    private List<JsonObject> readJsonArray(
        File file
    ) throws Exception {

        List<JsonObject> result =
            new ArrayList<>();

        try (
            FileReader reader =
                new FileReader(file)
        ) {

            JsonArray array =
                gson.fromJson(
                    reader,
                    JsonArray.class
                );

            if (array == null) {
                return result;
            }

            for (JsonElement element :
                array) {

                if (
                    element != null &&
                    element.isJsonObject()
                ) {
                    result.add(
                        element.getAsJsonObject()
                    );
                }
            }
        }

        return result;
    }

    private String getString(
        JsonObject item,
        String key,
        String defaultValue
    ) {
        if (
            item == null ||
            !item.has(key) ||
            item.get(key).isJsonNull()
        ) {
            return defaultValue;
        }

        return item
            .get(key)
            .getAsString();
    }

    private int getInt(
        JsonObject item,
        String key,
        int defaultValue
    ) {
        if (
            item == null ||
            !item.has(key) ||
            item.get(key).isJsonNull()
        ) {
            return defaultValue;
        }

        return item
            .get(key)
            .getAsInt();
    }

    // ================================================================
    // Pattern scanner
    // ================================================================

    /*
     * IDA-style:
     *
     * 48 8B 05 ?? ?? ?? ?? 48 85 C0
     *
     * Ghidra mask:
     *
     * exact byte -> FF
     * wildcard   -> 00
     */
    private PatternBytes parsePattern(
        String pattern
    ) {
        if (pattern == null) {
            throw new IllegalArgumentException(
                "Pattern is null"
            );
        }

        String trimmed =
            pattern.trim();

        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(
                "Pattern is empty"
            );
        }

        String[] tokens =
            trimmed.split("\\s+");

        byte[] bytes =
            new byte[tokens.length];

        byte[] mask =
            new byte[tokens.length];

        for (
            int i = 0;
            i < tokens.length;
            i++
        ) {

            String token =
                tokens[i].trim();

            if (
                token.equals("?") ||
                token.equals("??")
            ) {
                bytes[i] = 0;
                mask[i] = 0;
                continue;
            }

            if (token.length() != 2) {
                throw new IllegalArgumentException(
                    "Unsupported pattern token '" +
                    token +
                    "' in: " +
                    pattern
                );
            }

            bytes[i] =
                (byte)Integer.parseInt(
                    token,
                    16
                );

            mask[i] =
                (byte)0xff;
        }

        return new PatternBytes(
            bytes,
            mask
        );
    }

    private Address findPattern(
        String pattern
    ) throws Exception {

        PatternBytes parsed =
            parsePattern(pattern);

        Memory memory =
            currentProgram.getMemory();

        for (MemoryBlock block :
            memory.getBlocks()) {

            if (monitor.isCancelled()) {
                return null;
            }

            if (!block.isInitialized()) {
                continue;
            }

            if (
                block.getSize() <
                parsed.bytes.length
            ) {
                continue;
            }

            Address result =
                memory.findBytes(
                    block.getStart(),
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

    // ================================================================
    // Signature target resolution
    // ================================================================

    private Address resolveItemAddress(
        JsonObject item
    ) throws Exception {

        String pattern =
            getString(
                item,
                "pattern",
                null
            );

        String type =
            getString(
                item,
                "type",
                "absolute"
            );

        if (
            pattern == null ||
            pattern.trim().isEmpty()
        ) {
            return null;
        }

        Address match =
            findPattern(pattern);

        if (match == null) {
            return null;
        }

        if (
            "absolute".equalsIgnoreCase(
                type
            )
        ) {
            return match;
        }

        int operandIndex =
            getInt(
                item,
                "operand",
                0
            );

        if (
            "operand".equalsIgnoreCase(
                type
            )
        ) {
            return resolveOperandAddress(
                match,
                operandIndex,
                false
            );
        }

        if (
            "other".equalsIgnoreCase(
                type
            )
        ) {
            /*
             * IDA version does:
             *
             * imageBase +
             * get_operand_value(...)
             */
            return resolveOperandAddress(
                match,
                operandIndex,
                true
            );
        }

        println(
            "Unknown signature type '" +
            type +
            "' for " +
            getString(
                item,
                "name",
                "<unnamed>"
            )
        );

        return match;
    }

    private Address resolveOperandAddress(
        Address instructionAddress,
        int operandIndex,
        boolean addImageBase
    ) throws Exception {

        Instruction instruction =
            currentProgram
                .getListing()
                .getInstructionAt(
                    instructionAddress
                );

        if (instruction == null) {
            return null;
        }

        if (
            operandIndex < 0 ||
            operandIndex >=
                instruction.getNumOperands()
        ) {
            return null;
        }

        /*
         * "other" signatures need the raw scalar displacement.
         */
        if (addImageBase) {
            Scalar scalar =
                getOperandScalar(
                    instruction,
                    operandIndex
                );

            if (scalar != null) {
                try {
                    return currentProgram
                        .getImageBase()
                        .add(
                            scalar.getSignedValue()
                        );
                }
                catch (Exception ignored) {
                }
            }
        }

        /*
         * Ghidra normally creates references for:
         * - CALL targets
         * - JMP targets
         * - RIP-relative variables
         */
        Reference[] refs =
            instruction
                .getOperandReferences(
                    operandIndex
                );

        if (
            refs != null &&
            refs.length > 0
        ) {

            for (Reference ref : refs) {

                Address to =
                    ref.getToAddress();

                if (
                    to != null &&
                    to.isMemoryAddress()
                ) {
                    return to;
                }
            }

            if (
                refs[0].getToAddress() != null
            ) {
                return refs[0]
                    .getToAddress();
            }
        }

        Scalar scalar =
            getOperandScalar(
                instruction,
                operandIndex
            );

        if (scalar == null) {
            return null;
        }

        /*
         * Fallback for unresolved relative CALL/JMP.
         */
        String mnemonic =
            instruction
                .getMnemonicString()
                .toUpperCase();

        if (
            mnemonic.startsWith("CALL") ||
            mnemonic.startsWith("J")
        ) {
            try {
                return instruction
                    .getMaxAddress()
                    .add(1)
                    .add(
                        scalar.getSignedValue()
                    );
            }
            catch (Exception ignored) {
            }
        }

        /*
         * Last fallback: scalar interpreted as absolute address.
         */
        try {
            AddressSpace space =
                currentProgram
                    .getAddressFactory()
                    .getDefaultAddressSpace();

            Address candidate =
                space.getAddress(
                    scalar.getUnsignedValue()
                );

            if (
                currentProgram
                    .getMemory()
                    .contains(candidate)
            ) {
                return candidate;
            }
        }
        catch (Exception ignored) {
        }

        return null;
    }

    private Scalar getOperandScalar(
        Instruction instruction,
        int operandIndex
    ) {
        Object[] objects =
            instruction.getOpObjects(
                operandIndex
            );

        if (objects == null) {
            return null;
        }

        for (Object object : objects) {
            if (object instanceof Scalar) {
                return (Scalar)object;
            }
        }

        return null;
    }

    // ================================================================
    // Functions / variables
    // ================================================================

    private void processFunction(
        JsonObject item
    ) throws Exception {

        String name =
            getString(
                item,
                "name",
                "<unnamed>"
            );

        Address address;

        try {
            address =
                resolveItemAddress(item);
        }
        catch (Exception e) {
            brokenSignatures++;

            println(
                "[ERROR] " +
                name +
                " - scanner error: " +
                e.getMessage()
            );

            return;
        }

        if (address == null) {
            brokenSignatures++;

            println(
                "[BROKEN] " +
                name +
                " - signature not found/resolved"
            );

            return;
        }

        Function function =
            ensureFunction(
                address,
                name
            );

        if (function == null) {
            resolutionFailures++;

            println(
                "[RESOLVE FAILED] " +
                name +
                " @ " +
                address
            );

            return;
        }

        try {
            function.setName(
                name,
                SourceType.USER_DEFINED
            );
        }
        catch (Exception e) {
            println(
                "[NAME FAILED] " +
                name +
                " @ " +
                address +
                ": " +
                e.getMessage()
            );

            return;
        }

        String summary =
            getString(
                item,
                "summary",
                null
            );

        applySummary(
            address,
            function,
            summary
        );

        renamedFunctions++;

        println(
            "[FUNC] " +
            name +
            " @ " +
            address
        );
    }

    private void processVariable(
        JsonObject item
    ) throws Exception {

        String name =
            getString(
                item,
                "name",
                "<unnamed>"
            );

        Address address;

        try {
            address =
                resolveItemAddress(item);
        }
        catch (Exception e) {
            brokenSignatures++;

            println(
                "[ERROR] " +
                name +
                " - scanner error: " +
                e.getMessage()
            );

            return;
        }

        if (address == null) {
            brokenSignatures++;

            println(
                "[BROKEN] " +
                name +
                " - signature not found/resolved"
            );

            return;
        }

        try {
            createOrRenameGlobalLabel(
                address,
                name
            );
        }
        catch (Exception e) {
            resolutionFailures++;

            println(
                "[NAME FAILED] " +
                name +
                " @ " +
                address +
                ": " +
                e.getMessage()
            );

            return;
        }

        String summary =
            getString(
                item,
                "summary",
                null
            );

        applySummary(
            address,
            null,
            summary
        );

        renamedVariables++;

        println(
            "[VAR ] " +
            name +
            " @ " +
            address
        );
    }

    private Function ensureFunction(
        Address address,
        String name
    ) {

        Function function =
            currentProgram
                .getFunctionManager()
                .getFunctionAt(address);

        if (function != null) {
            return function;
        }

        try {
            function =
                createFunction(
                    address,
                    name
                );
        }
        catch (Exception ignored) {
            function = null;
        }

        if (function == null) {
            return currentProgram
                .getFunctionManager()
                .getFunctionAt(address);
        }

        return function;
    }

    private void createOrRenameGlobalLabel(
        Address address,
        String name
    ) throws Exception {

        Symbol primary =
            currentProgram
                .getSymbolTable()
                .getPrimarySymbol(address);

        if (
            primary != null &&
            primary.getSource() ==
                SourceType.DEFAULT
        ) {
            primary.setName(
                name,
                SourceType.USER_DEFINED
            );

            return;
        }

        List<Symbol> existing =
            currentProgram
                .getSymbolTable()
                .getGlobalSymbols(name);

        if (existing != null) {
            for (Symbol symbol :
                existing) {

                if (
                    address.equals(
                        symbol.getAddress()
                    )
                ) {
                    if (!symbol.isPrimary()) {
                        symbol.setPrimary();
                    }

                    return;
                }
            }
        }

        Symbol created =
            currentProgram
                .getSymbolTable()
                .createLabel(
                    address,
                    name,
                    SourceType.USER_DEFINED
                );

        if (
            created != null &&
            !created.isPrimary()
        ) {
            created.setPrimary();
        }
    }

    private void applySummary(
        Address address,
        Function function,
        String summary
    ) {

        if (
            summary == null ||
            summary.trim().isEmpty()
        ) {
            return;
        }

        try {
            currentProgram
                .getListing()
                .setComment(
                    address,
                    CodeUnit.PLATE_COMMENT,
                    summary
                );
        }
        catch (Exception ignored) {
        }

        if (function != null) {
            try {
                function.setComment(
                    summary
                );
            }
            catch (Exception ignored) {
            }
        }
    }

    // ================================================================
    // Known D2R function tables
    // ================================================================

    private void expandKnownFunctionTables()
        throws Exception {

        expandD2GSS2C();

        expandSimplePointerTable(
            "g_D2GS_C2S_FunctionTable",
            0x64,
            0x8,
            "D2GS_C2S_0x%02X_PacketHandler"
        );

        expandSimplePointerTable(
            "g_SkillsSrvStFunc",
            0x42,
            0x8,
            "SKILLS_SrvStFunc_%03d"
        );

        expandSimplePointerTable(
            "g_SkillsSrvDoFunc",
            0x98,
            0x8,
            "SKILLS_SrvDoFunc_%03d"
        );

        expandSimplePointerTable(
            "g_SkillsCltStFunc",
            0x35,
            0x8,
            "SKILLS_CltStFunc_%03d"
        );

        expandSimplePointerTable(
            "g_SkillsCltDoFunc",
            0x60,
            0x8,
            "SKILLS_CltDoFunc_%03d"
        );

        expandSimplePointerTable(
            "g_AssignProperty",
            0x20,
            0x8,
            "ITEMMODS_PropertyFunc_%02d"
        );
    }

    private void expandD2GSS2C()
        throws Exception {

        Address table =
            getGlobalAddress(
                "g_D2GS_S2C_FunctionTable"
            );

        if (table == null) {
            println(
                "Skipping g_D2GS_S2C_FunctionTable " +
                "expansion (table not resolved)"
            );
            return;
        }

        println(
            "Expanding g_D2GS_S2C_FunctionTable @ " +
            table
        );

        for (
            int i = 0;
            i < 0xAE;
            i++
        ) {

            if (monitor.isCancelled()) {
                return;
            }

            Address entry =
                table.add(
                    (long)i * 0x18L
                );

            Address handler =
                readPointer(entry);

            if (handler != null) {
                renameTableFunction(
                    handler,
                    String.format(
                        "D2GS_S2C_0x%02X_PacketHandler",
                        i
                    )
                );
            }

            Address sizeAddress =
                entry.add(0x8);

            try {
                createOrRenameGlobalLabel(
                    sizeAddress,
                    String.format(
                        "D2GS_S2C_0x%02X_PacketSize",
                        i
                    )
                );
            }
            catch (Exception ignored) {
            }

            Address handlerEx =
                readPointer(
                    entry.add(0x10)
                );

            if (handlerEx != null) {
                renameTableFunction(
                    handlerEx,
                    String.format(
                        "D2GS_S2C_0x%02X_PacketHandlerEx",
                        i
                    )
                );
            }
        }
    }

    private void expandSimplePointerTable(
        String tableName,
        int count,
        int stride,
        String format
    ) throws Exception {

        Address table =
            getGlobalAddress(
                tableName
            );

        if (table == null) {
            println(
                "Skipping " +
                tableName +
                " expansion " +
                "(table not resolved)"
            );

            return;
        }

        println(
            "Expanding " +
            tableName +
            " @ " +
            table
        );

        for (
            int i = 0;
            i < count;
            i++
        ) {

            if (monitor.isCancelled()) {
                return;
            }

            Address pointerAddress =
                table.add(
                    (long)i *
                    (long)stride
                );

            Address functionAddress =
                readPointer(
                    pointerAddress
                );

            if (functionAddress == null) {
                continue;
            }

            String functionName =
                String.format(
                    format,
                    i
                );

            renameTableFunction(
                functionAddress,
                functionName
            );
        }
    }

    private void renameTableFunction(
        Address address,
        String name
    ) {

        if (
            address == null ||
            !currentProgram
                .getMemory()
                .contains(address)
        ) {
            return;
        }

        Function function =
            ensureFunction(
                address,
                name
            );

        if (function == null) {
            return;
        }

        try {
            function.setName(
                name,
                SourceType.USER_DEFINED
            );

            renamedFunctions++;
        }
        catch (Exception ignored) {
        }
    }

    private Address getGlobalAddress(
        String name
    ) {

        List<Symbol> symbols =
            currentProgram
                .getSymbolTable()
                .getGlobalSymbols(name);

        if (
            symbols == null ||
            symbols.isEmpty()
        ) {
            return null;
        }

        return symbols
            .get(0)
            .getAddress();
    }

    private Address readPointer(
        Address pointerAddress
    ) {

        try {
            long raw =
                currentProgram
                    .getMemory()
                    .getLong(
                        pointerAddress
                    );

            if (raw == 0) {
                return null;
            }

            AddressSpace space =
                currentProgram
                    .getAddressFactory()
                    .getDefaultAddressSpace();

            Address target =
                space.getAddress(raw);

            if (
                !currentProgram
                    .getMemory()
                    .contains(target)
            ) {
                return null;
            }

            return target;
        }
        catch (Exception e) {
            return null;
        }
    }
}
