// Port of D2R/update.py for Ghidra.
// Reuses D2R/data/functions.json and variables.json without changing their format.
//@author d2.re contributors
//@category D2R

import com.google.gson.*;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

public class D2RUpdate extends GhidraScript {

    private static class PatternBytes {
        final byte[] bytes;
        final byte[] mask;
        PatternBytes(byte[] bytes, byte[] mask) {
            this.bytes = bytes;
            this.mask = mask;
        }
    }

    private File d2rDir;
    private Address imageBase;
    private Listing listing;
    private Memory memory;
    private FunctionManager functionManager;
    private SymbolTable symbolTable;
    private DataTypeManager dataTypeManager;
    private DataTypeManagerService dtmService;

    private int functionCount = 0;
    private int variableCount = 0;
    private int brokenCount = 0;
    private int typeFailureCount = 0;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            popup("Open D2R.exe in Ghidra before running D2RUpdate.");
            return;
        }

        File selected = askDirectory("Select the d2.re D2R directory", "Select D2R");
        d2rDir = normalizeD2RDirectory(selected);
        if (d2rDir == null) {
            popup("Could not find data/functions.json and data/variables.json under the selected directory.");
            return;
        }

        imageBase = currentProgram.getImageBase();
        listing = currentProgram.getListing();
        memory = currentProgram.getMemory();
        functionManager = currentProgram.getFunctionManager();
        symbolTable = currentProgram.getSymbolTable();
        dataTypeManager = currentProgram.getDataTypeManager();
        dtmService = state.getTool().getService(DataTypeManagerService.class);

        println("// d2.re Ghidra updater");
        println("// Program: " + currentProgram.getName());
        println("// Image Base: " + imageBase);
        println("// Data directory: " + new File(d2rDir, "data").getAbsolutePath());

        List<JsonObject> functions = loadEntries("functions.json", "_functions.json");
        List<JsonObject> variables = loadEntries("variables.json", "_variables.json");

        println("Loaded " + functions.size() + " function signatures and " + variables.size() + " variable signatures.");

        for (JsonObject item : functions) {
            if (monitor.isCancelled()) return;
            applyFunctionEntry(item);
        }

        for (JsonObject item : variables) {
            if (monitor.isCancelled()) return;
            applyVariableEntry(item);
        }

        renameKnownTables(variables);

        println("");
        println("Renamed/created " + functionCount + " functions and " + variableCount + " variables.");
        println("Broken signatures: " + brokenCount);
        println("Type/signature applications skipped or failed: " + typeFailureCount);
        println("Done.");
    }

    private File normalizeD2RDirectory(File selected) {
        if (selected == null) return null;
        if (hasDataFiles(selected)) return selected;
        File child = new File(selected, "D2R");
        if (hasDataFiles(child)) return child;
        return null;
    }

    private boolean hasDataFiles(File dir) {
        return dir != null &&
            new File(dir, "data/functions.json").isFile() &&
            new File(dir, "data/variables.json").isFile();
    }

    private List<JsonObject> loadEntries(String publicName, String privateName) throws IOException {
        ArrayList<JsonObject> out = new ArrayList<>();
        readJsonArray(new File(d2rDir, "data/" + publicName), out);
        File optional = new File(d2rDir, "data/" + privateName);
        if (optional.isFile()) readJsonArray(optional, out);
        out.sort(Comparator.comparing(o -> getString(o, "name", "")));
        return out;
    }

    private void readJsonArray(File file, List<JsonObject> out) throws IOException {
        String text = Files.readString(file.toPath(), StandardCharsets.UTF_8);
        JsonArray array = JsonParser.parseString(text).getAsJsonArray();
        for (JsonElement e : array) out.add(e.getAsJsonObject());
    }

    private void applyFunctionEntry(JsonObject item) {
        String name = getString(item, "name", "unnamed");
        Address resolved = resolveItem(item);
        if (resolved == null) {
            brokenCount++;
            println(String.format("[BROKEN] %-60s pattern not found/resolved", name));
            return;
        }

        try {
            Function f = getOrCreateFunction(resolved, name);
            if (f == null) {
                println("[WARN] Could not create function " + name + " at " + resolved);
                return;
            }

            f.setName(name, SourceType.USER_DEFINED);
            functionCount++;

            String summary = getString(item, "summary", null);
            if (summary != null && !summary.isBlank()) {
                f.setComment(summary);
                setPlateComment(resolved, summary);
            }

            String ret = getString(item, "ret", null);
            String args = getString(item, "args", null);
            if (ret != null && args != null) {
                applyFunctionSignature(f, ret, name, args);
            }

            println(String.format("[FUNC]   %-60s %s (+0x%X)", name, resolved, resolved.subtract(imageBase)));
        }
        catch (Exception e) {
            println("[WARN] " + name + " at " + resolved + ": " + e.getMessage());
        }
    }

    private void applyVariableEntry(JsonObject item) {
        String name = getString(item, "name", "unnamed");
        Address resolved = resolveItem(item);
        if (resolved == null) {
            brokenCount++;
            println(String.format("[BROKEN] %-60s pattern not found/resolved", name));
            return;
        }

        try {
            removeExistingUserSymbol(name, resolved);
            createLabel(resolved, name, true, SourceType.USER_DEFINED);
            variableCount++;

            String summary = getString(item, "summary", null);
            if (summary != null && !summary.isBlank()) setPlateComment(resolved, summary);

            String ctype = getString(item, "ctype", null);
            if (ctype != null && !ctype.equals("void")) {
                applyVariableType(resolved, ctype);
            }

            println(String.format("[VAR]    %-60s %s (+0x%X)", name, resolved, resolved.subtract(imageBase)));
        }
        catch (Exception e) {
            println("[WARN] " + name + " at " + resolved + ": " + e.getMessage());
        }
    }

    private Address resolveItem(JsonObject item) {
        String pattern = getString(item, "pattern", null);
        if (pattern == null) return null;

        Address match = findPattern(pattern);
        if (match == null) return null;

        String type = getString(item, "type", "absolute");
        if (type.equals("absolute")) return match;

        int operand = getInt(item, "operand", 0);
        Instruction ins = listing.getInstructionAt(match);
        if (ins == null) {
            disassemble(match);
            ins = listing.getInstructionAt(match);
        }
        if (ins == null || operand < 0 || operand >= ins.getNumOperands()) return null;

        if (type.equals("operand")) {
            Address target = resolveOperandReference(ins, operand);
            if (target != null) return target;
            return resolveOperandAddressObject(ins, operand);
        }

        if (type.equals("other")) {
            Long value = resolveOperandScalar(ins, operand);
            if (value == null) {
                Address a = resolveOperandAddressObject(ins, operand);
                if (a != null) value = a.getOffset();
            }
            if (value == null) return null;
            try {
                return imageBase.add(value);
            }
            catch (AddressOutOfBoundsException e) {
                return null;
            }
        }

        return match;
    }

    private Address resolveOperandReference(Instruction ins, int operandIndex) {
        Reference[] refs = ins.getOperandReferences(operandIndex);
        for (Reference ref : refs) {
            if (ref.isMemoryReference()) return ref.getToAddress();
        }
        return null;
    }

    private Address resolveOperandAddressObject(Instruction ins, int operandIndex) {
        for (Object obj : ins.getOpObjects(operandIndex)) {
            if (obj instanceof Address) return (Address)obj;
        }
        return null;
    }

    private Long resolveOperandScalar(Instruction ins, int operandIndex) {
        for (Object obj : ins.getOpObjects(operandIndex)) {
            if (obj instanceof Scalar) return ((Scalar)obj).getUnsignedValue();
        }
        return null;
    }

    private Address findPattern(String text) {
        PatternBytes p;
        try {
            p = parsePattern(text);
        }
        catch (IllegalArgumentException e) {
            println("[WARN] Invalid pattern '" + text + "': " + e.getMessage());
            return null;
        }

        for (MemoryBlock block : memory.getBlocks()) {
            if (monitor.isCancelled()) return null;
            if (!block.isInitialized()) continue;
            Address found = memory.findBytes(block.getStart(), block.getEnd(), p.bytes, p.mask, true, monitor);
            if (found != null) return found;
        }
        return null;
    }

    private PatternBytes parsePattern(String text) {
        String[] tokens = text.trim().split("\\s+");
        byte[] bytes = new byte[tokens.length];
        byte[] mask = new byte[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            String t = tokens[i].trim();
            if (t.equals("?") || t.equals("??")) {
                bytes[i] = 0;
                mask[i] = 0;
            }
            else {
                if (t.length() != 2) throw new IllegalArgumentException("bad byte token " + t);
                bytes[i] = (byte)Integer.parseInt(t, 16);
                mask[i] = (byte)0xff;
            }
        }
        return new PatternBytes(bytes, mask);
    }

    private Function getOrCreateFunction(Address address, String name) throws Exception {
        Function f = functionManager.getFunctionAt(address);
        if (f != null) return f;

        disassemble(address);
        f = createFunction(address, name);
        if (f == null) f = functionManager.getFunctionAt(address);
        return f;
    }

    private void removeExistingUserSymbol(String name, Address desiredAddress) {
        SymbolIterator it = symbolTable.getSymbols(name);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (!s.getAddress().equals(desiredAddress) && s.getSource() == SourceType.USER_DEFINED) {
                s.delete();
            }
        }
    }

    private void applyFunctionSignature(Function f, String ret, String name, String args) {
        String cleanedRet = normalizeCType(ret);
        String cleanedArgs = normalizeArgumentText(args);
        String declaration = cleanedRet + " " + name + cleanedArgs;

        try {
            FunctionSignatureParser parser = new FunctionSignatureParser(dataTypeManager, dtmService);
            FunctionSignature signature = parser.parse(null, declaration);
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                f.getEntryPoint(), signature, SourceType.USER_DEFINED);
            if (!cmd.applyTo(currentProgram, monitor)) {
                typeFailureCount++;
                appendRepeatableComment(f, "d2.re signature: " + declaration);
            }
        }
        catch (Exception e) {
            typeFailureCount++;
            appendRepeatableComment(f, "d2.re signature: " + declaration);
        }
    }

    private String normalizeCType(String s) {
        if (s == null) return "void";
        return s
            .replace("unsigned __int64", "uint64_t")
            .replace("unsigned __int32", "uint32_t")
            .replace("unsigned __int16", "uint16_t")
            .replace("unsigned __int8", "uint8_t")
            .replace("__int64", "int64_t")
            .replace("__int32", "int32_t")
            .replace("__int16", "int16_t")
            .replace("__int8", "int8_t")
            .replace("__fastcall", "")
            .replace("__stdcall", "")
            .replace("__cdecl", "")
            .replaceAll("\\s+", " ")
            .trim();
    }

    private String normalizeArgumentText(String args) {
        String s = normalizeCType(args);
        if (s.equals("()")) return "(void)";
        return s;
    }

    private void appendRepeatableComment(Function f, String text) {
        String old = f.getRepeatableComment();
        if (old == null || old.isBlank()) f.setRepeatableComment(text);
        else if (!old.contains(text)) f.setRepeatableComment(old + "\n" + text);
    }

    private void applyVariableType(Address address, String ctype) {
        try {
            String normalized = normalizeCType(ctype);
            DataTypeParser parser = new DataTypeParser(
                dataTypeManager, dataTypeManager, null, AllowedDataTypes.ALL);
            DataType dt = parser.parse(normalized);
            if (dt == null || dt.getLength() <= 0) {
                typeFailureCount++;
                return;
            }

            Data existing = listing.getDataAt(address);
            if (existing != null && existing.isDefined() && existing.getDataType().isEquivalent(dt)) return;

            Address end = address.add(Math.max(0, dt.getLength() - 1));
            listing.clearCodeUnits(address, end, false);
            listing.createData(address, dt);
        }
        catch (Exception e) {
            typeFailureCount++;
            setPlateComment(address, mergeComment(getPlateComment(address), "d2.re type: " + ctype));
        }
    }

    private String mergeComment(String old, String extra) {
        if (old == null || old.isBlank()) return extra;
        if (old.contains(extra)) return old;
        return old + "\n" + extra;
    }

    private void renameKnownTables(List<JsonObject> variables) {
        renameTable(variables, "g_D2GS_S2C_FunctionTable", 0xAE, 0x18, true, 0x10, "D2GS_S2C_0x%02X_PacketHandler", "D2GS_S2C_0x%02X_PacketHandlerEx");
        renameSimpleFunctionTable(variables, "g_D2GS_C2S_FunctionTable", 0x64, "D2GS_C2S_0x%02X_PacketHandler");
        renameSimpleFunctionTable(variables, "g_SkillsSrvStFunc", 0x42, "SKILLS_SrvStFunc_%03d");
        renameSimpleFunctionTable(variables, "g_SkillsSrvDoFunc", 0x98, "SKILLS_SrvDoFunc_%03d");
        renameSimpleFunctionTable(variables, "g_SkillsCltStFunc", 0x35, "SKILLS_CltStFunc_%03d");
        renameSimpleFunctionTable(variables, "g_SkillsCltDoFunc", 0x60, "SKILLS_CltDoFunc_%03d");
        renameSimpleFunctionTable(variables, "g_AssignProperty", 0x20, "ITEMMODS_PropertyFunc_%02d");
    }

    private JsonObject findByName(List<JsonObject> entries, String name) {
        for (JsonObject e : entries) if (name.equals(getString(e, "name", ""))) return e;
        return null;
    }

    private void renameSimpleFunctionTable(List<JsonObject> variables, String variableName, int count, String format) {
        JsonObject item = findByName(variables, variableName);
        if (item == null) return;
        Address table = resolveItem(item);
        if (table == null) return;

        println("Expanding table " + variableName + " at " + table);
        for (int i = 0; i < count; i++) {
            if (monitor.isCancelled()) return;
            Address slot = table.add((long)i * 8L);
            Address target = readPointer(slot);
            if (target == null || target.getOffset() == 0) continue;
            String name = String.format(format, i);
            renameTableFunction(target, name);
        }
    }

    private void renameTable(List<JsonObject> variables, String variableName, int count, int stride,
                             boolean namePacketSize, int secondPointerOffset,
                             String firstFormat, String secondFormat) {
        JsonObject item = findByName(variables, variableName);
        if (item == null) return;
        Address table = resolveItem(item);
        if (table == null) return;

        println("Expanding table " + variableName + " at " + table);
        for (int i = 0; i < count; i++) {
            if (monitor.isCancelled()) return;
            Address row = table.add((long)i * stride);
            Address first = readPointer(row);
            if (first != null && first.getOffset() != 0) renameTableFunction(first, String.format(firstFormat, i));

            if (namePacketSize) {
                try {
                    createLabel(row.add(8), String.format("D2GS_S2C_0x%02X_PacketSize", i), true, SourceType.USER_DEFINED);
                }
                catch (Exception ignored) { }
            }

            Address second = readPointer(row.add(secondPointerOffset));
            if (second != null && second.getOffset() != 0) renameTableFunction(second, String.format(secondFormat, i));
        }
    }

    private void renameTableFunction(Address target, String name) {
        try {
            Function f = getOrCreateFunction(target, name);
            if (f != null) {
                f.setName(name, SourceType.USER_DEFINED);
                functionCount++;
            }
        }
        catch (Exception e) {
            println("[WARN] Could not rename table function " + name + " at " + target);
        }
    }

    private Address readPointer(Address address) {
        try {
            long value = memory.getLong(address);
            if (value == 0) return null;
            return address.getAddressSpace().getAddress(value);
        }
        catch (Exception e) {
            return null;
        }
    }

    private String getString(JsonObject o, String key, String defaultValue) {
        JsonElement e = o.get(key);
        if (e == null || e.isJsonNull()) return defaultValue;
        return e.getAsString();
    }

    private int getInt(JsonObject o, String key, int defaultValue) {
        JsonElement e = o.get(key);
        if (e == null || e.isJsonNull()) return defaultValue;
        try { return e.getAsInt(); }
        catch (Exception ex) { return defaultValue; }
    }
}
