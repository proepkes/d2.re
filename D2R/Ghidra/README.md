# d2.re Ghidra support

`D2RUpdate.java` is a Ghidra port of `D2R/update.py`. It deliberately reuses the existing d2.re JSON databases instead of introducing a Ghidra-specific copy.

## What it ports

The script currently implements the parts of the IDA updater that are useful for a Ghidra workflow:

- loads `data/functions.json` and optional `data/_functions.json`
- loads `data/variables.json` and optional `data/_variables.json`
- searches IDA-style byte patterns with `?` / `??` wildcards
- supports d2.re `absolute`, `operand`, and `other` signature resolution modes
- creates/renames functions
- creates/renames variable labels
- carries `summary` text into Ghidra comments
- applies function signatures when Ghidra can resolve the referenced data types
- applies variable data types when Ghidra can resolve them
- preserves unresolved declarations as comments instead of aborting the import
- expands and renames the same known function tables handled by `update.py`

The source JSON remains the single source of truth.

## Requirements

- Ghidra 12.x is the target for this port.
- Import the 64-bit `D2R.exe` as a PE image and let normal analysis complete first.
- Keep a local checkout of this repository because the script reads the JSON files from disk.

## Run it

1. Open `D2R.exe` in Ghidra's CodeBrowser and allow auto-analysis to finish.
2. Open **Window -> Script Manager**.
3. Add `D2R/Ghidra` as a script directory using the Script Manager's script-directory button.
4. Refresh the script list.
5. Find **D2RUpdate.java** under the `D2R` category and run it.
6. When asked for the d2.re D2R directory, select your local `.../d2.re/D2R` folder. Selecting the repository root also works.
7. Review the Script Manager console. Entries marked `[BROKEN]` are signatures that no longer resolve against the loaded executable.

For the checkout used in the original setup, the directory would be:

```text
D:\Projects\RE\d2.re\D2R
```

## Types and `IDA.h`

The Ghidra importer does **not** require `IDA.h` to rename symbols. This is intentional: `IDA.h` and `data/D2Enums.h` contain IDA/C++-oriented constructs that are not guaranteed to parse unchanged with Ghidra's C parser.

If the relevant structures have already been imported into the current program's Data Type Manager, `D2RUpdate.java` will apply function prototypes and variable types automatically where possible. If a declaration cannot be resolved, the script keeps the d2.re declaration as a repeatable/plate comment and continues.

Ghidra's built-in **Parse C Source** tool can extract structures, enums, typedefs and function signatures from compatible C headers. A dedicated d2.re header-conversion step can be added separately without changing the JSON importer.

## Differences from the IDA updater

`D2R/update.py` uses IDA's `get_operand_value()` semantics. The Ghidra port resolves operands by using Ghidra instruction references first, then operand address/scalar objects. The `other` mode retains d2.re's original `imageBase + operandValue` behavior.

Calling-convention keywords such as `__fastcall` and `__stdcall` are stripped before feeding declarations into Ghidra's `FunctionSignatureParser`. On x64 Windows these keywords do not represent the same ABI distinction they did on 32-bit x86, and current Ghidra's parser does not reliably accept them in a declaration string.

## Validation

After running the importer, useful checks are:

- search for `CLIENT_GetCurrentInteractingNPC`
- search for `g_D2GS_S2C_FunctionTable`
- inspect several `D2GS_S2C_0xXX_PacketHandler` functions
- compare the number of `[BROKEN]` entries against the game build you are analyzing

Do not assume a successful script run means every signature matches the current D2R build. The JSON patterns are version-sensitive by design.

## Next step: ChatGPT / MCP

Once this importer is working in the local Ghidra project, the next layer can expose Ghidra operations to ChatGPT through an MCP bridge. The useful initial surface is read-only:

- list/find functions
- decompile a function
- get callers/callees and references
- read strings and bytes
- inspect symbols and data types

Mutation operations such as rename/comment/type changes can be added after the read path is stable.
