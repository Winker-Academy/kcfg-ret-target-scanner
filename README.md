# KCFG Return Target Scanner

A read-only WinDbg JavaScript tool for inspecting a loaded module's Guard CF function table. It lists the table's call targets and highlights entries whose first eight bytes contain `C3`, the x86-64 opcode for a near `ret`.

The result is a **byte-pattern candidate**, not a verified return instruction or proof that a particular indirect call will pass a live kCFG check. This tool does not modify kernel memory.

## Requirements

- WinDbg with JavaScript scripting support.
- A debugging session where the module of interest is loaded (.reload /f <module> if not).
- Readable module headers and Guard CF load-configuration data. For incomplete dumps, a matching PE image can supply missing table entries or target bytes.

## Usage

Load the script in WinDbg and scan a loaded module:

```text
.scriptload C:\path\to\kcfg-scan.js
dx @$scriptContents.kcfg("nt")
dx @$scriptContents.kcfg("ci")
```

If a dump omits the Guard CF table or target bytes, place the matching PE image beside `kcfg-scan.js` using its normal file name (for example, `CI.dll`). The scanner checks the script directory first, then WinDbg's working directory and the usual Windows image directories. You can also supply the path explicitly:

```text
dx @$scriptContents.kcfg("ci", "D:\\images\\CI.dll")
```

## Output and interpretation

The scan prints each Guard CF table entry with its address, nearest symbol, and available metadata. A line marked `FOUND!` contains a `C3` byte in the first eight bytes at that target. The final `FOUND RECAP` repeats those lines and reports scanned and unreadable counts. `[table: file]` and `[bytes: file]` identify data recovered from a matching PE image instead of debugger memory.

The scan checks raw bytes. It does not disassemble instruction boundaries or verify that execution reaches the `C3`. Guard CF table membership is static image metadata and is not, by itself, a runtime authorization test. Results depend on the exact module build and on the pages available in the debugging session. In a partial dump, missing pages remain unreported unless a matching PE image is available.

## Scope

This repository contains the standalone scanner. It has no bundled Windows binary byte cache. The scanner reads the loaded module's Guard CF table, so it is not tied to a particular Windows build. Use a PE image from the same build as the module being inspected when a dump lacks the relevant bytes. Modules without a readable Guard CF function table cannot be scanned.
