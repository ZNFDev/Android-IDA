# IDA for Android

A pocket-sized AArch64 reverse-engineering environment that behaves like IDA — an analysis core
written in C++17 with a native-Java IDA-style UI, built to run on-device (Termux + AIDE, no desktop
toolchain needed).

**Package:** `com.znfdev.ida` · **Target:** arm64-v8a · **Core:** `libidacore.so` (C++17)

---

## Features

### IDA View-A
- Full AArch64 listing with IDA chrome: `sec:0000000000CA1A58` prefixes, subroutine headers,
  `sub_XXXX` / `loc_XXXX` / data labels, `; CODE XREF` / `; DATA XREF` comment columns,
  `; End of function` markers, string literals, ADRP+ADD `@PAGEOFF` name resolution.
- Token highlighting, tap-to-jump, double-tap xrefs, long-press menu (**Copy line**, xrefs, hex dump).
- Pinch-zoom, fling scrolling, G (jump) and X (xrefs) hotkeys on the disassembly tab.

### Pseudocode-A (Hex-Rays-style decompiler)
- If/else/while/do-while/goto reconstruction, stack-slot variables, call-argument tracking.
- **Variable declarations** like real IDA: every function starts with
  `__int64 v8; // x0` style declarations inside the function body.
- Unnamed call targets display as `sub_XXXX` — never raw `0x…` addresses.
- Syntax coloring, **selectable/copyable text** (long-press selection), and **A- / A+** font
  sizing with persistence.

### Hex View-A
- IDA layout: `sec:addr  XX XX XX … ascii`, 16 bytes/row, byte selection, jump-following.
- **Long-press copies the full row** to the clipboard.

### Signature maker (SigMaker, inbuilt)
- `Search > Signature maker` builds a byte pattern for the function under the cursor:
  ```
  IDA:      FD 7B BE A9 F4 4F 01 A9 FD ? ? 91 3F ? ? 31
  x64dbg:   FD 7B BE A9 F4 4F 01 A9 FD ?? ?? 91 3F ?? ?? 31
  C array:  \xFD\x7B\xBE\xA9\xF4\x4F\x01\xA9\xFD\x00\x00\x91\x3F\x00\x00\x31
  Bitmask:  xxxxxxxxx??xx??x
  Address:  0x19EF8
  Length:   16 bytes (4 insns)
  Matches:  1 in file
  ```
- AArch64-aware wildcarding: branch/ADRP/ADR/literal-load immediates are wildcarded,
  opcode and register fields are kept; the pattern auto-extends until it is unique
  across the whole file.

### Tables (IDA-ordered tabs)
`Pseudocode-A · IDA View-A · Hex View-A · Functions · Strings · Imports · Exports · Names · Segments`
— all tables tap-to-jump, long-press for xrefs, checkpoint-refreshed every 600 ms.

### Analysis engine
- Streaming auto-analysis with live progress, cancel/pause/resume, string/function/label naming
  passes (`aStrName`, `sub_XXXX`, `loc_XXXX`), xref graph, saved databases with UI-state restore
  (cursor, hex position, open tab).

---

## Building

### Native core (Termux)
```sh
cd app/src/main
~/android/android-ndk-aide/ndk-build -j4
cp libs/arm64-v8a/libidacore.so jniLibs/arm64-v8a/libidacore.so
```

### Java gate (lint check without the app toolchain)
```sh
T=$TMPDIR; rm -rf $T/stubs; sh $TMPDIR/genstubs.sh          # regenerates javac stubs
cd $T && STUBS=$(find stubs -name "*.java")
javac -sourcepath stubs -cp . -d $T/out $STUBS \
  $PWD/app/src/main/java/com/znfdev/ida/*.java
```
Then build the APK in **AIDE** on-device (Java 7 syntax, minSdk 21, no AndroidX).

### Host-side testing (Termux, ASan)
```sh
g++ -std=c++17 -O0 -g -fsanitize=address -I app/src/main/jni \
    t4.cpp app/src/main/jni/{a64,database,pseudo}.cpp -o t4a
ASAN_OPTIONS=detect_leaks=0 ./t4a          # full pseudocode sweep over the corpus
```

---

## Architecture

| Layer | Files | Role |
|---|---|---|
| Core | `jni/ida_core.h`, `a64.cpp`, `database.cpp` | ELF loader, section map, analysis passes, xrefs, snapshots, disasm records |
| Decompiler | `jni/pseudo.cpp` | Block builder → structured pseudocode + **signature maker** |
| Bridge | `jni/jni_bridge.cpp`, `NativeBridge.java` | JNI surface (open/close/disasm/pseudo/sig/live analysis) |
| UI | `MainActivity.java`, `DisasmView`, `HexView`, `PseudoView`, `TableView`, `Session`, `LineBuilder` | IDA-style window chrome, views, tables |

Record formats:
- **Disasm record:** `sec \1 addr \1 bytes \1 funcName \1 label \1 codeXref \1 dataXref \1 mnem \1 ops \1 comment`
- **Pseudo record:** kind prefix + `\1` + text (`H` header, `V` declaration, `B` brace, `S` statement)

## Changelog highlights

- Tab order aligned with IDA; Pseudocode-A is the default tab.
- Variable declarations emitted (the V-record pass now runs after statement generation).
- Inbuilt SigMaker with AArch64 wildcard rules and whole-file uniqueness check.
- Selectable pseudocode text, resizable fonts, copyable hex rows and disassembly lines.
- Unnamed functions are always displayed as `sub_XXXX` (listing, proc lines, end markers, call sites).
- Hardened pseudocode engine: recursive-walk depth caps, claimed-range loop detection,
  reachability pruning, callee-save spill suppression, and fixed `vars[-1]` for X29/X30/X31.
