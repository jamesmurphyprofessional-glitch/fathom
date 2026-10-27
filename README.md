# Fathom

Fathom is a local C++ workbench for loading, disassembling, triaging, and debugging native binaries on this Mac. It reads PE, ELF, COFF, and Mach-O (including universal) images through LLVM, disassembles with Capstone, and writes text, JSON, and Graphviz reports.

Fathom is a separate program. It does not load IDA, Ghidra, or Binary Ninja databases, and it does not reproduce those products.

## Hex-Rays and HexRaysCodeXplorer

[HexRaysCodeXplorer](https://github.com/REhints/HexRaysCodeXplorer) is an IDA plugin. It includes `hexrays.hpp` and the IDA SDK, and it walks the Hex-Rays ctree. IDA Freeware 8.2 on this machine does not ship the IDA SDK or the Hex-Rays SDK, so that plugin cannot be built or loaded here. Fathom does not pretend to implement the Hex-Rays ctree or microcode ABI, and it does not embed proprietary Hex-Rays headers.

What Fathom does cover, on its own instruction list, is the kind of navigation that plugin is used for: cross-references, vtable-shaped pointer runs, Itanium and Microsoft symbol names, a control-flow graph, and a structural pseudo-C listing. The listing says in its header that it is not decompiler output.

## ret-sync

The [ret-sync](https://github.com/bootleg/ret-sync) debugger plugins are a separate GPL-3 project. Clone them with the command in `third_party/README.md`. Fathom does not compile or link those sources.

Fathom implements the disassembler side of the wire protocol. `fathom sync serve <file>` listens on `127.0.0.1:9100`. A debugger plugin connects as a client and sends newline-delimited `[notice]` and `[sync]` JSON. Location messages move Fathom's cursor. Comment messages are stored as text. Nothing in an inbound message is passed to a shell.

The LLDB plugin executes any line Fathom writes back. Fathom writes a line only when you type `dbg <command>` in the session, or when the peer asks for the short `idb_list` / `idb_n` text reply.

```
(lldb) command script import /path/to/fathom/third_party/ret-sync/ext_lldb/sync.py
(lldb) sync 127.0.0.1
```

The plugin's port comes from its config and defaults to 9100. `--allow-remote` binds a non-loopback address. That listener has no authentication. Fathom prints a warning and still does not execute peer text.

IDA Freeware on this Mac has no IDAPython, so the IDA side of ret-sync cannot be loaded there either. Ghidra can keep using its own ret-sync extension; Fathom is the disassembler end of the same protocol.

## Debugger

`fathom debug launch <program> [args...]` starts Xcode `debugserver` on `127.0.0.1` and speaks the GDB remote protocol. `fathom debug attach <pid>` attaches to a process you name. The session can continue, step, step over a call, set a breakpoint, read registers, read memory, and list modules.

This is an ordinary debug session. It does not hide from the program, and it does not inject code. Quitting a launched session stops that process. Quitting an attach session detaches.

`explore`, `debug`, and `sync serve` share one cursor. A ret-sync location and a debug stop both move it.

## Samples stay local

Reports are produced on this machine. Fathom does not upload the file it is analyzing. The only network use is the loopback debugger socket and the ret-sync socket, unless you pass `--allow-remote`.

## Application

`Fathom.app` is the native Mac workbench. It links the same engine as the command-line tool. File, Open loads a binary on a background thread. The sidebar lists functions, strings, triage, and cross-references into the cursor. The upper panes are the disassembly and the structural listing. The lower pane is a hex view, or the control-flow graph from View, Graph. One cursor moves every pane. Drop a file on the window to open it.

The listing header still says what it is: a structural listing, not Hex-Rays output.

```
cmake -S . -B build -G Ninja \
  -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm@22/bin/clang \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm@22/bin/clang++ \
  -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qtbase
cmake --build build --target fathom_app
open build/Fathom.app
```

Copy `build/Fathom.app` to `~/Applications` when you want it in the Finder. The command-line tool remains `fathom`.

Qt 6 Widgets comes from Homebrew `qtbase`. Without it, CMake still builds the command-line tool and skips the app.

## Build

The compilers are Homebrew LLVM 22. A non-interactive shell does not see `~/.zshrc`, so the CMake command names them.

```
cmake -S . -B build -G Ninja \
  -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm@22/bin/clang \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm@22/bin/clang++ \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache \
  -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
./build/fathom_tests
```

Before a release binary, run `python3 tools/audit.py` and the test suite. The audit looks for credential-shaped strings and for C calls that do not bound their writes or that start a shell. `snprintf` is allowed.

An ASan/UBSan build of the unit tests:

```
cmake -S . -B build-asan -G Ninja \
  -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm@22/bin/clang \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm@22/bin/clang++ \
  -DCMAKE_BUILD_TYPE=Debug \
  -DFATHOM_SANITIZE=ON
cmake --build build-asan
./build-asan/fathom_tests
```

The debugserver integration test is compiled only into the unsanitized binary. ASan and `debugserver`'s own launch path do not cooperate reliably.

Release install:

```
cmake -S . -B build-release -G Ninja \
  -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm@22/bin/clang \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm@22/bin/clang++ \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
cmake --install build-release --prefix "$HOME/.local"
```

## Commands

`inspect` is the default when the first argument is a file. The others are `triage`, `disasm`, `decompile`, `functions`, `strings`, `xrefs`, `cfg`, `objects`, `hex`, `find`, `report`, `explore`, `debug`, `sync`, `batch`, and `version`.

`batch` reads one directory, not its children, and stops at 10000 entries. Output names are a sanitized basename plus `.json` under `--out`. Symlinks are skipped.

Files larger than 256 MiB are refused. Raise the cap with `--max-bytes`. Disassembly, strings, and cross-references each stop at a fixed cap and record that in the program notes.

## What the analysis is

Imports are labeled by capability (process, credential, network, and so on). A label is not a description of a procedure. High entropy and a writable executable section are reported as packing indicators. The vtable pass records aligned pointer runs into executable addresses and symbol names that look like typeinfo vtables. The structural listing walks the recovered blocks and calls. It has no types and no Hex-Rays microcode.
