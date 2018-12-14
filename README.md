# tiny-interpreter
Limited use interpreter project for fun / example purposes. Very fast, ~350ms for recursive `fib(34)` without safe mode & ~500ms with safe mode

## Building
VS Code build tasks are included for clang-cl on Windows and clang/clang++ on Linux.
To run Clang on Windows you also need the MSVC build tools, and to run Clang on Linux you also need the GCC build tools, as Clang uses their standard headers and linkers.

Tested on Windows 10 (natively) and Ubuntu 16.4 (in a VM).

CodeView debug information is enabled for both components on Windows, and GDB debug information is enabled on Linux.
Currently only a Windows debug profile is included in the VS Code launch.json, as
VS Code's C++ extension debugger is currently broken on Linux. (See https://github.com/Microsoft/vscode-cpptools/issues/2922)

If you build this on another platform or compiler, please let me know how it went and/or submit a pull request with additional tasks/makefile/etc.

There are conditional defines available for the C library build:

> `TI_SAFE_MODE` - Enables run time checks of various things to help catch errors in bytecode (Now enabled by default)

> `TI_DEBUG_MODE` - Enables print statements for each instruction to allow visualizing the VM's execution state

> `TI_ALLOCATOR_FREE_DEFRAG_LOOPS` - Determines the maximum number of iterations the allocator will continue defragmenting after blocks are freed (Default is 10)