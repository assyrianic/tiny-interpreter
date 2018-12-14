# tiny-interpreter
Limited use interpreter project for fun / example purposes. Very fast, ~350ms for recursive `fib(34)` without safe mode & ~500ms with safe mode

## Building
VS Code build tasks are included for clang-cl on Windows.
To run Clang on Windows you also need the msvc build tools, as Clang uses its standard headers and linker.

Nothing in the interpreter code is windows-specific as far as I'm aware of, but other platforms are currently untested.

If you build this on another platform or compiler, please let me know how it went and/or submit a pull request with additional tasks/makefile/etc.

There are conditional defines available for the C library build:

> `TI_SAFE_MODE` - Enables run time checks of various things to help catch errors in bytecode

> `TI_DEBUG_MODE` - Enables print statements for each instruction to allow visualizing the VM's execution state

> `TI_ALLOCATOR_FREE_DEFRAG_LOOPS` - Determines the maximum number of iterations the allocator will continue defragmenting after blocks are freed (default is 10)

CodeView Debug info is enabled for both components by default.
