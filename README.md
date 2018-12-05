# tiny-interpreter
Limited use interpreter project for fun / example purposes. Very fast, ~350ms for recursive fib(34)

## Building
VS Code build tasks are included for Clang, and currently this has only been tested on Windows.
To run Clang on Windows you also need the msvc build tools, as Clang uses it's standard headers and linker.

If you build this on another platform or compiler please let me know how it went and/or submit a pull request with additional tasks/makefile etc

There are conditional defines avaiable for the C library build:
> `SAFE_MODE` - Enables run time checks of various things to help catch errors in bytecode
> `DEBUG_MODE` - Enables print statements for each instruction to allow visualizing the VM's execution state

CodeView Debug info is enabled for both components by default.
