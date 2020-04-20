# Cool Debugger
## A ptrace based debugger for x86_64 Dynamic and Static ELFs binaries.

Supported features:
- Single-step and continue;
- Breakpoints (symbols and addresses);
- Displays information about the breakpoints and symbols;
- Change registers values with set;
- Check ASLR;
- Dissasembly view (integrated with Capstone);
- Registers view;
- Eflags view;
- Inspect memory (addresses and registers);
- Command-line args for the tracee;
- Last changes (shows a report of the changed registers and their respective old values and new values);
- Integrated manual.

Dependencies:
- libcapstone3 (version 3.0.4-5).
- libcapstone-dev (version 3.0.4-5).

Compile:
- On your terminal type "make" for compiling the release version.
- On your terminal type "make debug" for compiling the debug version.

Usage:
- If is your first time, after executing the debugger, type man.