# HeavensGate
A header containing utilities for executing, reading and writing 64-bit data in a 32-bit WoW64 process and more

# Features worth noting
* 64-Bit GetModuleHandleA
* 64-Bit GetModuleSize
* 64-Bit VirtualProtect
* 64-Bit memcpy, memset, zeromemory
* Direct system calls
* Direct function calls
* Byte pattern scanning in 64-bit regions
* Setting direct Wow64 instrumentation callback for the 32-bit process
* Replacing ntdll32!KiUserExceptionDispatcher with your own

# Credits
Partial credit goes to [Cr4sh](https://gist.github.com/Cr4sh) for providing a foundation of research
