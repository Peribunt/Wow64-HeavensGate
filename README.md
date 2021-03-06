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
* Setting direct Wow64 instrumentation callbacks for the 32-bit process
* Hijacking ntdll32!KiUserExceptionDispatcher without touching anything in ntdll

# Examples
### Hijacking the 32-bit exception dispatcher
```cpp
ZwContinue_t ZwContinue = NULL;

LONG
WINAPI
ExceptionHandler(
    IN LPEXCEPTION_RECORD ExceptionRecord,
    IN LPCONTEXT          ContextRecord
    )
{
    //
    // VEH code here...
    //
}

LONG
main(
    VOID
    )
{
    //
    // Activates the Wow64 instrumentation callback
    //
    if ( HgStartup32BitInstrumentation( ) == TRUE )
        //
        // Populates a ZwContinue to be used in the hijacked handler,
        // and redirects the exception instrumentation callback
        //
        HgSet32BitExceptionDispatcher( ExceptionHandler, &ZwContinue );
}
```

# Credits
Partial credit goes to [Cr4sh](https://gist.github.com/Cr4sh) for providing a foundation of research
