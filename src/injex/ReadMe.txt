========================================================================
    Injex - DLL Injector
========================================================================

This is the DLL injector itself. Its implementation is very simple. It creates
a new thread in the target application at the address of "LoadLibrary" to load
the DLL of your choice.

Command Line Use:

Start up a copy of calc.exe and inject the dll injexdll.dll into it:
 injex.exe injexdll.dll calc.exe

Inject injexdll.dll into an already running application where the Process ID is 987:
 injex.exe injexdll.dll 987

Starting an application to inject into with arguements:
 injex.exe injexdll.dll cmd.exe /C "copy C:\*.* C:\new\*.*"

 Note: cmd.exe is started with the command line 'cmd.exe /C "copy C:\*.* C:\new\*.*"'

/////////////////////////////////////////////////////////////////////////////
