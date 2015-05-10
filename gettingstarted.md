# Introduction #

Injex is a Visual Studio 2010 solution. You can download the latest release source from the [Downloads](http://code.google.com/p/injex/downloads/list) section. It is designed to be a template to use to make your injectable DLL and a platform to inject it.

# Getting It Running #

You can get the latest copy of injex running in just a few simple steps:

  1. Make sure you have the prerequisits:
    * Visual Studio 2010 installed or at least [Visual C++ Express 2010](http://www.microsoft.com/visualstudio/en-us/products/2010-editions/visual-cpp-express).
    * [SysInternal Suite](http://technet.microsoft.com/en-us/sysinternals/bb842062)
  1. Download the latest source RAR from [Downloads](http://code.google.com/p/injex/downloads/list).
  1. Unpack it to a directory of your choice.
  1. Navigate to that directory in explorer.
  1. Double click **injex.sln**.
  1. Once the solution is open press Ctrl+Shift+B to build the solution.
  1. Open a command prompt at the build directory.
  1. Run "dbgview.exe" from SysInternal Suite.
  1. Run the command `injex -d injexdll.dll -b notepad.exe`.
  1. Notepad will open, write some stuff in it and go to save it.
  1. When notepad saves the file you will see dbgview print a message.
  1. Congrats! You have injected your first Injex DLL.

Now to customize the DLL, you will edit the function "start" inside of the project named "injexdll". Good luck!