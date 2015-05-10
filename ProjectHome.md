Injex is comprised of two parts a DLL injector, and a DLL template that is to be edited and compiled. The template DLL comes with standard functionality to place hooks for function hooking in whatever it is injected into.

Supported Injection Methods:
  * **Ritcher Method** - Injects your DLL into the target process by creating a thread on LoadLibrary. This causes your DLL to be loaded by the target process.
  * **Thread Hijacking** - Uses an existing thread in the target process to call LoadLibrary.

Supported Hooking Methods:
  * **Entry Stub Trampoline Hooks (Advanced Code Overwriting)** - Places a jump in the original function to jump to your function, but saves off the original bytes for unhooking and also for your personal use. This allows you to use the "original" function, while forcing the hooked application to use w/e you specified. This is a rare and powerful hooking method. It employs a disassembly engine to determine how many bytes of the original function to keep and where to jump back to.
  * **Import Address Table Hooks** - Replaces the pointers in the import address table of the hooked application. This makes it so that when the application calls an imported function, it calls your function instead. This doesn't alter the original, and allows you to still use the original function. This is a very common hooking method.
  * **VTable Hooks** - Hooking virtual method table entries for C++ object virtual function entries.

Compatible Operating Systems:
  * Windows XP (All Versions & Service Packs)
  * Windows Server 2003 (All Versions & Service Packs)
  * Windows Vista (All Versions & Service Packs)
  * Windows 7 (All Versions & Service Packs)
  * Windows Server 2008 (All Versions & Service Packs)
  * Windows 8 (Only Tested on Developer Preview)