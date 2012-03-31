
/**
	@example	iat_hook.c
	@brief		An example of hooking WriteFile in any application.
	@author		Eric Johnson
	@date		March 31st, 2012
	@version	1.0
	@ingroup	ImportAddressTableHooking
	@sa			injectable_dllmain_example.c
**/

#include <Windows.h>
#include "conlib.h"
#include "hooklib.h"

// Just a typedef for WriteFile.
typedef BOOL (__stdcall *fpWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

// We use this later as a way to call the original (real) WriteFile function.
fpWriteFile realWriteFile;

BOOL WINAPI fakeWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
	odprintf("Writing to a file...");
	return realWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

// This should be called from within the application that is to be hooked.
DWORD WINAPI start(LPVOID lpParameter){
	// Hook the WriteFile function...
	IAT_hook("kernel32.dll","WriteFile",(PVOID*)&realWriteFile,fakeWriteFile);
}