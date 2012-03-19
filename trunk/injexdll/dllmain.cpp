// dllmain.cpp : Defines the entry point for the DLL application.

#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include "conlib.h"
#include "hooklib.h"

typedef BOOL (__stdcall *fpWriteFile)(HANDLE hFile,
									  LPCVOID lpBuffer,
									  DWORD nNumberOfBytesToWrite,
									  LPDWORD lpNumberOfBytesWritten,
									  LPOVERLAPPED lpOverlapped);
fpWriteFile realWriteFile;

BOOL WINAPI fakeWriteFile(HANDLE hFile,
	                      LPCVOID lpBuffer,
						  DWORD nNumberOfBytesToWrite,
						  LPDWORD lpNumberOfBytesWritten,
						  LPOVERLAPPED lpOverlapped)
{
	odprintf("Writing to File...");

	return realWriteFile(hFile,
		                 lpBuffer,
						 nNumberOfBytesToWrite,
						 lpNumberOfBytesWritten,
						 lpOverlapped);
}

DWORD WINAPI start(LPVOID lpParameter){
	odprintf("Laying hooks inside %d.", GetCurrentProcessId());
	// START YOU CODE HERE...

	IAT_hook("kernel32.dll","WriteFile",(PVOID*)&realWriteFile,fakeWriteFile);

	// STOP HERE.
	odprintf("%d:%d exiting...", GetCurrentProcessId(), GetCurrentThreadId());
	FreeLibraryAndExitThread(GetModuleHandle(NULL),0);
	return 0;
}

void createNewThread(){
	HANDLE t;
	DWORD tid;
	t = CreateThread(NULL, 0, start, NULL, 0, &tid);
	odprintf("Created thread %d inside of process %d.", tid, GetCurrentProcessId());
	CloseHandle(t);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	//odprintf("DLL: %p, TARGET: %p",hModule, GetModuleHandle(NULL));
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		odprintf("Loading injexdll.dll!");
		createNewThread();
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		odprintf("Unloading injexdll.dll!");
		break;
	}

	return TRUE;
}

