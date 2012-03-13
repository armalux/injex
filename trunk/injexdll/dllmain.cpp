// dllmain.cpp : Defines the entry point for the DLL application.

#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include "conlib.h"
#include "hooklib.h"

/* This is used to keep track of the hook layed for SaveFile(). */
PENTRY_STUB_TRAMP pSaveFileStub;

/* A typedef for the SaveFile function. */
typedef BOOL (__fastcall *fpSaveFile)(int,int,HWND hWnd,LPCWSTR lpFileName,BOOL bShareWritePermissions);

/* A pointer to the "real" SaveFile function, for our use later. */
fpSaveFile SaveFile;

/* = FunctionAddress - ( BaseOfCode + ImageBase ) */
/* 
	You can get IDA to give you the address to put here:
	1. Edit -> Segments -> Rebase Program...
	2. Enter "0" and press Ok.
	3. Look at the new address displayed.
*/
PVOID SaveFileDebasedAddress = (PVOID)0x6CD7;

/* This is called in place of SaveFile after the hooks are layed. */
BOOL __fastcall fakeSaveFile(int aUnused,int bUnused,HWND hWnd,LPCWSTR lpFileName,BOOL bShareWritePermissions){
	/* We could just not save the file, then tell them we did...
	░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░
	░░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░
	░░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░
	░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░
	░▄▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░
	█░▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█
	█░▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█
	░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░
	░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░
	░░░█░░░░██░░▀█▄▄▄█▄▄█▄████░█░░░
	░░░░█░░░░▀▀▄░█░░░█░█▀██████░█░░
	░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░
	░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░▒░░░█░
	░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░░░░█░
	░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░░░░█░░
	Problem?
	
	// 33 C0	xor eax,eax
	// 40 		inc eax
	// C2 0C 00	ret 12
	
	return TRUE;
	*/
	
	/* According to IDA Pro, a and b are never set when calling and are not used in the function. I think its a WoW64 thing. */
	odprintf("Notepad called SaveFile(HWND 0x%08X, LPCWSTR \"%S\", BOOL %i)",hWnd,lpFileName,bShareWritePermissions);
	
	bShareWritePermissions = FALSE;

	if(wcscmp(L"C:\\test.txt",lpFileName) == 0){
		odprintf("Saving the magic file!!!");
	}

	odprintf("Calling the real save file function...");
	BOOL ret = SaveFile(aUnused,bUnused,hWnd,lpFileName,bShareWritePermissions);

	odprintf("The real function returned %i",ret);

	return ret;
}

DWORD WINAPI layHooks()
{
	DWORD dwRet = HOOKING_SUCCESS;
	BOOL bFunctionHooked = FALSE;
	BOOL bSafeToCleanup = FALSE;

	/* We get the address of the real function from its offset inside the Portable Executable which is 0x6CD7. */
	fpSaveFile realSaveFile = (fpSaveFile)getPostAslrAddr(SaveFileDebasedAddress);

	odprintf("Patching SaveFile @ %p",realSaveFile);

	/* Set up the ENTRY_STUB_TRAMP structure by calling the create function */
	dwRet = EntryStub_create(&pSaveFileStub, realSaveFile, SIZEOF_JMPPATCH);
	if(HOOKING_SUCCESS == dwRet)
	{
		/* Hook the function */
		bFunctionHooked = EntryStub_hook(pSaveFileStub, fakeSaveFile);
		if(FALSE == bFunctionHooked)
		{
			dwRet = HOOKING_FAILURE;
		} else {
			/* Setup the SaveFile pointer for later use. */
			SaveFile = (fpSaveFile)(pSaveFileStub->pTrampoline);
		}

	}

	return dwRet;
}

DWORD WINAPI start(LPVOID lpParameter){
	odprintf("Laying hooks inside %d.", GetCurrentProcessId());

	/* Hook the SaveFile function...*/
	if(layHooks() == HOOKING_FAILURE){
		odprintf("Failed to hook SaveFile in process %d", GetProcessId(GetCurrentProcess()));	
	}

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

