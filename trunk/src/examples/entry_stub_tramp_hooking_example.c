
/**
	@example	entry_stub_tramp_hooking_example.c
	@brief		An example of using a Entry Stub Trampoline Hook to hook SaveFile in notepad.exe (WoW64 version on Windows 7)
	@author		Eric Johnson
	@date		March 31st, 2012
	@version	1.0
	@ingroup	EntryStubTrampolineHooking
	@sa			injectable_dllmain_example.c
**/

#include <Windows.h>
#include "conlib.h"
#include "hooklib.h"

// This is used to keep track of the hook layed for SaveFile(). 
PENTRY_STUB_TRAMP pSaveFileStub;

// A typedef for the SaveFile function. 
typedef BOOL (__fastcall *fpSaveFile)(int,int,HWND hWnd,LPCWSTR lpFileName,BOOL bShareWritePermissions);

// A pointer to the "real" SaveFile function, for our use later.
fpSaveFile SaveFile;

// You can get IDA to give you the address to put here:
// 1. Edit -> Segments -> Rebase Program...
// 2. Enter "0" and press Ok.
// 3. Look at the new address displayed.
PVOID SaveFileDebasedAddress = (PVOID)0x6CD7;

// This is called in place of SaveFile after the hooks are layed. 
BOOL __fastcall fakeSaveFile(int aUnused,int bUnused,HWND hWnd,LPCWSTR lpFileName,BOOL bShareWritePermissions){

	// According to IDA Pro, a and b are never set when calling and are not used in the function. I think its a WoW64 compatibility thing.
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

// To lay the hooks call layHooks()
DWORD WINAPI layHooks()
{
	DWORD dwRet = HOOKING_SUCCESS;
	BOOL bFunctionHooked = FALSE;
	BOOL bSafeToCleanup = FALSE;

	// We get the address of the real function from its offset inside the Portable Executable which is 0x6CD7. 
	fpSaveFile realSaveFile = (fpSaveFile)getPostAslrAddr(SaveFileDebasedAddress);

	odprintf("Patching SaveFile @ %p",realSaveFile);

	// Set up the ENTRY_STUB_TRAMP structure by calling the create function 
	dwRet = EntryStub_create(&pSaveFileStub, realSaveFile, SIZEOF_JMPPATCH);
	if(dwRet == HOOKING_SUCCESS)
	{
		// Hook the function 
		bFunctionHooked = EntryStub_hook(pSaveFileStub, fakeSaveFile);

		if(bFunctionHooked == FALSE)
		{
			dwRet = HOOKING_FAILURE;
		} else {
			// Setup the SaveFile pointer for later use. 
			SaveFile = (fpSaveFile)(pSaveFileStub->pTrampoline);
		}

	}

	return dwRet;
}

// This should be called from within the application that is to be hooked.
DWORD WINAPI start(LPVOID lpParameter){
	// Hook the SaveFile function...
	if(layHooks() == HOOKING_FAILURE){
		odprintf("Failed to hook SaveFile in process %d", GetProcessId(GetCurrentProcess()));	
	}
}