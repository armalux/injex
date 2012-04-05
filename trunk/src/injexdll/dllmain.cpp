// dllmain.cpp : Defines the entry point for the DLL application.

#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include "conlib.h"
#include "hooklib.h"

LRESULT CALLBACK KeyboardHook(int nCode,WPARAM wParam,LPARAM lParam)
{
	KBDLLHOOKSTRUCT* key;
	if(wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN){
		key = (KBDLLHOOKSTRUCT*)lParam;

		if(key->vkCode == VkKeyScan('a')){
			odprintf("You pressed 'a'");
		}

		if(key->vkCode == VK_F1){
			odprintf("You pressed F1");
		}
	}
	
	return 0;
}

DWORD WINAPI start(HMODULE hModule){
	odprintf("Laying hooks inside %d.", GetCurrentProcessId());
	// START YOU CODE HERE...
	
	UnlinkModuleByName(hModule);

	HookKeyboard(KeyboardHook);

	odprintf("Sleeping with the hook running, press some keys...");
	Sleep(25000);
	odprintf("Awake...");
	
	UnhookKeyboard();
	
	//UnloadSelfAndExit(hModule);
	
	// STOP HERE.
	odprintf("%d:%d exiting...", GetCurrentProcessId(), GetCurrentThreadId());
	return 0;
}

void createNewThread(HMODULE hModule){
	HANDLE t;
	DWORD tid;
	t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)start, (LPVOID)hModule, 0, &tid);
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
		createNewThread(hModule);
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		odprintf("Unloading injexdll.dll!");
		break;

	case DLL_PROCESS_DETACH:
		odprintf("Unloading injexdll.dll!");
		break;
	}

	return TRUE;
}

