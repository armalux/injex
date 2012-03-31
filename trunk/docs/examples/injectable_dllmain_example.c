
/**
	@example	injectable_dllmain_example.c
	@brief		An example of a DLL that is injectable.
	@author		Eric Johnson
	@date		March 31st, 2012
	@version	1.0
	@sa			http://blogs.msdn.com/b/oldnewthing/archive/2004/01/28/63880.aspx
	@sa			http://msdn.microsoft.com/en-us/library/windows/desktop/ms682583(v=vs.85).aspx
**/

#include <Windows.h>

DWORD WINAPI start(LPVOID lpParameter){
	// START YOUR CODE HERE...

	// Lay some hooks, season libraly with pwnsauce.
	// Do whatever you want here, this is your thread to play with.
	// NOTE: This is used as the starting function in most examples.

	// STOP HERE.
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
				   DWORD  ul_reason_for_call,
				   LPVOID lpReserved
				 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// We create a new thread to do our bidding in, this way we don't hold the loader lock.
		// We close the handle to the thread for various reasons.
		CloseHandle(CreateThread(NULL, 0, start, (LPVOID)hModule, 0, NULL));
		
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}