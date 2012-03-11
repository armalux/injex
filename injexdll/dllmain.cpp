// dllmain.cpp : Defines the entry point for the DLL application.

#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

void __cdecl odprintf(const char *format, ...);

DWORD WINAPI start(LPVOID lpParameter){
	odprintf("Calling out from inside %d.", GetCurrentProcessId());

	// TODO: Lay some hooks and season liberaly with pwnsauce...
	Sleep(5000);

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

void __cdecl odprintf(const char *format, ...)
{
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = _vsnprintf_s(p, 4096, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while ( p > buf  &&  isspace(p[-1]) )
			*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p   = '\0';

	OutputDebugStringA(buf);
}