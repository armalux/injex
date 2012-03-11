// injex.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
//#include <Shlwapi.h>

BOOL InjectDLL(DWORD ProcessID);
void __cdecl odprintf(const char *format, ...);
int isNumeric(const char *s);

int main(int argc, CHAR* argv[])
{
	if(argc < 3){
		printf("USAGE: injex.exe <dllToInject.dll> <[PID to inject into]|[Path to exe to start]> [args for exe]\r\n");
		return -1;
	}

	// Get the path to the DLL to inject.
	CHAR dllName[MAX_PATH];
	GetFullPathNameA(argv[1],MAX_PATH,dllName,NULL);

	HANDLE proc; // The handle of the process we will inject into.

	// Get the handle to the process to inject into and store it in proc.
	if(!isNumeric(argv[2])){
		PROCESS_INFORMATION		pi;
		STARTUPINFOA				si;

		CHAR lpApplicationName[MAX_PATH];
		GetFullPathNameA(argv[2],MAX_PATH,lpApplicationName,NULL);

		CHAR CommandLine[8191] = {""};
		for(int i=3;i<argc;i++)
			strcat_s(CommandLine, 8191, argv[i]);

		GetStartupInfoA(&si);
		//printf("Starting %s %s\r\n",lpApplicationName,CommandLine);
		LPSTR cmdLine = GetCommandLineA();

		cmdLine = (LPSTR)(cmdLine + strlen(argv[0]) + strlen(argv[1]) + 3);

		printf("Starting new process to inject into:\r\n%s\r\n",cmdLine);

		if(CreateProcessA(NULL,cmdLine,NULL,NULL,0,0,NULL,NULL,&si,&pi) == 0)
		{
			// Failed to create the process.
			printf("CreateProcessA failed, GetLastError: %i\r\n",GetLastError());
			return -1;
		}

		proc = pi.hProcess;
	}
	else{
		DWORD pid = atoi(argv[2]);
		proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION , FALSE, pid);

		if(proc == NULL)
		{
			printf("OpenProcess failed, GetLastError: %i\r\n", GetLastError());
			return -1;
		}

		printf("proc: %d\r\n",proc);
	}

	printf("Injecting %s into pid %d.\r\n", argv[1], GetProcessId(proc));

	LPVOID RemoteString, LoadLibAddy;
	LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	RemoteString = (LPVOID)VirtualAllocEx(proc, NULL, strlen(dllName), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if(RemoteString == NULL){
		printf("VirtualAllocEx failed, GetLastError: %i\r\n",GetLastError());
		CloseHandle(proc); // Close the process handle.
		return -1; // Exit.
	}

	if(WriteProcessMemory(proc, (LPVOID)RemoteString, dllName,strlen(dllName), NULL) == 0){
		printf("WriteProcessMemory failed, GetLastError: %i\r\n", GetLastError());
		VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
		CloseHandle(proc); // Close the process handle.
		return -1; // Exit.
	}
	
	if(CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL) == NULL){
		printf("CreateRemoteThread failed, GetLastError: %i\r\n", GetLastError());
		VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
		CloseHandle(proc); // Close the process handle.
		return -1; // Exit.
	}
	
	CloseHandle(proc);

	printf("DLL Injection Successful!\r\n");
	return 0;
}

void __cdecl odprintf(const char *format, ...)
{
	char    buf[4096], *p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = _vsnprintf(p, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while ( p > buf  &&  isspace(p[-1]) )
			*--p = '\0';

	*p++ = '\r';
	*p++ = '\n';
	*p   = '\0';

	OutputDebugStringA(buf);
}

int isNumeric (const char * s)
{
    if (s == NULL || *s == '\0' || isspace(*s))
      return 0;
    char * p;
    strtod (s, &p);
    return *p == '\0';
}