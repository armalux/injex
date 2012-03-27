// injex.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <winternl.h>
#include "conlib.h"
//#include <Shlwapi.h>

BOOL InjectDLL(DWORD ProcessID);
void __cdecl odprintf(const char *format, ...);
int isNumeric(const char *s);

// This function is pretty much straight from http://msdn.microsoft.com/en-us/library/windows/desktop/ms680582(v=vs.85).aspx
void ErrorExit(LPTSTR lpszFunction, LPCSTR lpAdditionalHelp) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("ERROR: %s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 
    //MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	wprintf((LPWSTR)lpDisplayBuf);
	if(lpAdditionalHelp != NULL)
		printf("ADDITIONAL HELP: %s\n",lpAdditionalHelp);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw);
}

void Usage(){
	printf("Usage: injex -d <dllName> < -b <binary name> [-a <arguments>] | -p <Process ID> > [-w <milliseconds>]\n");
	printf("  -d: Specify the DLL to inject.\n");
	printf("  -b: Specify a binary to run then inject into.\n");
	printf("  -a: Used in conjunction with '-b' to provide command line arguments to the program to inject into.\n");
	printf("  -p: Use instead of '-b' to inject into an application that is already running.\n");
	printf("  -w: Use with '-b' when running an application to start it suspended and allow <milliseconds>\n      for the injected DLL to lay hooks before resuming it.\n");
	ExitProcess(-1);
}

int main(int argc, CHAR* argv[])
{
	char *dllArg = NULL;
	char *programPath = NULL;
	char *procArgs = NULL;
	DWORD pid = 0;
	DWORD waitMs = 0;
	BOOL startProcess;
	
	for(int i=1;i<argc;i++){
		if(strcmp(argv[i],"-d") == 0){
			dllArg = argv[++i];

		} else if(strcmp(argv[i],"-b") == 0) {
			programPath = argv[++i];
			startProcess = TRUE;

		} else if(strcmp(argv[i],"-p") == 0) {
			if(isNumeric(argv[i+1]))
				pid = atoi(argv[++i]);
			else{
				printf("ERROR: Invalid Process Id specified \"%s\"; Process Id should be numeric.\n",argv[i+1]);
				Usage();
			}
			startProcess = FALSE;

		} else if(strcmp(argv[i],"-a") == 0) {
			procArgs = argv[++i];

		} else if(strcmp(argv[i],"-h") == 0) {
			Usage();

		} else if(strcmp(argv[i],"-w") == 0) {
			waitMs = atoi(argv[++i]);

		} else {
			printf("ERROR: Unknown command line option \"%s\"\n",argv[i]);
			Usage();
		}
	}

	// Validate their command line options.
	if(pid == 0 && programPath == NULL){
		printf("ERROR: Please specify either a Process ID or a binary to launch.\n");
		Usage();
	} else if(dllArg == NULL){
		printf("ERROR: Please specify a DLL to inject.\n");
		Usage();
	}

	// Get the path to the DLL to inject.
	CHAR dllName[MAX_PATH];
	GetFullPathNameA(dllArg,MAX_PATH,dllName,NULL);

	// The handle of the process we will inject into.
	HANDLE proc;

	// Used for keeping track of the suspended threads.
	DWORD threadCount = 0;
	// Assuming 1MB stacks, 2048*1MB =~ 2GB. I am assuming that the thread count in an application will never exceed this due to hardware contraints. 
	#define MAX_THREADS 2048
	HANDLE threads[MAX_THREADS];

	// Get the handle to the process to inject into and store it in proc.
	if(startProcess){
		PROCESS_INFORMATION		pi;
		STARTUPINFOA			si;
		GetStartupInfoA(&si);

		char CommandLine[8191] = {0};

		// We put quotes around the program path to ensure it still works if it has spaces in it.
		sprintf(CommandLine,"\"%s\"", programPath);
		if(procArgs != NULL){
			strcat(CommandLine, " ");
			strcat(CommandLine, procArgs);
		}
		
		DWORD dwFlags = 0;
		if(waitMs) dwFlags |= CREATE_SUSPENDED;
		
		printf("Starting new process to inject into:\n%s\n",CommandLine);
		if(CreateProcessA(NULL,CommandLine,NULL,NULL,0,dwFlags,NULL,NULL,&si,&pi) == 0)
		{
			ErrorExit(TEXT("CreateProcessA"), "Check your process path.");
		}

		if(waitMs){
			threadCount = 1;
			threads[0] = pi.hThread;
		}

		proc = pi.hProcess;
	}
	else{
		proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

		if(proc == NULL)
		{
			ErrorExit(TEXT("OpenProcess"), "Check the provided Process Id.");
			return -1;
		}

		printf("proc: %d\n",proc);

		if(waitMs){

		}
	}

	// Credit for this method of injection goes to Jeffrey Richter!
	// Explanation: http://www.codeproject.com/Articles/2082/API-hooking-revealed CTRL+F: "Injecting DLL by using CreateRemoteThread() API function"

	printf("Injecting %s into pid %d.\n", dllName, GetProcessId(proc));

	LPVOID RemoteString, LoadLibAddy;
	LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	RemoteString = (LPVOID)VirtualAllocEx(proc, NULL, strlen(dllName), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	if(RemoteString == NULL){
		CloseHandle(proc); // Close the process handle.
		ErrorExit(TEXT("VirtualAllocEx"), NULL);
	}

	if(WriteProcessMemory(proc, (LPVOID)RemoteString, dllName,strlen(dllName), NULL) == 0){
		VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
		CloseHandle(proc); // Close the process handle.
		ErrorExit(TEXT("WriteProcessMemory"), NULL);
	}
	
	if(CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL) == NULL){
		VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
		CloseHandle(proc); // Close the process handle.
		ErrorExit(TEXT("CreateRemoteThread"), NULL);
	}
	
	if(waitMs && startProcess){
		printf("Waiting %ims for DLL to lay hooks before resuming the process.\n",waitMs);
		Sleep(waitMs);
		for(DWORD i=0;i<threadCount;i++){
			printf("Resuming Thread %d in Process %d...\n", GetThreadId(threads[i]), GetProcessId(proc));
			ResumeThread(threads[i]);
		}
	}

	CloseHandle(proc);

	printf("DLL Injection Complete!\n");
	return 0;
}

int isNumeric (const char * s)
{
    if (s == NULL || *s == '\0' || isspace(*s))
      return 0;
    char * p;
    strtod (s, &p);
    return *p == '\0';
}