/** 
	@file	injex.cpp
	
	@brief	The functional portion of the injector.
	
	@private
	
	@todo	Look into using SetWindowsHookEx for DLL Injection.
	@todo	Make this file's functionality into a library and 
			just reference that functionality from here.
**/


#pragma warning(disable:4995)
#pragma warning(disable:4996)
#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <Psapi.h>
#include "winstructs.h"
#include "conlib.h"

void __cdecl odprintf(const char *format, ...);
int isNumeric(const char *s);
WCHAR *GetFileName(WCHAR *path);

/**
	@brief	This function is pretty much straight from http://msdn.microsoft.com/en-us/library/windows/desktop/ms680582(v=vs.85).aspx
	@note	It is edited for console output, but thats about it.
	
	@param[in]	lpszFunction - The function that failed.
	@param[in]	lpAdditionalHelp - Any sort of additional information that might be useful for the user.
	
	@return	Nothing, execution does not return from this function.
	
	@private
**/
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

/**
	@brief	Just prints out a usage statement.
	
	@private
**/
void Usage(){
	printf("Usage: injex -d <dllName> < -b <binary name> [-a <arguments>] | -p <Process ID> > [-w <milliseconds>]\n");
	printf("  -d: Specify the DLL to inject.\n");
	printf("  -b: Specify a binary to run then inject into.\n");
	printf("  -a: Used in conjunction with '-b' to provide command line arguments to the\n      program to inject into.\n");
	printf("  -p: Use instead of '-b' to inject into an application that is already \n      running.\n");
	printf("  -w: Use with '-b' when running an application to start it suspended and \n      allow <milliseconds> for the injected DLL to lay hooks before\n      resuming it.\n");
	printf("  -n: The name of the running process (ie. explorer.exe) to inject into. If\n      there are multiple copies of the named process running, this will inject\n      into the first process with the specified name that it finds.\n");
	ExitProcess(-1);
}

/**
	@brief	herp derp.
	
	@private
**/
int main(int argc, CHAR* argv[])
{
	char *dllArg = NULL;
	char *programPath = NULL;
	char *procArgs = NULL;
	WCHAR procNameBuffer[MAX_PATH] = {0};
	PWCHAR procName = NULL;
	DWORD pid = 0;
	DWORD waitMs = 0;
	BOOL startProcess;
	
	if(argc==1){
		Usage();
	}

	// Get Windows Version Information.
	OSVERSIONINFOEX OsInfo = {0};
	OsInfo.dwOSVersionInfoSize = sizeof(OsInfo);
	GetVersionEx((LPOSVERSIONINFO)&OsInfo);

	// These are used later to make decisions on how to do things.
	BOOL is2kOrAbove = FALSE;
	BOOL isXpOrAbove = FALSE;
	BOOL isVistaOrAbove = FALSE;
	BOOL is7OrAbove = FALSE;

	if(OsInfo.dwMajorVersion >= 6){
		isVistaOrAbove = TRUE;
		if(OsInfo.dwMinorVersion >= 1){
			is7OrAbove = TRUE;
		}
	}

	if(OsInfo.dwMajorVersion >= 5){
		is2kOrAbove = TRUE;
		if(OsInfo.dwMinorVersion >= 1){
			isXpOrAbove = TRUE;
		}
	}


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

		} else if (strcmp(argv[i],"-n") == 0) {
			
			if(isXpOrAbove == FALSE){
				printf("ERROR: Selecting a process by name is only supported on Windows XP or above. Please use process id instead.");
				Usage();
			}

			i++;
			procName = procNameBuffer;
			MultiByteToWideChar(CP_UTF8, 0, argv[i], INT(strlen(argv[i])), procName, MAX_PATH);

			startProcess = FALSE;

		} else {
			printf("ERROR: Unknown command line option \"%s\"\n",argv[i]);
			Usage();
		}
	}

	// Validate their command line options.
	if(pid == 0 && programPath == NULL && procName==0){
		printf("ERROR: Please specify either a Process ID, a binary to launch, or the name of a running process.\n");
		Usage();
	} else if(dllArg == NULL){
		printf("ERROR: Please specify a DLL to inject.\n");
		Usage();
	}

	// Get the path to the DLL to inject.
	CHAR dllName[MAX_PATH];
	GetFullPathNameA(dllArg,MAX_PATH,dllName,NULL);

	// The handle of the process we will inject into.
	HANDLE proc=INVALID_HANDLE_VALUE;

	// Used for keeping track of the suspended threads.
	DWORD threadCount = 0;
	// Assuming 1MB stacks, 2048*1MB =~ 2GB. I am ASSUMING that the thread count in an application will never exceed this due to hardware contraints. 
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
		// Find the Pid of the process if they specified it with a name.
		if(procName != NULL){

			// Assuming that the computer this runs on wont have more than 2048 processes.
			DWORD ProcessIds[2048];
			DWORD dwProcessIdBytes;
			
			EnumProcesses(ProcessIds, sizeof(ProcessIds), &dwProcessIdBytes);

			// Now we look at each process.
			for(DWORD i=0;i<dwProcessIdBytes/sizeof(DWORD);i++){
				proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessIds[i]);

				// We probably don't have permissions to mess with it.
				if(proc==INVALID_HANDLE_VALUE){
					continue;
				}

				// Lets get the name of the process.
				WCHAR procQueryName[MAX_PATH];
				WCHAR *procFileName;
				GetModuleFileNameExW(proc, 0, procQueryName, MAX_PATH);

				if(wcslen(procQueryName) == 284 || wcslen(procQueryName) == 285){
					continue;
				}
				procFileName = GetFileName(procQueryName);

				// Break if the name matches the one we are searching for.
				if(wcscmp(procFileName, procName) == 0){
					pid = GetProcessId(proc);
					break;
				}

				CloseHandle(proc);
			}

			if(pid==0){
				printf("ERROR: Failed to find a process by the name of '%S'.\n", procName);
				ExitProcess(-1);
			}

		} else {

			// TODO: Add thread suspension for open processes.
			proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

			if(proc == NULL)
			{
				ErrorExit(TEXT("OpenProcess"), "Check the Process Id that you provided.");
				return -1;
			}
		}

		if(waitMs){
			/** @todo Add the ability to suspend already running processes. */
		}
	}

	/**
		@brief	Credit for this method of injection goes to Jeffrey Richter!
		@sa		http://www.codeproject.com/Articles/2082/API-hooking-revealed CTRL+F: "Injecting DLL by using CreateRemoteThread() API function"
	*/

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
			printf("Resuming threads in process %d...\n", GetProcessId(proc));
			ResumeThread(threads[i]);
		}
	}

	CloseHandle(proc);

	printf("DLL Injection Complete!\n");
	return 0;
}

/** @private */
int isNumeric (const char * s)
{
    if (s == NULL || *s == '\0' || isspace(*s))
      return 0;
    char * p;
    strtod (s, &p);
    return *p == '\0';
}

// Thanks to Jonathan Wood from stackoverflow.com for this.
// Returns filename portion of the given path
// Returns empty string if path is directory
WCHAR *GetFileName(WCHAR *path)
{
    WCHAR *filename = wcsrchr(path, WCHAR(0x5C));
    if (filename == NULL)
        filename = path;
    else
        filename++;

    return filename;
}