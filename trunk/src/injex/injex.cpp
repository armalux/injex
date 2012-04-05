/** 
	@file	injex.cpp
	
	@brief	The functional portion of the injector.
	
	@private
	
	@todo	Look into using SetWindowsHookEx for DLL Injection.
	@todo	Look into thread hijacking for DLL injection.
	@todo	Make this file's functionality into a library and 
			just reference that functionality from here.
**/

/*
	There once was a man named Dwight,
	who could travel faster than light.
	He departed one day (in a relative way),
	and arrived the previous night.
*/

#pragma warning(disable:4995)
#pragma warning(disable:4996)
#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include "winstructs.h"
#include "conlib.h"

void __cdecl odprintf(const char *format, ...);
int isNumeric(const char *s);
WCHAR *GetFileName(WCHAR *path);
HANDLE GetProcessHandleFromName(LPWSTR procName);
HANDLE GetProcessHandleFromPid(DWORD Pid);
DWORD LoadLibraryInjection(HANDLE proc, PCHAR dllName);
SIZE_T ReadProcessUnicodeString(HANDLE hProcess, UNICODE_STRING *inString, UNICODE_STRING *outString);
VOID UnlinkModuleInProcess(HANDLE hProcess, LPWSTR lpModuleName);
extern "C" VOID __cdecl GetLoaderPic( PVOID picBuffer, PVOID LoadLibraryA, PCHAR dllName, DWORD dllNameLen);
extern "C" DWORD __cdecl GetLoaderPicSize();
DWORD ThreadHijackInjection(HANDLE hProcess, PCHAR dllName);

#define PROCESS_INJECT_PERMISSIONS PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
#define THREAD_INJECT_PERMISSIONS THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME
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
	printf("  -i: Injection method to be used:\n");
	printf("      0 - LoadLibrary (Default)\n");
	printf("      1 - Thread Hijacking\n");
	ExitProcess(-1);
}

/**
	@brief	herp derp.
	
	@private

	@bug	Sometimes on windows XP, if a process is started up to be 
			injected into, the process will exit before completing 
			startup if the DLL unloads itself before process startup
			is complete.
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
	DWORD injectionMethod = 0;
	
	unsigned char dllCount = 0;
	char *dllList[128];

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

	// This really wont event get shown, the program just crashes when run.
	if(isXpOrAbove == FALSE){
		printf("ERROR: Injex is not compatible with this version of windows.");
		ExitProcess(-1);
	}

	for(int i=1;i<argc;i++){
		if(strcmp(argv[i],"-d") == 0){

			// Add the DLL list
			dllList[dllCount] = (char*)malloc(MAX_PATH);

			// Get the full path to the DLL to inject, the application loading will need this.
			GetFullPathNameA(argv[++i],MAX_PATH,dllList[dllCount],NULL);

			// Inc the dll count.
			dllCount++;

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
			if(isXpOrAbove == FALSE){
				printf("ERROR: Process suspension is only supported on Windows XP/2003 or above.\n");
				Usage();
			}

			waitMs = atoi(argv[++i]);

		} else if (strcmp(argv[i],"-n") == 0) {
			
			if(isXpOrAbove == FALSE){
				printf("ERROR: Selecting a process by name is only supported on Windows XP or above. Please use process id instead.\n");
				Usage();
			}

			i++;
			procName = procNameBuffer;
			MultiByteToWideChar(CP_UTF8, 0, argv[i], INT(strlen(argv[i])), procName, MAX_PATH);

			startProcess = FALSE;

		} else if (strcmp(argv[i],"-i") == 0) {
			if(isNumeric(argv[i+1]))
				injectionMethod = atoi(argv[++i]);
			else{
				printf("ERROR: Invalid injection method, injection methods are provided by number.\n");
				Usage();
			}

		} else {
			printf("ERROR: Unknown command line option \"%s\"\n",argv[i]);
			Usage();
		}
	}

	// Validate their command line options.
	if(pid == 0 && programPath == NULL && procName == 0){
		printf("ERROR: Please specify either a Process ID, a binary to launch, or the name of a running process.\n");
		Usage();
	}

	// Check to make sure the specified a DLL.
	if(dllCount == 0){
		printf("ERROR: Please specify a DLL to inject.\n");
		Usage();
	}

	// Ensure that they selected an injection method that is within range.
	if(injectionMethod>1){
		printf("ERROR: Invalid injection method selected.\n");
		Usage();
	}

	// The handle of the process we will inject into.
	HANDLE proc=INVALID_HANDLE_VALUE;

	// Used for keeping track of the suspended threads.
	DWORD threadCount = 0;

	// Assuming 1MB stacks, 2048*1MB =~ 2GB. I am ASSUMING that the thread count in an application will never exceed this due to hardware contraints. 
	#define MAX_THREADS 2048
	HANDLE threads[MAX_THREADS];

	// Get the handle to the process to inject into and store it in proc.
	if(startProcess){
		// startProcess means that we need to start it up...
		PROCESS_INFORMATION		pi;
		STARTUPINFOA			si;
		GetStartupInfoA(&si);

		// Assemble the command line to start the process.
		char CommandLine[8191] = {0};
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

		// The process is already running, we need to get a handle to it with the correct permissions.
		if(procName != NULL){
			// Open a handle to the process if they specified it with a name.
			proc = GetProcessHandleFromName(procName);

			if(proc == NULL){
				printf("ERROR: Failed to find a process by the name of '%S' that we have permissions to inject into. Make sure that your have proper permissions and the process is running.\n", procName);
				ExitProcess(-1);
			}

		} else {
			// Open a handle to the process specified by PID.
			proc = GetProcessHandleFromPid(pid);

			if(proc == NULL)
			{
				ErrorExit(TEXT("OpenProcess"), "Check the Process Id that you provided.");
			}
		}

		if(waitMs){
			/** @todo Add the ability to suspend already running processes. */
		}
	}
	
	// Inject each dll listed.
	for(DWORD i=0;i<dllCount;i++){
		printf("Injecting %s into pid %d.\n", dllList[i], GetProcessId(proc));
		DWORD dwThreadExitCode;

		switch(injectionMethod){
			case 0:
				printf("Using LoadLibrary injection (Richter Method).\n");
				dwThreadExitCode = LoadLibraryInjection(proc, dllList[i]);
				break;

			case 1:
				printf("Using Thread Hijacking...\n");
				dwThreadExitCode = ThreadHijackInjection(proc, dllList[i]);
				break;
		}

		if(dwThreadExitCode == 0){
			printf("ERROR: The target process failed to load %s. Check the DLL path you specified.\n",dllList[i]);
			printf("DLL Injection Failed!");
		} else {
			printf("%s Injection Successful!\n",dllList[i]);
		}

		// Free up that memory...
		free(dllList[i]);
	}

	if(waitMs && startProcess){
		printf("Waiting %ims for DLL to lay hooks before resuming the process.\n",waitMs);
		Sleep(waitMs);
		for(DWORD i=0;i<threadCount;i++){
			printf("Resuming threads in process %d...\n", GetProcessId(proc));
			ResumeThread(threads[i]);
			CloseHandle(threads[i]);
		}
	}

	// No need for this handle anymore.
	CloseHandle(proc);

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

HANDLE GetProcessHandleFromName(LPWSTR procName){
	// Assuming that the computer this runs on wont have more than 2048 processes.
	DWORD dwProcessIds[2048];
	DWORD dwProcessIdBytes;
	EnumProcesses(dwProcessIds, sizeof(dwProcessIds), &dwProcessIdBytes);

	// Now we look at each process.
	for(DWORD i=0;i<dwProcessIdBytes/sizeof(DWORD);i++){
		HANDLE proc = OpenProcess(PROCESS_INJECT_PERMISSIONS, FALSE, dwProcessIds[i]);

		// We probably don't have permissions to mess with it.
		if(proc == INVALID_HANDLE_VALUE){
			continue;
		}

		// Lets get the name of the process.
		WCHAR procQueryName[MAX_PATH];
		WCHAR *procFileName;
		GetModuleFileNameExW(proc, 0, procQueryName, MAX_PATH);

		// No idea what these processes are, maybe something to do with x64 processes hiding from x86 processes??
		if(wcslen(procQueryName) == 284 || wcslen(procQueryName) == 285){
			continue;
		}

		procFileName = GetFileName(procQueryName);

		if(wcscmp(procFileName, procName) == 0){
			// Break if the name matches the one we are searching for.
			return proc;
		} else {
			// Otherwise close the handle.
			CloseHandle(proc);
		}
	}

	return NULL;
}

HANDLE GetProcessHandleFromPid(DWORD Pid){
	return OpenProcess(PROCESS_INJECT_PERMISSIONS, FALSE, Pid);
};

/**
	@bried	Inject a DLL into the target process by creating a new thread at LoadLibrary
	@note	Credit for this method of injection goes to Jeffrey Richter!
	@sa		http://www.codeproject.com/Articles/2082/API-hooking-revealed CTRL+F: "Injecting DLL by using CreateRemoteThread() API function"
*/
DWORD LoadLibraryInjection(HANDLE proc, PCHAR dllName){
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
	
	HANDLE hThread;

	if((hThread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL)) == NULL){
		VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE); // Free the memory we were going to use.
		CloseHandle(proc); // Close the process handle.
		ErrorExit(TEXT("CreateRemoteThread"), NULL);
	}
	DWORD dwThreadExitCode=0;

	// Lets wait for the thread to finish 10 seconds is our limit.
	// During this wait, DllMain is running in the injected DLL, so
	// DllMain has 10 seconds to run.
	WaitForSingleObject(hThread, 10000);

	// Lets see what it says...
	GetExitCodeThread(hThread,  &dwThreadExitCode);

	// No need for this handle anymore, lets get rid of it.
	CloseHandle(hThread);

	// Lets clear up that memory we allocated earlier.
	VirtualFreeEx(proc, RemoteString, 0, MEM_RELEASE);

	// Alright lets remove this DLL from the loaded DLL list!
	WCHAR dllNameW[MAX_PATH];
	MultiByteToWideChar(CP_UTF8, 0, dllName, (int)(strlen(dllName)+1), dllNameW, MAX_PATH);

	//UnlinkModuleInProcess(proc, dllNameW);

	return dwThreadExitCode;
}

/**
	@brief		Reads a UNICODE_STRING from the specified process.
	@details	Uses inOutString.MaximumLength for the number of bytes to read,
				and inOutString.Buffer as the address to read. This allocates
				a new buffer that must be free()d.

	@returns	The number of bytes read.
**/
SIZE_T ReadProcessUnicodeString(HANDLE hProcess, UNICODE_STRING *inString, UNICODE_STRING *outString){
	SIZE_T dwRead;

	outString->Length = inString->Length;
	outString->MaximumLength = inString->MaximumLength;
	outString->Buffer = (PWSTR)malloc(inString->MaximumLength);

	ReadProcessMemory(hProcess, inString->Buffer, outString->Buffer, inString->MaximumLength, &dwRead);

	return dwRead;
}

VOID UnlinkModuleInProcess(HANDLE hProcess, LPWSTR lpModuleName){
	typedef NTSTATUS (WINAPI *fpNtQueryInformationProcess)(
	  __in       HANDLE ProcessHandle,
	  __in       PROCESSINFOCLASS ProcessInformationClass,
	  __out      PVOID ProcessInformation,
	  __in       ULONG ProcessInformationLength,
	  __out_opt  PULONG ReturnLength
	);
	
	fpNtQueryInformationProcess NtQueryInformationProcess = (fpNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationProcess");

	PROCESS_BASIC_INFORMATION procinfo;
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &procinfo, sizeof(procinfo), NULL);

	SIZE_T dwRead;

	PEB peb;
	ReadProcessMemory(hProcess, procinfo.PebBaseAddress, &peb, sizeof(peb), &dwRead);

	PEB_LDR_DATA ldrData;
	ReadProcessMemory(hProcess, peb.LoaderData, &ldrData, sizeof(ldrData), &dwRead);

	LDR_MODULE ldrModuleA = {0};
	
	LIST_ENTRY *Flink=ldrData.InInitializationOrderModuleList.Flink;
	LIST_ENTRY *Start=Flink;
	LIST_ENTRY *Blink = 0;

	do{
		// Lets find the entry in the InInitializationOrderModuleList first.
		ReadProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InInitializationOrderModuleList), &ldrModuleA, sizeof(ldrModuleA), &dwRead);
		Blink = ldrModuleA.InInitializationOrderModuleList.Blink;
		Flink = ldrModuleA.InInitializationOrderModuleList.Flink;

		if(ldrModuleA.InInitializationOrderModuleList.Flink == Start)
			break;

		UNICODE_STRING FullDllName;
		ReadProcessUnicodeString(hProcess, &ldrModuleA.FullDllName, &FullDllName);
		if(wcscmp(FullDllName.Buffer, lpModuleName)==0){
			// Lets remove this list entry.
			LDR_MODULE Previous;
			LDR_MODULE Next;

			// Overwriting the entry at Flink, so it points to the one behind us.
			ReadProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InInitializationOrderModuleList), &Next, sizeof(Next), &dwRead);
			Next.InInitializationOrderModuleList.Blink = Blink;
			WriteProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InInitializationOrderModuleList), &Next, sizeof(Next), NULL);

			// Overwriting the entry at Blink, so it points to the one in front of us.
			ReadProcessMemory(hProcess, CONTAINING_RECORD(Blink, LDR_MODULE, InInitializationOrderModuleList), &Previous, sizeof(Previous), &dwRead);
			Previous.InInitializationOrderModuleList.Flink = Flink;
			WriteProcessMemory(hProcess, CONTAINING_RECORD(Blink, LDR_MODULE, InInitializationOrderModuleList), &Previous, sizeof(Previous), NULL);

			// Break out, to continue on to the next list...
			break;
		}
		free(FullDllName.Buffer);

	}while(TRUE);
	
	Flink=ldrData.InLoadOrderModuleList.Flink;
	Start=Flink;
	Blink = 0;

	do{
		// Lets find the entry in the InInitializationOrderModuleList first.
		ReadProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InLoadOrderModuleList), &ldrModuleA, sizeof(ldrModuleA), &dwRead);
		Blink = ldrModuleA.InLoadOrderModuleList.Blink;
		Flink = ldrModuleA.InLoadOrderModuleList.Flink;

		if(ldrModuleA.InLoadOrderModuleList.Flink == Start)
			break;

		UNICODE_STRING FullDllName;
		ReadProcessUnicodeString(hProcess, &ldrModuleA.FullDllName, &FullDllName);
		if(wcscmp(FullDllName.Buffer, lpModuleName)==0){
			// Lets remove this list entry.
			LDR_MODULE Previous;
			LDR_MODULE Next;

			// Overwriting the entry at Flink, so it points to the one behind us.
			ReadProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InLoadOrderModuleList), &Next, sizeof(Next), &dwRead);
			Next.InLoadOrderModuleList.Blink = Blink;
			WriteProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InLoadOrderModuleList), &Next, sizeof(Next), NULL);

			// Overwriting the entry at Blink, so it points to the one in front of us.
			ReadProcessMemory(hProcess, CONTAINING_RECORD(Blink, LDR_MODULE, InLoadOrderModuleList), &Previous, sizeof(Previous), &dwRead);
			Previous.InLoadOrderModuleList.Flink = Flink;
			WriteProcessMemory(hProcess, CONTAINING_RECORD(Blink, LDR_MODULE, InLoadOrderModuleList), &Previous, sizeof(Previous), NULL);

			// Break out, to continue on to the next list...
			break;
		}
		free(FullDllName.Buffer);

	}while(TRUE);
	
	
	Flink=ldrData.InMemoryOrderModuleList.Flink;
	Start=Flink;
	Blink = 0;

	do{
		// Lets find the entry in the InInitializationOrderModuleList first.
		ReadProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InMemoryOrderModuleList), &ldrModuleA, sizeof(ldrModuleA), &dwRead);
		Blink = ldrModuleA.InMemoryOrderModuleList.Blink;
		Flink = ldrModuleA.InMemoryOrderModuleList.Flink;

		if(ldrModuleA.InMemoryOrderModuleList.Flink == Start)
			break;

		UNICODE_STRING FullDllName;
		ReadProcessUnicodeString(hProcess, &ldrModuleA.FullDllName, &FullDllName);
		if(wcscmp(FullDllName.Buffer, lpModuleName)==0){
			// Lets remove this list entry.
			LDR_MODULE Previous;
			LDR_MODULE Next;

			// Overwriting the entry at Flink, so it points to the one behind us.
			ReadProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InMemoryOrderModuleList), &Next, sizeof(Next), &dwRead);
			Next.InMemoryOrderModuleList.Blink = Blink;
			WriteProcessMemory(hProcess, CONTAINING_RECORD(Flink, LDR_MODULE, InMemoryOrderModuleList), &Next, sizeof(Next), NULL);

			// Overwriting the entry at Blink, so it points to the one in front of us.
			ReadProcessMemory(hProcess, CONTAINING_RECORD(Blink, LDR_MODULE, InMemoryOrderModuleList), &Previous, sizeof(Previous), &dwRead);
			Previous.InMemoryOrderModuleList.Flink = Flink;
			WriteProcessMemory(hProcess, CONTAINING_RECORD(Blink, LDR_MODULE, InMemoryOrderModuleList), &Previous, sizeof(Previous), NULL);

			// Break out, to continue on to the next list...
			break;
		}
		free(FullDllName.Buffer);

	}while(TRUE);
}

DWORD ThreadHijackInjection(HANDLE hProcess, PCHAR dllName){
	
	DWORD CurrentPid = GetProcessId(hProcess);
	DWORD dwInjectionThread;
	HANDLE hThread;

	// We are going to just get a handle to a thread in the process, any thread.
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te;

	if (h != INVALID_HANDLE_VALUE) {
		te.dwSize = sizeof(te);
		if (Thread32First(h, &te)) {
			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID)) {
					if(te.th32OwnerProcessID == CurrentPid){
						dwInjectionThread = te.th32ThreadID;
					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
		CloseHandle(h);
	}

	// Suspend that thread.
	hThread = OpenThread(THREAD_INJECT_PERMISSIONS, FALSE, te.th32ThreadID);
	SuspendThread(hThread);

	// Get its context, so we know where to return to after redirecting logic flow.
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &context);

	DWORD_PTR *returnPointer;

#ifdef _WIN64
	returnPointer = &context.Rip;
	#define PLACEHOLDER 0xDEADBEEFDEADBEEF
#else
	returnPointer = &context.Eip;
	#define PLACEHOLDER 0xDEADBEEF
#endif

	// Make a buffer for the PIC
	PVOID picBuf = malloc(GetLoaderPicSize());

	// Have the pic copied into that buffer.
	GetLoaderPic(picBuf, GetProcAddress(GetModuleHandleA("Kernel32.dll"),"LoadLibraryA"), dllName, (DWORD)(strlen(dllName)+1));

	// Replace deadbeef (return address) in the pic with a pointer to the thread's current position.
	for(DWORD i=0; i < GetLoaderPicSize() - sizeof(PVOID);i++){
		DWORD_PTR *deadbeef = (DWORD_PTR*)((DWORD_PTR)picBuf + i);
		if(*deadbeef == PLACEHOLDER){
			*deadbeef = *returnPointer;
			break;
		}
	}

	// Create a code cave in the target process.
	LPVOID cave = VirtualAllocEx(hProcess, 0, GetLoaderPicSize(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Copy over the pic
	WriteProcessMemory(hProcess, cave, picBuf, GetLoaderPicSize(), NULL);

	// Redirect execution flow.
	*returnPointer = (DWORD_PTR)cave;
	SetThreadContext(hThread,&context);
	ResumeThread(hThread);

	return 1;
}