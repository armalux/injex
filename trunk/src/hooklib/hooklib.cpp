/**
	@brief	The C functional component of hooklib.
	
	@author	Eric Johnson (megamandos@gmail.com)
	
	@date	2012
	
	@private
**/

#include "hooklib.h"
#include "udis86.h"
#include "decode.h"
#include "conlib.h"
#include "..\injex\winstructs.h"

/**
	@brief	Remove a LIST_ENTRY from a list.
**/
#define UNLINK(x) (x).Blink->Flink = (x).Flink; \
	(x).Flink->Blink = (x).Blink;

/* Global udis86 object */
ud_t g_ud_obj;

/**
	@brief	udisInit initializes the udis86 lib for use.

	@param	NONE

	@retval	VOID
*/
VOID udisInit()
{
	ud_t ud_obj = {0};

	g_ud_obj = ud_obj;

	ud_init(&g_ud_obj);
	uint8_t mode;

	#ifdef _WIN64
	mode=64;
	#else
	mode=32;
	#endif

	ud_set_mode(&g_ud_obj, 32);
	ud_set_syntax(&g_ud_obj, UD_SYN_INTEL);
}

ULONG getInstructionLength(PVOID pAddr)
{
	ULONG ulCurrInstrLen = 0;
	
	ud_set_input_buffer(&g_ud_obj, (uint8_t*)pAddr, 20);
	ud_set_pc(&g_ud_obj, (uint64_t)pAddr);
	
	__try
	{
		ulCurrInstrLen = ud_disassemble(&g_ud_obj);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		ulCurrInstrLen = 0;
	}

	return ulCurrInstrLen;
}

DWORD EntryStub_create(PENTRY_STUB_TRAMP *ppStub, PVOID pOriginalEntryPoint, ULONG ulMinPatchSize)
{
	DWORD dwResult = HOOKING_SUCCESS;
	PBYTE pOriginalEntryDerefed = NULL;
	ULONG ulOriginalEntryPointSize = 0;
	ULONG ulInstLen = 0;
	ULONG ulTrampolineSize = 0;
	PBYTE pTrampoline = NULL;
	DWORD dwOldProtect;
	PENTRY_STUB_TRAMP pStub = NULL;

	if(!ppStub || !pOriginalEntryPoint || (ulMinPatchSize == 0))
	{
		dwResult = HOOKING_ERROR_INVALID_PARAM;
	}
	else
	{
		udisInit();

		/* Deref any jump that may be between the call and the actual function */
		pOriginalEntryDerefed = (PBYTE)derefJump(pOriginalEntryPoint);
		if(NULL == pOriginalEntryPoint)
		{
			dwResult = HOOKING_ERROR_DEREF_JMP;
		}

		/* Loop and accumulate how many bytes of the original function entry */
		/* we have to save off in order to create the patch.  */
		while((HOOKING_SUCCESS == dwResult) && (ulOriginalEntryPointSize < ulMinPatchSize))
		{
			ulInstLen = getInstructionLength(pOriginalEntryDerefed + ulOriginalEntryPointSize);
			if(ulInstLen == 0)
			{
				dwResult = HOOKING_ERROR_DISASM;
			}
			ulOriginalEntryPointSize += ulInstLen;
		}
	
		if(HOOKING_SUCCESS == dwResult)
		{
			/* Allocate the entry stub and trampoline. */
			pStub = (PENTRY_STUB_TRAMP)VirtualAlloc(NULL, sizeof(ENTRY_STUB_TRAMP), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}

		if(pStub)
		{
			/* Determine the size of the trampoline and allocate. */
			ulTrampolineSize = ulOriginalEntryPointSize + SIZEOF_JMPPATCH;
			pTrampoline = (PBYTE)VirtualAlloc(NULL, ulTrampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		}
		else
		{
			dwResult = HOOKING_ERROR_OUT_OF_MEM;
		}

		if(pTrampoline)
		{
			/* Copy the first bytes form the original function into the trampoline. */
			memcpy(pTrampoline, pOriginalEntryDerefed, ulOriginalEntryPointSize);

			/* Create jump from end of trampoline back to remaining original function. */
			pTrampoline[ulOriginalEntryPointSize] = 0xE9;
			*(PLONG)(pTrampoline + ulOriginalEntryPointSize + 1) = (((LONG)pOriginalEntryDerefed) + ulOriginalEntryPointSize) - (LONG)(pTrampoline + ulTrampolineSize);

			/* Set permissions on trampoline */
			/* NOTE: a better method may be to use your own VirtualAllocated pool instead of the heap. */
			if(VirtualProtect(pTrampoline, ulTrampolineSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			{
				/* Set the entry stub structures values. */
				pStub->ulOriginalEntrySize = ulOriginalEntryPointSize;
				pStub->pOriginalEntryPoint = pOriginalEntryDerefed;
				pStub->pTrampoline = pTrampoline;

				*ppStub = pStub;
			}
			else
			{
				dwResult = HOOKING_ERROR_PROTECTION;
			}
		}
		else
		{
			dwResult = HOOKING_ERROR_OUT_OF_MEM;
		}

		/* Clean up if something went wrong */
		if(HOOKING_SUCCESS != dwResult)
		{
			free(pTrampoline);
			free(pStub);
			pStub = NULL;
		}
	}
	return dwResult;
}

BOOL EntryStub_hook(PENTRY_STUB_TRAMP pStub, PVOID hooker)
{
	return writeJump(pStub->pOriginalEntryPoint, hooker);
}

BOOL EntryStub_unhook(PENTRY_STUB_TRAMP pStub)
{
	/* This re-writes the original first few bytes of the hooked function with what */
	/* we saved off using the hook function. Without the jump at the beginning, the */
	/* function is no longer hooked, and behaves like normal */
	return patchCode(pStub->pOriginalEntryPoint, pStub->pTrampoline, pStub->ulOriginalEntrySize);
}

VOID EntryStub_free(PENTRY_STUB_TRAMP pStub)
{
	free(pStub->pTrampoline);
	free(pStub);
}

PVOID derefJump(PVOID pTargetAddress)
{
	PVOID pDerefedAddress = NULL;
	PBYTE pTargetAddressAsBytes = NULL;
	
	if(NULL != pTargetAddress)
	{
		pTargetAddressAsBytes = (PBYTE)pTargetAddress;

		__try
		{
			if(pTargetAddressAsBytes[0] == 0xE9) 
			{
				pDerefedAddress = (pTargetAddressAsBytes + SIZEOF_JMPPATCH);	/* Jump targets are relative to the end of the jump instruction */
				pDerefedAddress = PVOID(LONG(pDerefedAddress) + *(PLONG)(pTargetAddressAsBytes + 1));	/* Now add the relative offset after the 0xE9 */
			}
			else
			{
				pDerefedAddress = pTargetAddress;								/* If the address passed in is not a jump, then it is the function */
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			printf("Something went terribly wrong trying to deref a jump...\n");
			pDerefedAddress = NULL;
		}
	}
	return pDerefedAddress;
}

BOOL patchCode(PVOID pTargetAddress, PVOID pPatchBytes, ULONG cbPatchLen)
{
	BOOL bRet = FALSE;
	DWORD dwOldProtect = 0;

	if(pTargetAddress && pPatchBytes && cbPatchLen)
	{
		__try
		{
			if(VirtualProtect(pTargetAddress, cbPatchLen, PAGE_EXECUTE_READWRITE, &dwOldProtect))
			{
				/* Copy the bytes, patching the code */
				memcpy(pTargetAddress, pPatchBytes, cbPatchLen);

				/* Reset the original protections */
				VirtualProtect(pTargetAddress, cbPatchLen, dwOldProtect, &dwOldProtect);

				bRet = TRUE;
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{ 
			printf("Something went terribly wrong trying to patch the code...\n");
		}
	}
	return bRet;
}

BOOL writeJump(PVOID pOriginalFunctionAddress, PVOID pNewTargetAddress)
{
	BOOL bRet = FALSE;
	BYTE cPatch[SIZEOF_JMPPATCH] = {0};
	LONG lOffset = 0;

	if(pOriginalFunctionAddress && pNewTargetAddress)
	{
		/* 5-byte relative jump */
		cPatch[0] = 0xE9;

		/* Calculate the distance in bytes between target and end of jump instruction */
		lOffset = ( (LONG)pNewTargetAddress ) - ( ( (LONG)pOriginalFunctionAddress ) + SIZEOF_JMPPATCH );

		/* Copy this value into the remaining bytes of the patch array */
		memcpy(cPatch + 1, &lOffset, sizeof(lOffset));
		
		/* Call our patchCode function with the jump patch we just created */
		bRet = patchCode(pOriginalFunctionAddress, cPatch, SIZEOF_JMPPATCH);
	}
	return bRet;
}

PVOID getPostAslrAddr(PVOID ImageBaseOffset){
	// Get the image base address from GetModuleHandle, since the HMODULE is just the image base address.
	PVOID ImageBaseAddress = (PVOID)GetModuleHandle(NULL);

	// Get the base of the code in memory.
	IMAGE_DOS_HEADER* IDH = (IMAGE_DOS_HEADER*)ImageBaseAddress;
	IMAGE_OPTIONAL_HEADER* IOH = (IMAGE_OPTIONAL_HEADER*)((BYTE*)ImageBaseAddress + IDH->e_lfanew + 24);
	PVOID CodeBase = (PVOID)(IOH->ImageBase+IOH->BaseOfCode);

	// Add the base offset of the code to the debased function address.
	return PCHAR(CodeBase) + DWORD(ImageBaseOffset);
};

DWORD IAT_hook(PCHAR lpModuleName, PCHAR lpProcName, PVOID *fpOriginal, PVOID fpReplacement){
	// We convert to all caps for case-insensitivity.
	CHAR ModuleName[MAX_PATH];
	for(DWORD i=0;i<strlen(lpModuleName)+1;i++){
		ModuleName[i] = toupper(lpModuleName[i]);
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR pImpDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)pDosHeader + pDataDir->VirtualAddress);

	BOOL FoundImportModule = FALSE;
	BOOL FoundImportFunction = FALSE;

	for(;pImpDescriptor->Name!=NULL;pImpDescriptor++){
		// We convert to all caps for case-insensitivity.
		CHAR ImpModuleName[MAX_PATH];
		for(DWORD i=0;i<strlen((char*)((BYTE *)pDosHeader + pImpDescriptor->Name))+1;i++){
			ImpModuleName[i] = toupper((char)((BYTE *)pDosHeader + pImpDescriptor->Name)[i]);
		}

		// Is this the module we are looking for??
		if(strcmp(ImpModuleName,ModuleName))
			continue; // If not, then skip it.

		FoundImportModule = TRUE;

		PIMAGE_THUNK_DATA pOFThunk = (PIMAGE_THUNK_DATA)((BYTE *)pDosHeader + pImpDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFThunk = (PIMAGE_THUNK_DATA)((BYTE *)pDosHeader + pImpDescriptor->FirstThunk);

		for(;pOFThunk->u1.Function != 0;pOFThunk++, pFThunk++){
			PIMAGE_IMPORT_BY_NAME pOFTImportName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)pDosHeader + pOFThunk->u1.AddressOfData);
			PIMAGE_IMPORT_BY_NAME pFTImportName = (PIMAGE_IMPORT_BY_NAME)(pFThunk->u1.AddressOfData);
			//char *szFunc = (char *)pImportName->Name;
	
			PCHAR FuncName = (PCHAR)pOFTImportName->Name;

			// Is this the function we are looking for?
			if(strcmp(lpProcName, FuncName))
				continue;

			FoundImportFunction = TRUE;

			// Save off that function pointer for their use.
			*fpOriginal = (PVOID)pFThunk->u1.Function;

			// Windows Vista marks the Import Address Table as PAGE_EXECUTE_READ, so we can't tamper with it, but we will anyways.
			MEMORY_BASIC_INFORMATION MemInfo;
			VirtualQuery(&pFThunk->u1.Function, &MemInfo, sizeof(MemInfo));
			DWORD oldProtect;
			
			// Remove these stupid protections...
			VirtualProtect(MemInfo.BaseAddress, MemInfo.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

			// Write in our pointer.
			pFThunk->u1.Function = (DWORD_PTR)fpReplacement;

			// Replace the protections, so if anyone asks, everything here is legit ;)
			VirtualProtect(MemInfo.BaseAddress, MemInfo.RegionSize, oldProtect, &oldProtect);

			/* There is nothing that indicates that this next part is actually used for anything, and it has caused some phuquin strange bugs on Vista and 7.
			
			// Lets temporkarily remove these restrictions too...
			VirtualQuery(&pFTImportName->Name, &MemInfo, sizeof(MemInfo));
			VirtualProtect(MemInfo.BaseAddress, MemInfo.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

			//NOTE: pFTImportName->Name is actually a function pointer too. It points to the "actual" function start.
			PVOID *pFTINName = (PVOID*)&pFTImportName->Name;
			*pFTINName = fpReplacement;
			
			// Replace the protections, so if anyone asks, everything here is legit ;)
			VirtualProtect(MemInfo.BaseAddress, MemInfo.RegionSize, oldProtect, &oldProtect);
			
			*/
		}
	}

	// Module not imported.
	if(FoundImportModule == FALSE)
		return 1;

	// Function not imported, but module is. :)
	if(FoundImportFunction == FALSE)
		return 2;

	return 0;
}


PVOID getVMTPointerMSVCPP(PVOID pClassInstance){
	PVOID *ppVmtPointer = (PVOID*)pClassInstance;
	return *ppVmtPointer;
}


BOOL setVMTPointerMSVCPP(PVOID pVmt, PVOID pClassInstance){
	PVOID *ppVmtPointer = (PVOID*)pClassInstance;
	*ppVmtPointer = pVmt;
	return TRUE; // Yeah, it always works.
}


DWORD nopInstructions(PVOID pInstructions, DWORD dwInstructionCount, PBYTE pOriginalInstructions){
	PVOID pAddr = pInstructions;

	// Count the bytes.
	for(DWORD i=0;i<dwInstructionCount;i++){
		 pAddr = (PVOID)((DWORD)pAddr + getInstructionLength(pAddr));
	}

	// This gets optimized out, but its nice to look at in C.
	DWORD byteCount = (DWORD)pAddr - (DWORD)pInstructions;

	// Just a nice way to look at things.
	PBYTE pOpCode = (PBYTE)pInstructions;

	// Save off the old bytes.
	if(pOriginalInstructions != NULL){
		for(DWORD i=0;i<byteCount;i++){
			pOriginalInstructions[i] = pOpCode[i];
		}
	}

	// Write NOP sled.
	for(DWORD i=0;i<byteCount;i++){
		pOpCode[i] = 0x90;
	}

	return byteCount;
}

void printBytes(PBYTE pBytes, DWORD count, PCHAR lpOut){
	for(DWORD i=0;i<count;i++){
		if(i % 16 == 0){
			lpOut++[0]='\n';
			lpOut += sprintf(lpOut, "0x%p:  ", &pBytes[i]);
		}

		lpOut += sprintf(lpOut, "%02hhX ",pBytes[i]);
	}
}

HANDLE g_kbHookThread=INVALID_HANDLE_VALUE;
HHOOK g_kbHook=NULL;
DWORD g_dwHookThreadId=0;
fpKeyboardHook g_kbHookFunction=NULL;

LRESULT CALLBACK _KeyboardHookProc(int nCode,WPARAM wParam,LPARAM lParam){
	g_kbHookFunction(nCode,wParam,lParam);
	return CallNextHookEx(g_kbHook,nCode,wParam,lParam);
};

int _KeyboardHookThread(fpKeyboardHook kbHookFunction){
	// Set the hook
	odprintf("Keyboard hook set...");
	g_kbHook = SetWindowsHookEx(WH_KEYBOARD_LL,_KeyboardHookProc,GetModuleHandle(NULL),0);
	
	// GetMessage: "If the function retrieves the WM_QUIT message, the return value is zero."
	MSG msg;
	while(GetMessage(&msg,0,0,0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	odprintf("Removing keyboard hook.");

	// Remove the hook
	UnhookWindowsHookEx(g_kbHook);
	
	odprintf("Keyboard hook removed.");
	
	g_dwHookThreadId = 0;
	g_kbHookThread = INVALID_HANDLE_VALUE;
	g_kbHook = NULL;
	g_kbHookFunction = NULL;

	return 0;
}

int HookKeyboard(fpKeyboardHook kbHookFunction){

	if(g_kbHookThread == INVALID_HANDLE_VALUE){
		g_kbHookFunction = kbHookFunction;
		g_kbHookThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)_KeyboardHookThread,(LPVOID)kbHookFunction, 0, &g_dwHookThreadId);
	} else {
		odprintf("We cannot create another keyboard hook, we already have one active.");
		return -1;
	}

	return 0;
}

BOOL UnhookKeyboard(){
	// Send WM_QUIT to the keyboard hook thread.
	if(g_dwHookThreadId == 0)
		return TRUE;
	return PostThreadMessage(g_dwHookThreadId,WM_QUIT,0,0);
}

DWORD *d3d9_GetVirtualTable()
{
	DWORD* pTable = NULL;        
	PVOID device = ScanPattern((PVOID)GetModuleHandleA(D3D9_MODULE), 0x1280000, (PBYTE)"\xC7\x06\x00\x00\x00\x00\x89\x86\x00\x00\x00\x00\x89\x86", "xx????xx????xx");
	if ( device != 0 )
		pTable = *(DWORD**)((DWORD_PTR)device + 2);
	return pTable;
}


inline BOOL bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for(;*szMask;++szMask,++pData,++bMask)
		if(*szMask=='x' && *pData!=*bMask) 
			return false;
	return (*szMask) == NULL;
}

PVOID ScanPattern(PVOID dwAddress, DWORD_PTR dwLen, BYTE *bMask, char *szMask)
{
	for(DWORD_PTR i=0; i < dwLen; i++)
		if( bCompare((BYTE*)((DWORD_PTR)dwAddress+i),bMask,szMask))
			return (PVOID)((DWORD_PTR)dwAddress+i);
	return 0;
}

PVOID GetPebAddress(){
	typedef NTSTATUS (WINAPI *fpNtQueryInformationProcess)(
	  __in       HANDLE ProcessHandle,
	  __in       PROCESSINFOCLASS ProcessInformationClass,
	  __out      PVOID ProcessInformation,
	  __in       ULONG ProcessInformationLength,
	  __out_opt  PULONG ReturnLength
	);
	
	fpNtQueryInformationProcess NtQueryInformationProcess = (fpNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationProcess");

	PROCESS_BASIC_INFORMATION procinfo;
	NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &procinfo, sizeof(procinfo), NULL);

	return procinfo.PebBaseAddress;
};

VOID UnlinkModuleByName(HINSTANCE hModule){
	PLDR_MODULE ldrModule;
	PLIST_ENTRY Flink = ((PPEB)GetPebAddress())->LoaderData->InInitializationOrderModuleList.Flink;

	do{
		ldrModule = CONTAINING_RECORD(Flink, LDR_MODULE, InInitializationOrderModuleList);
	}while(ldrModule->BaseAddress != hModule);

	// Unlink it from the three module lists.
	UNLINK(ldrModule->InInitializationOrderModuleList);
	UNLINK(ldrModule->InLoadOrderModuleList);
	UNLINK(ldrModule->InMemoryOrderModuleList);

	// Zero out the BaseDllName
	memset(ldrModule->BaseDllName.Buffer, 0, ldrModule->BaseDllName.MaximumLength);

	// Zero out the FullDllName
	memset(ldrModule->FullDllName.Buffer, 0, ldrModule->FullDllName.MaximumLength);

	// Zero out the LDR_MODULE structure.
	memset(ldrModule, 0, sizeof(LDR_MODULE));
}