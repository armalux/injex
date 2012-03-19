#include "hooklib.h"
#include "udis86.h"
#include "decode.h"
#include <winternl.h>
#include "conlib.h"

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
	ud_set_mode(&g_ud_obj, 32);
	ud_set_syntax(&g_ud_obj, UD_SYN_INTEL);
}

/**
	@brief	getInstructionLength decodes a single instruction at the address pAddr
			and returns the length in bytes of that instruction.

	@param	[IN] pAddr - The address of the instruction to disassemble.

	@retval	ULONG length in bytes of the instruction at pAddr.
*/
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

/**
	@brief	EntryStub_create takes a pointer to a PENTRY_STUB_TRAMP structure, a pointer to the
			function that will be hooked, and the minimum number of bytes at the entry point of
			the function to save off (these bytes will be replaced with our jump patch).

			This function will allocate two buffers: One being the ENTRY_STUB_TRAMP that is
			returned via the ppStub parameter, the other being the trampoline. The trampoline
			will be at least ulMinPatchSize bytes long (longer if the disassembler determines)
			plus the length of a jump. The first few bytes of the original function will be copied
			into the trampoline, followed by a jump back to the original function starting at the
			next instruction after the original bytes that were overwritten.

			Note: The trampoline must be marked as PAGE_EXECUTE_READWRITE.

	@param	[OUT] ppStub - Pointer to a PENTRRY_STUB_TRAMP structure.
	@param	[IN] pOriginalEntryPoint - Pointer to the function to be hooked. Remember that this may
			be a jump and in that case need to be dereferenced.
	@param	[IN] ulMinPatchSize - Count of bytes of the jump patch that will overwrite the original
			function entry point.

	@retval	DWORD - HOOKING_SUCCESS if the function was successfully hooked, an error otherwise.
*/
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

/**
	@brief	EntryStub_hook is a convenience wrapper around writeJump.

	@param	[IN] pStub - A pointer to a PENTRY_STUB_TRAMP initialized by EntryStub_create.
	@param	[IN] hooker - The hooker routine that will modify the original functions behavior.

	@retval	BOOL - Passes along the return value of writeJump.
*/
BOOL EntryStub_hook(PENTRY_STUB_TRAMP pStub, PVOID hooker)
{
	return writeJump(pStub->pOriginalEntryPoint, hooker);
}

/**
	@brief	EntryStub_unhook is a convenience wrapper around patchCode. This routine will
			unhook a hooked function by re-writing the original bytes that were saved off in
			the trampoline over the beginning of the hooked function.

	@param	[IN] pStub - A pointer to a PENTRY_STUB_TRAMP initialized by EntryStub_create.

	@retval	BOOL - Passes along the return value of patchCode.	
*/
BOOL EntryStub_unhook(PENTRY_STUB_TRAMP pStub)
{
	/* This re-writes the original first few bytes of the hooked function with what */
	/* we saved off using the hook function. Without the jump at the beginning, the */
	/* function is no longer hooked, and behaves like normal */
	return patchCode(pStub->pOriginalEntryPoint, pStub->pTrampoline, pStub->ulOriginalEntrySize);
}

/**
	@brief	EntryStub_free simply frees malloced buffers that were allocated by EntryStub_create.

	@param	[IN] pStub - A pointer to a PENTRY_STUB_TRAMP initialized by EntryStub_create.
*/
VOID EntryStub_free(PENTRY_STUB_TRAMP pStub)
{
	free(pStub->pTrampoline);
	free(pStub);
}

/**
	@brief	derefJump. Given an address (of a function) try and determine if it is a jump to the actual function and
			if so, get the actual address of the target function so we may patch it, and not the jump to it.

	@param	[IN] pTargetAddress - The address to deref.

	@retval	PVOID - The actual address of the function.
*/
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

/**
	@brief	patchCode. This function will write cbPatchLen bytes of pPatchBytes over whatever lives at pTargetAddress.

	@param	[IN] pTargetAddress - The address to patch.
	@param	[IN] pPatchBytes - The patch code.
	@param	[IN] cbPatchLen - The length of pPatchBytes in bytes.

	@retval TRUE if the patch succeeded, FALSE if there was a problem.

*/
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

/**
	@brief	writeJump calculates the relative offset from a given function, pOriginalFunctionAddress, to a new function,
			pNewTargetAddress. A five byte relative jump will be written at pOriginalFunctionAddress redirecting execution
			to pNewTargetAddress.

	@param	[IN] pOriginalFunctionAddress 
	@param	[IN] pNewTargetAddress 

	@retval	TRUE if the patch was written, FALSE otherwise.

*/
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

/**
	@brief	getPostAslrAddr calculated the new address of a function after windows has applied
			address space layout randomization to the process.

	@param	[IN] ImageBaseOffset - The address of the function inside the PE (Like what you see in IDA).

	@return The new correct address (like what you would see in WinDbg/OllyDbg).
**/
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

/**
	@brief	HookProcAddress will place an import address table hook based on the provided 
			module and function names. Simply call this function again, but with the original
			and replacement functions switched place to unhook.

	@param	[IN] lpModuleName - The name of the module from which the target proceedure is imported.
	@param	[IN] lpProcName - The name of the proceedure to hook.
	@param	[IN] fpOriginal - A pointer to a void pointer. This will be used to store the original 
			address of the function, so it can still be called by your code.
	@param	[IN] fpReplacement - A pointer to the replacement function.

	@return	0 on success. Non-Zero on failure (ie. the specified function isn't imported).
**/
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
			//DWORD *Hint = (DWORD*)((BYTE *)pDosHeader + pOFThunk->u1.Function);
			//PVOID FunctionAfterPatchSpace = pFTImportName->Name;
			//PVOID FunctionPointer = (PVOID)pFThunk->u1.Function;

			// Uncomment this line to see the import table stuff! :)
			//printf("Function:\n\tName: %s\n\tHint: %hX\n\tAddress: %p\n\tPatch Address: %p\n", FuncName, Hint, FunctionAfterPatchSpace, FunctionPointer);

			// Is this the function we are looking for?
			if(strcmp(lpProcName, FuncName))
				continue;

			FoundImportFunction = TRUE;

			//printf("Hooking Function:\n\tName: %s\n\tHint: %hX\n\tAddress: %p\n\tPatch Address: %p\n", FuncName, Hint, FunctionAfterPatchSpace, FunctionPointer);
			
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
			// Lets temporarily remove these restrictions too...
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
		return -1;

	// Function not imported, but module is. Try Export Address Table hooking :)
	if(!FoundImportFunction == FALSE)
		return -2;

	return 0;
}
