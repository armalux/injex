#ifndef _HOOKING_H_
#define _HOOKING_H_

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define SIZEOF_JMPPATCH 5

#define HOOKING_SUCCESS             (DWORD)0x00000000
#define HOOKING_ERROR_DISASM        (DWORD)0x80000001
#define HOOKING_ERROR_DEREF_JMP     (DWORD)0x80000002
#define HOOKING_ERROR_INVALID_PARAM (DWORD)0x80000003
#define HOOKING_ERROR_PROTECTION    (DWORD)0x80000004
#define HOOKING_ERROR_OUT_OF_MEM    (DWORD)0x80000005
#define HOOKING_FAILURE             (DWORD)0x80000006

/* The Entry Stub Trampoline structure. */
typedef struct _ENTRY_STUB_TRAMP
{
	PVOID pOriginalEntryPoint;
	ULONG ulOriginalEntrySize;
	PVOID pTrampoline;
} ENTRY_STUB_TRAMP, *PENTRY_STUB_TRAMP;

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
DWORD EntryStub_create(PENTRY_STUB_TRAMP *ppStub, PVOID pOriginalEntryPoint, ULONG ulSize);

/**
	@brief	EntryStub_hook is a convenience wrapper around writeJump.

	@param	[IN] pStub - A pointer to a PENTRY_STUB_TRAMP initialized by EntryStub_create.
	@param	[IN] hooker - The hooker routine that will modify the original functions behavior.

	@retval	BOOL - Passes along the return value of writeJump.
*/
BOOL EntryStub_hook(PENTRY_STUB_TRAMP pStub, PVOID hooker);

/**
	@brief	EntryStub_unhook is a convenience wrapper around patchCode. This routine will
			unhook a hooked function by re-writing the original bytes that were saved off in
			the trampoline over the beginning of the hooked function.

	@param	[IN] pStub - A pointer to a PENTRY_STUB_TRAMP initialized by EntryStub_create.

	@retval	BOOL - Passes along the return value of patchCode.	
*/
BOOL EntryStub_unhook(PENTRY_STUB_TRAMP pStub);

/**
	@brief	EntryStub_free simply frees malloced buffers that were allocated by EntryStub_create.

	@param	[IN] pStub - A pointer to a PENTRY_STUB_TRAMP initialized by EntryStub_create.
*/
VOID EntryStub_free(PENTRY_STUB_TRAMP pStub);


/**
	@brief	patchCode. This function will write cbPatchLen bytes of pPatchBytes over whatever lives at pTargetAddress.

	@param	[IN] pTargetAddress - The address to patch.
	@param	[IN] pPatchBytes - The patch code.
	@param	[IN] cbPatchLen - The length of pPatchBytes in bytes.

	@retval TRUE if the patch succeeded, FALSE if there was a problem.

*/
BOOL patchCode(PVOID pTargetAddress, PVOID pPatchBytes, ULONG cbPatchLen);

/**
	@brief	writeJump calculates the relative offset from a given function, pOriginalFunctionAddress, to a new function,
			pNewTargetAddress. A five byte relative jump will be written at pOriginalFunctionAddress redirecting execution
			to pNewTargetAddress.

	@param	[IN] pOriginalFunctionAddress 
	@param	[IN] pNewTargetAddress 

	@retval	TRUE if the patch was written, FALSE otherwise.

*/
BOOL writeJump(PVOID pOriginalFunctionAddress, PVOID pNewTargetAddress);

/**
	@brief	derefJump. Given an address (of a function) try and determine if it is a jump to the actual function and
			if so, get the actual address of the target function so we may patch it, and not the jump to it.

	@param	[IN] pTargetAddress - The address to deref.

	@retval	PVOID - The actual address of the function.
*/
PVOID derefJump(PVOID pTargetAddress);

/* Use this to get an address after ASLR has moved shit around. */
PVOID getPostAslrAddr(PVOID ImageBaseOffset);

/* Function prototype for the hooked MessageBox function. */
INT WINAPI wrapperMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

/* The function pointer prototype for MessageBoxA */
typedef INT (WINAPI* fpMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

#endif //_HOOKING_H_