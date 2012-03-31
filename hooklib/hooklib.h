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

/**
	@brief	getPostAslrAddr calculated the new address of a function after windows has applied
			address space layout randomization to the process.

	@param	[IN] ImageBaseOffset - The address of the function inside the PE (Like what you see in IDA).

	@return The new correct address (like what you would see in WinDbg/OllyDbg).
**/
PVOID getPostAslrAddr(PVOID ImageBaseOffset);

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

	@link http://www.gamedeception.net/archive/index.php?t-19273.html
**/
DWORD IAT_hook(PCHAR lpModuleName, PCHAR lpProcName, PVOID *fpOriginal, PVOID fpReplacement);

/**
	@brief	Used to retrieve a VMT pointer from a class pointer in an application that was
			compiled using Microsoft Visual C++. This can later be used for VMT hooking methods.

	@param	[IN] pClassInstance - A pointer to the instance of the class.
	
	@return	A Pointer to the Virtual Method Table used by that class.

	@link	http://www.mpgh.net/forum/289-alliance-valiant-arms-ava-tutorials/357643-vtable-hooking-vmt-hooking.html
**/
PVOID getVMTPointerMSVCPP(PVOID pClassInstance);

/**
	@brief	Used to set the VMT pointer for an instance of a class in an application that was
			compiled using Microsoft Visual C++.

	@param	[IN] pVmt - A pointer to a Virtual Method Table that the class will use.
	@param	[IN] pClassInstance - A pointer to an instance of a class.

	@return	TRUE on success, FALSE on failure to set the pointer.

	@link	http://www.mpgh.net/forum/289-alliance-valiant-arms-ava-tutorials/357643-vtable-hooking-vmt-hooking.html
**/
BOOL setVMTPointerMSVCPP(PVOID pVmt, PVOID pClassInstance);

/**
	@brief	getInstructionLength decodes a single instruction at the address pAddr
			and returns the length in bytes of that instruction.

	@param	[IN] pAddr - The address of the instruction to disassemble.

	@return	ULONG length in bytes of the instruction at pAddr.
*/
ULONG getInstructionLength(PVOID pAddr);

/**
	@brief	Write 0x90's over the specified number of instructions at the specified address.

	@param	[IN] pInstructions - A pointer to the instructions to overwrite with a nop sled.
	@param	[IN] dwInstructionCount - The number of instructions to overwrite with NOPs.
	@param	[OUT] pOriginalInstructions - (optional) A buffer to receive the instructions that were at 
			the address before they get overwritten with NOPs. If this is NULL, the parameter is ignored.

	@return	DWORD number of BYTES overwritten.
**/
DWORD nopInstructions(PVOID pInstructions, DWORD dwInstructionCount, PBYTE pOriginalInstructions);

/**
	@brief	Prints out the bytes at the specified location, for dynamic memory inspection.

	@param	[IN] pBytes - A pointer to the bytes to print.
	@param	[IN] count - The number of bytes to print.
**/
void printBytes(PBYTE pBytes, DWORD count, PCHAR lpOut);


/**
	@brief	Sets up a low level keyboard hook for setting up hotkeys.

	@param	[IN] kbHookFunction - The function to call when a keyboard event occures.
	
	@return	0 on success, -1 on failure.

	@link	http://www.mpgh.net/forum/31-c-c-programming/201964-c-c-vc-snippets.html#post2807915
	
**/
typedef LRESULT (CALLBACK *fpKeyboardHook)(int nCode,WPARAM wParam,LPARAM lParam);
int HookKeyboard(fpKeyboardHook kbHookFunction);

/**
	@brief	Removes the keyboard hook.

	@link	http://www.mpgh.net/forum/31-c-c-programming/201964-c-c-vc-snippets.html#post2807915
**/
BOOL UnhookKeyboard();

extern "C" VOID __stdcall UnloadSelfAndExit(HMODULE hModule);

#endif //_HOOKING_H_