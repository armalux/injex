
/**
	@example	kb_hook_example.c
	@brief		An example of setting up a low level keyboard hook.
	@author		Eric Johnson
	@date		March 31st, 2012
	@version	1.0
	@ingroup	LowLevelKeyboardHooking
	@sa			injectable_dllmain_example.c
	@sa			http://www.mpgh.net/forum/31-c-c-programming/201964-c-c-vc-snippets.html#post2807915
**/

// This will be called when keys are pressed.
LRESULT CALLBACK KeyboardHook(int nCode,WPARAM wParam,LPARAM lParam)
{
	KBDLLHOOKSTRUCT* key;
	if(wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN){
		key = (KBDLLHOOKSTRUCT*)lParam;

		if(key->vkCode == VkKeyScan('a')){
			odprintf("You pressed 'a'");
		}

		if(key->vkCode == VK_F1){
			odprintf("You pressed F1");
		}
	}
	
	return 0;
}


DWORD WINAPI start(LPVOID lpParameter){
	
	// Lay the hook.
	HookKeyboard(KeyboardHook);

	// Sleeping for 25sec while the hook is running, press some keys at this time...
	Sleep(25000);
	
	// Remove the hook.
	UnhookKeyboard();
	
	return 0;
}