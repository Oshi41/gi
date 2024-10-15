#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	MessageBoxA(NULL, "Some text", "Caption", MB_OK);
	
    return TRUE;
}

