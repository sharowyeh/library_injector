// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

HMODULE ThisModuleHandle = NULL;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		ThisModuleHandle = hModule;
		LOGFILE("DllProcessAttach: module=0x%p reason=%d pid=%d tid=%d\n", hModule, ul_reason_for_call, GetCurrentProcessId(), GetCurrentThreadId());
    case DLL_THREAD_ATTACH:
		LOGFILE("DllThreadAttach: module=0x%p reason=%d pid=%d tid=%d\n", hModule, ul_reason_for_call, GetCurrentProcessId(), GetCurrentThreadId());
    case DLL_THREAD_DETACH:
		LOGFILE("DllThreadDetech: module=0x%p reason=%d pid=%d tid=%d\n", hModule, ul_reason_for_call, GetCurrentProcessId(), GetCurrentThreadId());
    case DLL_PROCESS_DETACH:
		LOGFILE("DllProcessDetach: module=0x%p reason=%d pid=%d tid=%d\n", hModule, ul_reason_for_call, GetCurrentProcessId(), GetCurrentThreadId());
        break;
    }
    return TRUE;
}

