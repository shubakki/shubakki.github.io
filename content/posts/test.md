---
title: "Test"
date: 2022-11-29T01:17:12+01:00
draft: false
toc: false
images:
tags:
  - untagged
---

```cpp
#include "minhook/include/MinHook.h"


typedef DWORD( NTAPI *pNtDelayExecution )( IN BOOLEAN Alertable, IN PLARGE_INTEGER DelayInterval );

extern pNtDelayExecution pOrigNtDelayExecution = (pNtDelayExecution)GetProcAddress( GetModuleHandle( L"ntdll.dll" ), "NtDelayExecution" );

DWORD NTAPI NtDelayExecution( IN BOOLEAN Alertable, IN PLARGE_INTEGER DelayInterval )
{
    // Intercept whatever
    MessageBoxA( 0, "NO SLEEP 4 U", "BTFO", 0 );

    // Return legit function ?
    return pOrigNtDelayExecution( Alertable, (PLARGE_INTEGER)0 );
}


DWORD WINAPI InitHooksThread( LPVOID param ) {

    // MinHook itself requires initialisation, lets do this
    // before we hook specific API calls.
    if (MH_Initialize() != MH_OK) {
        OutputDebugString( TEXT( "Failed to initalize MinHook library\n" ) );
        return -1;
    }

    
    MH_STATUS status = MH_CreateHookApi( TEXT( "ntdll" ), "NtDelayExecution", NtDelayExecution,
        reinterpret_cast<LPVOID *>( &pOrigNtDelayExecution ) );

    // Enable our hooks so they become active
    status = MH_EnableHook( MH_ALL_HOOKS );

    return status;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch ( ul_reason_for_call )
    {
    case DLL_PROCESS_ATTACH: {
        //We are not interested in callbacks when a thread is created
        DisableThreadLibraryCalls( hModule );

        //We need to create a thread when initialising our hooks since
        //DllMain is prone to lockups if executing code inline.
        HANDLE hThread = CreateThread( nullptr, 0, InitHooksThread, nullptr, 0, nullptr );
        if (hThread != nullptr) {
            CloseHandle( hThread );
        }
        break;
    }
    case DLL_PROCESS_DETACH:

        break;
	}
    return TRUE;
}
```