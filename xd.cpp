#include <Windows.h>
#include "minhook.h"

int index = 0;

#if _WIN64
#pragma comment(lib, "libMinHook.x64.lib")
#else
#pragma comment(lib, "libMinHook.x86.lib")
#endif

typedef BOOL(WINAPI* tWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
tWriteProcessMemory oWriteProcessMemory = nullptr;

typedef BOOL(WINAPI* tNtWriteVirtualMemory)(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesWritten);
tNtWriteVirtualMemory oNtWriteVirtualMemory = nullptr;

BOOL WINAPI hkWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) 
{
    wchar_t buf[512];
    wsprintf(buf, L"%li-WriteProcessMemory-pid%li.bin", static_cast<long>(index), static_cast<long>(GetProcessId(hProcess)));
  
    HANDLE hFile = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD bytesWritten;

    WriteFile(hFile, lpBuffer, nSize, &bytesWritten, nullptr);
    CloseHandle(hFile);

    index++;

    return oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL WINAPI hkNtWriteVirtualMemory(HANDLE hProcess, PVOID lpBaseAddress, PVOID lpBuffer, ULONG nSize, PULONG lpNumberOfBytesWritten) 
{
    wchar_t buf[512];
    wsprintf(buf, L"%li-NtWriteVirtualMemory-pid%li.bin", static_cast<long>(index), static_cast<long>(GetProcessId(hProcess)));

    HANDLE hFile = CreateFile(buf, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD bytesWritten;

    WriteFile(hFile, lpBuffer, nSize, &bytesWritten, nullptr);
    CloseHandle(hFile);

    index++;

    return oNtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

DWORD WINAPI MainThread(HMODULE hModule) 
{
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32)
        return FALSE;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return FALSE;

    char* WriteProcessMemory = (char*)GetProcAddress(kernel32, "WriteProcessMemory");
    char* NtWriteVirtualMemory = (char*)GetProcAddress(ntdll, "NtWriteVirtualMemory");

    if (MH_Initialize() != MH_OK)
        return FALSE;

    if (MH_CreateHook(WriteProcessMemory, &hkWriteProcessMemory, reinterpret_cast<void**>(&oWriteProcessMemory)) != MH_OK)
        return FALSE;

    if (MH_CreateHook(NtWriteVirtualMemory, &hkNtWriteVirtualMemory, reinterpret_cast<void**>(&oNtWriteVirtualMemory)) != MH_OK)
        return FALSE;

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        return FALSE;

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) 
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HANDLE handle = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);

        if (handle)
            CloseHandle(handle);
    }

    return TRUE;
}
