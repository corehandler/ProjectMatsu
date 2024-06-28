#include <windows.h>
#include <iostream>
#include <TlHelp32.h>

DWORD FindProcessId(const wchar_t* processName)
{
    DWORD pid = 0;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hProcessSnap, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }
    return pid;
}

int main()
{
    const wchar_t* processName = L"RobloxPlayerBeta.exe";
    const wchar_t* luaScript = L"print(\"Matsu\")";

    DWORD pid = FindProcessId(processName);
    while (pid == 0) 
    {
        pid = FindProcessId(processName);
        if (pid == 0) {
            std::wcout << ".";
            std::wcout.flush();
            Sleep(1000);
        }
    }
    if (!DebugActiveProcess(pid)) {
        std::cerr << "Failed to attach to RobloxPlayerBeta.exe. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "Attached to RobloxPlayerBeta.exe with PID: " << pid << std::endl;

    HMODULE hLuaDLL = LoadLibrary(L"lua.dll");
    if (hLuaDLL == NULL) {
        std::cerr << "Failed to load lua.dll. Error: " << GetLastError() << std::endl;
        DebugActiveProcessStop(pid);
        return 1;
    }

    FARPROC funcAddress = GetProcAddress(hLuaDLL, "luaL_loadstring");
    if (funcAddress == NULL) {
        std::cerr << "Failed to resolve luaL_loadstring. Error: " << GetLastError() << std::endl;
        FreeLibrary(hLuaDLL);
        DebugActiveProcessStop(pid);
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "Failed to open RobloxPlayerBeta.exe process. Error: " << GetLastError() << std::endl;
        FreeLibrary(hLuaDLL);
        DebugActiveProcessStop(pid);
        return 1;
    }

    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, wcslen(luaScript) * sizeof(wchar_t) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteBuffer == NULL) {
        std::cerr << "Failed to allocate memory in RobloxPlayerBeta.exe process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        FreeLibrary(hLuaDLL);
        DebugActiveProcessStop(pid);
        return 1;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteBuffer, luaScript, wcslen(luaScript) * sizeof(wchar_t) + 1, &bytesWritten)) {
        std::cerr << "Failed to write Lua script into RobloxPlayerBeta.exe process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        FreeLibrary(hLuaDLL);
        DebugActiveProcessStop(pid);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)funcAddress, remoteBuffer, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread in RobloxPlayerBeta.exe process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        FreeLibrary(hLuaDLL);
        DebugActiveProcessStop(pid);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    FreeLibrary(hLuaDLL);

    DebugActiveProcessStop(pid);

    return 0;
}
