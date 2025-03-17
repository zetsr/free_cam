#ifndef PROCESS_MANAGER_H
#define PROCESS_MANAGER_H

#include <windows.h>
#include <vector>
#include <string>

namespace ProcessManager {
    std::vector<DWORD> FindProcessesByName(const std::wstring& processName);
    HANDLE OpenProcessByPid(DWORD pid);
    bool IsProcessValid(HANDLE hProcess);
    uintptr_t GetModuleBaseAddress(DWORD pid, const std::wstring& moduleName);
    void CloseProcessHandle(HANDLE& hProcess);
}

#endif