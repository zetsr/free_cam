#include "process_manager.h"
#include <tlhelp32.h>
#include <psapi.h>
#include "utils.h"

using namespace std;

namespace ProcessManager {
    vector<DWORD> FindProcessesByName(const wstring& processName) {
        vector<DWORD> pids;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return pids;

        PROCESSENTRY32W pe32{};
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    pids.push_back(pe32.th32ProcessID);
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
        return pids;
    }

    HANDLE OpenProcessByPid(DWORD pid) {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

    bool IsProcessValid(HANDLE hProcess) {
        DWORD exitCode;
        return (GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE);
    }

    uintptr_t GetModuleBaseAddress(DWORD pid, const wstring& moduleName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

        MODULEENTRY32W me32{};
        me32.dwSize = sizeof(me32);

        if (Module32FirstW(hSnapshot, &me32)) {
            do {
                if (_wcsicmp(me32.szModule, moduleName.c_str()) == 0) {
                    CloseHandle(hSnapshot);
                    return (uintptr_t)me32.modBaseAddr;
                }
            } while (Module32NextW(hSnapshot, &me32));
        }
        CloseHandle(hSnapshot);
        return 0;
    }

    void CloseProcessHandle(HANDLE& hProcess) {
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = NULL;
        }
    }
}