// console.cpp
#include <iostream>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <string>
#include <sstream>
#include <iomanip>
#include "utils.h"
#include "console.h"

// 从 ntdll.dll 获取 RtlGetVersion 函数
typedef LONG(NTAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOEXW);

std::wstring GetOSVersion() {
    std::wstring result;

    // 尝试使用 RtlGetVersion
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (hNtDll) {
        RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtDll, "RtlGetVersion");
        if (RtlGetVersion) {
            RTL_OSVERSIONINFOEXW osInfo = { 0 };
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            if (RtlGetVersion(&osInfo) == 0) {
                if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber >= 22000) {
                    result = L"Windows 11";
                }
                else if (osInfo.dwMajorVersion == 10) {
                    result = L"Windows 10";
                }
                else {
                    result = L"未知 Windows 版本";
                }

                // 从注册表获取产品类型和显示版本
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    wchar_t productName[256];
                    DWORD size = sizeof(productName);
                    if (RegGetValueW(hKey, NULL, L"ProductName", RRF_RT_REG_SZ, NULL, productName, &size) == ERROR_SUCCESS) {
                        std::wstring fullName = productName;
                        size_t pos = fullName.find(L"Windows 10");
                        if (pos != std::wstring::npos && osInfo.dwBuildNumber >= 22000) {
                            fullName.replace(pos, 10, L"Windows 11");
                        }
                        result = fullName;
                    }

                    wchar_t displayVersion[256];
                    size = sizeof(displayVersion);
                    if (RegGetValueW(hKey, NULL, L"DisplayVersion", RRF_RT_REG_SZ, NULL, displayVersion, &size) == ERROR_SUCCESS) {
                        result += L" ";
                        result += displayVersion;
                    }
                    RegCloseKey(hKey);
                }
                return result;
            }
        }
    }

    // 备用方案：退回到注册表
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t productName[256];
        DWORD size = sizeof(productName);
        if (RegGetValueW(hKey, NULL, L"ProductName", RRF_RT_REG_SZ, NULL, productName, &size) == ERROR_SUCCESS) {
            result = productName;
        }
        else {
            result = L"未知系统";
        }

        wchar_t displayVersion[256];
        size = sizeof(displayVersion);
        if (RegGetValueW(hKey, NULL, L"DisplayVersion", RRF_RT_REG_SZ, NULL, displayVersion, &size) == ERROR_SUCCESS) {
            result += L" ";
            result += displayVersion;
        }
        RegCloseKey(hKey);
    }
    return result;
}

// 获取内存信息
std::wstring GetMemoryInfo() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);

    DWORDLONG totalMB = memInfo.ullTotalPhys / (1024 * 1024);
    double totalGB = static_cast<double>(memInfo.ullTotalPhys) / (1024 * 1024 * 1024);

    std::wostringstream oss;
    oss << totalMB << L" MB (" << std::fixed << std::setprecision(2) << totalGB << L" GB)";
    return oss.str();
}

bool initialize_console() {
    SetConsoleTitle(L"github.com/zetsr");

    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1) {
        std::wcout << GetTimestamp() << L" 控制台错误: 无法设置为 UTF-16 模式" << std::endl;
        system("pause");
        return false;
    }

    std::wcout << GetTimestamp() << L" 控制台已初始化" << std::endl;
    std::wcout << GetTimestamp() << L" 系统版本: " << GetOSVersion() << std::endl;
    std::wcout << GetTimestamp() << L" 总内存: " << GetMemoryInfo() << std::endl;

    return true;
}