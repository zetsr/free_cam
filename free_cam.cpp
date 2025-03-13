#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <iostream>
#include <string>
#include <sstream>
#include <fcntl.h>
#include <io.h>
#include <chrono>
#include <thread>
#include <mutex>

using namespace std;

// AOB 特征码
const string signatureStr = "00 ?? ?? ?? 00 00 96 43 00 00 C8 42 00 00 96 44";

// 扫描结果结构体
struct ScanResult {
    uintptr_t address;
    size_t size;
};

// 全局变量
HANDLE hProcess = NULL;
ScanResult g_scanResult = { 0, 0 };
bool g_isScanned = false;
float currentValue = 0.0f;
float stepValue = 50.0f;
mutex scanMutex;

// 枚举进程并返回符合名称的 PID 列表
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

// 解析特征码字符串
bool ParseSignature(const string& signature, vector<uint8_t>& bytes, vector<bool>& mask) {
    stringstream ss(signature);
    string byteStr;

    bytes.clear();
    mask.clear();

    while (ss >> byteStr) {
        if (byteStr == "??") {
            bytes.push_back(0);
            mask.push_back(false);
        }
        else {
            try {
                uint8_t byte = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
                bytes.push_back(byte);
                mask.push_back(true);
            }
            catch (...) {
                return false;
            }
        }
    }
    return !bytes.empty();
}

// 多线程扫描的核心函数
void AOBScanThread(HANDLE hProcess, uintptr_t startAddress, uintptr_t endAddress,
    const vector<uint8_t>& bytes, const vector<bool>& mask) {
    size_t patternSize = bytes.size();
    uintptr_t address = startAddress;
    const size_t bufferSize = 1024 * 1024;
    vector<uint8_t> buffer(bufferSize);

    while (address < endAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            address += 4096;
            continue;
        }

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_NOACCESS)) {

            SIZE_T bytesRead;
            SIZE_T regionSize = min(mbi.RegionSize, bufferSize);
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), regionSize, &bytesRead)) {
                for (size_t i = 0; i <= bytesRead - patternSize; i++) {
                    bool found = true;

                    for (size_t j = 0; j < patternSize; j++) {
                        if (mask[j] && buffer[i + j] != bytes[j]) {
                            found = false;
                            break;
                        }
                    }

                    if (found) {
                        lock_guard<mutex> lock(scanMutex);
                        if (g_scanResult.address == 0) {
                            g_scanResult.address = (uintptr_t)mbi.BaseAddress + i;
                            g_scanResult.size = patternSize;
                        }
                        return;
                    }
                }
            }
        }

        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (address < startAddress) break;
    }
}

// 封装的高层函数，添加多线程和计时
void AOBScan(HANDLE hProcess, const string& signature) {
    auto start = chrono::high_resolution_clock::now();

    vector<uint8_t> bytes;
    vector<bool> mask;
    if (!ParseSignature(signature, bytes, mask)) {
        wcout << L"无效的特征码格式！" << endl;
        return;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t minAddress = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    unsigned int threadCount = thread::hardware_concurrency();
    if (threadCount == 0) threadCount = 4;
    vector<thread> threads;

    g_scanResult = { 0, 0 };
    g_isScanned = false;

    uintptr_t rangeSize = (maxAddress - minAddress) / threadCount;
    for (unsigned int i = 0; i < threadCount; ++i) {
        uintptr_t threadStart = minAddress + i * rangeSize;
        uintptr_t threadEnd = (i == threadCount - 1) ? maxAddress : threadStart + rangeSize;
        threads.emplace_back(AOBScanThread, hProcess, threadStart, threadEnd, ref(bytes), ref(mask));
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end = chrono::high_resolution_clock::now();
    auto durationMs = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    double durationSec = durationMs / 1000.0;
    wcout << L"扫描耗时: " << durationSec << L" 秒" << endl;

    if (g_scanResult.address) {
        g_isScanned = true;
    }
}

// 修改内存值，每次操作前读取最新值
void ModifyValue(float delta) {
    if (hProcess && g_scanResult.address) {
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, (LPCVOID)g_scanResult.address, &currentValue, sizeof(float), &bytesRead)) {
            if (bytesRead == sizeof(float)) {
                currentValue += delta;
                WriteProcessMemory(hProcess, (LPVOID)g_scanResult.address, &currentValue, sizeof(float), NULL);
            }
            else {
                wcout << L"读取内存数据不足，地址: 0x" << hex << g_scanResult.address << dec << endl;
            }
        }
        else {
            wcout << L"读取内存失败，地址: 0x" << hex << g_scanResult.address << dec << endl;
        }
    }
}

// 修改步长
void ModifyStepValue(float delta) {
    stepValue += delta;
    if (stepValue < 50.0f) stepValue = 50.0f;
}

// 重置步长到初始值
void ResetStepValue() {
    stepValue = 50.0f;
    wcout << L"日志: Mouse3 键被按下，步长重置为: " << stepValue << endl;
}

// 检查进程是否仍然有效
bool IsProcessValid(HANDLE hProcess) {
    DWORD exitCode;
    if (GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
        return true;
    }
    return false;
}

// 主函数
int main() {
    SetConsoleTitle(L"github.com/zetsr");

    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1) {
        cout << "Failed to set console mode to UTF-16" << endl;
        system("pause");
        return 1;
    }

    while (true) { // 外层循环，用于重新选择进程
        wstring targetName = L"Dragons-Win64-Shipping.exe";
        vector<DWORD> pids = FindProcessesByName(targetName);

        if (pids.empty()) {
            wcout << L"未找到 Dragons-Win64-Shipping.exe 进程" << endl;
            wcout << L"请启动目标进程后按任意键重试..." << endl;
            system("pause");
            continue; // 返回选择进程
        }

        wcout << L"找到以下 " << pids.size() << L" 个 Dragons-Win64-Shipping.exe 进程:" << endl;
        for (size_t i = 0; i < pids.size(); ++i) {
            wcout << i + 1 << L". PID: " << pids[i] << endl;
        }

        int choice;
        wcout << L"请选择目标进程 (1-" << pids.size() << L"): ";
        cin >> choice;

        if (choice < 1 || choice > static_cast<int>(pids.size())) {
            wcout << L"无效选择，按任意键重试..." << endl;
            system("pause");
            continue; // 返回选择进程
        }

        DWORD selectedPid = pids[choice - 1];
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, selectedPid);
        if (!hProcess) {
            wcout << L"无法打开进程 PID: " << selectedPid << L"，按任意键重试..." << endl;
            system("pause");
            continue; // 返回选择进程
        }

        wcout << L"已附加到进程 PID: " << selectedPid << endl;
        wcout << L"按 Delete 开始扫描" << endl;
        wcout << L"“按下”或“按住” Z 或 C 调整视距" << endl;
        wcout << L"“按下”或“按住” - 或 = 调整步长" << endl;
        wcout << L"“按下” Mouse3 重置步长为50" << endl;
        wcout << L"当前步长值: " << stepValue << endl;
        wcout << L"每次连接至服务器之后需要再次进行扫描！！！" << endl;
        wcout << L"请勿在主菜单进行扫描！！！" << endl;

        // 内层循环，处理扫描和修改
        while (true) {
            if (!IsProcessValid(hProcess)) {
                wcout << L"目标进程已退出或失效，返回选择进程..." << endl;
                if (hProcess) {
                    CloseHandle(hProcess);
                    hProcess = NULL;
                }
                g_scanResult = { 0, 0 };
                g_isScanned = false;
                currentValue = 0.0f;
                Sleep(1000); // 短暂等待，避免快速循环
                break; // 跳出内层循环，返回选择进程
            }

            if (GetAsyncKeyState(VK_DELETE) & 0x8000) {
                wcout << L"日志: Delete 键被按下，开始扫描" << endl;
                AOBScan(hProcess, signatureStr);
                if (g_scanResult.address) {
                    ReadProcessMemory(hProcess, (LPCVOID)g_scanResult.address, &currentValue, sizeof(float), NULL);
                    wcout << L"找到地址: 0x" << hex << g_scanResult.address << dec << endl;
                    wcout << L"初始值: " << currentValue << endl;
                }
                else {
                    wcout << L"扫描失败，未找到匹配地址" << endl;
                }
                Sleep(200);
            }

            if (g_scanResult.address) {
                if (GetAsyncKeyState('Z') & 0x8000) {
                    ModifyValue(stepValue);
                }
                else if (GetAsyncKeyState('C') & 0x8000) {
                    ModifyValue(-stepValue);
                }
            }

            if (GetAsyncKeyState(VK_OEM_MINUS) & 0x8000) {
                ModifyStepValue(-10.0f);
            }
            else if (GetAsyncKeyState(VK_OEM_PLUS) & 0x8000) {
                ModifyStepValue(10.0f);
            }

            if (GetAsyncKeyState(VK_MBUTTON) & 0x8000) {
                ResetStepValue();
                Sleep(200);
            }

            // 检查 ModifyValue 是否失败（进程可能已失效）
            if (g_scanResult.address) {
                SIZE_T bytesRead;
                if (!ReadProcessMemory(hProcess, (LPCVOID)g_scanResult.address, &currentValue, sizeof(float), &bytesRead)) {
                    wcout << L"检测到内存访问失败，目标进程可能已失效，返回选择进程..." << endl;
                    if (hProcess) {
                        CloseHandle(hProcess);
                        hProcess = NULL;
                    }
                    g_scanResult = { 0, 0 };
                    g_isScanned = false;
                    currentValue = 0.0f;
                    Sleep(1000);
                    break; // 跳出内层循环，返回选择进程
                }
            }

            Sleep(1);
        }
    }

    if (hProcess) CloseHandle(hProcess);
    return 0;
}