#include <thread>
#include <mutex>
#include <sstream>
#include <vector>
#include <set>
#include <atomic>
#include <windows.h>

using namespace std;

// 扫描结果结构体
struct ScanResult {
    uintptr_t address; // 匹配的地址
    size_t size;       // 匹配的长度
};

// 全局变量
static mutex scanMutex;              // 保护扫描结果的互斥锁
static atomic<bool> found(false);    // 标记是否找到匹配，用于快速停止线程

// 解析特征码字符串
static bool ParseSignature(const string& signature, vector<pair<uint8_t, set<uint8_t>>>& pattern) {
    stringstream ss(signature);
    string token;
    pattern.clear();
    while (ss >> token) {
        if (token == "??") {
            // 通配符，允许任何字节
            pattern.push_back(make_pair(0, set<uint8_t>()));
        }
        else if (token.front() == '[' && token.back() == ']') {
            // 解析范围 [min-max]
            size_t dashPos = token.find('-');
            if (dashPos != string::npos) {
                string minStr = token.substr(1, dashPos - 1);
                string maxStr = token.substr(dashPos + 1, token.size() - dashPos - 2);
                try {
                    uint8_t minVal = static_cast<uint8_t>(stoi(minStr, nullptr, 16));
                    uint8_t maxVal = static_cast<uint8_t>(stoi(maxStr, nullptr, 16));
                    set<uint8_t> allowed;
                    for (uint8_t val = minVal; val <= maxVal; ++val) {
                        allowed.insert(val);
                    }
                    pattern.push_back(make_pair(0, allowed)); // 范围字节
                }
                catch (...) {
                    return false; // 解析失败
                }
            }
            else {
                return false;
            }
        }
        else {
            // 固定字节
            try {
                uint8_t byte = static_cast<uint8_t>(stoi(token, nullptr, 16));
                set<uint8_t> singleByte = { byte };
                pattern.push_back(make_pair(byte, singleByte));
            }
            catch (...) {
                return false;
            }
        }
    }
    return !pattern.empty();
}

// 支持通配符和范围的模式匹配函数
static bool MatchPattern(const uint8_t* data, const vector<pair<uint8_t, set<uint8_t>>>& pattern, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        const auto& p = pattern[i];
        if (p.second.empty()) {
            continue; // 通配符，跳过
        }
        else if (p.second.size() == 1) {
            if (data[i] != p.first) {
                return false; // 固定字节不匹配
            }
        }
        else {
            if (p.second.find(data[i]) == p.second.end()) {
                return false; // 范围字节不在允许集合中
            }
        }
    }
    return true;
}

// AOBS 扫描线程函数
static void AOBScanThread(HANDLE hProcess, uintptr_t startAddress, uintptr_t endAddress,
    const vector<pair<uint8_t, set<uint8_t>>>& pattern, ScanResult& result, atomic<bool>& found) {
    size_t patternSize = pattern.size();
    vector<uint8_t> buffer(1024 * 1024); // 1MB 缓冲区
    uintptr_t currentAddress = startAddress;

    while (currentAddress < endAddress && !found.load()) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProcess, (LPCVOID)currentAddress, &mbi, sizeof(mbi))) {
            currentAddress += 4096; // 页面大小
            continue;
        }
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            size_t bytesRead;
            size_t regionSize = mbi.RegionSize;
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), min(regionSize, buffer.size()), &bytesRead)) {
                for (size_t i = 0; i <= bytesRead - patternSize; ++i) {
                    if (MatchPattern(buffer.data() + i, pattern, patternSize)) {
                        lock_guard<mutex> lock(scanMutex);
                        if (!found.load()) {
                            result.address = (uintptr_t)mbi.BaseAddress + i;
                            result.size = patternSize;
                            found.store(true);
                        }
                        return;
                    }
                }
            }
        }
        currentAddress = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
}

// AOBS 扫描主函数
ScanResult AOBScan(HANDLE hProcess, const string& signature) {
    ScanResult result = { 0, 0 };
    vector<pair<uint8_t, set<uint8_t>>> pattern;
    if (!ParseSignature(signature, pattern)) {
        return result; // 解析失败
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t minAddress = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    // 动态确定线程数，略多于 CPU 核心数
    unsigned int cpuCores = thread::hardware_concurrency();
    unsigned int threadCount = cpuCores > 0 ? cpuCores * 2 : 8; // 核心数的两倍

    vector<thread> threads;
    found.store(false);
    uintptr_t rangeSize = (maxAddress - minAddress) / threadCount;
    for (unsigned int i = 0; i < threadCount; ++i) {
        uintptr_t threadStart = minAddress + i * rangeSize;
        uintptr_t threadEnd = (i == threadCount - 1) ? maxAddress : threadStart + rangeSize;
        threads.emplace_back(AOBScanThread, hProcess, threadStart, threadEnd, ref(pattern), ref(result), ref(found));
    }

    for (auto& t : threads) {
        t.join();
    }
    return result;
}