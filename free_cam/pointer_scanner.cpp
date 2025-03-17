#include "pointer_scanner.h"
#include <iostream>
#include "utils.h"

using namespace std;

// 读取指针值
static uintptr_t ReadPointer(HANDLE hProcess, uintptr_t address) {
    uintptr_t value = 0;
    SIZE_T bytesRead;
    if (ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(value), &bytesRead)) {
        if (bytesRead == sizeof(value)) {
            return value;
        }
    }
    wstring timestamp = GetTimestamp();
    wcout << timestamp << L" 读取指针失败，地址: 0x" << hex << address << dec << endl;
    return 0;
}

// 解析多级指针
uintptr_t GetMultiLevelPointer(HANDLE hProcess, uintptr_t baseAddress, const vector<uintptr_t>& offsets) {
    wstring timestamp = GetTimestamp();
    wcout << timestamp << L" 开始指针扫描，基地址: 0x" << hex << baseAddress << dec << endl;

    uintptr_t address = baseAddress;
    wcout << timestamp << L" 初始地址: 0x" << hex << address << dec << endl;

    for (size_t i = 0; i < offsets.size() - 1; ++i) {
        uintptr_t nextAddress = address + offsets[i];
        address = ReadPointer(hProcess, nextAddress);
        wcout << timestamp << L" 级别 " << i << L"，读取地址: 0x" << hex << nextAddress
            << L"，得到值: 0x" << address << dec << endl;
        if (address == 0) {
            wcout << timestamp << L"指针读取失败在级别 " << i << endl;
            return 0;
        }
    }
    address += offsets.back();
    wcout << timestamp << L" 最终地址: 0x" << hex << address << dec << endl;
    return address;
}