#ifndef AOBS_SCANNER_H
#define AOBS_SCANNER_H

#include <windows.h>
#include <vector>
#include <string>

struct ScanResult {
    uintptr_t address;
    size_t size;
};

ScanResult AOBScan(HANDLE hProcess, const std::string& signature);

#endif