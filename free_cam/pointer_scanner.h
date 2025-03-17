#ifndef POINTER_SCANNER_H
#define POINTER_SCANNER_H

#include <windows.h>
#include <vector>

uintptr_t GetMultiLevelPointer(HANDLE hProcess, uintptr_t baseAddress, const std::vector<uintptr_t>& offsets);

#endif