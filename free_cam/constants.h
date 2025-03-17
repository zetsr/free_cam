#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <string>
#include <vector>

namespace Constants {
    const std::wstring TARGET_PROCESS_NAME = L"Dragons-Win64-Shipping.exe";
    const std::string SIGNATURE_STR = "00 ?? ?? [42-44] 00 00 96 43 00 00 C8 42 00 00 96 44";
    const std::vector<uintptr_t> LP_OFFSETS = { 0x02F746D0, 0x10, 0x28, 0x2A0, 0x740 };
    const std::vector<uintptr_t> CAMERA_OFFSETS = { 0x0304B3C0, 0x2D0 };
    const float DEFAULT_STEP_VALUE = 50.0f;
    const float MIN_STEP_VALUE = 50.0f;
    const int SPECIFIC_CAMERA_Z = -100000;
}

#endif