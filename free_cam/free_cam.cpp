#include <windows.h>
#include <iostream>
#include <fcntl.h>
#include <io.h>
#include <thread>
#include <chrono>
#include "aobs_scanner.h"
#include "pointer_scanner.h"
#include "process_manager.h"
#include "constants.h"
#include "utils.h"
#include "types.h"

using namespace std;

HANDLE hProcess = NULL;
ScanResult feature_scan_result = { 0, 0 };
float view_distance = 0.0f;
float step_value = Constants::DEFAULT_STEP_VALUE;

uintptr_t local_player_addr = 0;
uintptr_t camera_base_addr = 0;
uintptr_t camera_y_addr = 0;
uintptr_t camera_z_addr = 0;

void modify_view_distance(float delta) {
    if (hProcess && feature_scan_result.address) {
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, (LPCVOID)feature_scan_result.address, &view_distance, sizeof(float), &bytesRead)) {
            if (bytesRead == sizeof(float)) {
                view_distance += delta;
                WriteProcessMemory(hProcess, (LPVOID)feature_scan_result.address, &view_distance, sizeof(float), NULL);
            }
        }
    }
}

void request_feature_scan(bool& has_seen_specific_value) {
    wcout << GetTimestamp() << L" 特征码扫描开始，特征码: " << Constants::SIGNATURE_STR.c_str() << endl;
    auto start_time = chrono::steady_clock::now();

    feature_scan_result = AOBScan(hProcess, Constants::SIGNATURE_STR);
    if (feature_scan_result.address) {
        ReadProcessMemory(hProcess, (LPCVOID)feature_scan_result.address, &view_distance, sizeof(float), NULL);
    }

    auto end_time = chrono::steady_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time).count();
    wcout << GetTimestamp() << L" 特征码扫描结束，地址: 0x" << hex << feature_scan_result.address
        << dec << L"，耗时: " << duration << L" 毫秒" << endl;
    has_seen_specific_value = false;
}

bool initialize_console() {
    SetConsoleTitle(L"github.com/zetsr");
    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1) {
        wcout << GetTimestamp() << L" 控制台错误: 无法设置为 UTF-16 模式" << endl;
        system("pause");
        return false;
    }
    wcout << GetTimestamp() << L" 控制台已初始化" << endl;
    return true;
}

bool attach_to_process(DWORD& selected_pid) {
    vector<DWORD> pids = ProcessManager::FindProcessesByName(Constants::TARGET_PROCESS_NAME);
    if (pids.empty()) {
        wcout << GetTimestamp() << L" 未找到进程: " << Constants::TARGET_PROCESS_NAME << endl;
        wcout << GetTimestamp() << L" 请启动目标进程后按任意键重试..." << endl;
        system("pause");
        return false;
    }

    wcout << GetTimestamp() << L" 找到 " << pids.size() << L" 个进程:" << endl;
    for (size_t i = 0; i < pids.size(); ++i) {
        wcout << GetTimestamp() << L" 选项 " << (i + 1) << L": PID " << pids[i] << endl;
    }

    int choice;
    wcout << GetTimestamp() << L" 请选择目标进程 (1-" << pids.size() << L"): ";
    cin >> choice;
    if (choice < 1 || choice > static_cast<int>(pids.size())) {
        wcout << GetTimestamp() << L" 错误: 无效的选择" << endl;
        system("pause");
        return false;
    }

    selected_pid = pids[choice - 1];
    hProcess = ProcessManager::OpenProcessByPid(selected_pid);
    if (!hProcess) {
        wcout << GetTimestamp() << L" 错误: 无法打开进程 PID " << selected_pid << endl;
        system("pause");
        return false;
    }

    wcout << GetTimestamp() << L" 已附加到进程 PID " << selected_pid << endl;
    wcout << GetTimestamp() << L" 控制说明: 按 Z/C 调整视距" << endl;
    wcout << GetTimestamp() << L" 控制说明: 按 -/= 调整步长" << endl;
    wcout << GetTimestamp() << L" 控制说明: 按鼠标中键重置步长为 50" << endl;
    return true;
}

bool initialize_pointers(DWORD selected_pid) {
    uintptr_t base_address = ProcessManager::GetModuleBaseAddress(selected_pid, Constants::TARGET_PROCESS_NAME);
    if (!base_address) {
        wcout << GetTimestamp() << L" 指针错误: 无法获取模块基地址" << endl;
        return false;
    }
    wcout << GetTimestamp() << L" 模块基地址: 0x" << hex << base_address << dec << endl;

    wcout << GetTimestamp() << L" 指针扫描开始，偏移量 LP_OFFSETS: ";
    for (auto offset : Constants::LP_OFFSETS) wcout << hex << L"0x" << offset << L" " << dec;
    wcout << endl;
    auto start_time = chrono::steady_clock::now();
    local_player_addr = GetMultiLevelPointer(hProcess, base_address, Constants::LP_OFFSETS);
    auto end_time = chrono::steady_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time).count();
    wcout << GetTimestamp() << L" 指针扫描结束，local_player_addr: 0x" << hex << local_player_addr
        << dec << L"，耗时: " << duration << L" 毫秒" << endl;

    wcout << GetTimestamp() << L" 指针扫描开始，偏移量 CAMERA_OFFSETS: ";
    for (auto offset : Constants::CAMERA_OFFSETS) wcout << hex << L"0x" << offset << L" " << dec;
    wcout << endl;
    start_time = chrono::steady_clock::now();
    camera_base_addr = GetMultiLevelPointer(hProcess, base_address, Constants::CAMERA_OFFSETS);
    end_time = chrono::steady_clock::now();
    duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time).count();
    wcout << GetTimestamp() << L" 指针扫描结束，camera_base_addr: 0x" << hex << camera_base_addr
        << dec << L"，耗时: " << duration << L" 毫秒" << endl;

    if (!local_player_addr || !camera_base_addr || local_player_addr == camera_base_addr) {
        wcout << GetTimestamp() << L" 指针错误: 扫描失败或地址相同" << endl;
        return false;
    }
    camera_y_addr = camera_base_addr + 0x4;
    camera_z_addr = camera_base_addr + 0x8;
    return true;
}

void handle_user_input() {
    if (feature_scan_result.address) {
        if (GetAsyncKeyState('Z') & 0x8000) modify_view_distance(step_value);
        else if (GetAsyncKeyState('C') & 0x8000) modify_view_distance(-step_value);
    }

    if (GetAsyncKeyState(VK_OEM_MINUS) & 0x8000) step_value = max(Constants::MIN_STEP_VALUE, step_value - 10.0f);
    else if (GetAsyncKeyState(VK_OEM_PLUS) & 0x8000) step_value += 10.0f;
    if (GetAsyncKeyState(VK_MBUTTON) & 0x8000) {
        step_value = Constants::DEFAULT_STEP_VALUE;
        wcout << GetTimestamp() << L" 步长重置为 " << step_value << endl;
        Sleep(200);
    }
}

void run_main_loop() {
    bool local_player = false;
    SIZE_T bytes_read;
    if (!ReadProcessMemory(hProcess, (LPCVOID)local_player_addr, &local_player, sizeof(bool), &bytes_read) || bytes_read != sizeof(bool)) {
        wcout << GetTimestamp() << L" 内存错误: 无法读取 local_player" << endl;
        ProcessManager::CloseProcessHandle(hProcess);
        return;
    }
    bool last_local_player = local_player;
    bool has_seen_specific_value = false;

    if (local_player) {
        wcout << GetTimestamp() << L" 初始化触发: local_player 为 true" << endl;
        request_feature_scan(has_seen_specific_value);
    }

    auto last_read_time = chrono::steady_clock::now();
    auto last_log_time = chrono::steady_clock::now();

    while (true) {
        if (!ProcessManager::IsProcessValid(hProcess)) {
            wcout << GetTimestamp() << L" 进程已终止，返回选择进程" << endl;
            ProcessManager::CloseProcessHandle(hProcess);
            feature_scan_result = { 0, 0 };
            break;
        }

        auto now = chrono::steady_clock::now();
        if (chrono::duration_cast<chrono::milliseconds>(now - last_read_time).count() >= 100) {
            last_read_time = now;

            ReadProcessMemory(hProcess, (LPCVOID)local_player_addr, &local_player, sizeof(bool), NULL);
            Vec3 camera;
            ReadProcessMemory(hProcess, (LPCVOID)camera_base_addr, &camera.x, sizeof(float), NULL);
            ReadProcessMemory(hProcess, (LPCVOID)camera_y_addr, &camera.y, sizeof(float), NULL);
            ReadProcessMemory(hProcess, (LPCVOID)camera_z_addr, &camera.z, sizeof(float), NULL);

            if (!local_player && (camera.is_zero() || camera.is_below_specific_z(Constants::SPECIFIC_CAMERA_Z))) {
                has_seen_specific_value = true;
            }

            if (!last_local_player && local_player) {
                if (has_seen_specific_value || camera.is_zero() || camera.is_below_specific_z(Constants::SPECIFIC_CAMERA_Z)) {
                    request_feature_scan(has_seen_specific_value);
                }
            }

            last_local_player = local_player;
        }

        // 每秒输出一次内存值
        if (chrono::duration_cast<chrono::milliseconds>(now - last_log_time).count() >= 1000) {
            last_log_time = now;
            Vec3 camera;
            ReadProcessMemory(hProcess, (LPCVOID)camera_base_addr, &camera.x, sizeof(float), NULL);
            ReadProcessMemory(hProcess, (LPCVOID)camera_y_addr, &camera.y, sizeof(float), NULL);
            ReadProcessMemory(hProcess, (LPCVOID)camera_z_addr, &camera.z, sizeof(float), NULL);
            wcout << GetTimestamp() << L" 内存值 | 本地玩家: 0x" << hex << local_player_addr << L" = " << dec << local_player
                << L" | 相机X: 0x" << hex << camera_base_addr << L" = " << dec << camera.x
                << L" | 相机Y: 0x" << hex << camera_y_addr << L" = " << dec << camera.y
                << L" | 相机Z: 0x" << hex << camera_z_addr << L" = " << dec << camera.z
                << L" | 视距: 0x" << hex << feature_scan_result.address << L" = " << dec << view_distance << endl;
        }

        handle_user_input();
        Sleep(1);
    }
}

int main() {
    if (!initialize_console()) {
        return 1;
    }

    while (true) {
        DWORD selected_pid;
        if (!attach_to_process(selected_pid)) {
            continue;
        }

        if (!initialize_pointers(selected_pid)) {
            ProcessManager::CloseProcessHandle(hProcess);
            continue;
        }

        run_main_loop();
    }

    ProcessManager::CloseProcessHandle(hProcess);
    return 0;
}