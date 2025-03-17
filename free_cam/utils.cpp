#include "utils.h"
#include <chrono>
#include <sstream>
#include <iomanip>

using namespace std;

wstring GetTimestamp() {
    auto now = chrono::system_clock::now();
    time_t tt = chrono::system_clock::to_time_t(now);
    tm local_tm;
    localtime_s(&local_tm, &tt);
    wstringstream ss;
    ss << L"[" << setfill(L'0') << setw(2) << local_tm.tm_hour << L":"
        << setfill(L'0') << setw(2) << local_tm.tm_min << L":"
        << setfill(L'0') << setw(2) << local_tm.tm_sec << L"]";
    return ss.str();
}