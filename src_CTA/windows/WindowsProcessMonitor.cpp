#include "WindowsProcessMonitor.h"

#include <iostream>
#include <algorithm>
#include <unordered_set>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

namespace sysmon
{
    // Chuyển đổi cấu trúc FILETIME (2 DWORDs 32-bit) sang số nguyên 64-bit (đơn vị 100-nanosecond)
    static inline uint64_t fileTimeToUint64(const FILETIME &ft)
    {
        return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    }

    // So khớp tên tiến trình không phân biệt hoa thường, cả trường hợp có hoặc không có đuôi ".exe"
    static bool matchProcessName(const std::string &exe_file, const std::string &target_name)
    {
        std::string s1 = exe_file;
        std::string s2 = target_name;
        std::transform(s1.begin(), s1.end(), s1.begin(), ::tolower);
        std::transform(s2.begin(), s2.end(), s2.begin(), ::tolower);

        if (s1 == s2)
        {
            return true;
        }
        // Nếu tên trong cấu hình không có ".exe" mà file hệ thống có ".exe"
        if (s1 == s2 + ".exe")
        {
            return true;
        }
        return false;
    }

    // Hàm khởi tạo: Lấy số lõi CPU của hệ thống Windows
    WindowsProcessMonitor::WindowsProcessMonitor()
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        num_cores_ = si.dwNumberOfProcessors > 0 ? si.dwNumberOfProcessors : 1;
    }

    // Lấy chi tiết thông số tài nguyên cho một tiến trình cụ thể qua PID
    bool WindowsProcessMonitor::getMetricsForPid(uint32_t pid, const std::string &process_name, ProcessMetrics &outMetrics)
    {
        // 1. Mở tiến trình với quyền đọc thông tin giới hạn và bộ nhớ
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess == nullptr)
        {
            return false; // Không thể mở process (có thể là tiến trình hệ thống được bảo vệ hoặc đã tắt)
        }

        // 2. Đọc thời gian thực thi CPU của tiến trình (Kernel + User time)
        FILETIME create_time{}, exit_time{}, proc_kernel_time{}, proc_user_time{};
        if (!GetProcessTimes(hProcess, &create_time, &exit_time, &proc_kernel_time, &proc_user_time))
        {
            CloseHandle(hProcess);
            return false;
        }
        uint64_t cur_proc_time = fileTimeToUint64(proc_kernel_time) + fileTimeToUint64(proc_user_time);

        // 3. Đọc tổng thời gian CPU toàn hệ thống (Kernel + User time)
        FILETIME idle_time{}, sys_kernel_time{}, sys_user_time{};
        if (!GetSystemTimes(&idle_time, &sys_kernel_time, &sys_user_time))
        {
            CloseHandle(hProcess);
            return false;
        }
        uint64_t cur_sys_time = fileTimeToUint64(sys_kernel_time) + fileTimeToUint64(sys_user_time);

        // 4. Đọc bộ nhớ RAM (Working Set Size, tương đương VmRSS trên Linux)
        PROCESS_MEMORY_COUNTERS_EX pmc{};
        double memory_mb = 0.0;
        if (GetProcessMemoryInfo(hProcess, reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&pmc), sizeof(pmc)))
        {
            memory_mb = static_cast<double>(pmc.WorkingSetSize) / (1024.0 * 1024.0);
        }

        // 5. Đọc tổng dữ liệu Disk I/O (ReadTransferCount + WriteTransferCount)
        IO_COUNTERS io{};
        uint64_t cur_disk_bytes = 0;
        if (GetProcessIoCounters(hProcess, &io))
        {
            cur_disk_bytes = io.ReadTransferCount + io.WriteTransferCount;
        }

        // Đóng handle tiến trình ngay khi đọc xong
        CloseHandle(hProcess);

        // 6. Tính toán chênh lệch với lần lấy mẫu trước
        auto now = std::chrono::steady_clock::now();
        ProcessHistoryWin &hist = history_[pid];

        double cpu_pct = 0.0;
        double disk_mb_s = 0.0;

        if (hist.initialized)
        {
            std::chrono::duration<double> elapsed = now - hist.last_time;
            double dt = elapsed.count();

            if (dt > 0.0)
            {
                // Tính % CPU = (Delta Process Time / Delta System Time) * 100 * num_cores
                if (cur_sys_time > hist.last_sys_time && cur_proc_time >= hist.last_proc_time)
                {
                    uint64_t delta_proc = cur_proc_time - hist.last_proc_time;
                    uint64_t delta_sys = cur_sys_time - hist.last_sys_time;
                    cpu_pct = (static_cast<double>(delta_proc) / delta_sys) * 100.0 * num_cores_;
                }

                // Tính Disk I/O (MB/s)
                if (cur_disk_bytes >= hist.last_disk_bytes)
                {
                    uint64_t delta_disk = cur_disk_bytes - hist.last_disk_bytes;
                    disk_mb_s = static_cast<double>(delta_disk) / (dt * 1024.0 * 1024.0);
                }
            }
        }

        // Cập nhật trạng thái cho lần kế tiếp
        hist.last_time = now;
        hist.last_proc_time = cur_proc_time;
        hist.last_sys_time = cur_sys_time;
        hist.last_disk_bytes = cur_disk_bytes;
        hist.initialized = true;

        // 7. Gán kết quả đầu ra
        outMetrics.pid = pid;
        outMetrics.process_name = process_name;
        outMetrics.cpu_percent = cpu_pct;
        outMetrics.memory_mb = memory_mb;
        outMetrics.disk_mb_s = disk_mb_s;
        outMetrics.network_kb_s = 0.0; 
        outMetrics.timestamp = getCurrentTimestamp();

        return true;
    }

    // Thu thập chỉ số phần cứng định kỳ cho danh sách tiến trình mục tiêu
    std::vector<ProcessMetrics> WindowsProcessMonitor::collectMetrics(
        const std::vector<std::string> &targetProcessNames)
    {
        std::vector<ProcessMetrics> results;
        if (targetProcessNames.empty())
        {
            return results;
        }

        // 1. Chụp snapshot danh sách tiến trình đang chạy (Toolhelp32)
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            std::cerr << "[WindowsProcessMonitor] Không thể tạo Process Snapshot." << std::endl;
            return results;
        }

        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(PROCESSENTRY32);

        std::unordered_set<uint32_t> current_active_pids;

        // 2. Duyệt qua từng tiến trình trong hệ thống
        if (Process32First(hSnapshot, &pe))
        {
            do
            {
                std::string exe_name = pe.szExeFile;

                // Chỉ kiểm tra sâu những tiến trình nằm trong cấu hình
                bool is_target = false;
                std::string matched_name;
                for (const auto &target : targetProcessNames)
                {
                    if (matchProcessName(exe_name, target))
                    {
                        is_target = true;
                        matched_name = target;
                        break;
                    }
                }

                if (!is_target)
                {
                    continue; // Bỏ qua ngay 
                }

                uint32_t pid = pe.th32ProcessID;
                if (pid == 0)
                {
                    continue; // Bỏ qua System Idle Process
                }

                current_active_pids.insert(pid);

                // Lấy chi tiết thông số tài nguyên cho tiến trình
                ProcessMetrics metrics;
                if (getMetricsForPid(pid, matched_name, metrics))
                {
                    results.push_back(std::move(metrics));
                }

            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);

        // 3. Dọn dẹp cache của các PID đã bị tắt để tránh rò rỉ bộ nhớ theo thời gian
        for (auto it = history_.begin(); it != history_.end();)
        {
            if (current_active_pids.find(it->first) == current_active_pids.end())
            {
                it = history_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        return results;
    }
}

#else
namespace sysmon
{
    WindowsProcessMonitor::WindowsProcessMonitor() {}
    std::vector<ProcessMetrics> WindowsProcessMonitor::collectMetrics(const std::vector<std::string> &) { return {}; }
    bool WindowsProcessMonitor::getMetricsForPid(uint32_t, const std::string &, ProcessMetrics &) { return false; }
}
#endif
