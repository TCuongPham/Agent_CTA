// Thu thập CPU %, RAM MB, Disk MB/s của tiến trình trên Windows bằng Win32 API & PSAPI.

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>

#include "IProcessMonitor.h"

namespace sysmon
{
    // Cấu trúc trạng thái lưu lại của lần trước để tính độ lệch
    struct ProcessHistoryWin
    {
        std::chrono::steady_clock::time_point last_time; ///< Thời điểm lấy mẫu lần trước
        uint64_t last_proc_time = 0;                     ///< utime + stime của tiến trình (100-nanosecond units)
        uint64_t last_sys_time = 0;                      ///< Tổng thời gian CPU hệ thống (100-nanosecond units)
        uint64_t last_disk_bytes = 0;                    ///< ReadTransferCount + WriteTransferCount
        bool initialized = false;                        ///< Đã có dữ liệu khởi tạo lần đầu chưa
    };

    class WindowsProcessMonitor : public IProcessMonitor
    {
    public:
        WindowsProcessMonitor();
        ~WindowsProcessMonitor() override = default;

        // Ngăn sao chép đối tượng
        WindowsProcessMonitor(const WindowsProcessMonitor &) = delete;
        WindowsProcessMonitor &operator=(const WindowsProcessMonitor &) = delete;
        // Cho phép di chuyển quyền sở hữu
        WindowsProcessMonitor(WindowsProcessMonitor &&) noexcept = default;
        WindowsProcessMonitor &operator=(WindowsProcessMonitor &&) noexcept = default;

        // Thu thập chỉ số phần cứng định kỳ cho danh sách tiến trình mục tiêu
        std::vector<ProcessMetrics> collectMetrics(
            const std::vector<std::string> &targetProcessNames) override;

    private:
        // Lấy chi tiết thông số tài nguyên cho một tiến trình cụ thể qua PID
        bool getMetricsForPid(uint32_t pid, const std::string &process_name, ProcessMetrics &outMetrics);

    private:
        uint32_t num_cores_ = 1;                                  ///< Số CPU core của máy
        std::unordered_map<uint32_t, ProcessHistoryWin> history_; ///< Bộ nhớ đệm lưu trạng thái cũ theo PID
    };
}
