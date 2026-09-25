// Thu thập CPU %, RAM MB, Disk MB/s và Network KB/s thông qua Linux Virtual Filesystem, sử dụng POSIX và /proc

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
    struct ProcessHistory
    {
        std::chrono::steady_clock::time_point last_time; ///< Thời điểm lấy mẫu lần trước
        uint64_t last_proc_ticks = 0;                    ///< utime + stime của tiến trình
        uint64_t last_sys_ticks = 0;                     ///< Tổng CPU ticks của toàn hệ thống
        uint64_t last_disk_bytes = 0;                    ///< read_bytes + write_bytes
        uint64_t last_net_bytes = 0;                     ///< rx_bytes + tx_bytes mạng
        bool initialized = false;                        ///< Đã có dữ liệu khởi tạo lần đầu chưa
    };

    //
    class LinuxProcessMonitor : public IProcessMonitor
    {
    public:
        LinuxProcessMonitor();
        ~LinuxProcessMonitor() override = default;
        // Ngăn sao chép đối tượng
        LinuxProcessMonitor(const LinuxProcessMonitor &) = delete;
        LinuxProcessMonitor &operator=(const LinuxProcessMonitor &) = delete;
        // Cho phép di chuyển quyền sở hữu
        LinuxProcessMonitor(LinuxProcessMonitor &&) noexcept = default;
        LinuxProcessMonitor &operator=(LinuxProcessMonitor &&) noexcept = default;

        // Hàm override từ IProcessMonitor
        std::vector<ProcessMetrics> collectMetrics(
            const std::vector<std::string> &targetProcessNames) override;
        std::vector<uint32_t> getPidsByName(const std::string &processName) override;
        bool getMetricsForPid(uint32_t pid, ProcessMetrics &outMetrics) override;

    private:
        // CÁC HÀM ĐỌC /proc
        static std::string readProcessComm(uint32_t pid);
        static uint64_t readSystemCpuTicks();
        static bool readProcessCpuTicks(uint32_t pid, uint64_t &out_proc_ticks);
        static double readProcessMemoryMb(uint32_t pid);
        static uint64_t readProcessDiskBytes(uint32_t pid);
        static uint64_t readProcessNetworkBytes(uint32_t pid);

    private:
        long num_cores_ = 1;                                   ///< Số lượng lõi CPU của máy
        std::unordered_map<uint32_t, ProcessHistory> history_; ///< Bộ nhớ đệm lưu trạng thái cũ theo PID
    };

}