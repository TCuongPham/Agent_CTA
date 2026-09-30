// Trên Linux: LinuxProcessMonitor (đọc /proc).
// Trên Windows: WindowsProcessMonitor (Win32 & PSAPI).

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>

#include "ConfigModel.h"

namespace sysmon
{
    class IProcessMonitor
    {
    public:
        // Hàm hủy cho phép ghi đè
        virtual ~IProcessMonitor() = default;
        IProcessMonitor() = default;

        // Cấm sao chép (Copy Constructor & Copy Assignment):
        IProcessMonitor(const IProcessMonitor &) = delete;
        IProcessMonitor &operator=(const IProcessMonitor &) = delete;
        // Cho phép di chuyển quyền sở hữu:
        IProcessMonitor(IProcessMonitor &&) noexcept = default;
        IProcessMonitor &operator=(IProcessMonitor &&) noexcept = default;

        // Thu thập chỉ số phần cứng định kỳ cho một danh sách các tiến trình mục tiêu.
        virtual std::vector<ProcessMetrics> collectMetrics(
            const std::vector<std::string> &targetProcessNames) = 0;
    };
}