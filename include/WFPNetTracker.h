// Module thu thập lưu lượng mạng theo PID trên Windows qua WFP (Windows Filtering Platform) & Network Flow APIs.

#pragma once

#include <cstdint>

namespace sysmon
{
    class WFPNetTracker
    {
    public:
        WFPNetTracker();
        ~WFPNetTracker();

        // Ngăn sao chép đối tượng
        WFPNetTracker(const WFPNetTracker &) = delete;
        WFPNetTracker &operator=(const WFPNetTracker &) = delete;
        // Cho phép di chuyển quyền sở hữu
        WFPNetTracker(WFPNetTracker &&) noexcept = default;
        WFPNetTracker &operator=(WFPNetTracker &&) noexcept = default;

        // Khởi tạo phiên kết nối tới Base Filtering Engine (BFE) của WFP
        bool initialize();

        // Lấy tổng số byte mạng (In + Out) của một PID
        bool getProcessNetworkBytes(uint32_t pid, uint64_t &out_total_bytes);

        // Đóng phiên kết nối WFP Engine
        void cleanup();

        // Kiểm tra WFP Engine có đang sẵn sàng
        bool isAvailable() const;

    private:
        void *engine_handle_ = nullptr; ///< Handle phiên làm việc với BFE (HANDLE)
        bool is_available_ = false;     ///< Trạng thái sẵn sàng
    };
}
