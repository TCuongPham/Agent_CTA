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

        // Lấy byte tải về (rx) và tải lên (tx) của PID
        bool getProcessNetworkRxTx(uint32_t pid, uint64_t &out_rx_bytes, uint64_t &out_tx_bytes);
        // Lấy tổng số byte mạng (In + Out) của một PID
        bool getProcessNetworkBytes(uint32_t pid, uint64_t &out_total_bytes);

        // Đóng phiên kết nối WFP Engine
        void cleanup();

        // Kiểm tra module có sẵn sàng hoạt động không
        bool isAvailable() const;
        // Kiểm tra xem hiện tại đang chạy bằng WFP Kernel Driver hay chế độ Fallback
        bool isKernelDriverActive() const;

    private:
        void *driver_handle_ = nullptr;     ///< Handle thiết bị Driver (HANDLE)
        bool is_driver_connected_ = false;  ///< Có đang kết nối trực tiếp với Kernel Driver không
        bool is_available_ = false;     ///< Trạng thái sẵn sàng
    };
}
