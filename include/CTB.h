/*
 * Đóng vai trò TCP Client:
 *     - Kết nối tới CTA Agent.
 *     - Gửi danh sách cấu hình tiến trình và ngưỡng giám sát dưới dạng JSON.
 *     - Lắng nghe sự kiện vi phạm và ghi file log theo chuẩn:
 *            "date time, process id, process name, type, value"
 */

#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <mutex>

#include "ConfigModel.h"
#include "ISocketChannel.h"

namespace sysmon
{
    class CTB
    {
    public:
        /**
         * Khởi tạo CTB với kênh truyền socket và đường dẫn file log.
         * Đường dẫn file lưu nhật ký cảnh báo (mặc định "ctb_alerts.log").
         */
        explicit CTB(std::unique_ptr<ISocketChannel> socket_channel = nullptr,
                     const std::string &log_file_path = "ctb_alerts.log");
        ~CTB();

        // Ngăn chặn sao chép đối tượng
        CTB(const CTB &) = delete;
        CTB &operator=(const CTB &) = delete;
        // Cho phép di chuyển quyền sở hữu
        CTB(CTB &&) noexcept = default;
        CTB &operator=(CTB &&) noexcept = default;

        // Kết nối tới CTA Agent qua TCP Socket.
        bool start(const std::string &host = "127.0.0.1", uint16_t port = 9000, int timeout_ms = 5000);
        
        // Gửi cấu hình MonitorConfig (tự động chuyển thành JSON) sang CTA.
        bool sendConfig(const MonitorConfig &config);
        
        // Gửi chuỗi JSON cấu hình thô sang CTA.
        bool sendConfigJson(const std::string &json_str);
        
        // Vòng lặp nhận cảnh báo từ CTA và ghi log 
        void runReceiveLoop();
        
        // Dừng tiến trình CTB và ngắt kết nối
        void stop();
        bool isRunning() const;

    private:
        // Ghi một dòng sự kiện cảnh báo ra màn hình console và file log.
        void writeAlertLog(const std::string &alert_line);

    private:
        std::unique_ptr<ISocketChannel> socket_channel_;
        std::string log_file_path_;
        std::atomic<bool> is_running_{false};
        std::mutex log_mutex_;
    };
}