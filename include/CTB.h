/*
 * Đóng vai trò TCP Server:
 *     - Lắng nghe kết nối từ CTA Agent.
 *     - Đọc file config.json và tự động gửi cấu hình sang CTA khi file được Save.
 *     - Lắng nghe sự kiện vi phạm và ghi file log theo chuẩn:
 *            "date time, process id, process name, type, value"
 */

#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <mutex>
#include <filesystem>

#include "ConfigModel.h"
#include "ISocketChannel.h"

namespace sysmon
{
    class CTB
    {
    public:
        // Khởi tạo CTB với kênh truyền socket, đường dẫn file log và file cấu hình
        explicit CTB(std::unique_ptr<ISocketChannel> socket_channel = nullptr,
                     const std::string &log_file_path = "ctb_alerts.log",
                     const std::string &config_file_path = "config.json");
        ~CTB();

        // Ngăn chặn sao chép đối tượng
        CTB(const CTB &) = delete;
        CTB &operator=(const CTB &) = delete;
        // Cho phép di chuyển quyền sở hữu
        CTB(CTB &&) noexcept = default;
        CTB &operator=(CTB &&) noexcept = default;

        // Khởi động TCP Socket Server
        bool start(const std::string &host = "0.0.0.0", uint16_t port = 9000);
        
        // Đọc cấu hình từ file
        bool loadConfigFromFile(const std::string &file_path);
        
        // Gửi chuỗi JSON cấu hình sang CTA
        bool sendConfigJson(const std::string &json_str);
        
        // Vòng lặp nhận cảnh báo từ CTA và ghi log 
        void runReceiveLoop();
        
        // Dừng tiến trình CTB và ngắt kết nối
        void stop();
        bool isRunning() const;

    private:
        // Ghi một dòng sự kiện cảnh báo ra màn hình console và file log
        void writeAlertLog(const std::string &alert_line);

        // Kiểm tra và tự động reload nếu file config.json vừa được Save
        void checkAndReloadConfigFile();

    private:
        std::unique_ptr<ISocketChannel> socket_channel_;
        std::string log_file_path_;
        std::string config_file_path_;
        std::filesystem::file_time_type last_config_time_{};
        std::string current_config_json_;
        std::atomic<bool> is_running_{false};
        std::mutex log_mutex_;
    };
}