#include "CTB.h"

#include <iostream>
#include <fstream>

namespace sysmon
{
    CTB::CTB(std::unique_ptr<ISocketChannel> socket_channel, const std::string &log_file_path)
        : socket_channel_(socket_channel ? std::move(socket_channel) : std::make_unique<ISocketChannel>()),
          log_file_path_(log_file_path)
    {
    }
    CTB::~CTB()
    {
        stop();
    }

    // Kết nối tới CTA Agent qua TCP Socket
    bool CTB::start(const std::string &host, uint16_t port, int timeout_ms)
    {
        if (is_running_.load())
        {
            return true;
        }
        std::cout << "[CTB] Đang kết nối tới CTA tại " << host << ":" << port << "..." << std::endl;
        if (!socket_channel_->connectClient(host, port, timeout_ms))
        {
            std::cerr << "[CTB] Không thể kết nối tới CTA Agent." << std::endl;
            return false;
        }
        is_running_.store(true);

        std::cout << "[CTB] Kết nối tới CTA Agent thành công!" << std::endl;
        return true;
    }

    // Dừng tiến trình CTB và ngắt kết nối
    void CTB::stop()
    {
        if (!is_running_.exchange(false))
        {
            return;
        }
        if (socket_channel_)
        {
            socket_channel_->disconnect();
        }
        std::cout << "[CTB] Đã ngắt kết nối an toàn." << std::endl;
    }

    bool CTB::isRunning() const
    {
        return is_running_.load();
    }

    // Gửi cấu hình MonitorConfig (tự động chuyển thành JSON) sang CTA
    bool CTB::sendConfig(const MonitorConfig &config)
    {
        try
        {
            // Chuyển C++ struct thành json
            json j = config;

            // Chuyển Json thành chuỗi string
            std::string payload = j.dump();

            return sendConfigJson(payload);
        }
        catch (const std::exception &e)
        {
            std::cerr << "[CTB] Lỗi chuyển đổi cấu hình sang JSON: " << e.what() << std::endl;
            return false;
        }
    }

    // Gửi chuỗi JSON cấu hình thô sang CTA.
    bool CTB::sendConfigJson(const std::string &json_str)
    {   
        // Kiểm tra kết nối socket
        if (!socket_channel_ || !socket_channel_->isConnected())
        {
            std::cerr << "[CTB] Không thể gửi cấu hình: Chưa kết nối tới CTA!" << std::endl;
            return false;
        }
        std::cout << "[CTB] Đang đẩy thông tin cấu hình sang CTA..." << std::endl;

        // Gửi thông tin cấu hình qua socket
        if (socket_channel_->sendMessage(json_str))
        {
            std::cout << "[CTB] Gửi cấu hình thành công!" << std::endl;
            return true;
        }
        else
        {
            std::cerr << "[CTB] Gửi cấu hình thất bại." << std::endl;
            return false;
        }
    }

    // Ghi một dòng sự kiện cảnh báo ra màn hình console và file log.
    void CTB::writeAlertLog(const std::string &alert_line)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);

        // 1. In ra màn hình console (chữ màu đỏ/nổi bật)
        std::cout << "\033[1;31m[CẢNH BÁO]\033[0m " << alert_line << std::endl;

        // 2. Ghi nối tiếp (append) vào file log
        std::ofstream out_file(log_file_path_, std::ios::out | std::ios::app);
        if (out_file.is_open())
        {
            out_file << alert_line << "\n";
            out_file.close();
        }
        else
        {
            std::cerr << "[CTB] Không thể mở file log: " << log_file_path_ << std::endl;
        }
    }

    // Vòng lặp nhận cảnh báo từ CTA và ghi log
    void CTB::runReceiveLoop()
    {
        std::cout << "[CTB] Cảnh báo từ CTA (Lưu vào: "
                  << log_file_path_ << ")..." << std::endl;
        while (is_running_.load())
        {
            std::string alert_msg;
            // Đọc thông điệp với timeout 200ms để vòng lặp có thể kiểm tra cờ is_running_
            if (socket_channel_->receiveMessage(alert_msg, 200))
            {
                if (!alert_msg.empty())
                {
                    writeAlertLog(alert_msg);
                }
            }
            else
            {
                // Nếu mất kết nối mạng
                if (!socket_channel_->isConnected())
                {
                    std::cerr << "[CTB] Mất kết nối tới CTA Agent." << std::endl;
                    is_running_.store(false);
                    break;
                }
            }
        }
    }
}