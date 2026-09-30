#include "CTB.h"

#include <iostream>
#include <fstream>
#include <sstream>

namespace sysmon
{
    CTB::CTB(std::unique_ptr<ISocketChannel> socket_channel, 
             const std::string &log_file_path,
             const std::string &config_file_path)
        : socket_channel_(socket_channel ? std::move(socket_channel) : std::make_unique<ISocketChannel>()),
          log_file_path_(log_file_path),
          config_file_path_(config_file_path)
    {
        if (!config_file_path_.empty())
        {
            loadConfigFromFile(config_file_path_);
        }
    }

    CTB::~CTB()
    {
        stop();
    }

    // Đọc cấu hình từ file json
    bool CTB::loadConfigFromFile(const std::string &file_path)
    {
        config_file_path_ = file_path;
        if (!std::filesystem::exists(config_file_path_))
        {
            return false;
        }

        try
        {
            std::ifstream file(config_file_path_);
            if (!file.is_open())
            {
                return false;
            }
            std::stringstream buffer;
            buffer << file.rdbuf();
            json j = json::parse(buffer.str());
            current_config_json_ = j.dump();
            last_config_time_ = std::filesystem::last_write_time(config_file_path_);
            std::cout << "[CTB] Đã nạp cấu hình từ " << config_file_path_ << std::endl;
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[CTB] Lỗi nạp cấu hình từ " << file_path << ": " << e.what() << std::endl;
            return false;
        }
    }

    // Khởi động CTB ở chế độ TCP Server
    bool CTB::start(const std::string &host, uint16_t port)
    {
        if (is_running_.load())
        {
            return true;
        }
        std::cout << "[CTB Server] Đang mở Server tại " << host << ":" << port << "..." << std::endl;
        if (!socket_channel_->startServer(host, port))
        {
            std::cerr << "[CTB] Không thể mở Server trên " << host << ":" << port << std::endl;
            return false;
        }
        is_running_.store(true);

        std::cout << "[CTB Server] Đang lắng nghe kết nối từ CTA trên cổng " << port << "..." << std::endl;
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

    // Gửi chuỗi JSON cấu hình sang CTA.
    bool CTB::sendConfigJson(const std::string &json_str)
    {   
        // Kiểm tra kết nối socket
        if (!socket_channel_ || !socket_channel_->isConnected())
        {
            std::cerr << "[CTB] Không thể gửi cấu hình: Chưa kết nối tới CTA!" << std::endl;
            return false;
        }
        std::cout << "[CTB] Đang đẩy thông tin cấu hình sang CTA..." << std::endl;

        // Đảm bảo JSON ở dạng compact 1 dòng (không chứa '\n' làm vỡ frame nhận)
        std::string payload;
        try
        {
            json j = json::parse(json_str);
            payload = j.dump();
        }
        catch (...)
        {
            payload = json_str;
        }

        // Gửi thông tin cấu hình qua socket
        if (socket_channel_->sendMessage(payload))
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

    // Kiểm tra và tự động reload nếu file config.json vừa được Save
    void CTB::checkAndReloadConfigFile()
    {
        if (config_file_path_.empty() || !std::filesystem::exists(config_file_path_))
        {
            return;
        }

        try
        {
            auto current_time = std::filesystem::last_write_time(config_file_path_);
            if (current_time != last_config_time_)
            {
                last_config_time_ = current_time;
                std::ifstream file(config_file_path_);
                if (file.is_open())
                {
                    std::stringstream buffer;
                    buffer << file.rdbuf();
                    json j = json::parse(buffer.str());
                    current_config_json_ = j.dump();
                    std::cout << "\n[CTB Server] File " << config_file_path_ 
                              << " vừa thay đổi! Tự động gửi cấu hình sang CTA..." << std::endl;
                    if (socket_channel_->isConnected())
                    {
                        sendConfigJson(current_config_json_);
                    }
                }
            }
        }
        catch (...)
        {
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
        std::cout << "[CTB Server] Cảnh báo từ CTA (Lưu vào: "
                  << log_file_path_ << ")..." << std::endl;

        while (is_running_.load())
        {
            // 1. Kiểm tra xem file config.json có thay đổi không
            checkAndReloadConfigFile();

            // 2. Nếu chưa có CTA kết nối, chờ CTA kết nối tới
            if (!socket_channel_->isConnected())
            {
                if (!socket_channel_->waitForClient(500))
                {
                    continue;
                }
                std::cout << "[CTB Server] CTA Agent đã kết nối thành công!" << std::endl;

                // Gửi ngay cấu hình hiện tại sang CTA khi vừa kết nối
                if (!current_config_json_.empty())
                {
                    sendConfigJson(current_config_json_);
                }
            }

            // 3. Đọc thông điệp cảnh báo từ CTA
            std::string alert_msg;
            if (socket_channel_->receiveMessage(alert_msg, 200))
            {
                if (!alert_msg.empty())
                {
                    writeAlertLog(alert_msg);
                }
            }
            else
            {
                // Nếu mất kết nối mạng với CTA
                if (!socket_channel_->isConnected())
                {
                    std::cerr << "[CTB Server] CTA Agent đã ngắt kết nối. Đang chờ CTA kết nối lại..." << std::endl;
                }
            }
        }
    }
}