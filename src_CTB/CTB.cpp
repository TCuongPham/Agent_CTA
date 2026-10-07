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
        std::string target_path = file_path;
        if (!std::filesystem::exists(target_path))
        {
            // Nếu không tìm thấy ở thư mục hiện tại (ví dụ đang ở build/), thử tìm ở thư mục cha
            if (std::filesystem::exists("../" + file_path))
            {
                target_path = "../" + file_path;
            }
            else if (std::filesystem::exists("../../" + file_path))
            {
                target_path = "../../" + file_path;
            }
        }

        config_file_path_ = target_path;
        if (!std::filesystem::exists(config_file_path_))
        {
            std::cerr << "[CTB] Canh bao: Khong tim thay file cau hinh tai " << file_path 
                      << " hoac ../" << file_path << std::endl;
            return false;
        }

        try
        {
            std::ifstream file(config_file_path_);
            if (!file.is_open())
            {
                std::cerr << "[CTB] Khong the mo file cau hinh: " << config_file_path_ << std::endl;
                return false;
            }
            std::stringstream buffer;
            buffer << file.rdbuf();
            json j = json::parse(buffer.str());
            current_config_json_ = j.dump();
            last_config_time_ = std::filesystem::last_write_time(config_file_path_);
            std::cout << "[CTB] Da nap cau hinh tu " << config_file_path_ << std::endl;
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[CTB] Loi nap cau hinh tu " << config_file_path_ << ": " << e.what() << std::endl;
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
        std::cout << "[CTB Server] Dang mo Server tai " << host << ":" << port << "..." << std::endl;
        if (!socket_channel_->startServer(host, port))
        {
            std::cerr << "[CTB] Khong the mo Server tren " << host << ":" << port << std::endl;
            return false;
        }
        is_running_.store(true);

        std::cout << "[CTB Server] Dang lang nghe ket noi tu CTA tren cong " << port << "..." << std::endl;
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
        std::cout << "[CTB] Da ngat ket noi an toan." << std::endl;
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
            std::cerr << "[CTB] Khong the gui cau hinh: Chua ket noi toi CTA!" << std::endl;
            return false;
        }
        std::cout << "[CTB] Dang day thong tin cau hinh sang CTA..." << std::endl;

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
            std::cout << "[CTB] Gui cau hinh thanh cong!" << std::endl;
            return true;
        }
        else
        {
            std::cerr << "[CTB] Gui cau hinh that bai." << std::endl;
            return false;
        }
    }

    // Kiểm tra và tự động reload nếu file config.json vừa được Save
    void CTB::checkAndReloadConfigFile()
    {
        if (config_file_path_.empty())
        {
            return;
        }

        if (!std::filesystem::exists(config_file_path_))
        {
            if (std::filesystem::exists("../" + config_file_path_))
            {
                config_file_path_ = "../" + config_file_path_;
            }
            else if (std::filesystem::exists("../../" + config_file_path_))
            {
                config_file_path_ = "../../" + config_file_path_;
            }
            else
            {
                return;
            }
        }

        try
        {
            auto current_time = std::filesystem::last_write_time(config_file_path_);
            if (current_time != last_config_time_)
            {
                std::ifstream file(config_file_path_);
                if (file.is_open())
                {
                    std::stringstream buffer;
                    buffer << file.rdbuf();
                    std::string content = buffer.str();
                    if (!content.empty())
                    {
                        json j = json::parse(content);
                        std::string new_json = j.dump();
                        last_config_time_ = current_time;

                        if (new_json != current_config_json_)
                        {
                            current_config_json_ = std::move(new_json);
                            std::cout << "\n[CTB Server] File " << config_file_path_ 
                                      << " vua thay doi! Tu dong gui cau hinh sang CTA..." << std::endl;
                            if (socket_channel_->isConnected())
                            {
                                sendConfigJson(current_config_json_);
                            }
                        }
                    }
                }
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "[CTB] Canh bao loi doc/parse file config: " << e.what() << std::endl;
        }
    }

    // Ghi một dòng sự kiện cảnh báo ra màn hình console và file log.
    void CTB::writeAlertLog(const std::string &alert_line)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);

        // Ghi nối tiếp (append) vào file log
        std::ofstream out_file(log_file_path_, std::ios::out | std::ios::app);
        if (out_file.is_open())
        {
            out_file << alert_line << "\n";
            out_file.close();
        }
        else
        {
            std::cerr << "[CTB] Khong the mo file log: " << log_file_path_ << std::endl;
        }
    }

    // Vòng lặp nhận cảnh báo từ CTA và ghi log
    void CTB::runReceiveLoop()
    {
        std::cout << "[CTB Server] Canh bao tu CTA (Luu vao: "
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
                std::cout << "[CTB Server] CTA Agent da ket noi thanh cong!" << std::endl;

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
                    std::cerr << "[CTB Server] CTA Agent da ngat ket noi. Dang cho CTA ket noi lai..." << std::endl;
                }
            }
        }
    }
}