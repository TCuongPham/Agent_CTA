#include "LinuxFileStorage.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace sysmon
{
    // Xác định đường dẫn file mặc định: chỉ sử dụng /tmp/cta_config.json
    std::string LinuxFileStorage::resolveDefaultPath()
    {
        return "/tmp/cta_config.json";
    }

    // Hàm khởi tạo
    LinuxFileStorage::LinuxFileStorage(const std::string &custom_path)
    {
        if (!custom_path.empty())
        {
            file_path_ = custom_path;
        }
        else
        {
            file_path_ = resolveDefaultPath();
        }
    }

    // Lấy đường dẫn file cấu hình thực tế đang sử dụng.
    std::string LinuxFileStorage::getFilePath() const
    {
        return file_path_.string();
    }

    // Lưu trữ chuỗi JSON cấu hình xuống bộ nhớ (File)
    bool LinuxFileStorage::saveConfig(const std::string &json)
    {
        try
        {
            // 1. Tự động tạo thư mục cha nếu chưa có
            auto parent_dir = file_path_.parent_path();
            if (!parent_dir.empty() && !std::filesystem::exists(parent_dir))
            {
                std::error_code ec;
                std::filesystem::create_directories(parent_dir, ec);
            }

            // 2. Mở file: nếu file đã tồn tại thì mở ghi đè KHÔNG DÙNG O_CREAT
            //    (để tránh bị Linux kernel fs.protected_regular chặn khi chuyển đổi giữa sudo/root và user thường)
            int fd = ::open(file_path_.c_str(), O_WRONLY | O_TRUNC);
            if (fd < 0 && errno == ENOENT)
            {
                // Chỉ dùng O_CREAT khi file chưa từng tồn tại
                fd = ::open(file_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
            }

            if (fd < 0)
            {
                std::cerr << "[LinuxFileStorage] Không thể mở file để ghi: " << file_path_ 
                          << " (Lỗi hệ thống: " << std::strerror(errno) << ")" << std::endl;
                return false;
            }

            ssize_t bytes_written = ::write(fd, json.data(), json.size());
            ::close(fd);

            if (bytes_written != static_cast<ssize_t>(json.size()))
            {
                std::cerr << "[LinuxFileStorage] Ghi file không hoàn tất: " << file_path_ << std::endl;
                return false;
            }

            // Đảm bảo file luôn có quyền đọc/ghi 0666 cho mọi user
            ::chmod(file_path_.c_str(), 0666);
            std::cout << "[LinuxFileStorage] Đã lưu cấu hình dự phòng vào: " << file_path_ << std::endl;
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[LinuxFileStorage] Ngoại lệ khi lưu file: " << e.what() << std::endl;
            return false;
        }
    }

    // Đọc chuỗi JSON cấu hình đã lưu từ trước.
    bool LinuxFileStorage::loadConfig(std::string &outJson)
    {
        try
        {
            // Chỉ đọc từ duy nhất 1 file cấu hình file_path_ (/tmp/cta_config.json)
            if (!std::filesystem::exists(file_path_))
            {
                return false; // Chưa có file cấu hình cũ
            }
            std::ifstream in_file(file_path_, std::ios::in);
            if (!in_file.is_open())
            {
                std::cerr << "[LinuxFileStorage] Không thể mở file để đọc: " << file_path_ << std::endl;
                return false;
            }
            std::stringstream buffer;
            buffer << in_file.rdbuf();
            outJson = buffer.str();
            in_file.close();
            return !outJson.empty();
        }
        catch (const std::exception &e)
        {
            std::cerr << "[LinuxFileStorage] Ngoại lệ khi đọc file: " << e.what() << std::endl;
            return false;
        }
    }
}