#include "LinuxFileStorage.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <cstdlib>

namespace sysmon
{
    // Xác định đường dẫn file mặc định dựa vào biến môi trường $HOME.
    std::string LinuxFileStorage::resolveDefaultPath()
    {
        const char *home = std::getenv("HOME");
        if (home != nullptr && *home != '\0')
        {
            return std::string(home) + "/.config/cta/config.json";
        }
        // Fallback nếu không đọc được biến HOME
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

    // Lưu trữ chuỗi JSON cấu hình xuống bộ nhớ (Registry hoặc File)
    bool LinuxFileStorage::saveConfig(const std::string &json)
    {
        try
        {
            // 1. Tự động tạo thư mục cha nếu chưa có (ví dụ ~/.config/cta/)
            auto parent_dir = file_path_.parent_path();
            if (!parent_dir.empty() && !std::filesystem::exists(parent_dir))
            {
                std::filesystem::create_directories(parent_dir);
            }
            // 2. Mở file và ghi đè nội dung cấu hình mới nhất
            std::ofstream out_file(file_path_, std::ios::out | std::ios::trunc);
            if (!out_file.is_open())
            {
                std::cerr << "[LinuxFileStorage] Không thể mở file để ghi: " << file_path_ << std::endl;
                return false;
            }
            out_file << json;
            out_file.close();
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
            // 1. Kiểm tra xem file có tồn tại không
            if (!std::filesystem::exists(file_path_))
            {
                return false; // Lần đầu khởi chạy, chưa có file cấu hình cũ
            }
            // 2. Đọc toàn bộ nội dung file vào chuỗi outJson
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