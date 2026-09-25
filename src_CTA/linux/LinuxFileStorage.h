// Trên Linux: LinuxFileStorage (đọc/ghi file JSON ~/.config/cta/config.json).

#pragma once

#include <string>
#include <filesystem>

#include "IConfigStorage.h"

namespace sysmon
{
    class LinuxFileStorage : public IConfigStorage
    {
    public:
        // Hàm khởi tạo và hàm hủy
        explicit LinuxFileStorage(const std::string &custom_path = "");
        ~LinuxFileStorage() override = default;

        // Ngăn chặn sao chép
        LinuxFileStorage(const LinuxFileStorage &) = delete;
        LinuxFileStorage &operator=(const LinuxFileStorage &) = delete;
        // Cho phép di chuyển quyền sở hữu
        LinuxFileStorage(LinuxFileStorage &&) noexcept = default;
        LinuxFileStorage &operator=(LinuxFileStorage &&) noexcept = default;


        // CÁC HÀM GHI ĐÈ TỪ IConfigStorage
        bool saveConfig(const std::string &json) override;
        bool loadConfig(std::string &outJson) override;

        // Lấy đường dẫn file cấu hình thực tế đang sử dụng.
        std::string getFilePath() const;

    private:
        // Xác định đường dẫn file mặc định dựa vào biến môi trường $HOME.
        static std::string resolveDefaultPath();

    private:
        std::filesystem::path file_path_; ///< Đường dẫn tuyệt đối của file cấu hình
    };
}