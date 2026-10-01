// Lưu trữ và nạp cấu hình dự phòng từ Windows Registry (HKEY_CURRENT_USER\Software\CTA).

#pragma once

#include <string>
#include "IConfigStorage.h"

namespace sysmon
{
    class WindowsRegistryStorage : public IConfigStorage
    {
    public:
        // Khởi tạo với subkey và tên value trong Registry
        explicit WindowsRegistryStorage(
            const std::string &sub_key = "Software\\CTA",
            const std::string &value_name = "ConfigJson");
        ~WindowsRegistryStorage() override = default;

        // Ngăn chặn sao chép đối tượng
        WindowsRegistryStorage(const WindowsRegistryStorage &) = delete;
        WindowsRegistryStorage &operator=(const WindowsRegistryStorage &) = delete;
        // Cho phép di chuyển quyền sở hữu
        WindowsRegistryStorage(WindowsRegistryStorage &&) noexcept = default;
        WindowsRegistryStorage &operator=(WindowsRegistryStorage &&) noexcept = default;

        // CÁC HÀM GHI ĐÈ TỪ IConfigStorage
        bool saveConfig(const std::string &json) override;
        bool loadConfig(std::string &outJson) override;

        // Lấy thông tin key và value đang sử dụng
        std::string getSubKey() const;
        std::string getValueName() const;

    private:
        std::string sub_key_;    ///< Đường dẫn subkey (mặc định: Software\CTA)
        std::string value_name_; ///< Tên giá trị lưu trữ (mặc định: ConfigJson)
    };
}
