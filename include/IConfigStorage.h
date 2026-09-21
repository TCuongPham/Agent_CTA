// Trên Linux: LinuxFileStorage (đọc/ghi file JSON ~/.config/cta/config.json).
// Trên Windows: WindowsRegistryStorage (đọc/ghi Windows Registry).

#pragma once

#include <string>
#include <memory>

namespace sysmon
{
    class IConfigStorage
    {
    public:
        // Hàm hủy cho phép ghi đè
        virtual ~IConfigStorage() = default;
        IConfigStorage() = default;

        // Cấm sao chép (Copy Constructor & Copy Assignment):
        IConfigStorage(const IConfigStorage &) = delete;
        IConfigStorage &operator=(const IConfigStorage &) = delete;
        // Cho phép di chuyển quyền sở hữu:
        IConfigStorage(IConfigStorage &&) noexcept = default;
        IConfigStorage &operator=(IConfigStorage &&) noexcept = default;

        // Lưu trữ chuỗi JSON cấu hình xuống bộ nhớ (Registry hoặc File).
        virtual bool saveConfig(const std::string& json) = 0;

        // Đọc chuỗi JSON cấu hình đã lưu từ trước.
        virtual bool loadConfig(std::string& outJson) = 0;
    };
}