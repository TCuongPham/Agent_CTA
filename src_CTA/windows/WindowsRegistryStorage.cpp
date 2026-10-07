#include "WindowsRegistryStorage.h"

#include <iostream>

#if defined(_WIN32)
#include <windows.h>

namespace sysmon
{
    WindowsRegistryStorage::WindowsRegistryStorage(
        const std::string &sub_key,
        const std::string &value_name)
        : sub_key_(sub_key),
          value_name_(value_name)
    {
    }

    std::string WindowsRegistryStorage::getSubKey() const { return sub_key_; }
    std::string WindowsRegistryStorage::getValueName() const { return value_name_; }

    // Lưu chuỗi JSON cấu hình vào Windows Registry
    bool WindowsRegistryStorage::saveConfig(const std::string &json)
    {
        HKEY hKey = nullptr;
        DWORD disposition = 0;

        // 1. Tạo hoặc mở khóa Registry tại HKEY_CURRENT_USER\Software\CTA
        LSTATUS status = RegCreateKeyExA(
            HKEY_CURRENT_USER,
            sub_key_.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &hKey,
            &disposition);

        if (status != ERROR_SUCCESS)
        {
            std::cerr << "[WindowsRegistryStorage] Khong the mo hoac tao Registry key: " 
                      << sub_key_ << " (Ma loi: " << status << ")" << std::endl;
            return false;
        }

        // 2. Ghi chuỗi JSON vào value dạng REG_SZ (bao gồm cả ký tự '\0')
        status = RegSetValueExA(
            hKey,
            value_name_.c_str(),
            0,
            REG_SZ,
            reinterpret_cast<const BYTE *>(json.c_str()),
            static_cast<DWORD>(json.size() + 1));

        RegCloseKey(hKey);

        if (status != ERROR_SUCCESS)
        {
            std::cerr << "[WindowsRegistryStorage] Khong the ghi gia tri vao Registry: " 
                      << value_name_ << " (Ma loi: " << status << ")" << std::endl;
            return false;
        }

        std::cout << "[WindowsRegistryStorage] Da luu cau hinh du phong vao Registry: HKCU\\" 
                  << sub_key_ << "\\" << value_name_ << std::endl;
        return true;
    }

    // Đọc chuỗi JSON cấu hình từ Windows Registry
    bool WindowsRegistryStorage::loadConfig(std::string &outJson)
    {
        HKEY hKey = nullptr;

        // 1. Mở Registry key ở chế độ đọc
        LSTATUS status = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            sub_key_.c_str(),
            0,
            KEY_QUERY_VALUE,
            &hKey);

        if (status != ERROR_SUCCESS)
        {
            return false;
        }

        // 2. Truy vấn kích thước dữ liệu cần đọc
        DWORD data_type = 0;
        DWORD data_size = 0;
        status = RegQueryValueExA(
            hKey,
            value_name_.c_str(),
            nullptr,
            &data_type,
            nullptr,
            &data_size);

        if (status != ERROR_SUCCESS || (data_type != REG_SZ && data_type != REG_EXPAND_SZ) || data_size <= 1)
        {
            RegCloseKey(hKey);
            return false;
        }

        // 3. Cấp phát buffer và đọc nội dung
        std::string buffer(data_size, '\0');
        status = RegQueryValueExA(
            hKey,
            value_name_.c_str(),
            nullptr,
            &data_type,
            reinterpret_cast<BYTE *>(&buffer[0]),
            &data_size);

        RegCloseKey(hKey);

        if (status != ERROR_SUCCESS)
        {
            std::cerr << "[WindowsRegistryStorage] Loi khi doc du lieu tu Registry (Ma loi: " 
                      << status << ")" << std::endl;
            return false;
        }

        // Loại bỏ ký tự null-terminator thừa ở cuối chuỗi
        while (!buffer.empty() && buffer.back() == '\0')
        {
            buffer.pop_back();
        }

        outJson = std::move(buffer);
        return !outJson.empty();
    }
}

#else

namespace sysmon
{
    WindowsRegistryStorage::WindowsRegistryStorage(const std::string &sub_key, const std::string &value_name)
        : sub_key_(sub_key), value_name_(value_name) {}
    std::string WindowsRegistryStorage::getSubKey() const { return sub_key_; }
    std::string WindowsRegistryStorage::getValueName() const { return value_name_; }
    bool WindowsRegistryStorage::saveConfig(const std::string &) { return false; }
    bool WindowsRegistryStorage::loadConfig(std::string &) { return false; }
}
#endif
