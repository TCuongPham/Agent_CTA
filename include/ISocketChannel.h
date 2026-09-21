// Trên Linux: LinuxUnixSocket (POSIX Unix Domain Socket: /tmp/cta_ctb.sock).
// Trên Windows: WindowsNamedPipe (Win32 Named Pipe: \\.\pipe\cta_ctb_pipe).

#pragma once

#include <string>
#include <memory>
#include <chrono>

namespace sysmon
{
    class ISocketChannel
    {
    public:
        // Hàm hủy cho phép ghi đè
        virtual ~ISocketChannel() = default;
        ISocketChannel() = default;

        // Cấm sao chép (Copy Constructor & Copy Assignment)
        ISocketChannel(const ISocketChannel &) = delete;
        ISocketChannel &operator=(const ISocketChannel &) = delete;
        // Cho phép di chuyển quyền sở hữu
        ISocketChannel(ISocketChannel &&) noexcept = default;
        ISocketChannel &operator=(ISocketChannel &&) noexcept = default;

        // Tạo kênh truyền ở server
        virtual bool startServer(const std::string &host = "0.0.0.0", uint16_t port = 9000) = 0;

        // Chờ CTB kết nối tới
        virtual bool waitForClient(int timeout_ms = -1) = 0;

        // CTB kết nối tới server
        virtual bool connectClient(const std::string &host = "127.0.0.1", uint16_t port = 9000, int timeout_ms = 5000) = 0;

        // Gửi thông điệp
        virtual bool sendMessage(const std::string &message) = 0;
        // Đọc một thông điệp
        virtual bool receiveMessage(std::string &outMessage, int timeout_ms = -1) = 0;

        // Kiểm tra kênh truyền
        virtual bool isConnected() const = 0;
        // Chủ động ngắt kết nối và giải phóng tài nguyên
        virtual void disconnect() = 0;
    };

}