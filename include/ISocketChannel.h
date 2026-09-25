// Trên Linux: LinuxUnixSocket (POSIX Unix Domain Socket: /tmp/cta_ctb.sock).
// Trên Windows: WindowsNamedPipe (Win32 Named Pipe: \\.\pipe\cta_ctb_pipe).

#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <atomic>
#include <mutex>

#if defined(_WIN32)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    using socket_t = SOCKET;
    constexpr socket_t INVALID_SOCKET_FD = INVALID_SOCKET;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    using socket_t = int;
    constexpr socket_t INVALID_SOCKET_FD = -1;
#endif

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

    private: 
        // Đóng socket theo từng OS
        void closeSocketHandle(socket_t& sock);

        // Khởi tạo và giải phóng môi trường socket cho Win
        static void initPlatformSockets();
        // static void cleanupPlatformSockets();

    private:
        socket_t server_fd_ = INVALID_SOCKET_FD;  ///< Socket lắng nghe của Server (CTA)
        socket_t client_fd_ = INVALID_SOCKET_FD;  ///< Socket truyền nhận dữ liệu kết nối
        std::atomic<bool> is_connected_{false};   ///< Trạng thái kết nối hiện tại
        std::string rx_buffer_;                   ///< Bộ đệm nhận phân tách thông điệp '\n'
        std::mutex send_mutex_;                   ///< Bảo vệ gửi dữ liệu đồng thời từ nhiều luồng
    };

}