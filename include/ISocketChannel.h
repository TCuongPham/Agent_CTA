// Giao tiếp TCP Socket đa nền tảng (Winsock2 trên Windows / POSIX Sockets trên Linux).

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
        virtual ~ISocketChannel();
        ISocketChannel();

        // Cấm sao chép (Copy Constructor & Copy Assignment)
        ISocketChannel(const ISocketChannel &) = delete;
        ISocketChannel &operator=(const ISocketChannel &) = delete;
        // Cho phép di chuyển quyền sở hữu
        ISocketChannel(ISocketChannel &&) noexcept = default;
        ISocketChannel &operator=(ISocketChannel &&) noexcept = default;

        // Tạo kênh truyền ở server
        virtual bool startServer(const std::string &host = "0.0.0.0", uint16_t port = 9000);

        // Chờ Client kết nối tới (Server mode)
        virtual bool waitForClient(int timeout_ms = -1);

        // Kết nối tới Server (Client mode)
        virtual bool connectClient(const std::string &host = "127.0.0.1", uint16_t port = 9000, int timeout_ms = 5000);

        // Gửi thông điệp
        virtual bool sendMessage(const std::string &message);
        // Đọc một thông điệp
        virtual bool receiveMessage(std::string &outMessage, int timeout_ms = -1);

        // Kiểm tra kênh truyền
        virtual bool isConnected() const;
        // Chủ động ngắt kết nối và giải phóng tài nguyên
        virtual void disconnect();

    private: 
        // Đóng socket theo từng OS
        void closeSocketHandle(socket_t& sock);

        // Khởi tạo và giải phóng môi trường socket cho Win
        static void initPlatformSockets();
        // static void cleanupPlatformSockets();

    private:
        socket_t server_fd_ = INVALID_SOCKET_FD;  ///< Socket lắng nghe của Server
        socket_t client_fd_ = INVALID_SOCKET_FD;  ///< Socket truyền nhận dữ liệu kết nối
        std::atomic<bool> is_connected_{false};   ///< Trạng thái kết nối hiện tại
        std::string rx_buffer_;                   ///< Bộ đệm nhận phân tách thông điệp '\n'
        std::mutex send_mutex_;                   ///< Bảo vệ gửi dữ liệu đồng thời từ nhiều luồng
    };

}