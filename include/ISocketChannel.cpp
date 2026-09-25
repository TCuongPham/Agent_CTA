#include "ISocketChannel.h"

#include <iostream>
#include <cstring>

#if defined(_WIN32)
#pragma comment(lib, "ws2_32.lib")
#else
#include <poll.h>
#include <fcntl.h>
#endif

namespace sysmon
{
    // Khởi tạo và giải phóng môi trường socket cho Win
    void ISocketChannel::initPlatformSockets()
    {
#if defined(_WIN32)
        static bool initialized = false;
        if (!initialized)
        {
            WSADATA wsa_data;
            int res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
            if (res != 0)
            {
                std::cerr << "[ISocketChannel] WSAStartup thất bại: " << res << std::endl;
            }
            else
            {
                initialized = true;
            }
        }
#endif
    }

    // Đóng socket theo từng OS
    void ISocketChannel::closeSocketHandle(socket_t &sock)
    {
        if (sock != INVALID_SOCKET_FD)
        {
#if defined(_WIN32)
            closesocket(sock);
#else
            ::close(sock);
#endif
            sock = INVALID_SOCKET_FD;
        }
    }

    // Hàm khởi tạo và hàm hủy kênh kết nối socket
    ISocketChannel::ISocketChannel()
    {
        initPlatformSockets();
    }
    ISocketChannel::~ISocketChannel()
    {
        disconnect();
        closeSocketHandle(server_fd_);
    }

    // Tạo kênh truyền ở server
    bool ISocketChannel::startServer(const std::string &host, uint16_t port)
    {
        closeSocketHandle(server_fd_);

        // 1. Tạo TCP Socket (IPv4, TCP Stream)
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ == INVALID_SOCKET_FD)
        {
            std::cerr << "[ISocketChannel] Không thể tạo server socket." << std::endl;
            return false;
        }

        // 2. Kích hoạt SO_REUSEADDR: Tránh lỗi "Address already in use" khi khởi động lại
        int opt = 1;
#if defined(_WIN32)
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&opt), sizeof(opt));
#else
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        // 3. Cấu hình IP và Port lắng nghe
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0)
        {
            server_addr.sin_addr.s_addr = INADDR_ANY; // Fallback lắng nghe mọi card mạng
        }

        // 4. Bind địa chỉ
        if (bind(server_fd_, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) < 0)
        {
            std::cerr << "[ISocketChannel] Bind cổng " << port << " thất bại." << std::endl;
            closeSocketHandle(server_fd_);
            return false;
        }

        // 5. Lắng nghe kết nối
        if (listen(server_fd_, 5) < 0)
        {
            std::cerr << "[ISocketChannel] Listen thất bại." << std::endl;
            closeSocketHandle(server_fd_);
            return false;
        }
        return true;
    }

    // Chờ CTB kết nối tới
    bool ISocketChannel::waitForClient(int timeout_ms)
    {
        if (server_fd_ == INVALID_SOCKET_FD)
        {
            return false;
        }

        // 1. Kiểm tra timeout bằng select / poll
        if (timeout_ms >= 0)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(server_fd_, &read_fds);
            timeval tv{};
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int ret = select(static_cast<int>(server_fd_ + 1), &read_fds, nullptr, nullptr, &tv);
            if (ret <= 0)
            {
                return false; // Hết thời gian chờ hoặc có lỗi
            }
        }

        // 2. Chấp nhận kết nối từ Client mới (CTB)
        sockaddr_in client_addr{};
#if defined(_WIN32)
        int addr_len = sizeof(client_addr);
#else
        socklen_t addr_len = sizeof(client_addr);
#endif
        socket_t new_client = accept(server_fd_, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
        if (new_client == INVALID_SOCKET_FD)
        {
            return false;
        }
        // Đóng client cũ nếu có và nhận client mới
        closeSocketHandle(client_fd_);
        client_fd_ = new_client;
        rx_buffer_.clear();
        is_connected_.store(true);
        return true;
    }

    // Gửi thông điệp
    bool ISocketChannel::sendMessage(const std::string &message)
    {
        if (!is_connected_.load() || client_fd_ == INVALID_SOCKET_FD)
        {
            return false;
        }
        // Đảm bảo thông điệp luôn kết thúc bằng '\n' để phân tách gói tin
        std::string payload = message;
        if (payload.empty() || payload.back() != '\n')
        {
            payload += '\n';
        }
        std::lock_guard<std::mutex> lock(send_mutex_);
        const char *data_ptr = payload.data();
        size_t total_sent = 0;
        size_t to_send = payload.size();

        // Vòng lặp gửi đủ số byte dữ liệu
        while (total_sent < to_send)
        {
#if defined(_WIN32)
            int sent = send(client_fd_, data_ptr + total_sent, static_cast<int>(to_send - total_sent), 0);
#else
            // MSG_NOSIGNAL ngăn hệ điều hành phát tín hiệu SIGPIPE khi Client ngắt đột ngột
            ssize_t sent = ::send(client_fd_, data_ptr + total_sent, to_send - total_sent, MSG_NOSIGNAL);
#endif
            if (sent <= 0)
            {
                disconnect();
                return false;
            }
            total_sent += static_cast<size_t>(sent);
        }
        return true;
    }

    // Đọc một thông điệp
    bool ISocketChannel::receiveMessage(std::string &outMessage, int timeout_ms)
    {
        if (!is_connected_.load() || client_fd_ == INVALID_SOCKET_FD)
        {
            return false;
        }

        // 1. Kiểm tra xem trong bộ đệm rx_buffer_ đã có sẵn 1 thông điệp kết thúc bằng '\n' chưa
        auto extract_line = [this, &outMessage]() -> bool
        {
            size_t pos = rx_buffer_.find('\n');
            if (pos != std::string::npos)
            {
                outMessage = rx_buffer_.substr(0, pos);
                // Loại bỏ ký tự '\r' nếu thông điệp dạng "\r\n" (Windows format)
                if (!outMessage.empty() && outMessage.back() == '\r')
                {
                    outMessage.pop_back();
                }
                rx_buffer_.erase(0, pos + 1);
                return true;
            }
            return false;
        };
        if (extract_line())
        {
            return true;
        }

        // 2. Chờ dữ liệu đến bằng select
        if (timeout_ms >= 0)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(client_fd_, &read_fds);
            timeval tv{};
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int ret = select(static_cast<int>(client_fd_ + 1), &read_fds, nullptr, nullptr, &tv);
            if (ret <= 0)
            {
                return false; // Hết timeout hoặc chưa có byte nào đến
            }
        }
        // 3. Đọc dữ liệu từ socket
        char chunk[4096];
#if defined(_WIN32)
        int bytes_read = recv(client_fd_, chunk, sizeof(chunk), 0);
#else
        ssize_t bytes_read = ::recv(client_fd_, chunk, sizeof(chunk), 0);
#endif
        if (bytes_read <= 0)
        {
            // Client đã đóng kết nối hoặc lỗi mạng
            disconnect();
            return false;
        }
        // Nạp dữ liệu vừa nhận vào bộ đệm 
        rx_buffer_.append(chunk, static_cast<size_t>(bytes_read));
        
        // 4. Trích xuất thông điệp hoàn chỉnh
        return extract_line();
    }

    // Kiểm tra kênh truyền
    bool ISocketChannel::isConnected() const
    {
        return is_connected_.load();
    }

    // Chủ động ngắt kết nối và giải phóng tài nguyên
    void ISocketChannel::disconnect()
    {
        is_connected_.store(false);
        closeSocketHandle(client_fd_);
    }
}