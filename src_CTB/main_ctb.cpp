#include <iostream>
#include <csignal>
#include <memory>
#include <fstream>

#include "CTB.h"
#include "ConfigModel.h"

namespace
{
    // Con trỏ toàn cục để bộ xử lý tín hiệu OS (Signal Handler) có thể gọi dừng an toàn
    sysmon::CTB *g_ctb_instance = nullptr;
    void signalHandler(int signum)
    {
        std::cout << "\n[main_ctb] Nhận tín hiệu dừng (" << signum << ")..." << std::endl;
        if (g_ctb_instance)
        {
            g_ctb_instance->stop();
        }
    }
}

int main(int argc, char *argv[])
{
    std::cout << " ===================CTB CONTROLLER (SERVER)===================" << std::endl;

    // Cấu hình địa chỉ lắng nghe, cổng, file cấu hình và file log
    std::string host = "0.0.0.0";
    uint16_t port = 9000;
    std::string config_file = "config.json";
    std::string log_file = "ctb_alerts.log";

    // Cho phép truyền tham số
    if (argc >= 2)
        host = argv[1];
    if (argc >= 3)
        port = static_cast<uint16_t>(std::stoi(argv[2]));
    if (argc >= 4)
        config_file = argv[3];
    if (argc >= 5)
        log_file = argv[4];
    
    // Đăng ký bắt các tín hiệu tắt hệ thống: Ctrl+C (SIGINT) và kill (SIGTERM)
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // 1. Khởi tạo đối tượng CTB (chế độ Server, theo dõi file config_file)
    sysmon::CTB ctb(nullptr, log_file, config_file);
    g_ctb_instance = &ctb;

    // 2. Mở TCP Server lắng nghe kết nối từ CTA Agent
    if (!ctb.start(host, port))
    {
        return 1;
    }

    // 3. Chạy vòng lặp lắng nghe CTA kết nối và nhận cảnh báo
    std::cout << "\n>>> CTB Server đang chạy... (Nhấn Ctrl+C để dừng) <<<\n"
              << std::endl;

    ctb.runReceiveLoop();

    g_ctb_instance = nullptr;

    std::cout << "[main_ctb] CTB đã dừng." << std::endl;
    return 0;
}