#include <iostream>
#include <csignal>
#include <memory>

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
    std::cout << " ===================CTB CONTROLLER===================" << std::endl;

    // Cấu hình cổng và địa chỉ lắng nghe
    std::string host = "127.0.0.1";
    uint16_t port = 9000;

    std::string log_file = "ctb_alerts.log";

    // Cho phép truyền tham số: ./CTB [host] [port] [log_file]
    if (argc >= 2)
        host = argv[1];
    if (argc >= 3)
        port = static_cast<uint16_t>(std::stoi(argv[2]));
    if (argc >= 4)
        log_file = argv[3];
    
    // Đăng ký bắt các tín hiệu tắt hệ thống: Ctrl+C (SIGINT) và kill (SIGTERM)
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // 1. Khởi tạo đối tượng CTB
    sysmon::CTB ctb(nullptr, log_file);
    g_ctb_instance = &ctb;

    // 2. Kết nối tới CTA Agent
    if (!ctb.start(host, port))
    {
        return 1;
    }

    // 3. Tạo cấu hình giám sát mẫu gửi sang CTA
    sysmon::MonitorConfig config;
    config.sampling_interval_ms = 1000; // Đo mỗi 1 giây
    // Cấu hình giám sát các tiến trình mẫu
    config.thresholds.push_back({
        "chrome", // Tên tiến trình
        30.0,     // Ngưỡng CPU: 30%
        1024.0,   // Ngưỡng RAM: 1024 MB (1GB)
        10.0,     // Ngưỡng Disk: 10 MB/s
        1024.0    // Ngưỡng Network: 1024 KB/s (1MB/s)
    });
    config.thresholds.push_back({
        "bash", // Theo dõi bash shell
        10.0,   // CPU > 10%
        500.0,  // RAM > 500 MB
        5.0,    // Disk > 5 MB/s
        500.0   // Net > 500 KB/s
    });

    // 4. Bắn cấu hình sang CTA
    if (!ctb.sendConfig(config))
    {
        std::cerr << "[main_ctb] Không thể gửi cấu hình sang CTA. Thoát." << std::endl;
        return 1;
    }
    
    // 5. Chạy vòng lặp hứng log cảnh báo
    std::cout << "\n>>> Đang lắng nghe cảnh báo... (Nhấn Ctrl+C để dừng) <<<\n"
              << std::endl;

    ctb.runReceiveLoop();

    g_ctb_instance = nullptr;

    std::cout << "[main_ctb] CTB đã dừng." << std::endl;
    return 0;
}