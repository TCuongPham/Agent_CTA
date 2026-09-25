#include <iostream>
#include <memory>
#include <csignal>
#include <thread>
#include <chrono>

#include "CTA.h"
#include "LinuxProcessMonitor.h"
#include "LinuxFileStorage.h"
#include "ISocketChannel.h"
#include "EventQueue.h"

namespace
{
    // Con trỏ toàn cục để bộ xử lý tín hiệu OS (Signal Handler) có thể gọi dừng an toàn
    sysmon::CTA *g_cta_instance = nullptr;
    void signalHandler(int signum)
    {
        std::cout << "\n[main_cta] Nhận tín hiệu dừng hệ thống (Signal: " << signum << ")..." << std::endl;
        if (g_cta_instance != nullptr)
        {
            g_cta_instance->stop();
        }
    }
}
int main(int argc, char *argv[])
{
    std::cout << " ===================CTA AGENT===================" << std::endl;

    // 1. Cấu hình cổng và địa chỉ lắng nghe
    std::string host = "0.0.0.0";
    uint16_t port = 9000;
    if (argc >= 2)
    {
        port = static_cast<uint16_t>(std::stoi(argv[1]));
    }
    if (argc >= 3)
    {
        host = argv[2];
    }
    // 2. Đăng ký bắt các tín hiệu tắt hệ thống: Ctrl+C (SIGINT) và kill (SIGTERM)
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    // 3. Khởi tạo các module thành phần thông qua Dependency Injection
    std::cout << "[main_cta] Đang khởi tạo các module thành phần..." << std::endl;
    auto monitor = std::make_unique<sysmon::LinuxProcessMonitor>();
    auto storage = std::make_unique<sysmon::LinuxFileStorage>();
    auto socket_channel = std::make_unique<sysmon::ISocketChannel>();
    auto event_queue = std::make_shared<sysmon::EventQueue>();
    std::cout << "[main_cta] Cấu hình dự phòng sẽ được lưu tại: "
              << storage->getFilePath() << std::endl;
    // 4. Ráp nối vào động cơ trung tâm CTA
    sysmon::CTA cta(
        std::move(monitor),
        std::move(storage),
        std::move(socket_channel),
        event_queue);
    g_cta_instance = &cta;
    // 5. Khởi động CTA (bật Socket Server và các Worker Threads)
    if (!cta.start(host, port))
    {
        std::cerr << "[main_cta] Khởi động CTA thất bại. Kết thúc chương trình." << std::endl;
        return 1;
    }
    std::cout << "\n>>> CTA AGENT ĐANG CHẠY TRÊN PORT " << port << " <<<" << std::endl;
    std::cout << ">>> Nhấn Ctrl+C để dừng chương trình an toàn <<<\n"
              << std::endl;
    // 6. Giữ tiến trình main sống cho đến khi nhận lệnh dừng
    while (cta.isRunning())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    g_cta_instance = nullptr;
    std::cout << "[main_cta] CTA Agent đã kết thúc hoàn tất. Tạm biệt!" << std::endl;
    return 0;
}