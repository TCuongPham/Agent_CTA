#include <iostream>
#include <memory>
#include <csignal>
#include <thread>
#include <chrono>

#include "CTA.h"
#if defined(_WIN32)
#include "WindowsProcessMonitor.h"
#include "WindowsRegistryStorage.h"
#else
#include "LinuxProcessMonitor.h"
#include "LinuxFileStorage.h"
#endif
#include "ISocketChannel.h"
#include "EventQueue.h"

namespace
{
    // Con trỏ toàn cục để bộ xử lý tín hiệu OS (Signal Handler) có thể gọi dừng an toàn
    sysmon::CTA *g_cta_instance = nullptr;
    void signalHandler(int signum)
    {
        std::cout << "\n[CTA] Nhận tín hiệu dừng hệ thống (Signal: " << signum << ")..." << std::endl;
        if (g_cta_instance != nullptr)
        {
            g_cta_instance->stop();
        }
    }
}
int main(int argc, char *argv[])
{
    std::cout << " ===================CTA AGENT===================" << std::endl;

    // 1. Cấu hình địa chỉ và cổng CTB Server
    std::string host = "127.0.0.1";
    uint16_t port = 9000;
    if (argc >= 2)
    {
        host = argv[1];
    }
    if (argc >= 3)
    {
        port = static_cast<uint16_t>(std::stoi(argv[2]));
    }
    // 2. Đăng ký bắt các tín hiệu tắt hệ thống: Ctrl+C (SIGINT) và kill (SIGTERM)
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // 3. Khởi tạo các module thành phần thông qua Dependency Injection
    std::cout << "[CTA] Đang khởi tạo Modules..." << std::endl;
#if defined(_WIN32)
    auto monitor = std::make_unique<sysmon::WindowsProcessMonitor>();
    auto storage = std::make_unique<sysmon::WindowsRegistryStorage>();
    std::cout << "[CTA] Cấu hình lưu tại Registry: HKCU\\"
              << storage->getSubKey() << "\\" << storage->getValueName() << std::endl;
#else
    auto monitor = std::make_unique<sysmon::LinuxProcessMonitor>();
    auto storage = std::make_unique<sysmon::LinuxFileStorage>();
    std::cout << "[CTA] Cấu hình lưu tại: "
              << storage->getFilePath() << std::endl;
#endif
    auto socket_channel = std::make_unique<sysmon::ISocketChannel>();
    auto event_queue = std::make_shared<sysmon::EventQueue>();

    // 4. Trung tâm CTA
    sysmon::CTA cta(
        std::move(monitor),
        std::move(storage),
        std::move(socket_channel),
        event_queue);

    g_cta_instance = &cta;

    // 5. Khởi động CTA (chế độ Client kết nối tới CTB Server)
    if (!cta.start(host, port))
    {
        std::cerr << "[CTA] Khởi động CTA thất bại. Kết thúc chương trình." << std::endl;
        return 1;
    }
    std::cout << "\n>>> CTA AGENT ĐANG CHẠY (KẾT NỐI SERVER " << host << ":" << port << ") <<<" << std::endl;

    // 6. Giữ tiến trình main cho đến khi nhận lệnh dừng
    while (cta.isRunning())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    g_cta_instance = nullptr;

    std::cout << "[CTA] CTA Agent đã kết thúc." << std::endl;
    return 0;
}