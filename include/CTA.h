/*
    Tích hợp và điều phối các thành phần:
        - IProcessMonitor: Thu thập thông số phần cứng từ OS.
        - IConfigStorage: Nạp và lưu cấu hình (Registry/File).
        - ISocketChannel: Lắng nghe và giao tiếp TCP với CTB.
        - EventQueue: Bộ đệm lưu trữ sự kiện cảnh báo.
*/

#pragma once

#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <string>
#include <vector>

#include "ConfigModel.h"
#include "IProcessMonitor.h"
#include "IConfigStorage.h"
#include "ISocketChannel.h"
#include "EventQueue.h"

namespace sysmon
{
    class CTA
    {
    public:
        // Hàm khởi tạo và hàm hủy
        CTA(std::unique_ptr<IProcessMonitor> monitor,
            std::unique_ptr<IConfigStorage> storage,
            std::unique_ptr<ISocketChannel> socket_channel,
            std::shared_ptr<EventQueue> event_queue = nullptr);
        ~CTA();

        // Ngăn chặn sao chép
        CTA(const CTA &) = delete;
        CTA &operator=(const CTA &) = delete;
        // Cho phép di chuyển quyền sở hữu
        CTA(CTA &&) noexcept = default;
        CTA &operator=(CTA &&) noexcept = default;

        // Khởi động máy chủ TCP Socket và các luồng làm việc nền
        bool start(const std::string &host = "0.0.0.0", uint16_t port = 9000);
        // Dừng toàn bộ các luồng làm việc và ngắt kết nối an toàn.
        void stop();
        // Kiểm tra CTA có đang chạy
        bool isRunning() const;

        // Lấy cấu hình giám sát mới từ chuỗi JSON và lưu cấu hình
        bool applyConfigFromJson(const std::string &json_str);

        // Lấy bản sao của cấu hình
        MonitorConfig getConfig() const;

        // Truy cập hàng đợi
        std::shared_ptr<EventQueue> getEventQueue() const;

    private:
        // Hàm thu thập thông số định kỳ và so khớp ngưỡng
        void samplingLoop();

        // Hàm quản lý kết nối Client, nhận và đẩy log
        void networkLoop();

        // Kiểm tra vượt ngưỡng
        void checkThresholds(const ProcessMetrics &metric, const ProcessThreshold &threshold);

        // Lấy cấu hình cũ
        void loadInitialConfig();

    private:
        // Các module 
        std::unique_ptr<IProcessMonitor> monitor_;
        std::unique_ptr<IConfigStorage> storage_;
        std::unique_ptr<ISocketChannel> socket_channel_;
        std::shared_ptr<EventQueue> event_queue_;

        // Trạng thái và quản lý luồng
        std::atomic<bool> is_running_{false}; ///< Cờ báo hiệu trạng thái hoạt động
        std::thread sampling_thread_;         ///< Luồng đo đạc tài nguyên
        std::thread network_thread_;          ///< Luồng giao tiếp TCP với CTB

        // Đồng bộ dừng luồng an toàn 
        std::mutex stop_mutex_;
        std::condition_variable cv_stop_;

        // Dữ liệu cấu hình và Mutex bảo vệ truy cập đồng thời
        MonitorConfig current_config_;
        mutable std::mutex config_mutex_;
    };
}
