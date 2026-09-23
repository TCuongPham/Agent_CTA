#include "CTA.h"

#include <iostream>
#include <algorithm>

namespace sysmon
{
    // Hàm khởi tạo và hàm hủy
    CTA::CTA(std::unique_ptr<IProcessMonitor> monitor,
             std::unique_ptr<IConfigStorage> storage,
             std::unique_ptr<ISocketChannel> socket_channel,
             std::shared_ptr<EventQueue> event_queue)
        : monitor_(std::move(monitor)),
          storage_(std::move(storage)),
          socket_channel_(std::move(socket_channel)),
          event_queue_(event_queue ? event_queue : std::make_shared<EventQueue>())
    {
        // Tự động nạp cấu hình cũ từ Registry/File nếu có
        loadInitialConfig();
    }
    CTA::~CTA()
    {
        stop();
    }

    // Lấy cấu hình cũ
    void CTA::loadInitialConfig()
    {
        if (!storage_)
        {
            return;
        }
        std::string saved_json;
        if (storage_->loadConfig(saved_json) && !saved_json.empty())
        {
            try
            {
                json j = json::parse(saved_json);
                MonitorConfig loaded_cfg = j.get<MonitorConfig>();
                std::lock_guard<std::mutex> lock(config_mutex_);
                current_config_ = std::move(loaded_cfg);
                std::cout << "[CTA] Đã nạp cấu hình cũ từ storage ("
                          << current_config_.thresholds.size() << " tiến trình)." << std::endl;
            }
            catch (const std::exception &e)
            {
                std::cerr << "[CTA] Lỗi đọc JSON cấu hình cũ: " << e.what() << std::endl;
            }
        }
        else
        {
            std::cout << "[CTA] Chưa có cấu hình cũ. Chờ cấu hình từ CTB." << std::endl;
        }
    }

    // Khởi động máy chủ TCP Socket và các luồng làm việc nền
    bool CTA::start(const std::string &host, uint16_t port)
    {
        // Kiểm tra trạng thái
        if (is_running_.load())
        {
            std::cout << "[CTA] Đang chạy." << std::endl;
            return true;
        }
        if (!socket_channel_)
        {
            std::cerr << "[CTA] Lỗi: SocketChannel chưa được khởi tạo!" << std::endl;
            return false;
        }
        // Khởi tạo máy chủ TCP Socket
        if (!socket_channel_->startServer(host, port))
        {
            std::cerr << "[CTA] Không thể mở TCP Socket Server trên " << host << ":" << port << std::endl;
            return false;
        }
        std::cout << "[CTA] TCP Socket Server đã sẵn sàng trên " << host << ":" << port << std::endl;
        is_running_.store(true);

        // Bắt đầu 2 luồng làm việc nền
        sampling_thread_ = std::thread(&CTA::samplingLoop, this);
        network_thread_ = std::thread(&CTA::networkLoop, this);
        return true;
    }

    // Dừng toàn bộ các luồng làm việc và ngắt kết nối an toàn.
    void CTA::stop()
    {
        // Nếu đã dừng rồi
        if (!is_running_.exchange(false))
        {
            return;
        }
        std::cout << "[CTA] Đang dừng các tiến trình..." << std::endl;

        // Đánh thức luồng lấy mẫu
        cv_stop_.notify_all();

        // Ngắt kết nối socket
        if (socket_channel_)
        {
            socket_channel_->disconnect();
        }

        // Chờ các luồng kết thúc hoàn toàn (Join)
        if (sampling_thread_.joinable())
        {
            sampling_thread_.join();
        }
        if (network_thread_.joinable())
        {
            network_thread_.join();
        }
        std::cout << "[CTA] Đã dừng." << std::endl;
    }

    // Hàm kiểm tra CTA có đang chạy
    bool CTA::isRunning() const
    {
        return is_running_.load();
    }

    // Lấy cấu hình giám sát mới từ chuỗi JSON và lưu cấu hình
    bool CTA::applyConfigFromJson(const std::string &json_str)
    {
        try
        {
            json j = json::parse(json_str);
            MonitorConfig new_cfg = j.get<MonitorConfig>();
            {
                std::lock_guard<std::mutex> lock(config_mutex_);
                current_config_ = new_cfg;
            }
            std::cout << "[CTA] Cập nhật cấu hình thành công: "
                      << new_cfg.thresholds.size() << " tiến trình, chu kỳ: "
                      << new_cfg.sampling_interval_ms << " ms." << std::endl;
            // Lưu cấu hình xuống bộ nhớ
            if (storage_)
            {
                storage_->saveConfig(json_str);
            }
            return true;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[CTA] Lỗi cú pháp JSON cấu hình: " << e.what() << std::endl;
            return false;
        }
    }

    // Lấy bản sao của cấu hình
    MonitorConfig CTA::getConfig() const
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return current_config_;
    }
    // Truy cập hàng đợi
    std::shared_ptr<EventQueue> CTA::getEventQueue() const
    {
        return event_queue_;
    }

    // Hàm thu thập thông số định kỳ và so khớp ngưỡng
    void CTA::samplingLoop()
    {
        std::cout << "[CTA] Đang lấy thông số tài nguyên sử dụng..." << std::endl;
        while (is_running_.load())
        {
            uint32_t interval_ms = 1000;
            std::vector<ProcessThreshold> active_thresholds;

            // 1. Sao chép cấu hình dưới khóa Mutex
            {
                std::lock_guard<std::mutex> lock(config_mutex_);
                interval_ms = current_config_.sampling_interval_ms;
                active_thresholds = current_config_.thresholds;
            }

            // 2. Nếu có danh sách tiến trình, tiến hành lấy mẫu
            if (monitor_ && !active_thresholds.empty())
            {
                std::vector<std::string> target_names;
                target_names.reserve(active_thresholds.size());
                for (const auto &th : active_thresholds)
                {
                    target_names.push_back(th.process_name);
                }
                // Gọi OS Native API thu thập dữ liệu (Targeted Filtering)
                std::vector<ProcessMetrics> metrics = monitor_->collectMetrics(target_names);

                // So sánh từng chỉ số đo được với ngưỡng tương ứng
                for (const auto &metric : metrics)
                {
                    for (const auto &th : active_thresholds)
                    {
                        if (metric.process_name == th.process_name)
                        {
                            checkThresholds(metric, th);
                            break;
                        }
                    }
                }
            }
            // 3. Ngủ theo chu kỳ
            std::unique_lock<std::mutex> lock(stop_mutex_);
            cv_stop_.wait_for(lock, std::chrono::milliseconds(interval_ms), [this]
                              { return !is_running_.load(); });
        }
        std::cout << "[CTA] Kết thúc." << std::endl;
    }
    void CTA::checkThresholds(const ProcessMetrics &m, const ProcessThreshold &th)
    {
        // 1. Kiểm tra CPU (%)
        if (th.cpu_percent > 0.0 && m.cpu_percent > th.cpu_percent)
        {
            event_queue_->push(EventRecord{
                getCurrentTimestamp(), m.pid, m.process_name, MetricType::CPU, m.cpu_percent, th.cpu_percent});
        }
        // 2. Kiểm tra RAM (MB)
        if (th.memory_mb > 0.0 && m.memory_mb > th.memory_mb)
        {
            event_queue_->push(EventRecord{
                getCurrentTimestamp(), m.pid, m.process_name, MetricType::MEMORY, m.memory_mb, th.memory_mb});
        }
        // 3. Kiểm tra Disk I/O (MB/s)
        if (th.disk_mb_s > 0.0 && m.disk_mb_s > th.disk_mb_s)
        {
            event_queue_->push(EventRecord{
                getCurrentTimestamp(), m.pid, m.process_name, MetricType::DISK, m.disk_mb_s, th.disk_mb_s});
        }
        // 4. Kiểm tra Network (KB/s)
        if (th.network_kb_s > 0.0 && m.network_kb_s > th.network_kb_s)
        {
            event_queue_->push(EventRecord{
                getCurrentTimestamp(), m.pid, m.process_name, MetricType::NETWORK, m.network_kb_s, th.network_kb_s});
        }
    }

    // Hàm quản lý kết nối Client, nhận và đẩy log
    void CTA::networkLoop()
    {
        std::cout << "[CTA] Network connect..." << std::endl;
        while (is_running_.load())
        {
            // 1. Chờ CTB kết nối (timeout 1000ms để kiểm tra lại cờ is_running_)
            if (!socket_channel_->isConnected())
            {
                if (!socket_channel_->waitForClient(1000))
                {
                    continue; // Chưa có client, tiếp tục chờ
                }
                std::cout << "[CTA] CTB đã kết nối thành công qua TCP Socket!" << std::endl;

                // 2. CTB vừa online đẩy log
                std::vector<EventRecord> pending_events = event_queue_->drainAll();
                if (!pending_events.empty())
                {
                    std::cout << "[CTA] Gửi " << pending_events.size()
                              << " log sang CTB..." << std::endl;
                    for (const auto &ev : pending_events)
                    {
                        if (!socket_channel_->sendMessage(ev.toLogString()))
                        {
                            break; // Nếu gửi lỗi thì dừng
                        }
                    }
                }
            }
            // 3. Lắng nghe thông điệp cấu hình từ CTB 
            std::string incoming_msg;
            if (socket_channel_->receiveMessage(incoming_msg, 100))
            {
                if (!incoming_msg.empty())
                {
                    std::cout << "[CTA] Nhận gói tin cấu hình từ CTB." << std::endl;
                    applyConfigFromJson(incoming_msg);
                }
            }
            // 4. Gửi các sự kiện mới phát sinh trong hàng đợi sang CTB
            EventRecord event;
            while (event_queue_->pop(event))
            {
                if (!socket_channel_->sendMessage(event.toLogString()))
                {
                    std::cerr << "[CTA] Mất kết nối tới CTB!" << std::endl;
                    // Nếu gửi lỗi, nạp lại sự kiện vào hàng đợi để không bị mất
                    event_queue_->push(std::move(event));
                    socket_channel_->disconnect();
                    break;
                }
            }
        }
        std::cout << "[CTA] Luồng truyền đã kết thúc." << std::endl;
    }

}