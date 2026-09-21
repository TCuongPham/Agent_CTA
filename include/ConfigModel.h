#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include "../third_party/json.hpp"

namespace sysmon
{
    using json = nlohmann::json;

    // 1. Các loại tài nguyên giám sát
    enum class MetricType
    {
        CPU,    // % CPU sử dụng
        MEMORY, // Bộ nhớ RAM thực tế (MB)
        DISK,   // Tốc độ đọc ghi (MB/s)
        NETWORK // Tổng lưu lượng mạng nhận/truyền (KB/s)
    };

    // Chuyển đổi MetricType enum thành chuỗi chữ thường
    inline std::string metricTypeToString(MetricType type)
    {
        switch (type)
        {
        case MetricType::CPU:
            return "cpu";
        case MetricType::MEMORY:
            return "memory";
        case MetricType::DISK:
            return "disk";
        case MetricType::NETWORK:
            return "network";
        default:
            return "unknown";
        }
    }
    // Chuyển đổi chuỗi chữ (không phân biệt hoa/thường) thành MetricType enum.
    inline MetricType metricTypeFromString(const std::string &str)
    {
        std::string lower = str;
        // Chuyển toàn bộ chuỗi về chữ thường để so sánh
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower == "cpu")
            return MetricType::CPU;
        if (lower == "memory")
            return MetricType::MEMORY;
        if (lower == "disk")
            return MetricType::DISK;
        if (lower == "network")
            return MetricType::NETWORK;
        return MetricType::CPU; // Giá trị fallback
    }

    // 2. Timestamp chuẩn ISO "YYYY-MM-DD HH:MM:SS".
    inline std::string getCurrentTimestamp()
    {
        const auto now = std::chrono::system_clock::now();
        const auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm buf{};

#if defined(_WIN32)
        localtime_s(&buf, &in_time_t);
#else
        localtime_r(&in_time_t, &buf);
#endif

        std::ostringstream ss;
        ss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    // 3. Cấu trúc ngưỡng cảnh báo cho từng tiến trình
    struct ProcessThreshold
    {
        std::string process_name;  // Tên proc
        double cpu_percent = 0.0;  // %
        double memory_mb = 0.0;    // MB
        double disk_mb_s = 0.0;    // MB/s
        double network_kb_s = 0.0; // KB/s
    };

    // 4. Cấu hình giám sát toàn cục gửi từ CTB
    struct MonitorConfig
    {
        uint32_t sampling_interval_ms = 1000; // Chu kỳ lấy mẫu (1000ms = 1 giây)

        std::vector<ProcessThreshold> thresholds; // DS proc cần theo dõi
    };

    // 5. Dữ liệu của 1 tiến trình tại thời điểm t
    struct ProcessMetrics
    {
        uint32_t pid = 0; // ID của proc
        std::string process_name;
        double cpu_percent = 0.0;
        double memory_mb = 0.0;
        double disk_mb_s = 0.0;
        double network_kb_s = 0.0;
        std::string timestamp; // Thời điểm t
    };

    // 6. Dữ liệu sự kiện cảnh báo gửi từ CTA sang CTB
    struct EventRecord
    {
        std::string timestamp;
        uint32_t pid = 0;
        std::string process_name;
        MetricType metric_type = MetricType::CPU;

        double value = 0.0;     // Giá trị thực
        double threshold = 0.0; // Ngưỡng bị vượt

        // Xuất chuỗi log chuẩn theo định dạng CTB:
        // date time, process id, process name, type, value
        std::string toLogString() const
        {
            std::ostringstream ss;
            ss << std::fixed << std::setprecision(2);
            ss << timestamp << ", "
               << pid << ", "
               << process_name << ", "
               << metricTypeToString(metric_type) << ", "
               << value;
            return ss.str();
        }
    };

    // -------------------------------------------------------------
    // 7. JSON Parsing
    // -------------------------------------------------------------

    // Chuyển đổi ProcessThreshold
    inline void to_json(json &j, const ProcessThreshold &p)
    {
        j = json{
            {"process_name", p.process_name},
            {"cpu_percent", p.cpu_percent},
            {"memory_mb", p.memory_mb},
            {"disk_mb_s", p.disk_mb_s},
            {"network_kb_s", p.network_kb_s}};
    }
    inline void from_json(const json &j, ProcessThreshold &p)
    {
        // j.value(key, default_val):
        p.process_name = j.value("process_name", "");
        p.cpu_percent = j.value("cpu_percent", 0.0);
        p.memory_mb = j.value("memory_mb", 0.0);
        p.disk_mb_s = j.value("disk_mb_s", 0.0);
        p.network_kb_s = j.value("network_kb_s", 0.0);
    }

    // Chuyển đổi MonitorConfig
    inline void to_json(json &j, const MonitorConfig &c)
    {
        j = json{
            {"sampling_interval_ms", c.sampling_interval_ms},
            {"thresholds", c.thresholds}};
    }

    inline void from_json(const json &j, MonitorConfig &c)
    {
        c.sampling_interval_ms = j.value("sampling_interval_ms", 1000u);
        // Kiểm tra thresholds có tồn tại và đúng kiểu mảng (array)
        if (j.contains("thresholds") && j["thresholds"].is_array())
        {
            c.thresholds = j["thresholds"].get<std::vector<ProcessThreshold>>();
        }
        else
        {
            c.thresholds.clear();
        }
    }

    // Chuyển đổi EventRecord
    inline void to_json(json &j, const EventRecord &e)
    {
        j = json{
            {"timestamp", e.timestamp},
            {"pid", e.pid},
            {"process_name", e.process_name},
            {"metric_type", metricTypeToString(e.metric_type)},
            {"value", e.value},
            {"threshold", e.threshold}};
    }
    inline void from_json(const json &j, EventRecord &e)
    {
        e.timestamp = j.value("timestamp", "");
        e.pid = j.value("pid", 0u);
        e.process_name = j.value("process_name", "");
        e.metric_type = metricTypeFromString(j.value("metric_type", "cpu"));
        e.value = j.value("value", 0.0);
        e.threshold = j.value("threshold", 0.0);
    }

    // Chuyển đổi ProcessMetrics
    inline void to_json(json &j, const ProcessMetrics &m)
    {
        j = json{
            {"pid", m.pid},
            {"process_name", m.process_name},
            {"cpu_percent", m.cpu_percent},
            {"memory_mb", m.memory_mb},
            {"disk_mb_s", m.disk_mb_s},
            {"network_kb_s", m.network_kb_s},
            {"timestamp", m.timestamp}};
    }
    inline void from_json(const json &j, ProcessMetrics &m)
    {
        m.pid = j.value("pid", 0u);
        m.process_name = j.value("process_name", "");
        m.cpu_percent = j.value("cpu_percent", 0.0);
        m.memory_mb = j.value("memory_mb", 0.0);
        m.disk_mb_s = j.value("disk_mb_s", 0.0);
        m.network_kb_s = j.value("network_kb_s", 0.0);
        m.timestamp = j.value("timestamp", "");
    }

}
