#pragma once

#include <deque>
#include <vector>
#include <mutex>
#include <cstddef>

#include "ConfigModel.h"

namespace sysmon
{
    class EventQueue
    {
    public:
        // Kích thước hàng đợi mặc định (20,000 sự kiện xấp xỉ 3-5 MB RAM)
        static constexpr size_t DEFAULT_MAX_CAPACITY = 20000;

        // Tạo hàng đợi
        explicit EventQueue(size_t max_capacity = DEFAULT_MAX_CAPACITY);
        ~EventQueue() = default;

        // Ngăn chặn sao chép đối tượng để đảm bảo tính an toàn của Mutex
        EventQueue(const EventQueue &) = delete;
        EventQueue &operator=(const EventQueue &) = delete;
        // Cho phép di chuyển quyền sở hữu
        EventQueue(EventQueue &&) noexcept = delete;
        EventQueue &operator=(EventQueue &&) noexcept = delete;

        // Đẩy sự kiện vào cuối hàng đợi. Nếu hàng đợi đầy, phần tử cũ nhất ở đầu hàng đợi sẽ bị loại bỏ
        void push(EventRecord event);

        // Lấy sự kiện cũ nhất đầu hàng đợi
        bool pop(EventRecord &outEvent);
        // Lấy toàn bộ sự kiện đang có trong hàng đợi chỉ trong 1 lần khóa Mutex.
        std::vector<EventRecord> drainAll();

    private:
        const size_t max_capacity_;     // Kích thước hàng đợi cho phép
        std::deque<EventRecord> queue_; // Bộ đệm lưu trữ nội bộ
        mutable std::mutex mutex_;      // Mutex bảo vệ truy cập đồng thời
    };
}
