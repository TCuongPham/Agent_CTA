#pragma once

#include <deque>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <cstddef>

#include "ConfigModel.h"

namespace sysmon
{
    class EventQueue
    {
    public:
        // Dung lượng max mặc định (20,000 sự kiện xấp xỉ 3-5 MB RAM)
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
        // Chờ đợi và lấy một sự kiện với thời gian timeout
        bool waitAndPop(EventRecord &outEvent, std::chrono::milliseconds timeout);

        // Lấy toàn bộ sự kiện đang có trong hàng đợi chỉ trong 1 lần khóa Mutex.
        std::vector<EventRecord> drainAll();

        size_t size() const;         // Lấy số lượng sự kiện hiện có trong hàng đợi
        bool empty() const;          // Kiểm tra hàng đợi có rỗng hay không
        void clear();                // Xóa toàn bộ sự kiện hiện có trong hàng đợi
        size_t capacity() const;     // Lấy dung lượng trần tối đa của hàng đợi
        size_t droppedCount() const; // Lấy tổng số lượng sự kiện đã bị loại bỏ do đầy queue

    private:
        const size_t max_capacity_;     // Dung lượng trần cho phép
        std::deque<EventRecord> queue_; // Bộ đệm lưu trữ nội bộ
        mutable std::mutex mutex_;      // Mutex bảo vệ truy cập đồng thời
        std::condition_variable cv_;    // Biến điều kiện đánh thức luồng Consumer
        size_t dropped_count_ = 0;      // Bộ đếm số sự kiện bị loại bỏ do đầy hàng đợi
    };
}
