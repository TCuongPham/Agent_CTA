#include "EventQueue.h"

namespace sysmon
{
    EventQueue::EventQueue(size_t max_capacity)
        : max_capacity_(max_capacity > 0 ? max_capacity : DEFAULT_MAX_CAPACITY)
    {
    }
    void EventQueue::push(EventRecord event)
    {
        {
            // Khóa mutex tự động giải phóng khi ra khỏi scope
            std::lock_guard<std::mutex> lock(mutex_);
            // Nếu hàng đợi đã chạm ngưỡng trần tối đa, loại bỏ phần tử cũ nhất (Ring Buffer drop-oldest)
            if (queue_.size() >= max_capacity_)
            {
                queue_.pop_front();
                ++dropped_count_;
            }
            // Tận dụng move semantics để tránh sao chép các trường chuỗi ký tự
            queue_.push_back(std::move(event));
        }
        // Đánh thức 1 luồng consumer đang chờ trong waitAndPop
        cv_.notify_one();
    }

    bool EventQueue::pop(EventRecord &outEvent)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty())
        {
            return false;
        }
        outEvent = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }
    bool EventQueue::waitAndPop(EventRecord &outEvent, std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        // Chờ cho đến khi hàng đợi có phần tử hoặc hết thời gian timeout
        bool has_data = cv_.wait_for(lock, timeout, [this]
                                     { return !queue_.empty(); });
        if (!has_data)
        {
            return false;
        }
        outEvent = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }
    std::vector<EventRecord> EventQueue::drainAll()
    {
        std::vector<EventRecord> result;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty())
            {
                return result;
            }
            // Cấp phát trước dung lượng (reserve) để tránh reallocate nhiều lần
            result.reserve(queue_.size());
            // Di chuyển toàn bộ phần tử sang vector kết quả
            while (!queue_.empty())
            {
                result.push_back(std::move(queue_.front()));
                queue_.pop_front();
            }
        }
        return result;
    }
    size_t EventQueue::size() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    bool EventQueue::empty() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    void EventQueue::clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
    }
    size_t EventQueue::capacity() const
    {
        return max_capacity_;
    }
    size_t EventQueue::droppedCount() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return dropped_count_;
    }
}