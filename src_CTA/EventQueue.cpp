#include "EventQueue.h"

namespace sysmon
{   
    // Thiết lập kích thước hàng đợi 
    EventQueue::EventQueue(size_t max_capacity)
        : max_capacity_(max_capacity > 0 ? max_capacity : DEFAULT_MAX_CAPACITY)
    {
    }

    // Đẩy sự kiện vào cuối hàng đợi
    void EventQueue::push(EventRecord event)
    {
        {
            // mutex tự động giải phóng khi ra khỏi scope
            std::lock_guard<std::mutex> lock(mutex_);
            // Nếu hàng đợi đầy, loại bỏ phần tử cũ nhất
            if (queue_.size() >= max_capacity_)
            {
                queue_.pop_front();
                ++dropped_count_;
            }
            
            queue_.push_back(std::move(event));
        }
        // Đánh thức 1 luồng consumer đang chờ trong waitAndPop
        cv_.notify_one();
    }

    // Lấy sự kiện cũ nhất đầu hàng đợi
    bool EventQueue::pop(EventRecord &outEvent)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty())
        {
            return false;
        }
        // Chuyển tài nguyên sang outEvent
        outEvent = std::move(queue_.front());
        // Loại bỏ phần tử đầu  
        queue_.pop_front();
        return true;
    }

    // Chờ đợi và lấy một sự kiện với thời gian timeout
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

    // Lấy toàn bộ sự kiện đang có trong hàng đợi 
    std::vector<EventRecord> EventQueue::drainAll()
    {
        std::vector<EventRecord> result;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queue_.empty())
            {
                return result;
            }
            // Cấp phát trước dung lượng 
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

    // Lấy số lượng sự kiện hiện có trong hàng đợi
    size_t EventQueue::size() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    // Kiểm tra hàng đợi rỗng
    bool EventQueue::empty() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    // Xóa toàn bộ sự kiện hiện có trong hàng đợi
    void EventQueue::clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
    }
    // Lấy kích thước tối đa của hàng đợi
    size_t EventQueue::capacity() const
    {
        return max_capacity_;
    }
    // Lấy tổng số lượng sự kiện đã bị loại bỏ do đầy queue
    size_t EventQueue::droppedCount() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return dropped_count_;
    }
}