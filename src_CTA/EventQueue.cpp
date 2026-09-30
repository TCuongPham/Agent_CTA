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
        std::lock_guard<std::mutex> lock(mutex_);
        // Nếu hàng đợi đầy, loại bỏ phần tử cũ nhất
        if (queue_.size() >= max_capacity_)
        {
            queue_.pop_front();
        }
        
        queue_.push_back(std::move(event));
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
}