// Lớp BPF này dùng thư viện libbpf để nạp file .bpf.o vào kernel và đọc Map.

#pragma once

#include <cstdint>

struct process_net_bpf;

namespace sysmon
{
    struct NetStats
    {
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
    };

    class BPFNetTracker
    {
    public:
        BPFNetTracker();
        ~BPFNetTracker();
        BPFNetTracker(const BPFNetTracker &) = delete;
        BPFNetTracker &operator=(const BPFNetTracker &) = delete;
        
        // Khởi tạo và nạp BPF vào Kernel thông qua Skeleton.
        bool initialize();
        
        //Lấy tổng số byte mạng (RX + TX) của một PID.
        bool getProcessNetworkBytes(uint32_t pid, uint64_t &out_total_bytes);

    private:
        struct process_net_bpf *skel_ = nullptr; ///< Con trỏ đối tượng Skeleton
        int map_fd_ = -1;                        ///< File descriptor của proc_net_map
        bool is_available_ = false;
    };
}