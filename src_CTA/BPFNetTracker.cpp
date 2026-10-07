// Lớp BPF này dùng thư viện libbpf để nạp file .bpf.o vào kernel và đọc Map.

#include "BPFNetTracker.h"
#include "bpf/process_net.skel.h" // Nhúng trực tiếp Skeleton

#include <bpf/bpf.h>
#include <iostream>

namespace sysmon
{
    BPFNetTracker::BPFNetTracker() = default;
    BPFNetTracker::~BPFNetTracker()
    {
        if (skel_)
        {
            // Tự động detach các kprobes và dọn dẹp bộ nhớ Kernel sạch sẽ
            process_net_bpf__destroy(skel_);
            skel_ = nullptr;
        }
    }
    bool BPFNetTracker::initialize()
    {
        // 1. Mở và nạp BPF vào Kernel
        skel_ = process_net_bpf__open_and_load();
        if (!skel_)
        {
            std::cerr << "[BPFNetTracker] Khong the nap eBPF vao kernel. (Can chay voi quyen sudo)" << std::endl;
            return false;
        }

        // 2. Gắn tự động các hook (kprobes) vào Linux Kernel
        int err = process_net_bpf__attach(skel_);
        if (err)
        {
            std::cerr << "[BPFNetTracker] Attach kprobes that bai: " << err << std::endl;
            process_net_bpf__destroy(skel_);
            skel_ = nullptr;
            return false;
        }

        // 3. Lấy Map FD để truy vấn 
        map_fd_ = bpf_map__fd(skel_->maps.proc_net_map);
        if (map_fd_ < 0)
        {
            std::cerr << "[BPFNetTracker] Khong lay duoc Map FD." << std::endl;
            process_net_bpf__destroy(skel_);
            skel_ = nullptr;
            return false;
        }

        is_available_ = true;
        std::cout << "[BPFNetTracker] Khoi tao eBPF Network Monitor thanh cong!" << std::endl;
        return true;

    }
    

    bool BPFNetTracker::getProcessNetworkBytes(uint32_t pid, uint64_t &out_total_bytes)
    {
        if (!is_available_ || map_fd_ < 0)
        {
            out_total_bytes = 0;
            return false;
        }
        NetStats stats{};

        // Truy vấn trực tiếp từ Kernel Map theo key là PID
        int res = bpf_map_lookup_elem(map_fd_, &pid, &stats);
        if (res == 0)
        {
            out_total_bytes = stats.rx_bytes + stats.tx_bytes;
            return true;
        }
        out_total_bytes = 0;
        return false;
    }

    bool BPFNetTracker::removeProcess(uint32_t pid)
    {
        if (!is_available_ || map_fd_ < 0)
        {
            return false;
        }
        return bpf_map_delete_elem(map_fd_, &pid) == 0;
    }
}