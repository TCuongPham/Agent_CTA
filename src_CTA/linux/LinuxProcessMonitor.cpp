#include "LinuxProcessMonitor.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <unistd.h>
#include <unordered_set>
#include <cstring>
#include <algorithm>

namespace sysmon
{
    // Hàm khởi tạo
    LinuxProcessMonitor::LinuxProcessMonitor()
    {
        // Lấy số lượng lõi CPU đang online của hệ thống
        num_cores_ = sysconf(_SC_NPROCESSORS_ONLN);
        if (num_cores_ < 1)
        {
            num_cores_ = 1;
        }
    }

    // 1. Đọc tên tiến trình từ /proc/[pid]/comm
    std::string LinuxProcessMonitor::readProcessComm(uint32_t pid)
    {
        std::ifstream file("/proc/" + std::to_string(pid) + "/comm");
        if (!file.is_open())
        {
            return "";
        }
        std::string comm;
        std::getline(file, comm);

        // Xóa ký tự xuống dòng ở cuối chuỗi
        while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r'))
        {
            comm.pop_back();
        }
        return comm;
    }

    // 2. Đọc tổng số ticks CPU toàn hệ thống từ /proc/stat
    uint64_t LinuxProcessMonitor::readSystemCpuTicks()
    {
        std::ifstream file("/proc/stat");
        if (!file.is_open())
        {
            return 0;
        }
        std::string cpu_label;
        file >> cpu_label; // Bỏ qua nhãn "cpu" đầu dòng
        if (cpu_label != "cpu")
        {
            return 0;
        }

        uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0;
        file >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

        return user + nice + system + idle + iowait + irq + softirq + steal;
    }

    // 3. Đọc CPU ticks (utime + stime) của tiến trình từ /proc/[pid]/stat
    bool LinuxProcessMonitor::readProcessCpuTicks(uint32_t pid, uint64_t &out_proc_ticks)
    {
        std::ifstream file("/proc/" + std::to_string(pid) + "/stat");
        if (!file.is_open())
        {
            return false;
        }
        std::string line;
        std::getline(file, line);

        // Tìm dấu đóng ngoặc ')' cuối cùng trong dòng để định vị phần số phía sau.
        size_t last_paren = line.rfind(')');
        if (last_paren == std::string::npos || last_paren + 2 >= line.size())
        {
            return false;
        }

        std::istringstream iss(line.substr(last_paren + 2));
        char state;
        int ppid, pgrp, session, tty_nr, tpgid;
        unsigned int flags;
        unsigned long minflt, cminflt, majflt, cmajflt, utime = 0, stime = 0;

        // Đọc lần lượt các trường: state(3), ppid(4)... utime(14), stime(15)
        iss >> state >> ppid >> pgrp >> session >> tty_nr >> tpgid >> flags >> minflt >> cminflt >> majflt >> cmajflt >> utime >> stime;
        if (iss.fail())
        {
            return false;
        }

        out_proc_ticks = utime + stime;
        return true;
    }

    // 4. Đọc lượng RAM VmRSS (MB) từ /proc/[pid]/status
    double LinuxProcessMonitor::readProcessMemoryMb(uint32_t pid)
    {
        std::ifstream file("/proc/" + std::to_string(pid) + "/status");
        if (!file.is_open())
        {
            return 0.0;
        }
        std::string line;
        while (std::getline(file, line))
        {
            if (line.rfind("VmRSS:", 0) == 0)
            { // Bắt đầu bằng "VmRSS:"
                std::istringstream iss(line.substr(6));
                uint64_t vmrss_kb = 0;
                iss >> vmrss_kb;
                return static_cast<double>(vmrss_kb) / 1024.0; // Đổi kB thành MB
            }
        }
        return 0.0;
    }

    // 5. Đọc tổng byte Disk I/O từ /proc/[pid]/io
    uint64_t LinuxProcessMonitor::readProcessDiskBytes(uint32_t pid)
    {
        std::ifstream file("/proc/" + std::to_string(pid) + "/io");
        if (!file.is_open())
        {
            return 0; // Nếu không có quyền root hoặc kernel
        }
        std::string key;
        uint64_t val = 0;
        uint64_t read_bytes = 0, write_bytes = 0;
        while (file >> key >> val)
        {
            if (key == "read_bytes:")
            {
                read_bytes = val;
            }
            else if (key == "write_bytes:")
            {
                write_bytes = val;
            }
        }
        return read_bytes + write_bytes;
    }

    // 6. Đọc tổng lưu lượng mạng qua /proc/[pid]/net/dev
    uint64_t LinuxProcessMonitor::readProcessNetworkBytes(uint32_t pid)
    {
        std::ifstream file("/proc/" + std::to_string(pid) + "/net/dev");
        if (!file.is_open())
        {
            return 0;
        }

        std::string line;
        // Bỏ qua 2 dòng header đầu tiên
        std::getline(file, line);
        std::getline(file, line);
        uint64_t total_bytes = 0;

        while (std::getline(file, line))
        {
            size_t colon = line.find(':');
            if (colon == std::string::npos)
                continue;

            std::string iface = line.substr(0, colon);

            // Bỏ qua loopback ("lo") vì là mạng nội bộ
            if (iface.find("lo") != std::string::npos)
                continue;

            std::istringstream iss(line.substr(colon + 1));
            uint64_t rx_bytes = 0, tx_bytes = 0, dummy = 0;
            // Định dạng cột: rx_bytes packets errs drop fifo frame compressed multicast tx_bytes ...
            iss >> rx_bytes;
            for (int i = 0; i < 7; ++i)
                iss >> dummy;
            iss >> tx_bytes;
            total_bytes += (rx_bytes + tx_bytes);
        }
        return total_bytes;
    }

    // Tìm kiếm toàn bộ PID của các tiến trình đang hoạt động khớp với tên.
    std::vector<uint32_t> LinuxProcessMonitor::getPidsByName(const std::string &processName)
    {
        std::vector<uint32_t> pids;
        DIR *dir = opendir("/proc");
        if (!dir)
        {
            return pids;
        }
        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr)
        {
            // Chỉ quan tâm các thư mục có tên là số nguyên (PID)
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
            {
                continue;
            }
            uint32_t pid = static_cast<uint32_t>(std::strtoul(entry->d_name, nullptr, 10));
            if (pid > 0 && readProcessComm(pid) == processName)
            {
                pids.push_back(pid);
            }
        }
        closedir(dir);
        return pids;
    }

    // Lấy chỉ số tài nguyên chi tiết cho một tiến trình cụ thể thông qua PID.
    bool LinuxProcessMonitor::getMetricsForPid(uint32_t pid, ProcessMetrics &outMetrics)
    {
        std::string comm = readProcessComm(pid);
        if (comm.empty())
        {
            return false; // Tiến trình đã tắt
        }
        uint64_t cur_proc_ticks = 0;
        if (!readProcessCpuTicks(pid, cur_proc_ticks))
        {
            return false;
        }
        uint64_t cur_sys_ticks = readSystemCpuTicks();
        uint64_t cur_disk_bytes = readProcessDiskBytes(pid);
        uint64_t cur_net_bytes = readProcessNetworkBytes(pid);

        auto now = std::chrono::steady_clock::now();
        ProcessHistory &hist = history_[pid];

        double cpu_pct = 0.0;
        double disk_mb_s = 0.0;
        double net_kb_s = 0.0;

        // Nếu đã có dữ liệu khởi tạo
        if (hist.initialized)
        {
            // 1. Tính toán thời gian trôi qua giữa 2 lần lấy mẫu (Delta t tính bằng giây)
            std::chrono::duration<double> elapsed = now - hist.last_time;
            double dt = elapsed.count();
            if (dt > 0.0)
            {
                // 2. Tính toán CPU (%)
                if (cur_sys_ticks > hist.last_sys_ticks && cur_proc_ticks >= hist.last_proc_ticks)
                {
                    uint64_t delta_proc = cur_proc_ticks - hist.last_proc_ticks;
                    uint64_t delta_sys = cur_sys_ticks - hist.last_sys_ticks;
                    cpu_pct = (static_cast<double>(delta_proc) / delta_sys) * 100.0 * num_cores_;
                }
                // 3. Tính toán Disk I/O (MB/s)
                if (cur_disk_bytes >= hist.last_disk_bytes)
                {
                    uint64_t delta_disk = cur_disk_bytes - hist.last_disk_bytes;
                    disk_mb_s = static_cast<double>(delta_disk) / (dt * 1024.0 * 1024.0);
                }
                // 4. Tính toán Network (KB/s)
                if (cur_net_bytes >= hist.last_net_bytes)
                {
                    uint64_t delta_net = cur_net_bytes - hist.last_net_bytes;
                    net_kb_s = static_cast<double>(delta_net) / (dt * 1024.0);
                }
            }
        }
        // Cập nhật trạng thái cho lần lấy mẫu tiếp theo
        hist.last_time = now;
        hist.last_proc_ticks = cur_proc_ticks;
        hist.last_sys_ticks = cur_sys_ticks;
        hist.last_disk_bytes = cur_disk_bytes;
        hist.last_net_bytes = cur_net_bytes;
        hist.initialized = true;

        // Gán dữ liệu đầu ra
        outMetrics.pid = pid;
        outMetrics.process_name = comm;
        outMetrics.cpu_percent = cpu_pct;
        outMetrics.memory_mb = readProcessMemoryMb(pid);
        outMetrics.disk_mb_s = disk_mb_s;
        outMetrics.network_kb_s = net_kb_s;
        outMetrics.timestamp = getCurrentTimestamp();
        return true;
    }

    // Thu thập chỉ số phần cứng định kỳ cho một danh sách các tiến trình mục tiêu
    std::vector<ProcessMetrics> LinuxProcessMonitor::collectMetrics(
        const std::vector<std::string> &targetProcessNames)
    {

        std::vector<ProcessMetrics> results;
        if (targetProcessNames.empty())
        {
            return results;
        }

        // Đưa danh sách vào hash set để tra cứu tên với độ phức tạp O(1)
        std::unordered_set<std::string> target_set(targetProcessNames.begin(), targetProcessNames.end());
        std::unordered_set<uint32_t> current_active_pids;
        DIR *dir = opendir("/proc");
        if (!dir)
        {
            return results;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr)
        {
            // Chỉ kiểm tra các thư mục số (PID)
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
            {
                continue;
            }
            uint32_t pid = static_cast<uint32_t>(std::strtoul(entry->d_name, nullptr, 10));
            if (pid == 0)
                continue;

            // TARGETED FILTERING: Đọc nhanh comm trước
            std::string comm = readProcessComm(pid);
            if (comm.empty() || target_set.find(comm) == target_set.end())
            {
                continue; // Bỏ qua ngay lập tức để tiết kiệm CPU (< 5%)
            }

            current_active_pids.insert(pid);
            // Chỉ khi tiến trình nằm trong cấu hình mới tính toán sâu
            ProcessMetrics metrics;
            if (getMetricsForPid(pid, metrics))
            {
                results.push_back(std::move(metrics));
            }
        }
    
        closedir(dir);

        // Dọn dẹp cache của các PID khỏi bảng history_ đã bị tắt để tránh rò rỉ RAM theo thời gian
        for (auto it = history_.begin(); it != history_.end();)
        {
            if (current_active_pids.find(it->first) == current_active_pids.end())
            {
                it = history_.erase(it);
            }
            else
            {
                ++it;
            }
        }
        return results;
    }

}