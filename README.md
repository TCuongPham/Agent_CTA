# Agent_CTA - Hệ Thống Giám Sát Tài Nguyên Tiến Trình (CTA & CTB)

---

## MỤC LỤC
1. [Kiến Trúc Hệ Thống](#1-kiến-trúc-hệ-thống)
2. [Cấu Trúc Thư Mục Dự Án](#2-cấu-trúc-thư-mục-dự-án)
3. [Công Nghệ & Native OS APIs](#3-công-nghệ--native-os-apis)
4. [Yêu Cầu Môi Trường](#4-yêu-cầu-môi-trường)
5. [Hướng Dẫn Biên Dịch](#5-hướng-dẫn-biên-dịch)
   - [5.1. Biên dịch trên Linux (eBPF, Clang, Skeleton, CMake)](#51-biên-dịch-trên-linux)
   - [5.2. Biên dịch trên Windows (Visual Studio, MSBuild, WDK Driver)](#52-biên-dịch-trên-windows)
6. [Cài Đặt Windows Kernel Driver (.sys)](#6-cài-đặt-windows-kernel-driver-sys)
7. [Hướng Dẫn Vận Hành](#7-hướng-dẫn-vận-hành)
8. [Cấu Hình](#8-cấu-hình)

---

## 1. KIẾN TRÚC HỆ THỐNG

```
+-----------------------------------------------------------------------------------+
|                                  CTB CONTROLLER                                   |
|               (TCP Server 0.0.0.0:9000 | Config Manager | Event Logger)           |
+-----------------------------------------------------------------------------------+
       | Gửi cấu hình JSON                          ^ Nhận log cảnh báo vượt ngưỡng
       |                                            | (date time, pid, name, type, val)
================================= [ TCP SOCKET ] ====================================
       |                                            |
       v                                            |
+-----------------------------------------------------------------------------------+
|                                     CTA AGENT                                     |
|               (TCP Client 127.0.0.1:9000 | Daemon Engine | Edge Processor)        |
|                                                                                   |
|  +--------------------+   +-----------------------+   +------------------------+  |
|  |   IConfigStorage   |   |    IProcessMonitor    |   |       EventQueue       |  |
|  |  ----------------  |   |  -------------------  |   |  --------------------  |  |
|  |  - Win Registry    |   |  - CPU %, RAM (MB)    |   |  - Thread-Safe Queue   |  |
|  |  - Linux File      |   |  - Disk IO (MB/s)     |   |  - Ring-Buffer RAM     |  |
|  |                    |   |  - Network IO (KB/s)  |   |  - Tự động đẩy khi     |  |
|  +--------------------+   +-----------------------+   |    kết nối             |  |
|                                       |               +------------------------+  |
+---------------------------------------|-------------------------------------------+
                                        |
                 +----------------------+----------------------+
                 | (Linux)                                     | (Windows)
                 v                                             v
     +-----------------------+                     +-----------------------+
     |   eBPF Kernel Mode    |                     |   WFP Kernel Driver   |
     | (kprobe tcp/udp hook) |                     | (WfpNetTrackerDriver) |
     |           +           |                     |           +           |
     |   libbpf Skeleton     |                     | User-Mode EStats Fall |
     +-----------------------+                     +-----------------------+
```

### Các vai trò:
- **CTA**:
  - Chạy ngầm định kỳ (mặc định 1000ms), lấy mẫu tài nguyên của các tiến trình được chỉ định.
  - Tích hợp **EventQueue**: Khi CTB chưa bật hoặc đường truyền mạng gián đoạn, toàn bộ cảnh báo được giữ trong RAM. Khi kết nối lại, CTA đẩy dữ liệu tồn đọng sang CTB.
  - Lưu bản sao cấu hình vào Windows Registry (`HKCU\Software\CTA`) hoặc POSIX File (`~/.config/cta/config.json`). Nếu mất kết nối với CTB khi khởi động, CTA tự nạp cấu hình offline để tiếp tục giám sát.
- **CTB**:
  - Khởi tạo TCP Socket Server (mặc định: `0.0.0.0:9000`).
  - Lắng nghe sự kiện từ Agent, ghi file log theo định dạng chuẩn hóa.
  - Theo dõi biến động của file `config.json` để tự động đẩy cấu hình mới xuống Agent.

---

## 2. CẤU TRÚC THƯ MỤC DỰ ÁN

```text
Agent_CTA/
├── CMakeLists.txt                         # CMake root tự động phân nhánh OS và target
├── config.json                            # Cấu hình mẫu: chu kỳ lấy mẫu và ngưỡng tiến trình
├── README.md                             
├── .gitignore                             
│
├── include/                               # DATA MODELS
│   ├── ConfigModel.h                      # Model: ProcessThreshold, MonitorConfig, EventRecord
│   ├── IConfigStorage.h                   # Interface lưu trữ cấu hình 
│   ├── IProcessMonitor.h                  # Interface đo phần cứng của tiến trình
│   ├── ISocketChannel.h / .cpp            # Interface và triển khai TCP Socket 
│   ├── EventQueue.h                       # Hàng đợi Thread-safe dữ liệu khi mất kết nối
│   ├── CTA.h                              # Lớp Agent, lấy mẫu, so khớp ngưỡng
│   ├── CTB.h                              # Lớp Controller: quản lý config, socket và ghi log
│   ├── BPFNetTracker.h                    # Wrapper C++ quản lý libbpf skeleton (Linux)
│   └── WFPNetTracker.h                    # Wrapper C++ giao tiếp IOCTL WFP Driver / EStats (Windows)
│
├── src_CTA/                               # TIẾN TRÌNH AGENT (CTA)
│   ├── main_cta.cpp                       # Entry point Agent
│   ├── CTA.cpp                            # Vòng lặp lấy mẫu, kiểm tra vi phạm ngưỡng, bắn event
│   ├── EventQueue.cpp                     # FIFO Queue với std::mutex & cv
│   ├── BPFNetTracker.cpp                  # Khởi tạo skeleton, attach kprobes, đọc BPF Hash Map
│   ├── WFPNetTracker.cpp                  # Giao tiếp DeviceIoControl tới Driver hoặc Fallback EStats
│   │
│   ├── bpf/                               # KERNEL eBPF 
│   │   ├── process_net.bpf.c              # eBPF C program: hook kprobe TCP/UDP TX/RX theo PID
│   │   ├── vmlinux.h                      # BTF Kernel header 
│   │   └── process_net.skel.h             # BPF Skeleton C header 
│   │
│   ├── linux/                             # OS NATIVE IMPLEMENTATION CHO LINUX
│   │   ├── LinuxProcessMonitor.h / .cpp   # POSIX: đọc /proc/[pid]/stat, status, io, net
│   │   └── LinuxFileStorage.h / .cpp      # POSIX File I/O (~/.config/cta/config.json)
│   │
│   └── windows/                           # OS NATIVE IMPLEMENTATION CHO WINDOWS
│       ├── WfpCommon.h                    # Header chia sẻ giữa User-mode và Kernel-mode (IOCTLs)
│       ├── WindowsProcessMonitor.h / .cpp # Win32: Toolhelp32, PSAPI, GetProcessTimes, IO_COUNTERS
│       └── WindowsRegistryStorage.h / .cpp# Win32 Registry (HKEY_CURRENT_USER\Software\CTA)
│
├── src_CTB/                               # TIẾN TRÌNH CONTROLLER (CTB)
│   ├── main_ctb.cpp                       # Entry point CTB
│   └── CTB.cpp                            # Vòng lặp nhận event, theo dõi hot-reload config.json
│
├── KMDF Driver/                           # WINDOWS KERNEL DRIVER (WDF / KMDF)
│   ├── KMDF Driver.slnx                   # Solution file Visual Studio 2022
│   └── WfpNetTrackerDriver/               # Dự án WFP Callout Driver
│       ├── CommonIoctl.h                  # Mã điều khiển IOCTL, GUID, cấu trúc trao đổi dữ liệu
│       ├── Driver.c                       # DriverEntry, Dispatch IRP, IoCreateDevice, SymbolicLink
│       ├── WfpCallouts.c / .h             # Đăng ký WFP Callout Layers (ALE Flow, Stream, Datagram)
│       ├── WfpNetTrackerDriver.inf        # File cài đặt cấu hình 
│       └── WfpNetTrackerDriver.vcxproj    # MSBuild Project file tích hợp WDK
│
└── third_party/                           # THƯ VIỆN BÊN THỨ 3
    └── json.hpp                           # Thư viện JSON header-only 
```

---

## 3. CÔNG NGHỆ & NATIVE OS APIS

| Giám sát | Trên Linux | Trên Windows |
| :--- | :--- | :--- |
| **Duyệt danh sách tiến trình** | Duyệt cây thư mục ảo `/proc`, đọc `/proc/[pid]/comm` | `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW` |
| **Đo CPU (%)** | Đọc `utime` & `stime` từ `/proc/[pid]/stat`, tính delta trên tổng CPU ticks của `/proc/stat` | `GetProcessTimes` (Kernel + User) chia cho `GetSystemTimes` $\times$ số nhân CPU |
| **Đo RAM (MB)** | Đọc trường `VmRSS` (Resident Set Size) từ `/proc/[pid]/status` | `GetProcessMemoryInfo` (PSAPI) $\rightarrow$ `pmc.WorkingSetSize` |
| **Đo Disk I/O (MB/s)** | Đọc `read_bytes` và `write_bytes` từ file `/proc/[pid]/io` | `GetProcessIoCounters` $\rightarrow$ `ReadTransferCount + WriteTransferCount` |
| **Đo Network I/O (KB/s)** | **eBPF Kernel Hooks**: kprobe `tcp_sendmsg`, `tcp_cleanup_rbuf`, `udp_sendmsg`, `udp_recvmsg` | **WFP KMDF Kernel Driver**: Hook ALE Flow Established, TCP Stream, UDP Datagram qua IOCTL.<br>*(Fallback: User-Mode IP Helper TCP EStats)* |
| **Lưu cấu hình** | File POSIX: `~/.config/cta/config.json` | Windows Registry: `HKCU\Software\CTA\ConfigJson` |
| **Giao tiếp Agent - Controller**| POSIX Sockets (TCP/IP) non-blocking / blocking | Winsock2 (`ws2_32.lib`) TCP/IP |

---

## 4. YÊU CẦU MÔI TRƯỜNG

### 4.1. Môi trường Linux
- **Hệ điều hành**: Ubuntu 20.04+ (Kernel $\ge$ 5.4 hỗ trợ BTF).
- **Trình biên dịch & Công cụ**:
  ```bash
  # Trên Ubuntu / Debian:
  sudo apt update
  sudo apt install -y build-essential cmake clang llvm libbpf-dev \
                      linux-tools-common linux-tools-generic linux-tools-$(uname -r)
  ```

### 4.2. Môi trường Windows
- **Hệ điều hành**: Windows 10/11 x64 hoặc Windows Server 2019/2022.
- **Visual Studio 2022**: Cài đặt Workload **Desktop development with C++**.
- **Windows Driver Kit (WDK)**: Cài đặt **WDK 10/11** tương ứng với phiên bản Windows SDK để biên dịch Driver `.sys`.
- **CMake**: Phiên bản $\ge$ 3.16.

---

## 5. HƯỚNG DẪN BIÊN DỊCH

### 5.1. Biên dịch trên Linux

Quy trình biên dịch trên Linux gồm 2 giai đoạn: Biên dịch chương trình **eBPF Kernel** và biên dịch **User-Mode Application (CTA & CTB)**.

```
       [Kernel BTF]                  [process_net.bpf.c]
            |                                 |
            v (bpftool btf dump)              v (clang -target bpf)
       [vmlinux.h] -----------------> [process_net.bpf.o]
                                              |
                                              v (bpftool gen skeleton)
                                     [process_net.skel.h]
                                              |
                                              v (cmake / g++)
                                      [Binary: CTA, CTB]
```

#### Bước 1: Trích xuất Kernel BTF (`vmlinux.h`)
File `vmlinux.h` đã được tạo sẵn trong thư mục `src_CTA/bpf/`:
```bash
cd src_CTA/bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

#### Bước 2: Biên dịch eBPF sang Bytecode và sinh Skeleton Header
```bash
cd src_CTA/bpf

# 1. Biên dịch process_net.bpf.c sang eBPF Object bytecode (.bpf.o)
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c process_net.bpf.c -o process_net.bpf.o

# 2. Sinh skeleton C/C++ header từ file .bpf.o
bpftool gen skeleton process_net.bpf.o > process_net.skel.h

cd ../..
```

#### Bước 3: Cấu hình và Biên dịch Dự án với CMake
```bash
# Tạo thư mục build 
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Biên dịch CTA và CTB
cmake --build build -j$(nproc)
```
**Kết quả trong thư mục `build/`:**
- `build/CTB`: Controller & Quản lý log.
- `build/CTA`: Agent giám sát tiến trình.

---

### 5.2. Biên dịch trên Windows

#### Bước 1: Biên dịch User-Mode Applications (CTA.exe & CTB.exe)
Mở **Developer Command Prompt for VS 2022** hoặc **PowerShell**:
```cmd
:: 1. Tạo thư mục build và cấu hình Visual Studio Solution qua CMake
cmake -B build -G "Visual Studio 17 2022" -A x64

:: 2. Biên dịch bản Release
cmake --build build --config Release
```
**Kết quả đầu ra:**
- `build\Release\CTB.exe`
- `build\Release\CTA.exe`

#### Bước 2: Biên dịch KMDF WFP Kernel Driver (`WfpNetTrackerDriver.sys`)
- **Cách 1: Sử dụng Visual Studio IDE**:
  1. Chạy Visual Studio và mở tệp `KMDF Driver\KMDF Driver.slnx` (hoặc mở trực tiếp `KMDF Driver\WfpNetTrackerDriver\WfpNetTrackerDriver.vcxproj`).
  2. Chọn cấu hình **Release** và **x64**.
  3. Nhấn `Ctrl + Shift + B` (hoặc chọn menu **Build** $\rightarrow$ **Build Solution**).

- **Cách 2: Sử dụng dòng lệnh MSBuild**:
  ```cmd
  msbuild "KMDF Driver\WfpNetTrackerDriver\WfpNetTrackerDriver.vcxproj" /p:Configuration=Release /p:Platform=x64
  ```

**Kết quả sau khi build Driver tại `KMDF Driver\WfpNetTrackerDriver\x64\Release\WfpNetTrackerDriver\`: `**
- `WfpNetTrackerDriver.sys` (File thực thi Kernel-Mode Driver).
- `WfpNetTrackerDriver.inf` (File cấu hình cài đặt Driver).
- `WfpNetTrackerDriver.cer` (Chứng chỉ số tự ký dùng cho môi trường Test).
- `wfpnettrackerdriver.cat` (File danh mục bảo mật).

---

## 6. CÀI ĐẶT WINDOWS KERNEL DRIVER (.SYS)

Do Windows 64-bit bắt buộc kiểm tra chữ ký số Kernel (**Driver Signature Enforcement - DSE**), các driver tự build trong môi trường phát triển cần được kích hoạt chế độ kiểm thử (Test Mode) và nạp chứng chỉ.

### 6.1. Bật chế độ Test Signing trên Windows
Mở **Command Prompt** hoặc **PowerShell** với quyền **Run as Administrator**:
```cmd
:: 1. Bật cờ Testsigning trong Windows Boot Configuration Data
bcdedit /set testsigning on

:: 2. Khởi động lại máy tính để thay đổi có hiệu lực
shutdown /r /t 0
```

### 6.2. Cài đặt chứng chỉ số vào Trusted Root
Để Windows chấp nhận chữ ký số của file `.sys`, cài đặt tệp `.cer` đã sinh ra vào kho chứng chỉ máy cục bộ:
```cmd
certutil -addstore root "KMDF Driver\WfpNetTrackerDriver\x64\Release\WfpNetTrackerDriver.cer"
```

### 6.3. Quản trị dịch vụ Driver bằng Service Control Manager (`sc.exe`)
```cmd **Administrator**
:: 1. Tạo dịch vụ Driver
sc create WfpNetTrackerDriver type= kernel binPath= "C:\Users\Cuong\source\repos\Agent_CTA\KMDF Driver\WfpNetTrackerDriver\x64\Release\WfpNetTrackerDriver\WfpNetTrackerDriver.sys"

:: 2. Khởi động Driver
sc start WfpNetTrackerDriver

:: 3. Kiểm tra trạng thái hoạt động của Driver (Đảm bảo STATE: 4 RUNNING)
sc query WfpNetTrackerDriver

:: 4. Dừng dịch vụ Driver khi không sử dụng
sc stop WfpNetTrackerDriver

:: 5. Xóa bỏ đăng ký dịch vụ Driver khỏi hệ điều hành
sc delete WfpNetTrackerDriver
```

### 6.4. Cách cài đặt thay thế qua INF bằng `pnputil`
Ngoài `sc.exe`, có thể cài đặt Driver trực tiếp thông qua file INF:
```cmd
pnputil /add-driver "KMDF Driver\WfpNetTrackerDriver\x64\Release\WfpNetTrackerDriver\WfpNetTrackerDriver.inf" /install
```

---

## 7. HƯỚNG DẪN VẬN HÀNH

### 7.1. Chạy trên Linux

#### Bước 1: Khởi động Controller CTB (Terminal 1)
```bash
# Cú pháp: ./CTB [host] [port] [config_file] [log_file]
./build/CTB 0.0.0.0 9000 config.json ctb_alerts.log
```

#### Bước 2: Khởi động Agent CTA (Terminal 2)
```bash
# Cú pháp: sudo ./CTA [server_host] [server_port]
sudo ./build/CTA 127.0.0.1 9000
```

### 7.2. Chạy trên Windows

#### Bước 1: Khởi động Controller CTB (Terminal 1)
```cmd
cd build\Release
.\CTB.exe 0.0.0.0 9000 ..\..\config.json ctb_alerts.log
```

#### Bước 2: Khởi động Agent CTA (Terminal 2)
```cmd
cd build\Release
.\CTA.exe 127.0.0.1 9000
```
---

## 8. CẤU HÌNH

### 8.1. Cấu trúc file cấu hình `config.json`
```json
{
  "sampling_interval_ms": 1000,
  "thresholds": [
    {
      "process_name": "firefox",
      "cpu_percent": 50.0,
      "memory_mb": 2000.0,
      "disk_mb_s": 1.0,
      "network_kb_s": 100.0
    },
    {
      "process_name": "nginx",
      "cpu_percent": 30.0,
      "memory_mb": 512.0,
      "disk_mb_s": 10.0,
      "network_kb_s": 2048.0
    },
    {
      "process_name": "curl",
      "cpu_percent": 15.0,
      "memory_mb": 20.0,
      "disk_mb_s": 2.0,
      "network_kb_s": 1.0
    }
  ]
}
```

### 8.2. Cơ chế cập nhật
1. Khi file `config.json` được chỉnh sửa và lưu lại tại CTB, gói tin JSON cấu hình mới được gửi qua CTA.
2. CTA tiếp nhận cấu hình mới, cập nhật và lưu vào:
   - **Windows**: Registry `HKEY_CURRENT_USER\Software\CTA\ConfigJson`
   - **Linux**: File POSIX `~/.config/cta/config.json`
---

