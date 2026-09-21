# HỆ THỐNG GIÁM SÁT TÀI NGUYÊN TIẾN TRÌNH: CTA & CTB
> **Chương trình CTA (Agent/Monitor)** & **Chương trình CTB (Controller/Logger)**  
> Ngôn ngữ: **C++17** | Kiến trúc: **Hướng đối tượng (OOP - Clean Architecture)** | Nền tảng: **Windows & Linux**

---

## 1. TỔNG QUAN DỰ ÁN

Hệ thống được thiết kế theo mô hình **Agent - Controller** tối ưu hóa hiệu năng, giao tiếp qua cơ chế **OS Native IPC** và sử dụng hoàn toàn **Native API** của hệ điều hành:

```
+-------------------------------------------------------------------------+
|                                CTB                                      |
|            (Controller / Config Provider / Event Logger)                |
+-------------------------------------------------------------------------+
          | Gửi cấu hình JSON                          ^ Nhận cảnh báo
          v                                            | (log vượt ngưỡng)
======================== [ OS Native IPC ] ================================
  (Windows: Named Pipes \\.\pipe\cta_ipc  |  Linux: Unix Socket /tmp/cta.sock)
===========================================================================
          |                                            |
          v                                            |
+-------------------------------------------------------------------------+
|                                CTA                                      |
|                       (Core Engine / Daemon)                            |
|                                                                         |
|  +---------------------+   +--------------------+   +----------------+  |
|  | IConfigStorage      |   | IProcessMonitor    |   | EventQueue     |  |
|  | (Registry / File)   |   | (Win32 / /proc)    |   | (Thread-safe   |  |
|  | Fallback tự động    |   | CPU, RAM, Disk, Net|   | Offline Buffer)|  |
|  +---------------------+   +--------------------+   +----------------+  |
+-------------------------------------------------------------------------+
```

### Chức năng chính:
1. **CTA (Monitoring Agent)**:
   - Chạy ngầm định kỳ thu thập tài nguyên (`CPU %`, `Memory MB`, `Disk MB/s`, `Network KB/s`) của các tiến trình được chỉ định.
   - Nhận cấu hình từ CTB. Nếu CTB không gửi cấu hình mới (hoặc khi CTB tắt), tự động nạp cấu hình cũ từ **Registry (Windows)** hoặc **Config File (Linux)**.
   - Phát hiện các chỉ số vượt ngưỡng trần và bắn cảnh báo về CTB.
   - Tích hợp **Hàng đợi ngoại tuyến (Offline Event Queue)**: Khi CTB chưa chạy hoặc mất kết nối, toàn bộ sự kiện được lưu an toàn trong hàng đợi. Ngay khi CTB online trở lại, CTA tự động rút cạn (flush) toàn bộ log tồn đọng sang CTB.
2. **CTB (Manager / Logger)**:
   - Gửi danh sách cấu hình tiến trình và ngưỡng giám sát dạng JSON sang CTA.
   - Nhận các sự kiện cảnh báo từ CTA và ghi ra file log theo đúng định dạng:
     `date time, process id, process name, type (cpu/memory/disk/network), value`

---

## 2. CÂY THƯ MỤC CHI TIẾT (PROJECT DIRECTORY STRUCTURE)

Dự án sử dụng **1 codebase duy nhất với Lớp trừu tượng (Interface Layer)** và quản lý biên dịch độc lập theo từng OS qua **CMake**:

```text
CTA/
├── .gitignore                      # Bộ lọc bỏ file rác, file build, binaries, logs
├── CMakeLists.txt                  # Script CMake tự động nhận diện OS và cấu hình target
├── README.md                       # Tài liệu hướng dẫn chi tiết hệ thống
│
├── include/                        # GIAO DIỆN TRỪU TƯỢNG VÀ CORE MODELS (Cross-platform)
│   ├── ConfigModel.h               # Structs: ProcessThreshold, MonitorConfig, EventRecord
│   ├── IConfigStorage.h            # Interface lưu trữ cấu hình (Registry / File)
│   ├── IProcessMonitor.h           # Interface thu thập metrics phần cứng của tiến trình
│   ├── IIPCChannel.h               # Interface kênh truyền IPC 2 chiều (Server/Client)
│   ├── EventQueue.h                # Hàng đợi Thread-safe bảo vệ dữ liệu khi CTB offline
│   ├── CTACore.h                   # Động cơ điều phối giám sát, so khớp ngưỡng
│   └── CTBClient.h                 # Module CTB: gửi config, nhận event và ghi log
│
├── src/                            # HIỆN THỰC LOGIC DÙNG CHUNG (C++17 Standard)
│   ├── main_cta.cpp                # Entry point của tiến trình CTA
│   ├── CTACore.cpp                 # Quản lý chu kỳ lấy mẫu, so sánh ngưỡng, kích hoạt event
│   ├── EventQueue.cpp              # Hiện thực Ring Buffer Thread-safe bảo vệ chống tràn RAM
│   │
│   ├── windows/                    # HIỆN THỰC OS NATIVE API CHO WINDOWS (Chỉ build trên Win)
│   │   ├── WindowsProcessMonitor.h/.cpp # Win32: Toolhelp32, PSAPI, IPHlpAPI
│   │   ├── WindowsRegistryStorage.h/.cpp# Win32 Registry (HKEY_CURRENT_USER\Software\CTA)
│   │   └── WindowsNamedPipe.h/.cpp      # Win32 Named Pipes (\\.\pipe\cta_ctb_pipe)
│   │
│   └── linux/                      # HIỆN THỰC OS NATIVE API CHO LINUX (Chỉ build trên Linux)
│       ├── LinuxProcessMonitor.h/.cpp   # POSIX: /proc/[pid]/stat, status, io, net
│       ├── LinuxFileStorage.h/.cpp      # POSIX File I/O (~/.config/cta/config.json)
│       └── LinuxUnixSocket.h/.cpp       # POSIX Unix Domain Socket (/tmp/cta_ctb.sock)
│
├── ctb/                            # TIẾN TRÌNH CTB (CONTROLLER & LOGGER)
│   └── main_ctb.cpp                # Entry point CTB: gửi config JSON, lắng nghe & ghi file log
│
└── third_party/                    # THƯ VIỆN BÊN THỨ 3 (HEADER-ONLY SIÊU NHẸ)
    └── json.hpp                    # nlohmann/json: Header-only C++ JSON parser chuẩn mực
```

---

## 3. CÔNG NGHỆ VÀ THƯ VIỆN SỬ DỤNG

### 3.1. Ngôn ngữ & Tiêu chuẩn lập trình
- **C++17**: Chuẩn ngôn ngữ tối ưu, an toàn, hỗ trợ `std::filesystem`, `std::optional`, `std::string_view`, structured binding, `std::scoped_lock`.
- **Nguyên tắc an toàn (Safe Modern C++)**:
  - Không sử dụng con trỏ trần (`raw pointer`) quản lý tài nguyên.
  - Sử dụng **RAII (Resource Acquisition Is Initialization)** cho mọi handle, socket, file descriptor và thread lock.
  - Tuyệt đối không dùng các hàm C không an toàn (`strcpy`, `sprintf`, `gets`...). Dùng `std::string`, `std::stringstream`, `snprintf`.
  - Quản lý đồng thời an toàn (Thread Safety) bằng `std::mutex`, `std::condition_variable`, `std::atomic<bool>`.

### 3.2. Hệ thống Build
- **CMake (>= 3.16)**: Hệ thống sinh build script tự động.
  - Nhận diện hệ điều hành mục tiêu qua biến `WIN32` hoặc `UNIX`.
  - Chỉ biên dịch các file nguồn tương ứng của hệ điều hành đó (Zero overhead, không bị lẫn thư viện).

### 3.3. Thư viện sử dụng
- **C++ Standard Library (STL)**: Toàn bộ cấu trúc dữ liệu (`vector`, `queue`, `unordered_map`, `thread`, `chrono`).
- **Thư viện JSON**: `nlohmann/json` (Header-only, single-file `json.hpp`). Không cần cài đặt thư viện ngoài, độc lập nền tảng, an toàn bộ nhớ.
- **Không dùng framework nặng**: Không dùng Boost, Qt hay các runtime cồng kềnh, đảm bảo dung lượng binary nhẹ nhất và tiêu thụ RAM cực thấp (< 10-20 MB).

---

## 4. BẢNG CHI TIẾT CÁC OS NATIVE API ĐƯỢC ÁP DỤNG

| Hạng mục | Windows Native API (Win32 / SDK) | Linux Native API (POSIX / `/proc`) |
| :--- | :--- | :--- |
| **Duyệt Process** | `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW` | Duyệt thư mục `/proc`, đọc `/proc/[pid]/comm` hoặc `cmdline` |
| **Đo CPU (%)** | `OpenProcess`, `GetProcessTimes`, `GetSystemTimes` | Đọc `/proc/[pid]/stat` (`utime`, `stime`), `/proc/stat` (CPU ticks) |
| **Đo RAM (MB)** | `GetProcessMemoryInfo` $\rightarrow$ `pmc.WorkingSetSize` | Đọc `/proc/[pid]/status` (`VmRSS`) hoặc `/proc/[pid]/statm` |
| **Đo Disk I/O (MB/s)** | `GetProcessIoCounters` $\rightarrow$ `ReadTransferCount + WriteTransferCount` | Đọc `/proc/[pid]/io` $\rightarrow$ `read_bytes + write_bytes` |
| **Đo Network (KB/s)**| `GetExtendedTcpTable`, `GetExtendedUdpTable` (IP Helper API) | Mapping Socket Inode từ `/proc/[pid]/fd/` và `/proc/net/tcp` |
| **Lưu trữ Cấu hình** | Windows Registry: `RegCreateKeyExW`, `RegSetValueExW`, `RegQueryValueExW` | File I/O POSIX: Đường dẫn `~/.config/cta/config.json` |
| **Kênh truyền IPC** | **Named Pipes**: `CreateNamedPipeW`, `ConnectNamedPipe`, `ReadFile`, `WriteFile` | **Unix Domain Sockets**: `socket(AF_UNIX)`, `bind`, `listen`, `accept`, `connect` |

---

## 5. PHƯƠNG PHÁP & THUẬT TOÁN ĐO LƯỜNG TÀI NGUYÊN

### 5.1. Thuật toán tính CPU (%)
CPU là giá trị biến thiên theo thời gian, được tính dựa trên độ lệch thời gian thực thi của tiến trình chia cho tổng thời gian trôi qua của toàn hệ thống trong khoảng thời gian $\Delta t$:

$$\text{CPU \%} = \frac{\Delta (\text{KernelTime} + \text{UserTime})}{\Delta \text{TotalSystemTime}} \times 100\% \times N_{\text{cores}}$$

- Trên **Windows**: Tính hiệu số giữa 2 lần gọi `GetProcessTimes` chia cho hiệu số giữa 2 lần gọi `GetSystemTimes`.
- Trên **Linux**: Tính hiệu số giữa `(utime + stime)` trong `/proc/[pid]/stat` chia cho tổng ticks CPU hệ thống trong `/proc/stat`.

### 5.2. Thuật toán tính Memory (MB)
Đo lượng RAM vật lý thực tế mà hệ điều hành cấp phát cho tiến trình (*Resident / Working Set*):
- Trên **Windows**: $\text{Memory (MB)} = \frac{\text{WorkingSetSize}}{1024 \times 1024}$
- Trên **Linux**: $\text{Memory (MB)} = \frac{\text{VmRSS (kB)}}{1024}$

### 5.3. Thuật toán tính Disk I/O (MB/s)
Đo tổng lượng dữ liệu đọc và ghi xuống ổ đĩa trên một giây:

$$\text{Disk Rate (MB/s)} = \frac{\Delta \text{ReadBytes} + \Delta \text{WriteBytes}}{\Delta t \times 1024 \times 1024}$$

### 5.4. Thuật toán tính Network I/O (KB/s)
Đo lưu lượng dữ liệu truyền nhận qua socket của tiến trình trên một giây:

$$\text{Network Rate (KB/s)} = \frac{\Delta \text{BytesSent} + \Delta \text{BytesRecv}}{\Delta t \times 1024}$$

---

## 6. THIẾT KẾ ĐẢM BẢO YÊU CẦU PHI CHỨC NĂNG

### 6.1. Tối ưu CPU (< 5%)
- **Chu kỳ lấy mẫu (Sampling Interval)**: 1000ms (1 giây). Tuyệt đối không dùng vòng lặp bận (busy-wait loop).
- **Lọc thông minh (Targeted Filtering)**: Chỉ mở process handle / đọc chi tiết `/proc/[pid]/...` đối với các tiến trình có tên nằm trong danh sách cấu hình. Không quét sâu toàn bộ hàng trăm tiến trình của OS.

### 6.2. Tối ưu Memory (< 100 MB)
- **Ring Buffer giới hạn**: Hàng đợi offline `EventQueue` được khống chế số lượng phần tử tối đa (ví dụ 20,000 sự kiện $\approx$ 3–5 MB RAM).
- Tránh cấp phát động liên tục trong vòng lặp chính (`reserve` dung lượng trước cho vector).

### 6.3. Khả năng chịu lỗi & Chống mất dữ liệu (Fault Tolerance)
- Khi CTB không chạy: CTA tự động lưu sự kiện vào `EventQueue` (Thread-safe, bảo vệ bằng mutex).
- Khi CTB khởi động lại: CTA bắt sự kiện kết nối thành công, lập tức gửi toàn bộ sự kiện trong hàng đợi sang CTB theo thứ tự thời gian (FIFO).

---

## 7. HƯỚNG DẪN BIÊN DỊCH VÀ VẬN HÀNH

### 7.1. Trên Linux (Ubuntu / Debian / CentOS / Fedora)
Yêu cầu: `cmake >= 3.16`, `g++ >= 9` hoặc `clang++ >= 10`.

```bash
# 1. Tạo thư mục build
mkdir -p build && cd build

# 2. Sinh Makefile qua CMake
cmake ..

# 3. Biên dịch chương trình
cmake --build . -j$(nproc)

# Kết quả sinh ra 2 file thực thi:
# ./CTA  (Chương trình giám sát)
# ./CTB  (Chương trình quản lý & ghi log)

# 4. Chạy thử nghiệm
# Terminal 1: Chạy CTA trước (CTA tự nạp cấu hình cũ hoặc chờ cấu hình)
./CTA

# Terminal 2: Chạy CTB để đẩy cấu hình và hứng log
./CTB
```

### 7.2. Trên Windows (Visual Studio / MSVC / MinGW)
Yêu cầu: Visual Studio 2019/2022 (với C++ Desktop Development) hoặc MinGW-w64.

```cmd
:: 1. Mở "Developer Command Prompt for VS"
mkdir build
cd build

:: 2. Cấu hình với CMake
cmake .. -G "Visual Studio 17 2022" -A x64

:: 3. Biên dịch Release
cmake --build . --config Release

:: Kết quả sinh ra:
:: Release\CTA.exe
:: Release\CTB.exe
```
