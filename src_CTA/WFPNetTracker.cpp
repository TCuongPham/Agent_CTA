#include "WFPNetTracker.h"

#include <iostream>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <tcpestats.h>

#if defined(_MSC_VER)
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

namespace sysmon
{
    // Con trỏ hàm động cho Windows EStats API
    typedef ULONG (WINAPI *pfnGetPerTcpConnectionEStats)(
        PMIB_TCPROW Row,
        TCP_ESTATS_TYPE EstatsType,
        PUCHAR Rw, ULONG RwVersion, ULONG RwSize,
        PUCHAR Ros, ULONG RosVersion, ULONG RosSize,
        PUCHAR Rod, ULONG RodVersion, ULONG RodSize
    );

    typedef ULONG (WINAPI *pfnSetPerTcpConnectionEStats)(
        PMIB_TCPROW Row,
        TCP_ESTATS_TYPE EstatsType,
        PUCHAR Rw, ULONG RwVersion, ULONG RwSize,
        ULONG Offset
    );

    static HMODULE g_iphlpapi_mod = nullptr;
    static pfnGetPerTcpConnectionEStats g_pfnGetEStats = nullptr;
    static pfnSetPerTcpConnectionEStats g_pfnSetEStats = nullptr;

    WFPNetTracker::WFPNetTracker() = default;

    WFPNetTracker::~WFPNetTracker()
    {
        cleanup();
    }

    // Khởi tạo phiên kết nối tới Base Filtering Engine (BFE) của WFP
    bool WFPNetTracker::initialize()
    {
        FWPM_SESSION0 session{};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC; // Tự động dọn dẹp bộ lọc khi tiến trình kết thúc

        HANDLE engine = nullptr;
        DWORD result = FwpmEngineOpen0(
            nullptr,           // Local host
            RPC_C_AUTHN_WINNT, // Phương thức xác thực người dùng Windows
            nullptr,           // Dùng user credentials hiện tại
            &session,          // Cấu hình session
            &engine            // Con trỏ nhận engine handle
        );

        if (result != ERROR_SUCCESS)
        {
            std::cerr << "[WFPNetTracker] Không thể mở kết nối tới WFP Base Filtering Engine (BFE). (Mã lỗi: " 
                      << result << ", cần quyền Administrator)" << std::endl;
            is_available_ = false;
            return false;
        }

        engine_handle_ = engine;
        is_available_ = true;

        // Nạp động các hàm tính byte TCP EStats từ iphlpapi.dll
        if (!g_iphlpapi_mod)
        {
            g_iphlpapi_mod = LoadLibraryA("iphlpapi.dll");
            if (g_iphlpapi_mod)
            {
                g_pfnGetEStats = reinterpret_cast<pfnGetPerTcpConnectionEStats>(
                    GetProcAddress(g_iphlpapi_mod, "GetPerTcpConnectionEStats"));
                g_pfnSetEStats = reinterpret_cast<pfnSetPerTcpConnectionEStats>(
                    GetProcAddress(g_iphlpapi_mod, "SetPerTcpConnectionEStats"));
            }
        }

        std::cout << "[WFPNetTracker] Khởi tạo kết nối WFP Base Filtering Engine thành công!" << std::endl;
        return true;
    }

    // Đóng phiên kết nối WFP Engine
    void WFPNetTracker::cleanup()
    {
        if (engine_handle_ != nullptr)
        {
            FwpmEngineClose0(reinterpret_cast<HANDLE>(engine_handle_));
            engine_handle_ = nullptr;
        }
        is_available_ = false;
    }

    bool WFPNetTracker::isAvailable() const
    {
        return is_available_;
    }

    // Lấy tổng số byte mạng (In + Out) của một PID
    bool WFPNetTracker::getProcessNetworkBytes(uint32_t pid, uint64_t &out_total_bytes)
    {
        out_total_bytes = 0;
        if (!is_available_)
        {
            return false;
        }

        // 1. Lấy bảng TCP Connections kèm Owner PID
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0)
        {
            return false;
        }

        std::vector<BYTE> buffer(size);
        if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        {
            return false;
        }

        auto pTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        uint64_t total_bytes = 0;
        bool found = false;

        for (DWORD i = 0; i < pTable->dwNumEntries; ++i)
        {
            const auto &row = pTable->table[i];
            if (row.dwOwningPid == pid)
            {
                found = true;

                if (g_pfnGetEStats && g_pfnSetEStats)
                {
                    MIB_TCPROW tcpRow{};
                    tcpRow.dwState = row.dwState;
                    tcpRow.dwLocalAddr = row.dwLocalAddr;
                    tcpRow.dwLocalPort = row.dwLocalPort;
                    tcpRow.dwRemoteAddr = row.dwRemoteAddr;
                    tcpRow.dwRemotePort = row.dwRemotePort;

                    // Kích hoạt Data EStats nếu chưa được kích hoạt
                    TCP_BOOLEAN_OPTIONAL enableSetting = TcpBoolOptEnabled;
                    g_pfnSetEStats(
                        &tcpRow,
                        TcpConnectionEstatsData,
                        reinterpret_cast<PUCHAR>(&enableSetting),
                        0,
                        sizeof(enableSetting),
                        0);

                    // Đọc lượng dữ liệu truyền/nhận (InBytes + OutBytes)
                    TCP_ESTATS_DATA_ROD_v0 rodData{};
                    if (g_pfnGetEStats(
                            &tcpRow,
                            TcpConnectionEstatsData,
                            nullptr, 0, 0,
                            nullptr, 0, 0,
                            reinterpret_cast<PUCHAR>(&rodData), 0, sizeof(rodData)) == NO_ERROR)
                    {
                        total_bytes += rodData.DataBytesIn + rodData.DataBytesOut;
                    }
                }
            }
        }

        out_total_bytes = total_bytes;
        return found;
    }
}

#else
// Stub dự phòng cho Linux IDE để không bị gạch đỏ và không sinh log rác
namespace sysmon
{
    WFPNetTracker::WFPNetTracker() = default;
    WFPNetTracker::~WFPNetTracker() = default;
    bool WFPNetTracker::initialize() { return false; }
    void WFPNetTracker::cleanup() {}
    bool WFPNetTracker::isAvailable() const { return false; }
    bool WFPNetTracker::getProcessNetworkBytes(uint32_t, uint64_t &out_total_bytes) { out_total_bytes = 0; return false; }
}
#endif
