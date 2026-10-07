#include "WFPNetTracker.h"
#include "windows/WfpCommon.h"

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
    // Con trỏ hàm động cho Windows EStats API (for fallback mode)
    typedef ULONG(WINAPI *pfnGetPerTcpConnectionEStats)(
        PMIB_TCPROW Row,
        TCP_ESTATS_TYPE EstatsType,
        PUCHAR Rw, ULONG RwVersion, ULONG RwSize,
        PUCHAR Ros, ULONG RosVersion, ULONG RosSize,
        PUCHAR Rod, ULONG RodVersion, ULONG RodSize);

    typedef ULONG(WINAPI *pfnSetPerTcpConnectionEStats)(
        PMIB_TCPROW Row,
        TCP_ESTATS_TYPE EstatsType,
        PUCHAR Rw, ULONG RwVersion, ULONG RwSize,
        ULONG Offset);

    static HMODULE g_iphlpapi_mod = nullptr;
    static pfnGetPerTcpConnectionEStats g_pfnGetEStats = nullptr;
    static pfnSetPerTcpConnectionEStats g_pfnSetEStats = nullptr;

    static void initFallbackEStats()
    {
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
    }

    WFPNetTracker::WFPNetTracker() = default;

    WFPNetTracker::~WFPNetTracker()
    {
        cleanup();
    }

    // Khoi tao phien ket noi toi Base Filtering Engine (BFE) cua WFP
    bool WFPNetTracker::initialize()
    {
        initFallbackEStats();

        HANDLE hDriver = CreateFileA(
            WFP_USER_DEVICE_NAME_A,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (hDriver != INVALID_HANDLE_VALUE)
        {
            driver_handle_ = hDriver;
            is_driver_connected_ = true;
            is_available_ = true;
            std::cout << "[WFPNetTracker] Da ket noi thanh cong toi WFP Kernel Driver! (Kernel-level monitoring)" << std::endl;
            return true;
        }

        // 2. Fallback: Neu Kernel Driver chua duoc cai/nap, chuyen sang User-Mode EStats
        DWORD err = GetLastError();
        driver_handle_ = nullptr;
        is_driver_connected_ = false;
        std::cout << "[WFPNetTracker] WFP Kernel Driver khong mo duoc (Ma loi: " << err
                  << "). Tu dong chuyen sang User-Mode (TCP EStats)." << std::endl;
        is_available_ = true;
        return true;
    }

    // Dong phien ket noi WFP Engine
    void WFPNetTracker::cleanup()
    {
        if (driver_handle_ != nullptr && driver_handle_ != INVALID_HANDLE_VALUE)
        {
            CloseHandle(static_cast<HANDLE>(driver_handle_));
            driver_handle_ = nullptr;
        }
        is_driver_connected_ = false;
        is_available_ = false;
    }

    bool WFPNetTracker::isAvailable() const
    {
        return is_available_;
    }

    bool WFPNetTracker::isKernelDriverActive() const
    {
        return is_driver_connected_;
    }

    // Lay tong so byte mang (In + Out) cua mot PID
    bool WFPNetTracker::getProcessNetworkRxTx(uint32_t pid, uint64_t &out_rx_bytes, uint64_t &out_tx_bytes)
    {
        out_rx_bytes = 0;
        out_tx_bytes = 0;
        if (!is_available_)
        {
            return false;
        }

        bool driver_ok = false;

        // --- NHANH 1: Su dung WFP Kernel Driver qua IOCTL ---
        if (is_driver_connected_ && driver_handle_ != nullptr)
        {
            uint32_t target_pid = pid;
            WFP_PROCESS_NET_STATS stats{};
            DWORD bytes_returned = 0;
            BOOL ok = DeviceIoControl(
                static_cast<HANDLE>(driver_handle_),
                IOCTL_WFP_GET_PROCESS_BYTES,
                &target_pid,
                sizeof(target_pid),
                &stats,
                sizeof(stats),
                &bytes_returned,
                nullptr);
            if (!ok)
            {
                // Thu ma lenh IOCTL phu (ALT)
                ok = DeviceIoControl(
                    static_cast<HANDLE>(driver_handle_),
                    IOCTL_WFP_GET_PROCESS_BYTES_ALT,
                    &target_pid,
                    sizeof(target_pid),
                    &stats,
                    sizeof(stats),
                    &bytes_returned,
                    nullptr);
            }
            if (ok && bytes_returned >= sizeof(WFP_PROCESS_NET_STATS))
            {
                out_rx_bytes = stats.rx_bytes;
                out_tx_bytes = stats.tx_bytes;
                driver_ok = true;
                if (out_rx_bytes > 0 || out_tx_bytes > 0)
                {
                    return true;
                }
            }
        }

        // --- NHANH 2: Fallback User-Mode (TCP EStats) ---
        // Neu Driver chua ghi nhan duoc byte nao, kiem tra them bang TCP EStats
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size > 0)
        {
            std::vector<BYTE> buffer(size);
            if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                auto pTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
                bool found = false;
                uint64_t estat_rx = 0;
                uint64_t estat_tx = 0;

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
                            TCP_BOOLEAN_OPTIONAL enableSetting = TcpBoolOptEnabled;
                            g_pfnSetEStats(
                                &tcpRow,
                                TcpConnectionEstatsData,
                                reinterpret_cast<PUCHAR>(&enableSetting),
                                0,
                                sizeof(enableSetting),
                                0);
                            TCP_ESTATS_DATA_ROD_v0 rodData{};
                            if (g_pfnGetEStats(
                                    &tcpRow,
                                    TcpConnectionEstatsData,
                                    nullptr, 0, 0,
                                    nullptr, 0, 0,
                                    reinterpret_cast<PUCHAR>(&rodData), 0, sizeof(rodData)) == NO_ERROR)
                            {
                                estat_rx += rodData.DataBytesIn;
                                estat_tx += rodData.DataBytesOut;
                            }
                        }
                    }
                }
                if (found)
                {
                    if (estat_rx > out_rx_bytes) out_rx_bytes = estat_rx;
                    if (estat_tx > out_tx_bytes) out_tx_bytes = estat_tx;
                    return true;
                }
            }
        }

        return driver_ok;
    }
    bool WFPNetTracker::getProcessNetworkBytes(uint32_t pid, uint64_t &out_total_bytes)
    {
        uint64_t rx = 0;
        uint64_t tx = 0;
        bool ok = getProcessNetworkRxTx(pid, rx, tx);
        out_total_bytes = rx + tx;
        return ok;
    }
}
#else
// Stub dự phòng cho Linux IDE
namespace sysmon
{
    WFPNetTracker::WFPNetTracker() = default;
    WFPNetTracker::~WFPNetTracker() = default;
    bool WFPNetTracker::initialize() { return false; }
    void WFPNetTracker::cleanup() {}
    bool WFPNetTracker::isAvailable() const { return false; }
    bool WFPNetTracker::getProcessNetworkBytes(uint32_t, uint64_t &out_total_bytes)
    {
        out_total_bytes = 0;
        return false;
    }
}
#endif
