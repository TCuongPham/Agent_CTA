#pragma once

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#endif
#include <cstdint>

// Tên thiết bị ảo để User-mode (CTA) mở handle kết nối tới Driver
#define WFP_DEVICE_NAME_L         L"\\Device\\WfpNetTrackerDriver"
#define WFP_DOS_DEVICE_NAME_L     L"\\DosDevices\\WfpNetTrackerDriver"
#define WFP_USER_DEVICE_NAME_A    "\\\\.\\WfpNetTrackerDriver"
#define WFP_USER_DEVICE_NAME_W    L"\\\\.\\WfpNetTrackerDriver"

// Định nghĩa mã điều khiển IOCTL (Device I/O Control Code)
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#ifndef FILE_DEVICE_NETWORK
#define FILE_DEVICE_NETWORK       0x00000012
#endif
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED           0
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS           0GetNetStatsForPid
#endif

// Mã IOCTL truy vấn byte mạng của một PID
#define IOCTL_WFP_GET_PROCESS_BYTES \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Dữ liệu trao đổi giữa Driver và CTA
#pragma pack(push, 1)
struct WFP_PROCESS_NET_STATS
{
    uint64_t rx_bytes; // Số byte tải về (Inbound)
    uint64_t tx_bytes; // Số byte tải lên (Outbound)
};
#pragma pack(pop)
