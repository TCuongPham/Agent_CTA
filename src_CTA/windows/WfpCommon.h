#pragma once

#if defined(_WIN32)
#include <windows.h>
#else
#include <cstdint>
#endif

// Tên thiết bị ảo để User-mode (CTA) mở handle kết nối tới Driver
#define WFP_DEVICE_NAME_L         L"\\Device\\WfpNetTracker"
#define WFP_DOS_DEVICE_NAME_L     L"\\DosDevices\\WfpNetTracker"
#define WFP_USER_DEVICE_NAME_A    "\\\\.\\WfpNetTracker"

// Định nghĩa mã điều khiển IOCTL (Device I/O Control Code)
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#define FILE_DEVICE_NETWORK             0x00000012
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0

#define IOCTL_WFP_GET_PROCESS_BYTES \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Dữ liệu trao đổi giữa Driver và CTA cho từng PID
#pragma pack(push, 1)
struct WFP_PROCESS_NET_STATS
{
    uint32_t pid;
    uint64_t rx_bytes; // Số byte tải về (Inbound)
    uint64_t tx_bytes; // Số byte tải lên (Outbound)
};
#pragma pack(pop)
