// File header dùng chung giữa Kernel Driver và User-Mode CTA định nghĩa mã lệnh IOCTL và struct trao đổi dữ liệu
#pragma once

#if defined(_KERNEL_MODE)
    // Trong Kernel Driver:
#include <ntddk.h>
#else
    // Trong User-Mode CTA (C++ Application)
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#endif
#include <stdint.h>
#endif

// Định nghĩa mã điều khiển IOCTL (Device Type 0x8000, Function 0x801)
#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED                 0
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS                 0
#endif
#ifndef FILE_DEVICE_NETWORK
#define FILE_DEVICE_NETWORK             0x00000012
#endif

// Tên thiết bị để User-mode mở kết nối qua CreateFile
#define NETMON_DEVICE_NAME        L"\\Device\\WfpNetTrackerDriver"
#define NETMON_DOS_DEVICE_NAME    L"\\DosDevices\\WfpNetTrackerDriver"
#define NETMON_USER_DEVICE_PATH_W L"\\\\.\\WfpNetTrackerDriver"
#define NETMON_USER_DEVICE_PATH_A "\\\\.\\WfpNetTrackerDriver"

// Mã IOCTL truy vấn thống kê byte theo PID (Device Type: FILE_DEVICE_NETWORK, Function: 0x801)
#define IOCTL_NETMON_GET_PID_STATS \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Dữ liệu thống kê mạng trả về cho mỗi PID
#pragma pack(push, 1)
typedef struct _NET_STATS_RECORD {
    unsigned __int64 rx_bytes; // Byte tải về (Download)
    unsigned __int64 tx_bytes; // Byte tải lên (Upload)
} NET_STATS_RECORD, *PNET_STATS_RECORD;
#pragma pack(pop)