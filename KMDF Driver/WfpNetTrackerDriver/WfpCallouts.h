// Khai báo các hàm xử lý gói tin của WFP và bảng lưu trữ PID

#pragma once

#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable: 4201)
#pragma warning(disable: 4214)
#define NDIS_SUPPORT_NDIS6 1
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#pragma warning(pop)
#pragma comment(lib, "fwpkclnt.lib")
#include "CommonIoctl.h"

// Context gắn vào mỗi luồng kết nối mạng (Flow) để lưu PID
typedef struct _FLOW_CONTEXT {
    UINT32 processId;
} FLOW_CONTEXT, * PFLOW_CONTEXT;

// Node trong bảng thống kê mạng theo PID (Linked List có SpinLock bảo vệ)
typedef struct _PID_NET_ENTRY {
    UINT32 processId;
    UINT64 rx_bytes;
    UINT64 tx_bytes;
    LIST_ENTRY listEntry;
} PID_NET_ENTRY, * PPID_NET_ENTRY;

// Khởi tạo và dọn dẹp WFP Callouts
NTSTATUS WfpRegisterCallouts(PDEVICE_OBJECT deviceObject);
VOID WfpUnregisterCallouts(VOID);

// Thêm byte vào bảng thống kê cho PID
VOID AddNetStats(UINT32 processId, UINT64 rx, UINT64 tx);

// Lấy thông số byte của một PID (IOCTL)
BOOLEAN GetNetStatsForPid(UINT32 processId, PNET_STATS_RECORD outStats);