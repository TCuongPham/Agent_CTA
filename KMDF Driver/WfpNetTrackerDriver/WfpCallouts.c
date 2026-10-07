#include <ntddk.h>
#include <initguid.h>
#include "WfpCallouts.h"

// =========================================================================
// GUIDs cho các Callout IPv4
// =========================================================================

// {E425686F-6B22-4D3C-8DE2-B37D427D6B10}
DEFINE_GUID(WFP_ALE_FLOW_ESTABLISHED_V4_CALLOUT_GUID,
    0xe425686f, 0x6b22, 0x4d3c, 0x8d, 0xe2, 0xb3, 0x7d, 0x42, 0x7d, 0x6b, 0x10);

// {B912C092-23E4-4345-9854-C3B24F5D7B20}
DEFINE_GUID(WFP_STREAM_V4_CALLOUT_GUID,
    0xb912c092, 0x23e4, 0x4345, 0x98, 0x54, 0xc3, 0xb2, 0x4f, 0x5d, 0x7b, 0x20);

// {68C2224A-4927-4D3F-B5E3-A57EFE6B1B82}
DEFINE_GUID(WFP_DATAGRAM_V4_CALLOUT_GUID,
    0x68c2224a, 0x4927, 0x4d3f, 0xb5, 0xe3, 0xa5, 0x7e, 0xfe, 0x6b, 0x1b, 0x82);

// =========================================================================
// GUIDs cho các Callout IPv6
// =========================================================================

// {4B0870F7-33D9-482A-A9E9-74D7522D4C01}
DEFINE_GUID(WFP_ALE_FLOW_ESTABLISHED_V6_CALLOUT_GUID,
    0x4b0870f7, 0x33d9, 0x482a, 0xa9, 0xe9, 0x74, 0xd7, 0x52, 0x2d, 0x4c, 0x01);

// {C7F5518B-59D8-4F24-9B24-5D51DCF87802}
DEFINE_GUID(WFP_STREAM_V6_CALLOUT_GUID,
    0xc7f5518b, 0x59d8, 0x4f24, 0x9b, 0x24, 0x5d, 0x51, 0xdc, 0xf8, 0x78, 0x02);

// {F9A803A6-8C44-48EE-A9EB-1B1567DB6203}
DEFINE_GUID(WFP_DATAGRAM_V6_CALLOUT_GUID,
    0xf9a803a6, 0x8c44, 0x48ee, 0xa9, 0xeb, 0x1b, 0x15, 0x67, 0xdb, 0x62, 0x03);

// =========================================================================
// GUID Sublayer của Driver
// =========================================================================

// {D803697E-5A23-4A47-9344-486E76775533}
DEFINE_GUID(WFP_NET_TRACKER_SUBLAYER_GUID,
    0xd803697e, 0x5a23, 0x4a47, 0x93, 0x44, 0x48, 0x6e, 0x76, 0x77, 0x55, 0x33);

// =========================================================================
// GUIDs cho các Filter IPv4
// =========================================================================

// {3CE7BC01-B12E-41F6-82B5-177DDF729D01}
DEFINE_GUID(WFP_ALE_FLOW_ESTABLISHED_V4_FILTER_GUID,
    0x3ce7bc01, 0xb12e, 0x41f6, 0x82, 0xb5, 0x17, 0x7d, 0xdf, 0x72, 0x9d, 0x01);

// {745E6135-2B8C-476F-B955-46D93D716612}
DEFINE_GUID(WFP_STREAM_V4_FILTER_GUID,
    0x745e6135, 0x2b8c, 0x476f, 0xb9, 0x55, 0x46, 0xd9, 0x3d, 0x71, 0x66, 0x12);

// {86E3C0F5-85A3-40B1-949A-03E261A72F67}
DEFINE_GUID(WFP_DATAGRAM_V4_FILTER_GUID,
    0x86e3c0f5, 0x85a3, 0x40b1, 0x94, 0x9a, 0x03, 0xe2, 0x61, 0xa7, 0x2f, 0x67);

// =========================================================================
// GUIDs cho các Filter IPv6
// =========================================================================

// {6D2A7153-0668-4720-BD7F-34CA59441204}
DEFINE_GUID(WFP_ALE_FLOW_ESTABLISHED_V6_FILTER_GUID,
    0x6d2a7153, 0x0668, 0x4720, 0xbd, 0x7f, 0x34, 0xca, 0x59, 0x44, 0x12, 0x04);

// {8A58EC9D-7DB0-4731-8F3B-FA1EA944F205}
DEFINE_GUID(WFP_STREAM_V6_FILTER_GUID,
    0x8a58ec9d, 0x7db0, 0x4731, 0x8f, 0x3b, 0xfa, 0x1e, 0xa9, 0x44, 0xf2, 0x05);

// {31A293F0-4FC7-4566-A36C-94191316B206}
DEFINE_GUID(WFP_DATAGRAM_V6_FILTER_GUID,
    0x31a293f0, 0x4fc7, 0x4566, 0xa3, 0x6c, 0x94, 0x19, 0x13, 0x16, 0xb2, 0x06);

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

static HANDLE g_engineHandle = NULL;

// Callout IDs trả về từ FwpsCalloutRegister0
static UINT32 g_flowEstablishedCalloutIdV4 = 0;
static UINT32 g_flowEstablishedCalloutIdV6 = 0;
static UINT32 g_streamCalloutIdV4 = 0;
static UINT32 g_streamCalloutIdV6 = 0;
static UINT32 g_datagramCalloutIdV4 = 0;
static UINT32 g_datagramCalloutIdV6 = 0;

// Filter IDs trả về từ FwpmFilterAdd0
static UINT64 g_aleFilterIdV4 = 0;
static UINT64 g_aleFilterIdV6 = 0;
static UINT64 g_streamFilterIdV4 = 0;
static UINT64 g_streamFilterIdV6 = 0;
static UINT64 g_datagramFilterIdV4 = 0;
static UINT64 g_datagramFilterIdV6 = 0;

static LIST_ENTRY g_statsListHead;
static KSPIN_LOCK g_statsLock;

// Forward declarations
VOID NTAPI AleFlowEstablishedClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID NTAPI StreamClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID NTAPI DatagramClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID NTAPI FlowDeleteNotify(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext);

NTSTATUS NTAPI CalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter);

// Thêm byte vào bảng thống kê cho PID
VOID AddNetStats(UINT32 processId, UINT64 rx, UINT64 tx)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_statsLock, &lockHandle);

    PLIST_ENTRY curr = g_statsListHead.Flink;
    PPID_NET_ENTRY targetEntry = NULL;

    while (curr != &g_statsListHead) {
        PPID_NET_ENTRY entry = CONTAINING_RECORD(curr, PID_NET_ENTRY, listEntry);
        if (entry->processId == processId) {
            targetEntry = entry;
            break;
        }
        curr = curr->Flink;
    }

    if (targetEntry) {
        targetEntry->rx_bytes += rx;
        targetEntry->tx_bytes += tx;
    }
    else {
        targetEntry = (PPID_NET_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PID_NET_ENTRY), 'ptcW');
        if (targetEntry) {
            targetEntry->processId = processId;
            targetEntry->rx_bytes = rx;
            targetEntry->tx_bytes = tx;
            InsertTailList(&g_statsListHead, &targetEntry->listEntry);
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

// Lấy thông số byte của một PID (IOCTL)
BOOLEAN GetNetStatsForPid(UINT32 processId, PNET_STATS_RECORD outStats)
{
    if (outStats == NULL) {
        return FALSE;
    }

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_statsLock, &lockHandle);

    PLIST_ENTRY curr = g_statsListHead.Flink;
    BOOLEAN found = FALSE;

    while (curr != &g_statsListHead) {
        PPID_NET_ENTRY entry = CONTAINING_RECORD(curr, PID_NET_ENTRY, listEntry);
        if (entry->processId == processId) {
            outStats->rx_bytes = entry->rx_bytes;
            outStats->tx_bytes = entry->tx_bytes;
            found = TRUE;
            break;
        }
        curr = curr->Flink;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return found;
}

// 1. Callout ALE: Bắt thời điểm kết nối được thiết lập (IPv4 & IPv6) để lấy PID và gán context vào Flow
VOID NTAPI AleFlowEstablishedClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Cho phép lưu lượng tiếp tục qua các filter khác (Windows Firewall,...)
    if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    if (inMetaValues != NULL &&
        FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID) &&
        FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE))
    {
        UINT64 processId = inMetaValues->processId;
        UINT64 flowId = inMetaValues->flowHandle;
        UINT16 layerId = inFixedValues->layerId;
        UINT8 ipProtocol = 0;

        if (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4) {
            ipProtocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
        }
        else if (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6) {
            ipProtocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;
        }

        PFLOW_CONTEXT ctx = (PFLOW_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FLOW_CONTEXT), 'fCtx');
        if (ctx != NULL) {
            ctx->processId = (UINT32)processId;

            NTSTATUS status = STATUS_NOT_SUPPORTED;
            if (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4) {
                if (ipProtocol == IPPROTO_TCP) {
                    status = FwpsFlowAssociateContext0(flowId, FWPS_LAYER_STREAM_V4, g_streamCalloutIdV4, (UINT64)ctx);
                }
                else if (ipProtocol == IPPROTO_UDP) {
                    status = FwpsFlowAssociateContext0(flowId, FWPS_LAYER_DATAGRAM_DATA_V4, g_datagramCalloutIdV4, (UINT64)ctx);
                }
            }
            else if (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6) {
                if (ipProtocol == IPPROTO_TCP) {
                    status = FwpsFlowAssociateContext0(flowId, FWPS_LAYER_STREAM_V6, g_streamCalloutIdV6, (UINT64)ctx);
                }
                else if (ipProtocol == IPPROTO_UDP) {
                    status = FwpsFlowAssociateContext0(flowId, FWPS_LAYER_DATAGRAM_DATA_V6, g_datagramCalloutIdV6, (UINT64)ctx);
                }
            }

            if (!NT_SUCCESS(status)) {
                // Tránh memory leak nếu gán context thất bại hoặc giao thức khác
                ExFreePoolWithTag(ctx, 'fCtx');
            }
        }
    }
}

// 2. Callout STREAM: Bắt trực tiếp dòng byte dữ liệu TCP (IPv4 & IPv6) để cộng dồn byte theo chiều IN/OUT
VOID NTAPI StreamClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(filter);

    if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    PFLOW_CONTEXT ctx = (PFLOW_CONTEXT)flowContext;
    FWPS_STREAM_CALLOUT_IO_PACKET0* packet = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;

    if (ctx != NULL && packet != NULL && packet->streamData != NULL) {
        SIZE_T byteLength = packet->streamData->dataLength;
        if (byteLength > 0) {
            // Kiểm tra cờ RECEIVE để phân biệt RX (Download) và TX (Upload)
            if (packet->streamData->flags & FWPS_STREAM_FLAG_RECEIVE) {
                AddNetStats(ctx->processId, byteLength, 0);
            }
            else {
                AddNetStats(ctx->processId, 0, byteLength);
            }
        }
    }
}

// 3. Callout DATAGRAM: Bắt trực tiếp gói dữ liệu UDP (IPv4 & IPv6) để cộng dồn byte theo chiều IN/OUT
VOID NTAPI DatagramClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(filter);

    if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    // Xác định PID: ưu tiên từ Flow Context (đã gán tại tầng ALE), nếu chưa có thì lấy từ Metadata của gói
    UINT32 processId = 0;
    if (flowContext != 0) {
        PFLOW_CONTEXT ctx = (PFLOW_CONTEXT)flowContext;
        processId = ctx->processId;
    }
    else if (inMetaValues != NULL &&
             FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (UINT32)inMetaValues->processId;
    }

    if (processId == 0) {
        return;
    }

    // Đọc độ dài dữ liệu từ NET_BUFFER_LIST
    PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
    if (nbl == NULL) {
        return;
    }

    SIZE_T totalBytes = 0;
    for (PNET_BUFFER_LIST currNbl = nbl; currNbl != NULL; currNbl = NET_BUFFER_LIST_NEXT_NBL(currNbl)) {
        for (PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(currNbl); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
            totalBytes += NET_BUFFER_DATA_LENGTH(nb);
        }
    }

    if (totalBytes == 0) {
        return;
    }

    // Phân biệt chiều Inbound (nhận về) và Outbound (gửi đi) theo Layer ID
    UINT32 direction = FWP_DIRECTION_OUTBOUND;
    if (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V4) {
        direction = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32;
    }
    else if (inFixedValues->layerId == FWPS_LAYER_DATAGRAM_DATA_V6) {
        direction = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].value.uint32;
    }

    if (direction == FWP_DIRECTION_INBOUND) {
        AddNetStats(processId, totalBytes, 0);
    }
    else {
        AddNetStats(processId, 0, totalBytes);
    }
}

// Hàm dọn dẹp context khi luồng mạng kết thúc
VOID NTAPI FlowDeleteNotify(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    if (flowContext != 0) {
        ExFreePoolWithTag((PVOID)flowContext, 'fCtx');
    }
}

NTSTATUS NTAPI CalloutNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}

// Đăng ký Callouts và Filters với WFP Engine (Hỗ trợ cả IPv4 & IPv6 cho TCP & UDP)
NTSTATUS WfpRegisterCallouts(PDEVICE_OBJECT deviceObject)
{
    InitializeListHead(&g_statsListHead);
    KeInitializeSpinLock(&g_statsLock);

    // 1. Mở engine WFP với cờ DYNAMIC session
    FWPM_SESSION0 session = { 0 };
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_engineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 2. Bắt đầu transaction
    status = FwpmTransactionBegin0(g_engineHandle, 0);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 3. Đăng ký các Callouts trong Kernel
    FWPS_CALLOUT0 sCallout = { 0 };

    // 3a. ALE V4
    sCallout.calloutKey = WFP_ALE_FLOW_ESTABLISHED_V4_CALLOUT_GUID;
    sCallout.classifyFn = AleFlowEstablishedClassify;
    sCallout.notifyFn = CalloutNotify;
    sCallout.flowDeleteFn = NULL;
    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_flowEstablishedCalloutIdV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 3b. ALE V6
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = WFP_ALE_FLOW_ESTABLISHED_V6_CALLOUT_GUID;
    sCallout.classifyFn = AleFlowEstablishedClassify;
    sCallout.notifyFn = CalloutNotify;
    sCallout.flowDeleteFn = NULL;
    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_flowEstablishedCalloutIdV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 3c. Stream V4 (TCP)
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = WFP_STREAM_V4_CALLOUT_GUID;
    sCallout.classifyFn = StreamClassify;
    sCallout.notifyFn = CalloutNotify;
    sCallout.flowDeleteFn = FlowDeleteNotify;
    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_streamCalloutIdV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 3d. Stream V6 (TCP)
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = WFP_STREAM_V6_CALLOUT_GUID;
    sCallout.classifyFn = StreamClassify;
    sCallout.notifyFn = CalloutNotify;
    sCallout.flowDeleteFn = FlowDeleteNotify;
    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_streamCalloutIdV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 3e. Datagram V4 (UDP)
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = WFP_DATAGRAM_V4_CALLOUT_GUID;
    sCallout.classifyFn = DatagramClassify;
    sCallout.notifyFn = CalloutNotify;
    sCallout.flowDeleteFn = FlowDeleteNotify;
    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_datagramCalloutIdV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 3f. Datagram V6 (UDP)
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = WFP_DATAGRAM_V6_CALLOUT_GUID;
    sCallout.classifyFn = DatagramClassify;
    sCallout.notifyFn = CalloutNotify;
    sCallout.flowDeleteFn = FlowDeleteNotify;
    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_datagramCalloutIdV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 4. Thêm Sublayer vào BFE
    FWPM_SUBLAYER0 subLayer = { 0 };
    subLayer.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    subLayer.displayData.name = L"WfpNetTrackerSublayer";
    subLayer.displayData.description = L"Sublayer for WFP Net Tracker Driver";
    subLayer.weight = 0x8000;
    status = FwpmSubLayerAdd0(g_engineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 5. Thêm các Callouts vào BFE
    FWPM_CALLOUT0 mCallout = { 0 };

    // 5a. ALE V4 Callout
    mCallout.calloutKey = WFP_ALE_FLOW_ESTABLISHED_V4_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpNetTrackerAleV4Callout";
    mCallout.displayData.description = L"Tracks Flow Established V4";
    mCallout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    status = FwpmCalloutAdd0(g_engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 5b. ALE V6 Callout
    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = WFP_ALE_FLOW_ESTABLISHED_V6_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpNetTrackerAleV6Callout";
    mCallout.displayData.description = L"Tracks Flow Established V6";
    mCallout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6;
    status = FwpmCalloutAdd0(g_engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 5c. Stream V4 Callout (TCP)
    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = WFP_STREAM_V4_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpNetTrackerStreamV4Callout";
    mCallout.displayData.description = L"Tracks Stream V4 bytes";
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;
    status = FwpmCalloutAdd0(g_engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 5d. Stream V6 Callout (TCP)
    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = WFP_STREAM_V6_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpNetTrackerStreamV6Callout";
    mCallout.displayData.description = L"Tracks Stream V6 bytes";
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V6;
    status = FwpmCalloutAdd0(g_engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 5e. Datagram V4 Callout (UDP)
    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = WFP_DATAGRAM_V4_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpNetTrackerDatagramV4Callout";
    mCallout.displayData.description = L"Tracks Datagram V4 bytes";
    mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;
    status = FwpmCalloutAdd0(g_engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 5f. Datagram V6 Callout (UDP)
    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = WFP_DATAGRAM_V6_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpNetTrackerDatagramV6Callout";
    mCallout.displayData.description = L"Tracks Datagram V6 bytes";
    mCallout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V6;
    status = FwpmCalloutAdd0(g_engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 6. Thêm các Filters vào BFE
    FWPM_FILTER0 filter = { 0 };

    // 6a. Filter ALE V4
    filter.filterKey = WFP_ALE_FLOW_ESTABLISHED_V4_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    filter.displayData.name = L"WfpNetTrackerAleV4Filter";
    filter.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_ALE_FLOW_ESTABLISHED_V4_CALLOUT_GUID;
    status = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_aleFilterIdV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 6b. Filter ALE V6
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = WFP_ALE_FLOW_ESTABLISHED_V6_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6;
    filter.displayData.name = L"WfpNetTrackerAleV6Filter";
    filter.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_ALE_FLOW_ESTABLISHED_V6_CALLOUT_GUID;
    status = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_aleFilterIdV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 6c. Filter Stream V4 (TCP)
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = WFP_STREAM_V4_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.displayData.name = L"WfpNetTrackerStreamV4Filter";
    filter.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_STREAM_V4_CALLOUT_GUID;
    status = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_streamFilterIdV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 6d. Filter Stream V6 (TCP)
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = WFP_STREAM_V6_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_STREAM_V6;
    filter.displayData.name = L"WfpNetTrackerStreamV6Filter";
    filter.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_STREAM_V6_CALLOUT_GUID;
    status = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_streamFilterIdV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 6e. Filter Datagram V4 (UDP)
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = WFP_DATAGRAM_V4_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;
    filter.displayData.name = L"WfpNetTrackerDatagramV4Filter";
    filter.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_DATAGRAM_V4_CALLOUT_GUID;
    status = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_datagramFilterIdV4);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 6f. Filter Datagram V6 (UDP)
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = WFP_DATAGRAM_V6_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V6;
    filter.displayData.name = L"WfpNetTrackerDatagramV6Filter";
    filter.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_DATAGRAM_V6_CALLOUT_GUID;
    status = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_datagramFilterIdV6);
    if (!NT_SUCCESS(status)) goto Cleanup;

    // 7. Commit transaction
    status = FwpmTransactionCommit0(g_engineHandle);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    return STATUS_SUCCESS;

Cleanup:
    FwpmTransactionAbort0(g_engineHandle);
    WfpUnregisterCallouts();
    return status;
}

VOID WfpUnregisterCallouts(VOID)
{
    // 1. Dọn dẹp Filter, Callout, Sublayer và đóng Engine
    if (g_engineHandle != NULL) {
        if (g_aleFilterIdV4 != 0) {
            FwpmFilterDeleteById0(g_engineHandle, g_aleFilterIdV4);
            g_aleFilterIdV4 = 0;
        }
        if (g_aleFilterIdV6 != 0) {
            FwpmFilterDeleteById0(g_engineHandle, g_aleFilterIdV6);
            g_aleFilterIdV6 = 0;
        }
        if (g_streamFilterIdV4 != 0) {
            FwpmFilterDeleteById0(g_engineHandle, g_streamFilterIdV4);
            g_streamFilterIdV4 = 0;
        }
        if (g_streamFilterIdV6 != 0) {
            FwpmFilterDeleteById0(g_engineHandle, g_streamFilterIdV6);
            g_streamFilterIdV6 = 0;
        }
        if (g_datagramFilterIdV4 != 0) {
            FwpmFilterDeleteById0(g_engineHandle, g_datagramFilterIdV4);
            g_datagramFilterIdV4 = 0;
        }
        if (g_datagramFilterIdV6 != 0) {
            FwpmFilterDeleteById0(g_engineHandle, g_datagramFilterIdV6);
            g_datagramFilterIdV6 = 0;
        }

        FwpmCalloutDeleteByKey0(g_engineHandle, &WFP_ALE_FLOW_ESTABLISHED_V4_CALLOUT_GUID);
        FwpmCalloutDeleteByKey0(g_engineHandle, &WFP_ALE_FLOW_ESTABLISHED_V6_CALLOUT_GUID);
        FwpmCalloutDeleteByKey0(g_engineHandle, &WFP_STREAM_V4_CALLOUT_GUID);
        FwpmCalloutDeleteByKey0(g_engineHandle, &WFP_STREAM_V6_CALLOUT_GUID);
        FwpmCalloutDeleteByKey0(g_engineHandle, &WFP_DATAGRAM_V4_CALLOUT_GUID);
        FwpmCalloutDeleteByKey0(g_engineHandle, &WFP_DATAGRAM_V6_CALLOUT_GUID);
        FwpmSubLayerDeleteByKey0(g_engineHandle, &WFP_NET_TRACKER_SUBLAYER_GUID);

        FwpmEngineClose0(g_engineHandle);
        g_engineHandle = NULL;
    }

    // 2. Hủy đăng ký Callouts khỏi Kernel
    if (g_flowEstablishedCalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(g_flowEstablishedCalloutIdV4);
        g_flowEstablishedCalloutIdV4 = 0;
    }
    if (g_flowEstablishedCalloutIdV6 != 0) {
        FwpsCalloutUnregisterById0(g_flowEstablishedCalloutIdV6);
        g_flowEstablishedCalloutIdV6 = 0;
    }
    if (g_streamCalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(g_streamCalloutIdV4);
        g_streamCalloutIdV4 = 0;
    }
    if (g_streamCalloutIdV6 != 0) {
        FwpsCalloutUnregisterById0(g_streamCalloutIdV6);
        g_streamCalloutIdV6 = 0;
    }
    if (g_datagramCalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(g_datagramCalloutIdV4);
        g_datagramCalloutIdV4 = 0;
    }
    if (g_datagramCalloutIdV6 != 0) {
        FwpsCalloutUnregisterById0(g_datagramCalloutIdV6);
        g_datagramCalloutIdV6 = 0;
    }

    // 3. Dọn dẹp danh sách bộ đếm
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_statsLock, &lockHandle);

    while (!IsListEmpty(&g_statsListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_statsListHead);
        PPID_NET_ENTRY p = CONTAINING_RECORD(entry, PID_NET_ENTRY, listEntry);
        ExFreePoolWithTag(p, 'ptcW');
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}