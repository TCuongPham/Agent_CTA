#include <ntddk.h>
#include <initguid.h>
#include "WfpCallouts.h"

// GUID định danh cho các Callout
// {E425686F-6B22-4D3C-8DE2-B37D427D6B10}
DEFINE_GUID(WFP_ALE_FLOW_ESTABLISHED_CALLOUT_GUID,
    0xe425686f, 0x6b22, 0x4d3c, 0x8d, 0xe2, 0xb3, 0x7d, 0x42, 0x7d, 0x6b, 0x10);

// {B912C092-23E4-4345-9854-C3B24F5D7B20}
DEFINE_GUID(WFP_STREAM_CALLOUT_GUID,
    0xb912c092, 0x23e4, 0x4345, 0x98, 0x54, 0xc3, 0xb2, 0x4f, 0x5d, 0x7b, 0x20);

// GUID Sublayer của Driver
// {D803697E-5A23-4A47-9344-486E76775533}
DEFINE_GUID(WFP_NET_TRACKER_SUBLAYER_GUID,
    0xd803697e, 0x5a23, 0x4a47, 0x93, 0x44, 0x48, 0x6e, 0x76, 0x77, 0x55, 0x33);

// GUID cho các Filter
// {3CE7BC01-B12E-41F6-82B5-177DDF729D01}
DEFINE_GUID(WFP_ALE_FLOW_ESTABLISHED_FILTER_GUID,
    0x3ce7bc01, 0xb12e, 0x41f6, 0x82, 0xb5, 0x17, 0x7d, 0xdf, 0x72, 0x9d, 0x01);

// {745E6135-2B8C-476F-B955-46D93D716612}
DEFINE_GUID(WFP_STREAM_FILTER_GUID,
    0x745e6135, 0x2b8c, 0x476f, 0xb9, 0x55, 0x46, 0xd9, 0x3d, 0x71, 0x66, 0x12);

static HANDLE g_engineHandle = NULL;
static UINT32 g_flowEstablishedCalloutId = 0;
static UINT32 g_streamCalloutId = 0;
static UINT64 g_aleFilterId = 0;
static UINT64 g_streamFilterId = 0;
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

// 1. Callout ALE: Bắt thời điểm kết nối được thiết lập để lấy PID và gán context vào Flow
VOID NTAPI AleFlowEstablishedClassify(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
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

        PFLOW_CONTEXT ctx = (PFLOW_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FLOW_CONTEXT), 'fCtx');
        if (ctx != NULL) {
            ctx->processId = (UINT32)processId;

            // Gán context chứa PID này vào luồng mạng ở tầng STREAM
            NTSTATUS status = FwpsFlowAssociateContext0(flowId, FWPS_LAYER_STREAM_V4, g_streamCalloutId, (UINT64)ctx);
            if (!NT_SUCCESS(status)) {
                // Tránh memory leak nếu gán context thất bại
                ExFreePoolWithTag(ctx, 'fCtx');
            }
        }
    }
}

// 2. Callout STREAM: Bắt trực tiếp dòng byte dữ liệu TCP để cộng dồn byte theo chiều IN/OUT
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

// Đăng ký Callouts và Filters với WFP Engine
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

    // 3. Đăng ký Callout ALE Flow Established trong Kernel
    FWPS_CALLOUT0 sCallout = { 0 };
    sCallout.calloutKey = WFP_ALE_FLOW_ESTABLISHED_CALLOUT_GUID;
    sCallout.classifyFn = AleFlowEstablishedClassify;
    sCallout.notifyFn = CalloutNotify;
    sCallout.flowDeleteFn = NULL; // Không gán flowDelete ở tầng ALE vì context được gắn ở tầng STREAM

    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_flowEstablishedCalloutId);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 4. Đăng ký Callout Stream trong Kernel
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey = WFP_STREAM_CALLOUT_GUID;
    sCallout.classifyFn = StreamClassify;
    sCallout.notifyFn = CalloutNotify;
    sCallout.flowDeleteFn = FlowDeleteNotify; // Dọn dẹp context FLOW_CONTEXT khi đóng luồng TCP

    status = FwpsCalloutRegister0(deviceObject, &sCallout, &g_streamCalloutId);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    
    // 5. Thêm Sublayer vào BFE
    FWPM_SUBLAYER0 subLayer = { 0 };
    subLayer.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    subLayer.displayData.name = L"WfpNetTrackerSublayer";
    subLayer.displayData.description = L"Sublayer for WFP Net Tracker Driver";
    subLayer.weight = 0x8000;

    status = FwpmSubLayerAdd0(g_engineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 6. Thêm Callout ALE vào BFE
    FWPM_CALLOUT0 mCallout = { 0 };
    mCallout.calloutKey = WFP_ALE_FLOW_ESTABLISHED_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpNetTrackerAleCallout";
    mCallout.displayData.description = L"Tracks Flow Established for PID";
    mCallout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;

    status = FwpmCalloutAdd0(g_engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 7. Thêm Callout Stream vào BFE
    RtlZeroMemory(&mCallout, sizeof(mCallout));
    mCallout.calloutKey = WFP_STREAM_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpNetTrackerStreamCallout";
    mCallout.displayData.description = L"Tracks Stream bytes";
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;

    status = FwpmCalloutAdd0(g_engineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 8. Thêm Filter ALE vào BFE
    FWPM_FILTER0 filter = { 0 };
    filter.filterKey = WFP_ALE_FLOW_ESTABLISHED_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
    filter.displayData.name = L"WfpNetTrackerAleFilter";
    filter.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY; // Trọng số tự động
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_ALE_FLOW_ESTABLISHED_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_aleFilterId);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 9. Thêm Filter Stream vào BFE
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = WFP_STREAM_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.displayData.name = L"WfpNetTrackerStreamFilter";
    filter.subLayerKey = WFP_NET_TRACKER_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_STREAM_CALLOUT_GUID;

    status = FwpmFilterAdd0(g_engineHandle, &filter, NULL, &g_streamFilterId);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    // 10. Commit transaction
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
        if (g_aleFilterId != 0) {
            FwpmFilterDeleteById0(g_engineHandle, g_aleFilterId);
            g_aleFilterId = 0;
        }
        if (g_streamFilterId != 0) {
            FwpmFilterDeleteById0(g_engineHandle, g_streamFilterId);
            g_streamFilterId = 0;
        }
        FwpmCalloutDeleteByKey0(g_engineHandle, &WFP_ALE_FLOW_ESTABLISHED_CALLOUT_GUID);
        FwpmCalloutDeleteByKey0(g_engineHandle, &WFP_STREAM_CALLOUT_GUID);
        FwpmSubLayerDeleteByKey0(g_engineHandle, &WFP_NET_TRACKER_SUBLAYER_GUID);

        FwpmEngineClose0(g_engineHandle);
        g_engineHandle = NULL;
    }

    // 2. Hủy đăng ký Callouts khỏi Kernel
    if (g_flowEstablishedCalloutId != 0) {
        FwpsCalloutUnregisterById0(g_flowEstablishedCalloutId);
        g_flowEstablishedCalloutId = 0;
    }

    if (g_streamCalloutId != 0) {
        FwpsCalloutUnregisterById0(g_streamCalloutId);
        g_streamCalloutId = 0;
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