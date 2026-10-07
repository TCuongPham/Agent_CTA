// Entry point của Kernel Driver, tạo Device Object và xử lý các lệnh IOCTL từ User-Mode

#include <ntddk.h>

#include "CommonIoctl.h"
#include "WfpCallouts.h"

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DispatchCreateClose;
DRIVER_DISPATCH DispatchDeviceControl;
PDEVICE_OBJECT g_deviceObject = NULL;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    UNICODE_STRING devName = RTL_CONSTANT_STRING(NETMON_DEVICE_NAME);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(NETMON_DOS_DEVICE_NAME);

    // 1. Tạo Device Object
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_deviceObject);
    if (!NT_SUCCESS(status)) return status;

    g_deviceObject->Flags |= DO_BUFFERED_IO;

    // 2. Tạo Symbolic Link để User Mode có thể gọi qua CreateFile
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_deviceObject);
        return status;
    }

    // 3. Đăng ký các hàm Dispatch
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // 4. Khởi động WFP Callouts
    status = WfpRegisterCallouts(g_deviceObject);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(g_deviceObject);
        return status;
    }
    return STATUS_SUCCESS;
}
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Xử lý truy vấn IOCTL từ tiến trình CTA User-Mode
NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytesReturned = 0;
    if (controlCode == IOCTL_NETMON_GET_PID_STATS) {
        if (inLength >= sizeof(UINT32) && outLength >= sizeof(NET_STATS_RECORD)) {
            if (Irp->AssociatedIrp.SystemBuffer != NULL) {
                UINT32 targetPid = *(UINT32*)Irp->AssociatedIrp.SystemBuffer;
                PNET_STATS_RECORD outBuffer = (PNET_STATS_RECORD)Irp->AssociatedIrp.SystemBuffer;
                NET_STATS_RECORD stats = { 0 };
                if (GetNetStatsForPid(targetPid, &stats)) {
                    *outBuffer = stats;
                }
                else {
                    outBuffer->rx_bytes = 0;
                    outBuffer->tx_bytes = 0;
                }
                status = STATUS_SUCCESS;
                bytesReturned = sizeof(NET_STATS_RECORD);
            }
            else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(NETMON_DOS_DEVICE_NAME);
    WfpUnregisterCallouts();
    IoDeleteSymbolicLink(&symLink);
    if (g_deviceObject) {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = NULL;
    }
}