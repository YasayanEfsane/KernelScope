#include "Driver.h"
#include "Trace.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KsCreateControlDevice)
#endif

static const UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KernelScope");
static const UNICODE_STRING g_SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\KernelScope");

_Use_decl_annotations_
NTSTATUS KsCreateControlDevice(WDFDRIVER Driver)
{
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_OBJECT_ATTRIBUTES fileAttributes;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDFDEVICE device = NULL;
    PDEVICE_CONTEXT context;
    NTSTATUS status;

    PAGED_CODE();

    deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(deviceInit, KS_DEVICE_TYPE);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, TRUE);
    WdfDeviceInitSetExclusive(deviceInit, FALSE);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

    status = WdfDeviceInitAssignName(deviceInit, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, KsEvtFileCreate, NULL, KsEvtFileCleanup);
    WDF_OBJECT_ATTRIBUTES_INIT(&fileAttributes);
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, &fileAttributes);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);
    deviceAttributes.ExecutionLevel = WdfExecutionLevelPassive;
    deviceAttributes.SynchronizationScope = WdfSynchronizationScopeNone;
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        if (deviceInit != NULL) {
            WdfDeviceInitFree(deviceInit);
        }
        return status;
    }

    context = KsGetDeviceContext(device);
    RtlZeroMemory(context, sizeof(*context));
    context->ControlDevice = device;

    status = WdfDeviceCreateSymbolicLink(device, &g_SymbolicLink);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }

    status = KsRingInitialize(device, &context->Ring);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }

    status = KsQueueInitialize(device);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }

    InterlockedExchange(&context->AcceptingEvents, 1);
    (VOID)InterlockedExchangePointer(
        (PVOID volatile*)&g_KsDeviceContext,
        context);

    status = KsTelemetryStart(context);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }

    WdfControlFinishInitializing(device);
    KS_TRACE_INFO("Control device initialized%s", "");
    return STATUS_SUCCESS;

Failure:
    InterlockedExchange(&context->AcceptingEvents, 0);
    KsTelemetryStop(context);
    (VOID)InterlockedCompareExchangePointer(
        (PVOID volatile*)&g_KsDeviceContext,
        NULL,
        context);
    KsRingCleanup(&context->Ring);
    WdfObjectDelete(device);
    return status;
}

_Use_decl_annotations_
VOID KsEvtFileCreate(WDFDEVICE Device, WDFREQUEST Request, WDFFILEOBJECT FileObject)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);

    /* The I/O manager enforces the device SDDL before this callback. */
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

_Use_decl_annotations_
VOID KsEvtFileCleanup(WDFFILEOBJECT FileObject)
{
    UNREFERENCED_PARAMETER(FileObject);
}

