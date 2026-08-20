#include "Driver.h"
#include "Trace.h"

PDEVICE_CONTEXT volatile g_KsDeviceContext = NULL;

_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver = NULL;
    NTSTATUS status;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = KsEvtDriverUnload;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        &driver);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KsCreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        KS_TRACE_ERROR("Control-device initialization failed: 0x%08X", (ULONG)status);
    }
    return status;
}

_Use_decl_annotations_
VOID KsEvtDriverUnload(WDFDRIVER Driver)
{
    PDEVICE_CONTEXT context;
    WDFDEVICE device;

    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();

    context = (PDEVICE_CONTEXT)InterlockedCompareExchangePointer(
        (PVOID volatile*)&g_KsDeviceContext,
        NULL,
        NULL);
    if (context == NULL) {
        return;
    }

    device = context->ControlDevice;
    InterlockedExchange(&context->AcceptingEvents, 0);
    KsTelemetryStop(context);
    (VOID)InterlockedExchangePointer((PVOID volatile*)&g_KsDeviceContext, NULL);
    KsRingCleanup(&context->Ring);
    if (device != NULL) {
        WdfObjectDelete(device);
    }
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, KsEvtDriverUnload)
#endif
