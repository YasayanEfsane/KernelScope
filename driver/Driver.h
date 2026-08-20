#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>

#include "../shared/Protocol.h"
#include "../shared/ProtocolValidation.h"

#define KS_POOL_TAG 'pScK'

typedef struct _KS_RING_BUFFER {
    WDFSPINLOCK Lock;
    WDFMEMORY StorageMemory;
    KS_TELEMETRY_EVENT* Storage;
    UINT32 Head;
    UINT32 Tail;
    UINT32 Count;
    UINT64 NextSequence;
    UINT64 EventsWritten;
    UINT64 EventsRead;
    UINT64 EventsDropped;
    UINT64 DropsPendingRecord;
    BOOLEAN Initialized;
} KS_RING_BUFFER;

typedef struct _DEVICE_CONTEXT {
    WDFDEVICE ControlDevice;
    KS_RING_BUFFER Ring;
    volatile LONG AcceptingEvents;
    BOOLEAN ProcessCallbackRegistered;
    BOOLEAN ImageCallbackRegistered;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, KsGetDeviceContext)

extern PDEVICE_CONTEXT volatile g_KsDeviceContext;

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD KsEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL KsEvtIoDeviceControl;
EVT_WDF_DEVICE_FILE_CREATE KsEvtFileCreate;
EVT_WDF_FILE_CLEANUP KsEvtFileCleanup;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS KsCreateControlDevice(_In_ WDFDRIVER Driver);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS KsQueueInitialize(_In_ WDFDEVICE Device);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS KsRingInitialize(_In_ WDFDEVICE Device, _Out_ KS_RING_BUFFER* Ring);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS KsRingPush(_Inout_ KS_RING_BUFFER* Ring, _In_ const KS_TELEMETRY_EVENT* Event);

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT32 KsRingPop(
    _Inout_ KS_RING_BUFFER* Ring,
    _Out_writes_(MaximumEvents) KS_TELEMETRY_EVENT* Events,
    _In_range_(1, KS_MAX_BATCH_EVENTS) UINT32 MaximumEvents,
    _Out_ UINT32* Remaining,
    _Out_ UINT64* DroppedTotal);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID KsRingGetStatistics(_Inout_ KS_RING_BUFFER* Ring, _Out_ KS_STATISTICS_RESPONSE* Statistics);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID KsRingResetStatistics(_Inout_ KS_RING_BUFFER* Ring, _Out_ KS_STATISTICS_RESPONSE* Statistics);

_IRQL_requires_(PASSIVE_LEVEL)
VOID KsRingCleanup(_Inout_ KS_RING_BUFFER* Ring);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS KsTelemetryStart(_Inout_ PDEVICE_CONTEXT Context);

_IRQL_requires_(PASSIVE_LEVEL)
VOID KsTelemetryStop(_Inout_ PDEVICE_CONTEXT Context);
