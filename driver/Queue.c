#include "Driver.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KsQueueInitialize)
#endif

static VOID KsInitializeHeader(
    _Out_ KS_PROTOCOL_HEADER* Header,
    _In_ UINT32 Size,
    _In_ UINT16 MessageType,
    _In_ UINT64 CorrelationId,
    _In_ UINT64 Sequence)
{
    Header->StructSize = Size;
    Header->ProtocolVersion = KS_PROTOCOL_VERSION_CURRENT;
    Header->MessageType = MessageType;
    Header->Flags = 0u;
    Header->Reserved = 0u;
    Header->Sequence = Sequence;
    Header->CorrelationId = CorrelationId;
}

static NTSTATUS KsGetExactInput(
    _In_ WDFREQUEST Request,
    _In_ size_t ExpectedSize,
    _Outptr_ PVOID* Buffer)
{
    size_t actualSize = 0u;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(Request, ExpectedSize, Buffer, &actualSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return actualSize == ExpectedSize ? STATUS_SUCCESS : STATUS_INFO_LENGTH_MISMATCH;
}

static NTSTATUS KsGetExactOutput(
    _In_ WDFREQUEST Request,
    _In_ size_t ExpectedSize,
    _Outptr_ PVOID* Buffer)
{
    size_t actualSize = 0u;
    NTSTATUS status;

    status = WdfRequestRetrieveOutputBuffer(Request, ExpectedSize, Buffer, &actualSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return actualSize == ExpectedSize ? STATUS_SUCCESS : STATUS_INFO_LENGTH_MISMATCH;
}

static NTSTATUS KsHandleQuery(
    _In_ WDFREQUEST Request,
    _Out_ size_t* Information)
{
    KS_QUERY_REQUEST* request;
    KS_QUERY_RESPONSE* response;
    UINT64 correlationId;
    NTSTATUS status;

    status = KsGetExactInput(Request, sizeof(*request), (PVOID*)&request);
    if (!NT_SUCCESS(status) || !KsValidateRequestHeader(
            status == STATUS_SUCCESS ? &request->Header : NULL,
            (UINT32)sizeof(*request), (UINT32)sizeof(*request), KS_MESSAGE_QUERY_REQUEST)) {
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }
    correlationId = request->Header.CorrelationId;

    status = KsGetExactOutput(Request, sizeof(*response), (PVOID*)&response);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(response, sizeof(*response));
    KsInitializeHeader(&response->Header, (UINT32)sizeof(*response),
        KS_MESSAGE_QUERY_RESPONSE, correlationId, 0u);
    response->MinimumProtocolVersion = KS_PROTOCOL_VERSION_MIN;
    response->MaximumProtocolVersion = KS_PROTOCOL_VERSION_MAX;
    response->NegotiatedProtocolVersion = KS_PROTOCOL_VERSION_CURRENT;
    response->Capabilities = KS_CAPABILITIES_ALL;
    response->MaximumBatchEvents = KS_MAX_BATCH_EVENTS;
    response->MaximumPathCharacters = KS_MAX_PATH_CHARS;
    response->RingCapacity = KS_RING_CAPACITY;
    *Information = sizeof(*response);
    return STATUS_SUCCESS;
}

static NTSTATUS KsHandleGetEvents(
    _In_ WDFREQUEST Request,
    _In_ PDEVICE_CONTEXT Context,
    _Out_ size_t* Information)
{
    KS_GET_EVENTS_REQUEST* request;
    KS_GET_EVENTS_RESPONSE* response;
    UINT32 expectedOutput;
    UINT32 maximumEvents;
    UINT32 remaining;
    UINT32 eventCount;
    UINT64 droppedTotal;
    UINT64 correlationId;
    NTSTATUS status;

    status = KsGetExactInput(Request, sizeof(*request), (PVOID*)&request);
    if (!NT_SUCCESS(status) || !KsValidateRequestHeader(
            status == STATUS_SUCCESS ? &request->Header : NULL,
            (UINT32)sizeof(*request), (UINT32)sizeof(*request), KS_MESSAGE_GET_EVENTS_REQUEST)) {
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }
    if (request->Reserved32 != 0u) {
        return STATUS_INVALID_PARAMETER;
    }
    maximumEvents = request->MaximumEvents;
    correlationId = request->Header.CorrelationId;
    expectedOutput = KsBatchResponseSize(maximumEvents);
    if (expectedOutput == 0u) {
        return STATUS_INVALID_PARAMETER;
    }

    status = KsGetExactOutput(Request, expectedOutput, (PVOID*)&response);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(response, expectedOutput);
    eventCount = KsRingPop(
        &Context->Ring,
        response->Events,
        maximumEvents,
        &remaining,
        &droppedTotal);
    KsInitializeHeader(&response->Header, expectedOutput,
        KS_MESSAGE_GET_EVENTS_RESPONSE, correlationId,
        eventCount == 0u ? 0u : response->Events[eventCount - 1u].Sequence);
    response->EventCount = eventCount;
    response->RemainingEventCount = remaining;
    response->DroppedTotal = droppedTotal;
    if (eventCount != 0u) {
        response->FirstSequence = response->Events[0].Sequence;
        response->LastSequence = response->Events[eventCount - 1u].Sequence;
    }
    *Information = expectedOutput;
    return STATUS_SUCCESS;
}

static NTSTATUS KsHandleStatistics(
    _In_ WDFREQUEST Request,
    _In_ PDEVICE_CONTEXT Context,
    _Out_ size_t* Information)
{
    KS_STATISTICS_REQUEST* request;
    KS_STATISTICS_RESPONSE* response;
    UINT64 correlationId;
    NTSTATUS status;

    status = KsGetExactInput(Request, sizeof(*request), (PVOID*)&request);
    if (!NT_SUCCESS(status) || !KsValidateRequestHeader(
            status == STATUS_SUCCESS ? &request->Header : NULL,
            (UINT32)sizeof(*request), (UINT32)sizeof(*request), KS_MESSAGE_GET_STATISTICS_REQUEST)) {
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }
    correlationId = request->Header.CorrelationId;
    status = KsGetExactOutput(Request, sizeof(*response), (PVOID*)&response);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(response, sizeof(*response));
    KsInitializeHeader(&response->Header, (UINT32)sizeof(*response),
        KS_MESSAGE_GET_STATISTICS_RESPONSE, correlationId, 0u);
    KsRingGetStatistics(&Context->Ring, response);
    *Information = sizeof(*response);
    return STATUS_SUCCESS;
}

static NTSTATUS KsHandleResetStatistics(
    _In_ WDFREQUEST Request,
    _In_ PDEVICE_CONTEXT Context,
    _Out_ size_t* Information)
{
    KS_RESET_STATISTICS_REQUEST* request;
    KS_STATISTICS_RESPONSE* response;
    UINT64 correlationId;
    NTSTATUS status;

    status = KsGetExactInput(Request, sizeof(*request), (PVOID*)&request);
    if (!NT_SUCCESS(status) || !KsValidateRequestHeader(
            status == STATUS_SUCCESS ? &request->Header : NULL,
            (UINT32)sizeof(*request), (UINT32)sizeof(*request), KS_MESSAGE_RESET_STATISTICS_REQUEST)) {
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }
    if (request->ResetFlags != KS_RESET_COUNTERS ||
        request->Reserved32[0] != 0u || request->Reserved32[1] != 0u ||
        request->Reserved32[2] != 0u) {
        return STATUS_INVALID_PARAMETER;
    }
    correlationId = request->Header.CorrelationId;
    status = KsGetExactOutput(Request, sizeof(*response), (PVOID*)&response);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(response, sizeof(*response));
    KsInitializeHeader(&response->Header, (UINT32)sizeof(*response),
        KS_MESSAGE_RESET_STATISTICS_RESPONSE, correlationId, 0u);
    KsRingResetStatistics(&Context->Ring, response);
    *Information = sizeof(*response);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS KsQueueInitialize(WDFDEVICE Device)
{
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;

    PAGED_CODE();
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.PowerManaged = WdfFalse;
    queueConfig.EvtIoDeviceControl = KsEvtIoDeviceControl;
    return WdfIoQueueCreate(Device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
}

_Use_decl_annotations_
VOID KsEvtIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode)
{
    WDFDEVICE device;
    PDEVICE_CONTEXT context;
    size_t information = 0u;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);
    device = WdfIoQueueGetDevice(Queue);
    context = KsGetDeviceContext(device);

    switch (IoControlCode) {
    case KS_IOCTL_QUERY_PROTOCOL:
        status = KsHandleQuery(Request, &information);
        break;
    case KS_IOCTL_GET_EVENTS:
        status = KsHandleGetEvents(Request, context, &information);
        break;
    case KS_IOCTL_GET_STATISTICS:
        status = KsHandleStatistics(Request, context, &information);
        break;
    case KS_IOCTL_RESET_STATISTICS:
        status = KsHandleResetStatistics(Request, context, &information);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    if (!NT_SUCCESS(status)) {
        information = 0u;
    }
    WdfRequestCompleteWithInformation(Request, status, information);
}

