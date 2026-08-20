#include "Driver.h"

C_ASSERT(KS_RING_CAPACITY <= (MAXULONG_PTR / sizeof(KS_TELEMETRY_EVENT)));

static VOID KsSaturatingIncrement(_Inout_ UINT64* Value)
{
    if (*Value != MAXUINT64) {
        ++(*Value);
    }
}

static VOID KsSaturatingAdd(_Inout_ UINT64* Value, _In_ UINT64 Amount)
{
    if (MAXUINT64 - *Value < Amount) {
        *Value = MAXUINT64;
    } else {
        *Value += Amount;
    }
}

static VOID KsRingInsertLocked(
    _Inout_ KS_RING_BUFFER* Ring,
    _In_ const KS_TELEMETRY_EVENT* Event)
{
    Ring->Storage[Ring->Tail] = *Event;
    Ring->Tail = (Ring->Tail + 1u) % KS_RING_CAPACITY;
    ++Ring->Count;
    KsSaturatingIncrement(&Ring->EventsWritten);
}

static BOOLEAN KsAssignSequenceLocked(
    _Inout_ KS_RING_BUFFER* Ring,
    _Out_ UINT64* Sequence)
{
    if (Ring->NextSequence == MAXUINT64) {
        return FALSE;
    }
    *Sequence = Ring->NextSequence;
    ++Ring->NextSequence;
    return TRUE;
}

_Use_decl_annotations_
NTSTATUS KsRingInitialize(WDFDEVICE Device, KS_RING_BUFFER* Ring)
{
    WDF_OBJECT_ATTRIBUTES attributes;
    size_t allocationBytes;
    NTSTATUS status;

    PAGED_CODE();
    RtlZeroMemory(Ring, sizeof(*Ring));

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = Device;
    status = WdfSpinLockCreate(&attributes, &Ring->Lock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    allocationBytes = sizeof(KS_TELEMETRY_EVENT) * (size_t)KS_RING_CAPACITY;
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = Device;
    status = WdfMemoryCreate(
        &attributes,
        NonPagedPoolNx,
        KS_POOL_TAG,
        allocationBytes,
        &Ring->StorageMemory,
        (PVOID*)&Ring->Storage);
    if (!NT_SUCCESS(status)) {
        Ring->Lock = NULL;
        return status;
    }

    RtlZeroMemory(Ring->Storage, allocationBytes);
    Ring->NextSequence = 1u;
    Ring->Initialized = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS KsRingPush(KS_RING_BUFFER* Ring, const KS_TELEMETRY_EVENT* Event)
{
    KS_TELEMETRY_EVENT record;
    KS_TELEMETRY_EVENT dropRecord;
    LARGE_INTEGER timestamp;
    NTSTATUS status = STATUS_SUCCESS;

    if (Ring == NULL || Event == NULL || !Ring->Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }
    record = *Event;

    WdfSpinLockAcquire(Ring->Lock);

    if (Ring->Count == KS_RING_CAPACITY) {
        UINT64 discardedSequence;
        (VOID)KsAssignSequenceLocked(Ring, &discardedSequence);
        KsSaturatingIncrement(&Ring->EventsDropped);
        KsSaturatingIncrement(&Ring->DropsPendingRecord);
        status = STATUS_BUFFER_OVERFLOW;
        goto Exit;
    }

    if (Ring->DropsPendingRecord != 0u &&
        Ring->Count <= KS_RING_CAPACITY - 2u) {
        RtlZeroMemory(&dropRecord, sizeof(dropRecord));
        dropRecord.StructSize = (UINT32)sizeof(dropRecord);
        dropRecord.ProtocolVersion = KS_PROTOCOL_VERSION_CURRENT;
        dropRecord.EventType = KS_EVENT_DROPPED_STATISTICS;
        dropRecord.Flags = KS_EVENT_FLAG_SYNTHETIC;
        dropRecord.PathCapacityCharacters = (UINT16)KS_MAX_PATH_CHARS;
        KeQuerySystemTimePrecise(&timestamp);
        dropRecord.Timestamp100ns = (UINT64)timestamp.QuadPart;
        dropRecord.AuxiliaryValue = Ring->DropsPendingRecord;
        if (!KsAssignSequenceLocked(Ring, &dropRecord.Sequence)) {
            status = STATUS_INTEGER_OVERFLOW;
            goto Exit;
        }
        Ring->DropsPendingRecord = 0u;
        KsRingInsertLocked(Ring, &dropRecord);
    }

    if (!KsAssignSequenceLocked(Ring, &record.Sequence)) {
        KsSaturatingIncrement(&Ring->EventsDropped);
        KsSaturatingIncrement(&Ring->DropsPendingRecord);
        status = STATUS_INTEGER_OVERFLOW;
        goto Exit;
    }
    KsRingInsertLocked(Ring, &record);

Exit:
    WdfSpinLockRelease(Ring->Lock);
    return status;
}

_Use_decl_annotations_
UINT32 KsRingPop(
    KS_RING_BUFFER* Ring,
    KS_TELEMETRY_EVENT* Events,
    UINT32 MaximumEvents,
    UINT32* Remaining,
    UINT64* DroppedTotal)
{
    UINT32 eventCount;
    UINT32 index;

    if (Ring == NULL || Events == NULL || Remaining == NULL || DroppedTotal == NULL ||
        MaximumEvents == 0u || MaximumEvents > KS_MAX_BATCH_EVENTS ||
        !Ring->Initialized) {
        return 0u;
    }

    WdfSpinLockAcquire(Ring->Lock);
    eventCount = Ring->Count < MaximumEvents ? Ring->Count : MaximumEvents;
    for (index = 0u; index < eventCount; ++index) {
        Events[index] = Ring->Storage[Ring->Head];
        RtlSecureZeroMemory(&Ring->Storage[Ring->Head], sizeof(KS_TELEMETRY_EVENT));
        Ring->Head = (Ring->Head + 1u) % KS_RING_CAPACITY;
    }
    Ring->Count -= eventCount;
    KsSaturatingAdd(&Ring->EventsRead, eventCount);
    *Remaining = Ring->Count;
    *DroppedTotal = Ring->EventsDropped;
    WdfSpinLockRelease(Ring->Lock);
    return eventCount;
}

static VOID KsFillStatisticsLocked(
    _In_ const KS_RING_BUFFER* Ring,
    _Out_ KS_STATISTICS_RESPONSE* Statistics)
{
    Statistics->NextSequence = Ring->NextSequence;
    Statistics->EventsWritten = Ring->EventsWritten;
    Statistics->EventsRead = Ring->EventsRead;
    Statistics->EventsDropped = Ring->EventsDropped;
    Statistics->RingCapacity = KS_RING_CAPACITY;
    Statistics->CurrentDepth = Ring->Count;
}

_Use_decl_annotations_
VOID KsRingGetStatistics(KS_RING_BUFFER* Ring, KS_STATISTICS_RESPONSE* Statistics)
{
    WdfSpinLockAcquire(Ring->Lock);
    KsFillStatisticsLocked(Ring, Statistics);
    WdfSpinLockRelease(Ring->Lock);
}

_Use_decl_annotations_
VOID KsRingResetStatistics(KS_RING_BUFFER* Ring, KS_STATISTICS_RESPONSE* Statistics)
{
    WdfSpinLockAcquire(Ring->Lock);
    Ring->EventsWritten = 0u;
    Ring->EventsRead = 0u;
    Ring->EventsDropped = 0u;
    Ring->DropsPendingRecord = 0u;
    KsFillStatisticsLocked(Ring, Statistics);
    WdfSpinLockRelease(Ring->Lock);
}

_Use_decl_annotations_
VOID KsRingCleanup(KS_RING_BUFFER* Ring)
{
    WDFMEMORY memory;
    size_t allocationBytes;

    PAGED_CODE();
    if (Ring == NULL || !Ring->Initialized || Ring->Lock == NULL) {
        return;
    }

    allocationBytes = sizeof(KS_TELEMETRY_EVENT) * (size_t)KS_RING_CAPACITY;
    WdfSpinLockAcquire(Ring->Lock);
    Ring->Initialized = FALSE;
    if (Ring->Storage != NULL) {
        RtlSecureZeroMemory(Ring->Storage, allocationBytes);
    }
    memory = Ring->StorageMemory;
    Ring->Storage = NULL;
    Ring->StorageMemory = NULL;
    Ring->Count = 0u;
    WdfSpinLockRelease(Ring->Lock);

    if (memory != NULL) {
        WdfObjectDelete(memory);
    }
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KsRingInitialize)
#pragma alloc_text(PAGE, KsRingCleanup)
#endif
