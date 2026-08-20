#include "Driver.h"
#include "Trace.h"

static VOID KsInitializeEvent(_Out_ KS_TELEMETRY_EVENT* Event, _In_ UINT16 EventType)
{
    LARGE_INTEGER timestamp;

    RtlZeroMemory(Event, sizeof(*Event));
    Event->StructSize = (UINT32)sizeof(*Event);
    Event->ProtocolVersion = KS_PROTOCOL_VERSION_CURRENT;
    Event->EventType = EventType;
    Event->PathCapacityCharacters = (UINT16)KS_MAX_PATH_CHARS;
    KeQuerySystemTimePrecise(&timestamp);
    Event->Timestamp100ns = (UINT64)timestamp.QuadPart;
}

static VOID KsCopyImagePath(
    _In_opt_ const UNICODE_STRING* Source,
    _Inout_ KS_TELEMETRY_EVENT* Event)
{
    USHORT characters;
    USHORT copyCharacters;

    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0u) {
        return;
    }

    if (Source->Length > Source->MaximumLength) {
        Event->Flags |= KS_EVENT_FLAG_PATH_TRUNCATED;
        return;
    }
    characters = (USHORT)(Source->Length / sizeof(WCHAR));
    copyCharacters = characters;
    if (copyCharacters >= KS_MAX_PATH_CHARS) {
        copyCharacters = (USHORT)(KS_MAX_PATH_CHARS - 1u);
        Event->Flags |= KS_EVENT_FLAG_PATH_TRUNCATED;
    }
    RtlCopyMemory(Event->ImagePath, Source->Buffer, copyCharacters * sizeof(WCHAR));
    Event->ImagePath[copyCharacters] = L'\0';
    Event->PathLengthCharacters = copyCharacters;
}

static BOOLEAN KsPathEndsWithExe(_In_opt_ const UNICODE_STRING* Path)
{
    const WCHAR* suffix;
    USHORT characters;

    if (Path == NULL || Path->Buffer == NULL || Path->Length < 4u * sizeof(WCHAR)) {
        return FALSE;
    }
    characters = (USHORT)(Path->Length / sizeof(WCHAR));
    suffix = &Path->Buffer[characters - 4u];
    return suffix[0] == L'.' &&
        (suffix[1] == L'e' || suffix[1] == L'E') &&
        (suffix[2] == L'x' || suffix[2] == L'X') &&
        (suffix[3] == L'e' || suffix[3] == L'E');
}

static PDEVICE_CONTEXT KsAcquireContext(VOID)
{
    PDEVICE_CONTEXT context;

    context = (PDEVICE_CONTEXT)InterlockedCompareExchangePointer(
        (PVOID volatile*)&g_KsDeviceContext,
        NULL,
        NULL);
    if (context == NULL ||
        InterlockedCompareExchange(&context->AcceptingEvents, 1, 1) == 0) {
        return NULL;
    }
    return context;
}

VOID KsProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PDEVICE_CONTEXT context;
    KS_TELEMETRY_EVENT eventRecord;

    UNREFERENCED_PARAMETER(Process);
    context = KsAcquireContext();
    if (context == NULL) {
        return;
    }

    KsInitializeEvent(
        &eventRecord,
        CreateInfo != NULL ? KS_EVENT_PROCESS_CREATE : KS_EVENT_PROCESS_EXIT);
    eventRecord.ProcessId = (UINT64)(ULONG_PTR)ProcessId;
    if (CreateInfo != NULL) {
        eventRecord.ParentProcessId = (UINT64)(ULONG_PTR)CreateInfo->ParentProcessId;
        KsCopyImagePath(CreateInfo->ImageFileName, &eventRecord);
    }
    (VOID)KsRingPush(&context->Ring, &eventRecord);
}

VOID KsImageLoadNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    PDEVICE_CONTEXT context;
    KS_TELEMETRY_EVENT eventRecord;
    UINT16 eventType;

    context = KsAcquireContext();
    if (context == NULL || ImageInfo == NULL) {
        return;
    }

    if (ImageInfo->SystemModeImage || ProcessId == NULL) {
        eventType = KS_EVENT_KERNEL_DRIVER_IMAGE_LOAD;
    } else if (KsPathEndsWithExe(FullImageName)) {
        eventType = KS_EVENT_EXECUTABLE_IMAGE_LOAD;
    } else {
        eventType = KS_EVENT_DLL_IMAGE_LOAD;
    }

    KsInitializeEvent(&eventRecord, eventType);
    eventRecord.ProcessId = (UINT64)(ULONG_PTR)ProcessId;
    eventRecord.ImageBase = (UINT64)(ULONG_PTR)ImageInfo->ImageBase;
    eventRecord.ImageSize = (UINT64)ImageInfo->ImageSize;
    if (ImageInfo->SystemModeImage) {
        eventRecord.Flags |= KS_EVENT_FLAG_SYSTEM_MODE_IMAGE;
    }
    KsCopyImagePath(FullImageName, &eventRecord);
    (VOID)KsRingPush(&context->Ring, &eventRecord);
}

_Use_decl_annotations_
NTSTATUS KsTelemetryStart(PDEVICE_CONTEXT Context)
{
    NTSTATUS status;

    PAGED_CODE();
    if (Context->ProcessCallbackRegistered || Context->ImageCallbackRegistered) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = PsSetCreateProcessNotifyRoutineEx(KsProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Context->ProcessCallbackRegistered = TRUE;

    status = PsSetLoadImageNotifyRoutine(KsImageLoadNotify);
    if (!NT_SUCCESS(status)) {
        NTSTATUS removalStatus;
        removalStatus = PsSetCreateProcessNotifyRoutineEx(KsProcessNotify, TRUE);
        if (NT_SUCCESS(removalStatus)) {
            Context->ProcessCallbackRegistered = FALSE;
            return status;
        }
        KS_TRACE_ERROR("Process callback rollback failed: 0x%08X", (ULONG)removalStatus);
        return removalStatus;
    }
    Context->ImageCallbackRegistered = TRUE;
    KS_TRACE_INFO("Telemetry callbacks registered%s", "");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID KsTelemetryStop(PDEVICE_CONTEXT Context)
{
    NTSTATUS status;

    PAGED_CODE();
    if (Context == NULL) {
        return;
    }
    InterlockedExchange(&Context->AcceptingEvents, 0);

    if (Context->ImageCallbackRegistered) {
        status = PsRemoveLoadImageNotifyRoutine(KsImageLoadNotify);
        if (!NT_SUCCESS(status)) {
            KS_TRACE_ERROR("Image callback removal failed: 0x%08X", (ULONG)status);
        } else {
            Context->ImageCallbackRegistered = FALSE;
        }
    }
    if (Context->ProcessCallbackRegistered) {
        status = PsSetCreateProcessNotifyRoutineEx(KsProcessNotify, TRUE);
        if (!NT_SUCCESS(status)) {
            KS_TRACE_ERROR("Process callback removal failed: 0x%08X", (ULONG)status);
        } else {
            Context->ProcessCallbackRegistered = FALSE;
        }
    }
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, KsTelemetryStart)
#pragma alloc_text(PAGE, KsTelemetryStop)
#endif
