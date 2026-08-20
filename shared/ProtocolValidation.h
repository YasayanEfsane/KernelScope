#pragma once

#include "Protocol.h"

#if defined(_MSC_VER)
#define KS_INLINE static __forceinline
#else
#define KS_INLINE static inline
#endif

KS_INLINE UINT32 KsBatchResponseSize(_In_ UINT32 maximumEvents)
{
    if (maximumEvents == 0u || maximumEvents > KS_MAX_BATCH_EVENTS) {
        return 0u;
    }
    return KS_GET_EVENTS_RESPONSE_BASE_SIZE +
        (maximumEvents * (UINT32)sizeof(KS_TELEMETRY_EVENT));
}

KS_INLINE int KsIsKnownMessageType(_In_ UINT16 messageType)
{
    return messageType >= KS_MESSAGE_QUERY_REQUEST &&
        messageType <= KS_MESSAGE_RESET_STATISTICS_RESPONSE;
}

KS_INLINE int KsValidateRequestHeader(
    _In_opt_ const KS_PROTOCOL_HEADER* header,
    _In_ UINT32 inputBytes,
    _In_ UINT32 expectedBytes,
    _In_ UINT16 expectedMessageType)
{
    if (header == NULL || inputBytes != expectedBytes ||
        header->StructSize != expectedBytes ||
        header->ProtocolVersion != KS_PROTOCOL_VERSION_CURRENT ||
        header->MessageType != expectedMessageType ||
        !KsIsKnownMessageType(header->MessageType) ||
        header->Flags != 0u || header->Reserved != 0u ||
        header->Sequence != 0u) {
        return 0;
    }
    return 1;
}

KS_INLINE int KsValidateResponseHeader(
    _In_opt_ const KS_PROTOCOL_HEADER* header,
    _In_ UINT32 returnedBytes,
    _In_ UINT16 expectedMessageType)
{
    if (header == NULL || header->StructSize != returnedBytes ||
        header->ProtocolVersion != KS_PROTOCOL_VERSION_CURRENT ||
        header->MessageType != expectedMessageType ||
        !KsIsKnownMessageType(header->MessageType) ||
        header->Flags != 0u || header->Reserved != 0u) {
        return 0;
    }
    return 1;
}

KS_INLINE int KsValidateEvent(_In_opt_ const KS_TELEMETRY_EVENT* eventRecord)
{
    if (eventRecord == NULL ||
        eventRecord->StructSize != sizeof(KS_TELEMETRY_EVENT) ||
        eventRecord->ProtocolVersion != KS_PROTOCOL_VERSION_CURRENT ||
        eventRecord->EventType < KS_EVENT_PROCESS_CREATE ||
        eventRecord->EventType > KS_EVENT_DROPPED_STATISTICS ||
        (eventRecord->Flags & ~KS_EVENT_FLAGS_KNOWN) != 0u ||
        eventRecord->Reserved0 != 0u || eventRecord->Reserved1 != 0u ||
        eventRecord->PathCapacityCharacters != KS_MAX_PATH_CHARS ||
        eventRecord->PathLengthCharacters >= KS_MAX_PATH_CHARS) {
        return 0;
    }
    return eventRecord->ImagePath[eventRecord->PathLengthCharacters] == 0u;
}

