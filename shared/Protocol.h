#pragma once

/*
 * KernelScope wire protocol.
 *
 * The ABI deliberately contains no pointers, handles, size_t values, enums,
 * bitfields, flexible arrays, or native-width integer fields. Every request
 * uses METHOD_BUFFERED and is validated independently at the trust boundary.
 */

#include <stddef.h>

#if defined(_KERNEL_MODE)
#include <ntddk.h>
#include <wdm.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winioctl.h>
#else
#include <stdint.h>
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uint16_t WCHAR;
#define FILE_DEVICE_UNKNOWN 0x00000022u
#define METHOD_BUFFERED 0u
#define FILE_READ_DATA 0x0001u
#define FILE_WRITE_DATA 0x0002u
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16u) | ((Access) << 14u) | ((Function) << 2u) | (Method))
#ifndef _In_
#define _In_
#define _In_opt_
#define _Out_
#define _Out_opt_
#define _Out_writes_(Count)
#define _In_reads_(Count)
#endif
#endif

#if defined(__cplusplus)
#define KS_STATIC_ASSERT(Expression, Message) static_assert((Expression), Message)
#elif defined(_MSC_VER)
#define KS_STATIC_ASSERT(Expression, Message) C_ASSERT(Expression)
#else
#define KS_STATIC_ASSERT(Expression, Message) _Static_assert((Expression), Message)
#endif

#define KS_PROTOCOL_VERSION_MIN 1u
#define KS_PROTOCOL_VERSION_MAX 1u
#define KS_PROTOCOL_VERSION_CURRENT 1u

#define KS_DEVICE_TYPE 0x8300u
#define KS_MAX_PATH_CHARS 260u
#define KS_MAX_BATCH_EVENTS 64u
#define KS_RING_CAPACITY 1024u

#define KS_IOCTL_QUERY_PROTOCOL \
    CTL_CODE(KS_DEVICE_TYPE, 0x800u, METHOD_BUFFERED, FILE_READ_DATA)
#define KS_IOCTL_GET_EVENTS \
    CTL_CODE(KS_DEVICE_TYPE, 0x801u, METHOD_BUFFERED, FILE_READ_DATA)
#define KS_IOCTL_GET_STATISTICS \
    CTL_CODE(KS_DEVICE_TYPE, 0x802u, METHOD_BUFFERED, FILE_READ_DATA)
#define KS_IOCTL_RESET_STATISTICS \
    CTL_CODE(KS_DEVICE_TYPE, 0x803u, METHOD_BUFFERED, FILE_WRITE_DATA)

/* MessageType values. */
#define KS_MESSAGE_QUERY_REQUEST 1u
#define KS_MESSAGE_QUERY_RESPONSE 2u
#define KS_MESSAGE_GET_EVENTS_REQUEST 3u
#define KS_MESSAGE_GET_EVENTS_RESPONSE 4u
#define KS_MESSAGE_GET_STATISTICS_REQUEST 5u
#define KS_MESSAGE_GET_STATISTICS_RESPONSE 6u
#define KS_MESSAGE_RESET_STATISTICS_REQUEST 7u
#define KS_MESSAGE_RESET_STATISTICS_RESPONSE 8u

/* EventType values. */
#define KS_EVENT_PROCESS_CREATE 1u
#define KS_EVENT_PROCESS_EXIT 2u
#define KS_EVENT_EXECUTABLE_IMAGE_LOAD 3u
#define KS_EVENT_DLL_IMAGE_LOAD 4u
#define KS_EVENT_KERNEL_DRIVER_IMAGE_LOAD 5u
#define KS_EVENT_DROPPED_STATISTICS 6u

/* Event flags; protocol-message flags are currently required to be zero. */
#define KS_EVENT_FLAG_PATH_TRUNCATED 0x00000001u
#define KS_EVENT_FLAG_SYSTEM_MODE_IMAGE 0x00000002u
#define KS_EVENT_FLAG_SYNTHETIC 0x00000004u
#define KS_EVENT_FLAGS_KNOWN \
    (KS_EVENT_FLAG_PATH_TRUNCATED | KS_EVENT_FLAG_SYSTEM_MODE_IMAGE | KS_EVENT_FLAG_SYNTHETIC)

#define KS_CAP_PROCESS_EVENTS 0x0000000000000001ull
#define KS_CAP_IMAGE_EVENTS 0x0000000000000002ull
#define KS_CAP_DROP_EVENTS 0x0000000000000004ull
#define KS_CAP_STATISTICS 0x0000000000000008ull
#define KS_CAP_RESET_STATISTICS 0x0000000000000010ull
#define KS_CAPABILITIES_ALL \
    (KS_CAP_PROCESS_EVENTS | KS_CAP_IMAGE_EVENTS | KS_CAP_DROP_EVENTS | \
     KS_CAP_STATISTICS | KS_CAP_RESET_STATISTICS)

#define KS_RESET_COUNTERS 0x00000001u
#define KS_RESET_FLAGS_KNOWN KS_RESET_COUNTERS

#pragma pack(push, 8)

typedef struct _KS_PROTOCOL_HEADER {
    UINT32 StructSize;
    UINT16 ProtocolVersion;
    UINT16 MessageType;
    UINT32 Flags;
    UINT32 Reserved;
    UINT64 Sequence;
    UINT64 CorrelationId;
} KS_PROTOCOL_HEADER;

typedef struct _KS_QUERY_REQUEST {
    KS_PROTOCOL_HEADER Header;
} KS_QUERY_REQUEST;

typedef struct _KS_QUERY_RESPONSE {
    KS_PROTOCOL_HEADER Header;
    UINT16 MinimumProtocolVersion;
    UINT16 MaximumProtocolVersion;
    UINT16 NegotiatedProtocolVersion;
    UINT16 Reserved16;
    UINT64 Capabilities;
    UINT32 MaximumBatchEvents;
    UINT32 MaximumPathCharacters;
    UINT32 RingCapacity;
    UINT32 Reserved32;
} KS_QUERY_RESPONSE;

typedef struct _KS_GET_EVENTS_REQUEST {
    KS_PROTOCOL_HEADER Header;
    UINT32 MaximumEvents;
    UINT32 Reserved32;
} KS_GET_EVENTS_REQUEST;

typedef struct _KS_TELEMETRY_EVENT {
    UINT32 StructSize;
    UINT16 ProtocolVersion;
    UINT16 EventType;
    UINT32 Flags;
    UINT32 Reserved0;
    UINT64 Sequence;
    UINT64 Timestamp100ns;
    UINT64 ProcessId;
    UINT64 ParentProcessId;
    UINT64 ImageBase;
    UINT64 ImageSize;
    UINT64 AuxiliaryValue;
    UINT16 PathLengthCharacters;
    UINT16 PathCapacityCharacters;
    UINT32 Reserved1;
    WCHAR ImagePath[KS_MAX_PATH_CHARS];
} KS_TELEMETRY_EVENT;

typedef struct _KS_GET_EVENTS_RESPONSE {
    KS_PROTOCOL_HEADER Header;
    UINT32 EventCount;
    UINT32 RemainingEventCount;
    UINT64 FirstSequence;
    UINT64 LastSequence;
    UINT64 DroppedTotal;
    KS_TELEMETRY_EVENT Events[KS_MAX_BATCH_EVENTS];
} KS_GET_EVENTS_RESPONSE;

typedef struct _KS_STATISTICS_REQUEST {
    KS_PROTOCOL_HEADER Header;
} KS_STATISTICS_REQUEST;

typedef struct _KS_STATISTICS_RESPONSE {
    KS_PROTOCOL_HEADER Header;
    UINT64 NextSequence;
    UINT64 EventsWritten;
    UINT64 EventsRead;
    UINT64 EventsDropped;
    UINT32 RingCapacity;
    UINT32 CurrentDepth;
    UINT32 Reserved32[2];
} KS_STATISTICS_RESPONSE;

typedef struct _KS_RESET_STATISTICS_REQUEST {
    KS_PROTOCOL_HEADER Header;
    UINT32 ResetFlags;
    UINT32 Reserved32[3];
} KS_RESET_STATISTICS_REQUEST;

#pragma pack(pop)

#define KS_GET_EVENTS_RESPONSE_BASE_SIZE \
    ((UINT32)offsetof(KS_GET_EVENTS_RESPONSE, Events))

KS_STATIC_ASSERT(sizeof(KS_PROTOCOL_HEADER) == 32u, "KS_PROTOCOL_HEADER ABI changed");
KS_STATIC_ASSERT(offsetof(KS_PROTOCOL_HEADER, Sequence) == 16u, "Header.Sequence offset changed");
KS_STATIC_ASSERT(offsetof(KS_PROTOCOL_HEADER, CorrelationId) == 24u, "Header.CorrelationId offset changed");
KS_STATIC_ASSERT(sizeof(KS_QUERY_REQUEST) == 32u, "KS_QUERY_REQUEST ABI changed");
KS_STATIC_ASSERT(sizeof(KS_QUERY_RESPONSE) == 64u, "KS_QUERY_RESPONSE ABI changed");
KS_STATIC_ASSERT(sizeof(KS_GET_EVENTS_REQUEST) == 40u, "KS_GET_EVENTS_REQUEST ABI changed");
KS_STATIC_ASSERT(sizeof(KS_TELEMETRY_EVENT) == 600u, "KS_TELEMETRY_EVENT ABI changed");
KS_STATIC_ASSERT(offsetof(KS_TELEMETRY_EVENT, ImagePath) == 80u, "Event.ImagePath offset changed");
KS_STATIC_ASSERT(KS_GET_EVENTS_RESPONSE_BASE_SIZE == 64u, "Batch base offset changed");
KS_STATIC_ASSERT(sizeof(KS_GET_EVENTS_RESPONSE) == 38464u, "Batch ABI changed");
KS_STATIC_ASSERT(sizeof(KS_STATISTICS_REQUEST) == 32u, "KS_STATISTICS_REQUEST ABI changed");
KS_STATIC_ASSERT(sizeof(KS_STATISTICS_RESPONSE) == 80u, "KS_STATISTICS_RESPONSE ABI changed");
KS_STATIC_ASSERT(sizeof(KS_RESET_STATISTICS_REQUEST) == 48u, "Reset request ABI changed");
KS_STATIC_ASSERT((KS_IOCTL_QUERY_PROTOCOL & 3u) == METHOD_BUFFERED, "Query IOCTL must be buffered");
KS_STATIC_ASSERT((KS_IOCTL_GET_EVENTS & 3u) == METHOD_BUFFERED, "Events IOCTL must be buffered");
KS_STATIC_ASSERT((KS_IOCTL_GET_STATISTICS & 3u) == METHOD_BUFFERED, "Stats IOCTL must be buffered");
KS_STATIC_ASSERT((KS_IOCTL_RESET_STATISTICS & 3u) == METHOD_BUFFERED, "Reset IOCTL must be buffered");
