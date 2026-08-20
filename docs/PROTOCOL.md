# Protocol version 1

## Purpose

The KernelScope protocol is the only application-defined trust boundary between
the KMDF driver and user-mode clients. It is defined in `shared/Protocol.h` and
validated by both `shared/ProtocolValidation.h` and component-specific checks.

The protocol is designed to remain deterministic across Windows x64 builds. It
contains no pointers, handles, `size_t`, flexible arrays, bitfields, native
enums, or architecture-dependent integer fields.

## Transport and access

All control codes use `METHOD_BUFFERED`. The I/O manager owns the system buffer;
the driver does not dereference a caller-provided pointer.

| IOCTL | Function | Required access | Method |
| --- | ---: | --- | --- |
| `KS_IOCTL_QUERY_PROTOCOL` | `0x800` | `FILE_READ_DATA` | `METHOD_BUFFERED` |
| `KS_IOCTL_GET_EVENTS` | `0x801` | `FILE_READ_DATA` | `METHOD_BUFFERED` |
| `KS_IOCTL_GET_STATISTICS` | `0x802` | `FILE_READ_DATA` | `METHOD_BUFFERED` |
| `KS_IOCTL_RESET_STATISTICS` | `0x803` | `FILE_WRITE_DATA` | `METHOD_BUFFERED` |

The device ACL allows only LocalSystem and built-in Administrators. The reset
operation adds an independent write-access requirement enforced by the I/O
manager before driver dispatch.

## Common header

Every request and response starts with `KS_PROTOCOL_HEADER`.

| Offset | Size | Field | Rule |
| ---: | ---: | --- | --- |
| `0` | `4` | `StructSize` | Exact request or returned response byte count |
| `4` | `2` | `ProtocolVersion` | Must equal `1` |
| `6` | `2` | `MessageType` | Must be a known request/response type |
| `8` | `4` | `Flags` | Must be zero in protocol messages |
| `12` | `4` | `Reserved` | Must be zero |
| `16` | `8` | `Sequence` | Zero in requests; response-specific in replies |
| `24` | `8` | `CorrelationId` | Chosen by the client and echoed by the driver |

Total size: **32 bytes**.

## Message types

| Value | Symbol | Direction |
| ---: | --- | --- |
| `1` | `KS_MESSAGE_QUERY_REQUEST` | User to kernel |
| `2` | `KS_MESSAGE_QUERY_RESPONSE` | Kernel to user |
| `3` | `KS_MESSAGE_GET_EVENTS_REQUEST` | User to kernel |
| `4` | `KS_MESSAGE_GET_EVENTS_RESPONSE` | Kernel to user |
| `5` | `KS_MESSAGE_GET_STATISTICS_REQUEST` | User to kernel |
| `6` | `KS_MESSAGE_GET_STATISTICS_RESPONSE` | Kernel to user |
| `7` | `KS_MESSAGE_RESET_STATISTICS_REQUEST` | User to kernel |
| `8` | `KS_MESSAGE_RESET_STATISTICS_RESPONSE` | Kernel to user |

Unknown message types are rejected.

## Query protocol

`KS_QUERY_REQUEST` contains only the 32-byte header.

`KS_QUERY_RESPONSE` is 64 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| `0` | `32` | Common header |
| `32` | `2` | Minimum protocol version |
| `34` | `2` | Maximum protocol version |
| `36` | `2` | Negotiated protocol version |
| `38` | `2` | Reserved, zero |
| `40` | `8` | Capability bitmask |
| `48` | `4` | Maximum batch events (`64`) |
| `52` | `4` | Maximum path characters (`260`) |
| `56` | `4` | Ring capacity (`1024`) |
| `60` | `4` | Reserved, zero |

Current capabilities cover process events, image events, dropped-event records,
statistics, and statistics reset.

## Telemetry event record

`KS_TELEMETRY_EVENT` is exactly 600 bytes.

| Offset | Size | Field | Meaning |
| ---: | ---: | --- | --- |
| `0` | `4` | `StructSize` | Must equal `600` |
| `4` | `2` | `ProtocolVersion` | Must equal `1` |
| `6` | `2` | `EventType` | Known event type |
| `8` | `4` | `Flags` | Only defined event flags |
| `12` | `4` | `Reserved0` | Zero |
| `16` | `8` | `Sequence` | Monotonic driver sequence |
| `24` | `8` | `Timestamp100ns` | Windows system time in 100 ns units |
| `32` | `8` | `ProcessId` | Zero when not applicable |
| `40` | `8` | `ParentProcessId` | Zero when unavailable |
| `48` | `8` | `ImageBase` | Image base when supplied by callback metadata |
| `56` | `8` | `ImageSize` | Image size when supplied by callback metadata |
| `64` | `8` | `AuxiliaryValue` | Drop count for synthetic drop events |
| `72` | `2` | `PathLengthCharacters` | Excludes NUL; must be less than `260` |
| `74` | `2` | `PathCapacityCharacters` | Must equal `260` |
| `76` | `4` | `Reserved1` | Zero |
| `80` | `520` | `ImagePath` | `WCHAR[260]`, always NUL-terminated |

### Event types

| Value | Symbol |
| ---: | --- |
| `1` | `KS_EVENT_PROCESS_CREATE` |
| `2` | `KS_EVENT_PROCESS_EXIT` |
| `3` | `KS_EVENT_EXECUTABLE_IMAGE_LOAD` |
| `4` | `KS_EVENT_DLL_IMAGE_LOAD` |
| `5` | `KS_EVENT_KERNEL_DRIVER_IMAGE_LOAD` |
| `6` | `KS_EVENT_DROPPED_STATISTICS` |

### Event flags

| Bit | Symbol | Meaning |
| ---: | --- | --- |
| `0x00000001` | `KS_EVENT_FLAG_PATH_TRUNCATED` | Source path exceeded the protocol bound |
| `0x00000002` | `KS_EVENT_FLAG_SYSTEM_MODE_IMAGE` | Callback identified a system-mode image |
| `0x00000004` | `KS_EVENT_FLAG_SYNTHETIC` | Driver created a bookkeeping record |

Unknown event flags are rejected by the collector.

## Event batch

`KS_GET_EVENTS_REQUEST` is 40 bytes: the common header, `MaximumEvents`, and one
zero-required 32-bit reserved field. `MaximumEvents` must be between 1 and 64.

The response uses a fixed-array C structure but returns only the exact requested
capacity:

```text
response bytes = 64 + MaximumEvents × 600
```

| Offset | Size | Field |
| ---: | ---: | --- |
| `0` | `32` | Common header |
| `32` | `4` | Delivered event count |
| `36` | `4` | Remaining ring depth |
| `40` | `8` | First delivered sequence, or zero |
| `48` | `8` | Last delivered sequence, or zero |
| `56` | `8` | Total events dropped since the last counter reset |
| `64` | variable | Up to the requested number of 600-byte events |

The response header's `Sequence` equals the last delivered event sequence, or
zero for an empty batch.

## Statistics and reset

`KS_STATISTICS_RESPONSE` is 80 bytes and contains:

- next sequence number;
- events written;
- events read;
- events dropped;
- fixed ring capacity;
- current ring depth;
- two zero-required reserved fields.

`KS_RESET_STATISTICS_REQUEST` is 48 bytes. `ResetFlags` must equal
`KS_RESET_COUNTERS`, and all three reserved fields must be zero. Reset clears
the counters and pending synthetic-drop count but does not reset the monotonic
sequence or discard queued events.

## Sequence and drop semantics

Sequence zero is reserved. Each attempted event consumes a sequence number when
possible, including events dropped because the ring is full. A later delivered
record therefore exposes a gap.

When capacity becomes available, the driver emits a synthetic dropped-event
record before a current event when at least two slots are free. Its
`AuxiliaryValue` reports the number of pending drops. Counters and sequence
handling saturate instead of wrapping.

## Validation rules

The driver rejects a request when any of these conditions is true:

- input size is not exact;
- output size is not exact for the operation/requested batch capacity;
- structure size does not match the actual byte count;
- protocol version or message type is unsupported;
- protocol flags, reserved fields, or request sequence are nonzero;
- reset flags are malformed;
- batch capacity is zero or greater than 64;
- IOCTL code is unknown.

Every failure completes with zero output bytes.

The collector independently validates:

- exact returned size and response message type;
- echoed correlation ID;
- response sequence rules;
- capabilities and advertised bounds;
- event count, ring depth, and first/last sequence summaries;
- every event structure, event type, flag set, path bound, terminator, and
  monotonic order.

Any validation failure stops collection with a protocol error instead of
attempting to recover from untrusted data.

## Versioning policy

Protocol version changes are independent of repository semantic versions.

- Backward-compatible implementation changes do not change the protocol version.
- A field-layout, semantic, flag, message, or validation change requires an
  explicit compatibility review.
- Breaking ABI changes require a new protocol version and new compile-time
  size/offset assertions.
- The driver must never silently reinterpret a version 1 field.
- The collector must negotiate before collection and reject unsupported versions.

See [`docs/RELEASE.md`](RELEASE.md) for release versioning and evidence rules.

