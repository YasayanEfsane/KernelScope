#include "TestHarness.h"

#include "../shared/Protocol.h"
#include "../shared/ProtocolValidation.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {

KS_PROTOCOL_HEADER MakeHeader(const std::uint16_t type, const std::uint32_t size)
{
    KS_PROTOCOL_HEADER header{};
    header.StructSize = size;
    header.ProtocolVersion = KS_PROTOCOL_VERSION_CURRENT;
    header.MessageType = type;
    header.CorrelationId = 42u;
    return header;
}

}  // namespace

KS_TEST_CASE("Protocol structure sizes and offsets are exact")
{
    KS_REQUIRE(sizeof(KS_PROTOCOL_HEADER) == 32u);
    KS_REQUIRE(sizeof(KS_QUERY_RESPONSE) == 64u);
    KS_REQUIRE(sizeof(KS_TELEMETRY_EVENT) == 600u);
    KS_REQUIRE(offsetof(KS_TELEMETRY_EVENT, ImagePath) == 80u);
    KS_REQUIRE(KS_GET_EVENTS_RESPONSE_BASE_SIZE == 64u);
    KS_REQUIRE(sizeof(KS_GET_EVENTS_RESPONSE) == 38464u);
    KS_REQUIRE(sizeof(KS_STATISTICS_RESPONSE) == 80u);
}

KS_TEST_CASE("Every IOCTL uses METHOD_BUFFERED and the intended access")
{
    KS_REQUIRE((KS_IOCTL_QUERY_PROTOCOL & 3u) == METHOD_BUFFERED);
    KS_REQUIRE((KS_IOCTL_GET_EVENTS & 3u) == METHOD_BUFFERED);
    KS_REQUIRE((KS_IOCTL_GET_STATISTICS & 3u) == METHOD_BUFFERED);
    KS_REQUIRE((KS_IOCTL_RESET_STATISTICS & 3u) == METHOD_BUFFERED);
    KS_REQUIRE(((KS_IOCTL_QUERY_PROTOCOL >> 14u) & 3u) == FILE_READ_DATA);
    KS_REQUIRE(((KS_IOCTL_GET_EVENTS >> 14u) & 3u) == FILE_READ_DATA);
    KS_REQUIRE(((KS_IOCTL_GET_STATISTICS >> 14u) & 3u) == FILE_READ_DATA);
    KS_REQUIRE(((KS_IOCTL_RESET_STATISTICS >> 14u) & 3u) == FILE_WRITE_DATA);
}

KS_TEST_CASE("Batch sizes reject zero and values above the maximum")
{
    KS_REQUIRE(KsBatchResponseSize(0u) == 0u);
    KS_REQUIRE(KsBatchResponseSize(1u) == 664u);
    KS_REQUIRE(KsBatchResponseSize(KS_MAX_BATCH_EVENTS) == sizeof(KS_GET_EVENTS_RESPONSE));
    KS_REQUIRE(KsBatchResponseSize(KS_MAX_BATCH_EVENTS + 1u) == 0u);
}

KS_TEST_CASE("Request validation rejects versions flags sequence and reserved data")
{
    constexpr auto requestSize = static_cast<std::uint32_t>(sizeof(KS_QUERY_REQUEST));
    auto header = MakeHeader(KS_MESSAGE_QUERY_REQUEST, requestSize);
    KS_REQUIRE(KsValidateRequestHeader(&header, requestSize,
        requestSize, KS_MESSAGE_QUERY_REQUEST));
    header.ProtocolVersion = 0xffffu;
    KS_REQUIRE(!KsValidateRequestHeader(&header, requestSize,
        requestSize, KS_MESSAGE_QUERY_REQUEST));
    header = MakeHeader(KS_MESSAGE_QUERY_REQUEST, requestSize);
    header.Flags = 1u;
    KS_REQUIRE(!KsValidateRequestHeader(&header, requestSize,
        requestSize, KS_MESSAGE_QUERY_REQUEST));
    header = MakeHeader(KS_MESSAGE_QUERY_REQUEST, requestSize);
    header.Reserved = 1u;
    KS_REQUIRE(!KsValidateRequestHeader(&header, requestSize,
        requestSize, KS_MESSAGE_QUERY_REQUEST));
    header = MakeHeader(KS_MESSAGE_QUERY_REQUEST, requestSize);
    header.Sequence = 1u;
    KS_REQUIRE(!KsValidateRequestHeader(&header, requestSize,
        requestSize, KS_MESSAGE_QUERY_REQUEST));
}

KS_TEST_CASE("Event validation rejects unknown flags and invalid paths")
{
    KS_TELEMETRY_EVENT eventRecord{};
    eventRecord.StructSize = static_cast<UINT32>(sizeof(eventRecord));
    eventRecord.ProtocolVersion = KS_PROTOCOL_VERSION_CURRENT;
    eventRecord.EventType = KS_EVENT_PROCESS_CREATE;
    eventRecord.PathCapacityCharacters = KS_MAX_PATH_CHARS;
    KS_REQUIRE(KsValidateEvent(&eventRecord));
    eventRecord.Flags = 0x80000000u;
    KS_REQUIRE(!KsValidateEvent(&eventRecord));
    eventRecord.Flags = 0u;
    eventRecord.PathLengthCharacters = KS_MAX_PATH_CHARS;
    KS_REQUIRE(!KsValidateEvent(&eventRecord));
}
