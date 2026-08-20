#include "DeviceClient.h"

#include "../shared/ProtocolValidation.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <utility>

namespace kernelscope {
namespace {

void InitializeHeader(
    KS_PROTOCOL_HEADER& header,
    const std::uint32_t size,
    const std::uint16_t type,
    const std::uint64_t correlation) noexcept
{
    std::memset(&header, 0, sizeof(header));
    header.StructSize = size;
    header.ProtocolVersion = KS_PROTOCOL_VERSION_CURRENT;
    header.MessageType = type;
    header.CorrelationId = correlation;
}

bool DeviceControl(
    const HANDLE device,
    const DWORD code,
    const void* input,
    const DWORD inputBytes,
    void* output,
    const DWORD outputBytes,
    DWORD& returned,
    std::string& error)
{
    returned = 0u;
    if (!DeviceIoControl(device, code, const_cast<void*>(input), inputBytes,
            output, outputBytes, &returned, nullptr)) {
        const DWORD lastError = GetLastError();
        error = "DeviceIoControl failed: " + Win32ErrorMessage(lastError);
        return false;
    }
    return true;
}

bool ValidateStatistics(
    const KS_STATISTICS_RESPONSE& response,
    const DWORD returned,
    const std::uint16_t type,
    const std::uint64_t correlation,
    std::string& error)
{
    if (returned != sizeof(response) ||
        !KsValidateResponseHeader(&response.Header, returned, type) ||
        response.Header.CorrelationId != correlation ||
        response.Header.Sequence != 0u ||
        response.Reserved32[0] != 0u || response.Reserved32[1] != 0u ||
        response.NextSequence == 0u ||
        response.RingCapacity != KS_RING_CAPACITY ||
        response.CurrentDepth > response.RingCapacity) {
        error = "The driver returned a malformed statistics response.";
        return false;
    }
    return true;
}

}  // namespace

UniqueHandle::~UniqueHandle() noexcept
{
    reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.handle_)
{
    other.handle_ = INVALID_HANDLE_VALUE;
}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept
{
    if (this != &other) {
        reset();
        handle_ = other.handle_;
        other.handle_ = INVALID_HANDLE_VALUE;
    }
    return *this;
}

bool UniqueHandle::valid() const noexcept
{
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
}

void UniqueHandle::reset(const HANDLE replacement) noexcept
{
    if (valid()) {
        (void)CloseHandle(handle_);
    }
    handle_ = replacement;
}

std::string Win32ErrorMessage(const DWORD error)
{
    LPWSTR message = nullptr;
    const DWORD characters = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&message),
        0u,
        nullptr);
    if (characters == 0u || message == nullptr) {
        return "Win32 error " + std::to_string(error);
    }
    std::size_t messageLength = wcslen(message);
    while (messageLength != 0u &&
        (message[messageLength - 1u] == L'\r' || message[messageLength - 1u] == L'\n')) {
        message[--messageLength] = L'\0';
    }
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        message, -1, nullptr, 0, nullptr, nullptr);
    std::string text;
    if (required > 1) {
        text.resize(static_cast<std::size_t>(required));
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                message, -1, text.data(), required, nullptr, nullptr) == required) {
            text.pop_back();
        } else {
            text.clear();
        }
    }
    LocalFree(message);
    return text.empty() ? "Win32 error " + std::to_string(error) : text;
}

bool DeviceClient::Open(const bool requestWriteAccess, std::string& error)
{
    error.clear();
    const DWORD access = GENERIC_READ | (requestWriteAccess ? GENERIC_WRITE : 0u);
    HANDLE handle = CreateFileW(L"\\\\.\\KernelScope", access,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        error = "Could not open \\\\.\\KernelScope: " + Win32ErrorMessage(GetLastError());
        return false;
    }
    device_.reset(handle);
    writeAccess_ = requestWriteAccess;
    negotiated_ = false;
    return true;
}

std::uint64_t DeviceClient::NextCorrelation() noexcept
{
    if (correlation_ == std::numeric_limits<std::uint64_t>::max()) {
        correlation_ = 1u;
    }
    return correlation_++;
}

bool DeviceClient::Negotiate(KS_QUERY_RESPONSE& response, std::string& error)
{
    error.clear();
    if (!device_.valid()) {
        error = "The driver device is not open.";
        return false;
    }
    KS_QUERY_REQUEST request{};
    const auto correlation = NextCorrelation();
    InitializeHeader(request.Header, static_cast<std::uint32_t>(sizeof(request)),
        KS_MESSAGE_QUERY_REQUEST, correlation);
    DWORD returned = 0u;
    if (!DeviceControl(device_.get(), KS_IOCTL_QUERY_PROTOCOL,
            &request, static_cast<DWORD>(sizeof(request)), &response,
            static_cast<DWORD>(sizeof(response)), returned, error)) {
        return false;
    }
    if (returned != sizeof(response) ||
        !KsValidateResponseHeader(&response.Header, returned, KS_MESSAGE_QUERY_RESPONSE) ||
        response.Header.CorrelationId != correlation || response.Header.Sequence != 0u ||
        response.Reserved16 != 0u || response.Reserved32 != 0u ||
        response.MinimumProtocolVersion > KS_PROTOCOL_VERSION_CURRENT ||
        response.MaximumProtocolVersion < KS_PROTOCOL_VERSION_CURRENT ||
        response.NegotiatedProtocolVersion != KS_PROTOCOL_VERSION_CURRENT ||
        response.MaximumBatchEvents == 0u || response.MaximumBatchEvents > KS_MAX_BATCH_EVENTS ||
        response.MaximumPathCharacters != KS_MAX_PATH_CHARS ||
        response.RingCapacity != KS_RING_CAPACITY ||
        (response.Capabilities & ~KS_CAPABILITIES_ALL) != 0u ||
        (response.Capabilities & (KS_CAP_PROCESS_EVENTS | KS_CAP_IMAGE_EVENTS |
            KS_CAP_STATISTICS)) !=
            (KS_CAP_PROCESS_EVENTS | KS_CAP_IMAGE_EVENTS | KS_CAP_STATISTICS)) {
        error = "The driver returned a malformed or incompatible query response.";
        return false;
    }
    negotiated_ = true;
    return true;
}

bool DeviceClient::GetEvents(
    const std::uint32_t maximumEvents,
    EventBatch& batch,
    std::string& error)
{
    error.clear();
    batch = {};
    if (!device_.valid() || !negotiated_) {
        error = "Protocol negotiation must succeed before event retrieval.";
        return false;
    }
    const std::uint32_t responseSize = KsBatchResponseSize(maximumEvents);
    if (responseSize == 0u) {
        error = "The requested batch size is outside the protocol bounds.";
        return false;
    }
    KS_GET_EVENTS_REQUEST request{};
    const auto correlation = NextCorrelation();
    InitializeHeader(request.Header, static_cast<std::uint32_t>(sizeof(request)),
        KS_MESSAGE_GET_EVENTS_REQUEST, correlation);
    request.MaximumEvents = maximumEvents;

    std::vector<std::byte> buffer(responseSize);
    DWORD returned = 0u;
    if (!DeviceControl(device_.get(), KS_IOCTL_GET_EVENTS,
            &request, static_cast<DWORD>(sizeof(request)), buffer.data(),
            responseSize, returned, error)) {
        return false;
    }
    if (returned != responseSize) {
        error = "The driver returned an unexpected batch response size.";
        return false;
    }
    const auto* response = reinterpret_cast<const KS_GET_EVENTS_RESPONSE*>(buffer.data());
    if (!KsValidateResponseHeader(&response->Header, returned,
            KS_MESSAGE_GET_EVENTS_RESPONSE) ||
        response->Header.CorrelationId != correlation ||
        response->EventCount > maximumEvents ||
        response->RemainingEventCount > KS_RING_CAPACITY ||
        (response->EventCount == 0u &&
            (response->FirstSequence != 0u || response->LastSequence != 0u ||
             response->Header.Sequence != 0u))) {
        error = "The driver returned a malformed event-batch header.";
        return false;
    }
    for (std::uint32_t index = 0u; index < response->EventCount; ++index) {
        if (!KsValidateEvent(&response->Events[index]) ||
            (index != 0u && response->Events[index].Sequence <=
                response->Events[index - 1u].Sequence)) {
            error = "The driver returned an invalid or non-monotonic event record.";
            return false;
        }
    }
    if (response->EventCount != 0u &&
        (response->FirstSequence != response->Events[0].Sequence ||
         response->LastSequence != response->Events[response->EventCount - 1u].Sequence ||
         response->Header.Sequence != response->LastSequence)) {
        error = "The event-batch sequence summary is inconsistent.";
        return false;
    }
    batch.events.assign(response->Events, response->Events + response->EventCount);
    batch.remaining = response->RemainingEventCount;
    batch.droppedTotal = response->DroppedTotal;
    return true;
}

bool DeviceClient::GetStatistics(
    KS_STATISTICS_RESPONSE& response,
    std::string& error)
{
    error.clear();
    if (!device_.valid() || !negotiated_) {
        error = "Protocol negotiation must succeed before statistics retrieval.";
        return false;
    }
    KS_STATISTICS_REQUEST request{};
    const auto correlation = NextCorrelation();
    InitializeHeader(request.Header, static_cast<std::uint32_t>(sizeof(request)),
        KS_MESSAGE_GET_STATISTICS_REQUEST, correlation);
    DWORD returned = 0u;
    if (!DeviceControl(device_.get(), KS_IOCTL_GET_STATISTICS,
            &request, static_cast<DWORD>(sizeof(request)), &response,
            static_cast<DWORD>(sizeof(response)), returned, error)) {
        return false;
    }
    return ValidateStatistics(response, returned,
        KS_MESSAGE_GET_STATISTICS_RESPONSE, correlation, error);
}

bool DeviceClient::ResetStatistics(
    KS_STATISTICS_RESPONSE& response,
    std::string& error)
{
    error.clear();
    if (!device_.valid() || !negotiated_ || !writeAccess_) {
        error = "Statistics reset requires a negotiated write-capable handle.";
        return false;
    }
    KS_RESET_STATISTICS_REQUEST request{};
    const auto correlation = NextCorrelation();
    InitializeHeader(request.Header, static_cast<std::uint32_t>(sizeof(request)),
        KS_MESSAGE_RESET_STATISTICS_REQUEST, correlation);
    request.ResetFlags = KS_RESET_COUNTERS;
    DWORD returned = 0u;
    if (!DeviceControl(device_.get(), KS_IOCTL_RESET_STATISTICS,
            &request, static_cast<DWORD>(sizeof(request)), &response,
            static_cast<DWORD>(sizeof(response)), returned, error)) {
        return false;
    }
    return ValidateStatistics(response, returned,
        KS_MESSAGE_RESET_STATISTICS_RESPONSE, correlation, error);
}

}  // namespace kernelscope
