#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include "../../shared/Protocol.h"
#include "../../shared/ProtocolValidation.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

class Handle final {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) noexcept : value_(value) {}
    ~Handle() noexcept { if (Valid()) (void)CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    [[nodiscard]] bool Valid() const noexcept
    {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
    [[nodiscard]] HANDLE Get() const noexcept { return value_; }

private:
    HANDLE value_;
};

std::size_t g_Failures = 0u;

void Check(const bool condition, const char* name)
{
    if (condition) {
        std::cout << "[PASS] " << name << '\n';
    } else {
        ++g_Failures;
        std::cerr << "[FAIL] " << name << " (Win32=" << GetLastError() << ")\n";
    }
}

void InitializeHeader(
    KS_PROTOCOL_HEADER& header,
    const std::uint32_t size,
    const std::uint16_t type)
{
    std::memset(&header, 0, sizeof(header));
    header.StructSize = size;
    header.ProtocolVersion = KS_PROTOCOL_VERSION_CURRENT;
    header.MessageType = type;
    header.CorrelationId = 0x4b53544u;
}

bool ExpectFailure(
    const HANDLE device,
    const DWORD code,
    void* input,
    const DWORD inputSize,
    void* output,
    const DWORD outputSize)
{
    DWORD returned = 0u;
    SetLastError(ERROR_SUCCESS);
    const BOOL success = DeviceIoControl(device, code, input, inputSize,
        output, outputSize, &returned, nullptr);
    return success == FALSE && returned == 0u;
}

bool Query(const HANDLE device)
{
    KS_QUERY_REQUEST request{};
    KS_QUERY_RESPONSE response{};
    InitializeHeader(request.Header, static_cast<std::uint32_t>(sizeof(request)),
        KS_MESSAGE_QUERY_REQUEST);
    DWORD returned = 0u;
    return DeviceIoControl(device, KS_IOCTL_QUERY_PROTOCOL,
        &request, static_cast<DWORD>(sizeof(request)),
        &response, static_cast<DWORD>(sizeof(response)), &returned, nullptr) &&
        returned == sizeof(response) &&
        KsValidateResponseHeader(&response.Header, returned, KS_MESSAGE_QUERY_RESPONSE);
}

void GenerateProcess()
{
    std::array<wchar_t, 32u> command{};
    (void)wcscpy_s(command.data(), command.size(), L"cmd.exe /c exit 0");
    STARTUPINFOW startup{};
    startup.cb = static_cast<DWORD>(sizeof(startup));
    PROCESS_INFORMATION process{};
    if (CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", command.data(),
            nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        (void)WaitForSingleObject(process.hProcess, 5000u);
        (void)CloseHandle(process.hThread);
        (void)CloseHandle(process.hProcess);
    }
}

}  // namespace

int wmain(const int argc, wchar_t* argv[])
{
    const bool overflow = argc == 2 && std::wstring(argv[1]) == L"--overflow";
    Handle device(CreateFileW(L"\\\\.\\KernelScope", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!device.Valid()) {
        std::cerr << "Open failed: " << GetLastError() << '\n';
        return 2;
    }

    Check(Query(device.Get()), "protocol negotiation");

    KS_QUERY_REQUEST query{};
    KS_QUERY_RESPONSE queryResponse{};
    InitializeHeader(query.Header, static_cast<std::uint32_t>(sizeof(query)),
        KS_MESSAGE_QUERY_REQUEST);
    constexpr DWORD invalidIoctl = CTL_CODE(KS_DEVICE_TYPE, 0x8ffu,
        METHOD_BUFFERED, FILE_READ_DATA);
    Check(ExpectFailure(device.Get(), invalidIoctl, &query,
        static_cast<DWORD>(sizeof(query)), &queryResponse,
        static_cast<DWORD>(sizeof(queryResponse))), "invalid IOCTL");
    Check(ExpectFailure(device.Get(), KS_IOCTL_QUERY_PROTOCOL, &query,
        static_cast<DWORD>(sizeof(query) - 1u), &queryResponse,
        static_cast<DWORD>(sizeof(queryResponse))), "undersized input");
    Check(ExpectFailure(device.Get(), KS_IOCTL_QUERY_PROTOCOL, &query,
        static_cast<DWORD>(sizeof(query)), &queryResponse,
        static_cast<DWORD>(sizeof(queryResponse) - 1u)), "undersized output");
    std::array<std::byte, sizeof(KS_QUERY_RESPONSE) + 8u> oversizedOutput{};
    Check(ExpectFailure(device.Get(), KS_IOCTL_QUERY_PROTOCOL, &query,
        static_cast<DWORD>(sizeof(query)), oversizedOutput.data(),
        static_cast<DWORD>(oversizedOutput.size())), "oversized output");

    std::array<std::byte, sizeof(KS_QUERY_REQUEST) + 8u> oversized{};
    std::memcpy(oversized.data(), &query, sizeof(query));
    Check(ExpectFailure(device.Get(), KS_IOCTL_QUERY_PROTOCOL, oversized.data(),
        static_cast<DWORD>(oversized.size()), &queryResponse,
        static_cast<DWORD>(sizeof(queryResponse))), "oversized input");

    query.Header.ProtocolVersion = 0xffffu;
    Check(ExpectFailure(device.Get(), KS_IOCTL_QUERY_PROTOCOL, &query,
        static_cast<DWORD>(sizeof(query)), &queryResponse,
        static_cast<DWORD>(sizeof(queryResponse))), "unsupported version");
    InitializeHeader(query.Header, static_cast<std::uint32_t>(sizeof(query)),
        KS_MESSAGE_QUERY_REQUEST);
    query.Header.Reserved = 1u;
    Check(ExpectFailure(device.Get(), KS_IOCTL_QUERY_PROTOCOL, &query,
        static_cast<DWORD>(sizeof(query)), &queryResponse,
        static_cast<DWORD>(sizeof(queryResponse))), "nonzero reserved field");
    query.Header.Reserved = 0u;
    query.Header.Flags = 0x80000000u;
    Check(ExpectFailure(device.Get(), KS_IOCTL_QUERY_PROTOCOL, &query,
        static_cast<DWORD>(sizeof(query)), &queryResponse,
        static_cast<DWORD>(sizeof(queryResponse))), "unknown flags");
    query.Header.Flags = 0u;
    query.Header.MessageType = 0xffffu;
    Check(ExpectFailure(device.Get(), KS_IOCTL_QUERY_PROTOCOL, &query,
        static_cast<DWORD>(sizeof(query)), &queryResponse,
        static_cast<DWORD>(sizeof(queryResponse))), "unknown message type");

    KS_GET_EVENTS_REQUEST events{};
    InitializeHeader(events.Header, static_cast<std::uint32_t>(sizeof(events)),
        KS_MESSAGE_GET_EVENTS_REQUEST);
    events.MaximumEvents = 0u;
    std::vector<std::byte> batch(sizeof(KS_GET_EVENTS_RESPONSE));
    Check(ExpectFailure(device.Get(), KS_IOCTL_GET_EVENTS, &events,
        static_cast<DWORD>(sizeof(events)), batch.data(),
        static_cast<DWORD>(batch.size())), "zero-length batch");
    events.MaximumEvents = KS_MAX_BATCH_EVENTS + 1u;
    Check(ExpectFailure(device.Get(), KS_IOCTL_GET_EVENTS, &events,
        static_cast<DWORD>(sizeof(events)), batch.data(),
        static_cast<DWORD>(batch.size())), "oversized event count");
    events.MaximumEvents = 1u;
    events.Reserved32 = 1u;
    Check(ExpectFailure(device.Get(), KS_IOCTL_GET_EVENTS, &events,
        static_cast<DWORD>(sizeof(events)), batch.data(),
        KsBatchResponseSize(events.MaximumEvents)), "batch reserved field");
    events.Reserved32 = 0u;

    for (int index = 0; index < 20; ++index) {
        Handle repeated(CreateFileW(L"\\\\.\\KernelScope", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr));
        Check(repeated.Valid(), "repeated open/close");
    }

    GenerateProcess();
    events.MaximumEvents = KS_MAX_BATCH_EVENTS;
    const DWORD expectedBatch = KsBatchResponseSize(events.MaximumEvents);
    DWORD returned = 0u;
    const BOOL retrieved = DeviceIoControl(device.Get(), KS_IOCTL_GET_EVENTS,
        &events, static_cast<DWORD>(sizeof(events)), batch.data(), expectedBatch,
        &returned, nullptr);
    Check(retrieved && returned == expectedBatch, "valid telemetry retrieval");

    KS_RESET_STATISTICS_REQUEST reset{};
    KS_STATISTICS_RESPONSE statistics{};
    InitializeHeader(reset.Header, static_cast<std::uint32_t>(sizeof(reset)),
        KS_MESSAGE_RESET_STATISTICS_REQUEST);
    reset.ResetFlags = KS_RESET_COUNTERS;
    Check(ExpectFailure(device.Get(), KS_IOCTL_RESET_STATISTICS, &reset,
        static_cast<DWORD>(sizeof(reset)), &statistics,
        static_cast<DWORD>(sizeof(statistics))), "reset denied on read-only handle");

    if (overflow) {
        for (std::size_t index = 0u; index < KS_RING_CAPACITY + 256u; ++index) {
            GenerateProcess();
        }
        KS_STATISTICS_REQUEST request{};
        InitializeHeader(request.Header, static_cast<std::uint32_t>(sizeof(request)),
            KS_MESSAGE_GET_STATISTICS_REQUEST);
        returned = 0u;
        const BOOL statsOk = DeviceIoControl(device.Get(), KS_IOCTL_GET_STATISTICS,
            &request, static_cast<DWORD>(sizeof(request)), &statistics,
            static_cast<DWORD>(sizeof(statistics)), &returned, nullptr);
        Check(statsOk && statistics.EventsDropped != 0u, "ring overflow accounting");
    }

    std::cout << "Integration failures=" << g_Failures << '\n';
    return g_Failures == 0u ? 0 : 1;
}
