#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include "../shared/Protocol.h"

#include <cstdint>
#include <string>
#include <vector>

namespace kernelscope {

class UniqueHandle final {
public:
    UniqueHandle() noexcept = default;
    explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueHandle() noexcept;
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept;
    UniqueHandle& operator=(UniqueHandle&& other) noexcept;

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] bool valid() const noexcept;
    void reset(HANDLE replacement = INVALID_HANDLE_VALUE) noexcept;

private:
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

struct EventBatch {
    std::vector<KS_TELEMETRY_EVENT> events;
    std::uint32_t remaining{};
    std::uint64_t droppedTotal{};
};

class DeviceClient final {
public:
    [[nodiscard]] bool Open(bool requestWriteAccess, std::string& error);
    [[nodiscard]] bool Negotiate(KS_QUERY_RESPONSE& response, std::string& error);
    [[nodiscard]] bool GetEvents(
        std::uint32_t maximumEvents,
        EventBatch& batch,
        std::string& error);
    [[nodiscard]] bool GetStatistics(
        KS_STATISTICS_RESPONSE& response,
        std::string& error);
    [[nodiscard]] bool ResetStatistics(
        KS_STATISTICS_RESPONSE& response,
        std::string& error);

private:
    [[nodiscard]] std::uint64_t NextCorrelation() noexcept;

    UniqueHandle device_;
    std::uint64_t correlation_{1u};
    bool negotiated_{};
    bool writeAccess_{};
};

[[nodiscard]] std::string Win32ErrorMessage(DWORD error);

}  // namespace kernelscope
