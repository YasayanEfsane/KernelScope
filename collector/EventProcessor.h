#pragma once

#include "../shared/Protocol.h"

#include <cstdint>
#include <optional>
#include <string>

namespace kernelscope {

struct SequenceGap {
    std::uint64_t expected{};
    std::uint64_t actual{};
    std::uint64_t missing{};
};

class SequenceTracker final {
public:
    [[nodiscard]] std::optional<SequenceGap> Observe(std::uint64_t sequence) noexcept;
    void Reset() noexcept { last_.reset(); }

private:
    std::optional<std::uint64_t> last_;
};

struct ProcessedEvent {
    std::string consoleLine;
    std::string jsonLine;
    std::optional<SequenceGap> gap;
};

class EventProcessor final {
public:
    [[nodiscard]] ProcessedEvent Process(const KS_TELEMETRY_EVENT& eventRecord);

private:
    SequenceTracker sequences_;
};

[[nodiscard]] std::string Utf16PathToUtf8(const KS_TELEMETRY_EVENT& eventRecord);
[[nodiscard]] std::string EventTypeName(std::uint16_t eventType);
[[nodiscard]] std::string JsonEscape(const std::string& value);

}  // namespace kernelscope

