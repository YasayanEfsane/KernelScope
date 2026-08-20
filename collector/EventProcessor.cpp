#include "EventProcessor.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>

namespace kernelscope {

std::optional<SequenceGap> SequenceTracker::Observe(const std::uint64_t sequence) noexcept
{
    std::optional<SequenceGap> result;
    if (last_.has_value() && *last_ != std::numeric_limits<std::uint64_t>::max()) {
        const std::uint64_t expected = *last_ + 1u;
        if (sequence > expected) {
            result = SequenceGap{expected, sequence, sequence - expected};
        }
    }
    if (!last_.has_value() || sequence > *last_) {
        last_ = sequence;
    }
    return result;
}

std::string Utf16PathToUtf8(const KS_TELEMETRY_EVENT& eventRecord)
{
    if (eventRecord.PathLengthCharacters == 0u) {
        return {};
    }
    const int characters = eventRecord.PathLengthCharacters;
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        eventRecord.ImagePath, characters, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return "<invalid-utf16>";
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            eventRecord.ImagePath, characters, result.data(), required, nullptr, nullptr) != required) {
        return "<invalid-utf16>";
    }
    return result;
}

std::string EventTypeName(const std::uint16_t eventType)
{
    switch (eventType) {
    case KS_EVENT_PROCESS_CREATE: return "process_create";
    case KS_EVENT_PROCESS_EXIT: return "process_exit";
    case KS_EVENT_EXECUTABLE_IMAGE_LOAD: return "executable_image_load";
    case KS_EVENT_DLL_IMAGE_LOAD: return "dll_image_load";
    case KS_EVENT_KERNEL_DRIVER_IMAGE_LOAD: return "kernel_driver_image_load";
    case KS_EVENT_DROPPED_STATISTICS: return "dropped_event_statistics";
    default: return "unknown";
    }
}

std::string JsonEscape(const std::string& value)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const unsigned char character : value) {
        switch (character) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (character < 0x20u) {
                output << "\\u" << std::setw(4) << static_cast<unsigned>(character);
            } else {
                output << static_cast<char>(character);
            }
        }
    }
    return output.str();
}

static std::string TimestampToIso8601(const std::uint64_t timestamp100ns)
{
    ULARGE_INTEGER value{};
    value.QuadPart = timestamp100ns;
    FILETIME fileTime{value.LowPart, value.HighPart};
    SYSTEMTIME systemTime{};
    if (!FileTimeToSystemTime(&fileTime, &systemTime)) {
        return "invalid";
    }
    std::ostringstream output;
    output << std::setfill('0') << std::setw(4) << systemTime.wYear << '-'
        << std::setw(2) << systemTime.wMonth << '-'
        << std::setw(2) << systemTime.wDay << 'T'
        << std::setw(2) << systemTime.wHour << ':'
        << std::setw(2) << systemTime.wMinute << ':'
        << std::setw(2) << systemTime.wSecond << '.'
        << std::setw(3) << systemTime.wMilliseconds << 'Z';
    return output.str();
}

ProcessedEvent EventProcessor::Process(const KS_TELEMETRY_EVENT& eventRecord)
{
    ProcessedEvent processed;
    processed.gap = sequences_.Observe(eventRecord.Sequence);
    const std::string type = EventTypeName(eventRecord.EventType);
    const std::string path = Utf16PathToUtf8(eventRecord);
    const std::string timestamp = TimestampToIso8601(eventRecord.Timestamp100ns);

    std::ostringstream console;
    console << '[' << timestamp << "] seq=" << eventRecord.Sequence
        << " type=" << type << " pid=" << eventRecord.ProcessId;
    if (eventRecord.ParentProcessId != 0u) {
        console << " ppid=" << eventRecord.ParentProcessId;
    }
    if (eventRecord.ImageBase != 0u) {
        console << " base=0x" << std::hex << eventRecord.ImageBase << std::dec
            << " size=" << eventRecord.ImageSize;
    }
    if (eventRecord.EventType == KS_EVENT_DROPPED_STATISTICS) {
        console << " dropped=" << eventRecord.AuxiliaryValue;
    }
    if (!path.empty()) {
        console << " path=\"" << path << '"';
    }
    if ((eventRecord.Flags & KS_EVENT_FLAG_PATH_TRUNCATED) != 0u) {
        console << " [path-truncated]";
    }
    processed.consoleLine = console.str();

    std::ostringstream json;
    json << "{\"schema_version\":1,\"timestamp\":\"" << JsonEscape(timestamp)
        << "\",\"sequence\":" << eventRecord.Sequence
        << ",\"event_type\":\"" << type << "\",\"flags\":" << eventRecord.Flags
        << ",\"process_id\":" << eventRecord.ProcessId
        << ",\"parent_process_id\":" << eventRecord.ParentProcessId
        << ",\"image_base\":" << eventRecord.ImageBase
        << ",\"image_size\":" << eventRecord.ImageSize
        << ",\"auxiliary_value\":" << eventRecord.AuxiliaryValue
        << ",\"image_path\":\"" << JsonEscape(path) << "\"}";
    processed.jsonLine = json.str();
    return processed;
}

}  // namespace kernelscope

