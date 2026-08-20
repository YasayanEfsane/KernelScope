#include "DeviceClient.h"
#include "EventProcessor.h"
#include "JsonWriter.h"

#include "../analyzer/Findings.h"
#include "../analyzer/Hashing.h"
#include "../analyzer/PeParser.h"
#include "../analyzer/SignatureVerifier.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <exception>
#include <memory>
#include <sstream>
#include <string>

namespace {

std::atomic_bool g_Cancelled{false};

BOOL WINAPI ConsoleHandler(const DWORD controlType)
{
    if (controlType == CTRL_C_EVENT || controlType == CTRL_BREAK_EVENT ||
        controlType == CTRL_CLOSE_EVENT || controlType == CTRL_SHUTDOWN_EVENT) {
        g_Cancelled.store(true, std::memory_order_relaxed);
        return TRUE;
    }
    return FALSE;
}

enum class ExitCode : int {
    Success = 0,
    Usage = 2,
    Device = 3,
    Protocol = 4,
    Io = 5,
    Analysis = 6,
    Cancelled = 130
};

void PrintUsage()
{
    std::cout
        << "KernelScopeCollector\n\n"
        << "Usage:\n"
        << "  KernelScopeCollector.exe monitor [--output events.jsonl] [--max-size-mb 64]\n"
        << "  KernelScopeCollector.exe status\n"
        << "  KernelScopeCollector.exe export --output events.jsonl [--max-size-mb 64]\n"
        << "  KernelScopeCollector.exe analyze <path-to-pe-or-driver>\n"
        << "  KernelScopeCollector.exe reset-stats\n";
}

bool ParseUnsigned(const std::wstring& text, std::uint64_t& value)
{
    const std::string narrow(text.begin(), text.end());
    const auto result = std::from_chars(narrow.data(), narrow.data() + narrow.size(), value);
    return result.ec == std::errc{} && result.ptr == narrow.data() + narrow.size();
}

bool OpenAndNegotiate(
    kernelscope::DeviceClient& client,
    const bool writeAccess,
    std::string& error)
{
    if (!client.Open(writeAccess, error)) {
        return false;
    }
    KS_QUERY_RESPONSE query{};
    return client.Negotiate(query, error);
}

ExitCode RunStatus(const bool reset)
{
    kernelscope::DeviceClient client;
    std::string error;
    if (!OpenAndNegotiate(client, reset, error)) {
        std::cerr << error << '\n';
        return ExitCode::Device;
    }
    KS_STATISTICS_RESPONSE statistics{};
    const bool success = reset
        ? client.ResetStatistics(statistics, error)
        : client.GetStatistics(statistics, error);
    if (!success) {
        std::cerr << error << '\n';
        return ExitCode::Protocol;
    }
    std::cout << (reset ? "Statistics reset.\n" : "Driver statistics:\n")
        << "  next_sequence: " << statistics.NextSequence << '\n'
        << "  events_written: " << statistics.EventsWritten << '\n'
        << "  events_read: " << statistics.EventsRead << '\n'
        << "  events_dropped: " << statistics.EventsDropped << '\n'
        << "  ring_depth: " << statistics.CurrentDepth << '/' << statistics.RingCapacity << '\n';
    return ExitCode::Success;
}

ExitCode RunCollection(
    const bool continuous,
    const std::filesystem::path& outputPath,
    const std::uint64_t maximumBytes)
{
    kernelscope::DeviceClient client;
    std::string error;
    if (!OpenAndNegotiate(client, false, error)) {
        std::cerr << error << '\n';
        return ExitCode::Device;
    }
    kernelscope::JsonWriter writer(outputPath, maximumBytes);
    if (!writer.Open(error)) {
        std::cerr << error << '\n';
        return ExitCode::Io;
    }
    kernelscope::EventProcessor processor;
    std::uint64_t previousDroppedTotal = 0u;

    do {
        kernelscope::EventBatch batch;
        if (!client.GetEvents(KS_MAX_BATCH_EVENTS, batch, error)) {
            std::cerr << error << '\n';
            return ExitCode::Protocol;
        }
        if (batch.droppedTotal > previousDroppedTotal) {
            std::cerr << "Warning: driver reports "
                << (batch.droppedTotal - previousDroppedTotal)
                << " newly dropped event(s).\n";
        }
        previousDroppedTotal = batch.droppedTotal;

        for (const auto& eventRecord : batch.events) {
            const auto processed = processor.Process(eventRecord);
            if (processed.gap.has_value()) {
                std::cerr << "Warning: sequence gap; expected "
                    << processed.gap->expected << ", received "
                    << processed.gap->actual << " (" << processed.gap->missing
                    << " missing).\n";
            }
            std::cout << processed.consoleLine << '\n';
            if (!writer.WriteLine(processed.jsonLine, error)) {
                std::cerr << error << '\n';
                return ExitCode::Io;
            }
        }
        if (!continuous && batch.remaining == 0u) {
            break;
        }
        if (batch.events.empty()) {
            Sleep(continuous ? 250u : 10u);
        }
    } while (!g_Cancelled.load(std::memory_order_relaxed));

    writer.Flush();
    return g_Cancelled.load(std::memory_order_relaxed)
        ? ExitCode::Cancelled : ExitCode::Success;
}

ExitCode RunAnalyze(const std::filesystem::path& path)
{
    using namespace kernelscope::analysis;
    std::string parseError;
    PeParser parser;
    PeAnalysis analysis = parser.ParseFile(path, parseError);
    const HashResult hash = ComputeSha256(path);
    const SignatureResult signature = VerifyAuthenticode(path);

    if (signature.status == SignatureStatus::Unsigned) {
        AddFinding(analysis.findings, Severity::High, "DRIVER_UNSIGNED",
            "The image has no supported Authenticode signature.");
    } else if (signature.status == SignatureStatus::Invalid) {
        AddFinding(analysis.findings, Severity::High, "DRIVER_SIGNATURE_INVALID",
            "Authenticode verification determined that the signature is invalid.");
    } else if (signature.status == SignatureStatus::RevocationStatusUnknown) {
        AddFinding(analysis.findings, Severity::Medium, "DRIVER_REVOCATION_UNKNOWN",
            "The cached trust check could not establish revocation status.");
    } else if (signature.status == SignatureStatus::VerificationError) {
        AddFinding(analysis.findings, Severity::Medium, "DRIVER_SIGNATURE_ERROR",
            "Authenticode verification could not reach a definitive result.");
    }

    std::cout << "File: " << path.u8string() << '\n'
        << "PE valid: " << (analysis.valid ? "yes" : "no") << '\n'
        << "SHA-256: " << (hash.success ? hash.sha256 : "unavailable") << '\n'
        << "Authenticode: " << SignatureStatusName(signature.status)
        << " (0x" << std::hex << static_cast<unsigned long>(signature.trustStatus)
        << std::dec << ")\n";
    if (!parseError.empty()) {
        std::cerr << "PE parser: " << parseError << '\n';
    }
    if (!hash.success) {
        std::cerr << "Hashing: " << hash.error << '\n';
    }
    std::cout << "Architecture: 0x" << std::hex << analysis.machine << std::dec
        << ", sections: " << analysis.sections.size()
        << ", imports: " << analysis.importDescriptorCount
        << ", exports: " << analysis.exportCount << '\n';
    if (!analysis.pdbPath.empty()) {
        std::cout << "PDB path: " << analysis.pdbPath << '\n';
    }
    for (const auto& finding : analysis.findings) {
        std::cout << '[' << SeverityName(finding.severity) << "] "
            << finding.code << ": " << finding.message << '\n';
    }

    std::ostringstream json;
    json << "{\"schema_version\":1,\"file\":\""
        << kernelscope::JsonEscape(path.u8string()) << "\",\"pe_valid\":"
        << (analysis.valid ? "true" : "false") << ",\"sha256\":\""
        << kernelscope::JsonEscape(hash.sha256) << "\",\"signature_status\":\""
        << SignatureStatusName(signature.status) << "\",\"machine\":"
        << analysis.machine << ",\"entry_point_rva\":" << analysis.entryPointRva
        << ",\"section_count\":" << analysis.sections.size() << ",\"findings\":[";
    for (std::size_t index = 0u; index < analysis.findings.size(); ++index) {
        const auto& finding = analysis.findings[index];
        if (index != 0u) json << ',';
        json << "{\"severity\":\"" << SeverityName(finding.severity)
            << "\",\"code\":\"" << kernelscope::JsonEscape(finding.code)
            << "\",\"message\":\"" << kernelscope::JsonEscape(finding.message) << "\"}";
    }
    json << "]}";
    std::cout << "JSON: " << json.str() << '\n';

    return analysis.valid && hash.success ? ExitCode::Success : ExitCode::Analysis;
}

}  // namespace

int wmain(const int argc, wchar_t* argv[])
{
    SetConsoleOutputCP(CP_UTF8);
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "Warning: could not install the Ctrl+C handler.\n";
    }
    if (argc < 2) {
        PrintUsage();
        return static_cast<int>(ExitCode::Usage);
    }

    try {
        const std::wstring command = argv[1];
        if (command == L"status") {
            return static_cast<int>(RunStatus(false));
        }
        if (command == L"reset-stats") {
            return static_cast<int>(RunStatus(true));
        }
        if (command == L"analyze") {
            if (argc != 3) {
                PrintUsage();
                return static_cast<int>(ExitCode::Usage);
            }
            return static_cast<int>(RunAnalyze(argv[2]));
        }
        if (command == L"monitor" || command == L"export") {
            const bool continuous = command == L"monitor";
            std::filesystem::path output = continuous ? L"kernelscope-events.jsonl" : L"";
            std::uint64_t maximumMiB = 64u;
            for (int index = 2; index < argc; ++index) {
                const std::wstring option = argv[index];
                if (option == L"--output" && index + 1 < argc) {
                    output = argv[++index];
                } else if (option == L"--max-size-mb" && index + 1 < argc) {
                    if (!ParseUnsigned(argv[++index], maximumMiB) || maximumMiB == 0u ||
                        maximumMiB > 4096u) {
                        std::cerr << "--max-size-mb must be between 1 and 4096.\n";
                        return static_cast<int>(ExitCode::Usage);
                    }
                } else {
                    PrintUsage();
                    return static_cast<int>(ExitCode::Usage);
                }
            }
            if (output.empty()) {
                std::cerr << "export requires --output <path>.\n";
                return static_cast<int>(ExitCode::Usage);
            }
            return static_cast<int>(RunCollection(
                continuous, output, maximumMiB * 1024u * 1024u));
        }
        PrintUsage();
        return static_cast<int>(ExitCode::Usage);
    } catch (const std::exception& exception) {
        std::cerr << "Fatal user-mode error: " << exception.what() << '\n';
        return static_cast<int>(ExitCode::Io);
    }
}
