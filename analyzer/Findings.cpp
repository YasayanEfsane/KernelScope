#include "Findings.h"

#include <utility>

namespace kernelscope::analysis {

const char* SeverityName(const Severity severity) noexcept
{
    switch (severity) {
    case Severity::Information: return "information";
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    }
    return "unknown";
}

void AddFinding(
    std::vector<Finding>& findings,
    const Severity severity,
    std::string code,
    std::string message)
{
    findings.push_back(Finding{severity, std::move(code), std::move(message)});
}

}  // namespace kernelscope::analysis

