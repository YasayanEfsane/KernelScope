#pragma once

#include <string>
#include <vector>

namespace kernelscope::analysis {

enum class Severity {
    Information,
    Low,
    Medium,
    High
};

struct Finding {
    Severity severity{Severity::Information};
    std::string code;
    std::string message;
};

[[nodiscard]] const char* SeverityName(Severity severity) noexcept;
void AddFinding(
    std::vector<Finding>& findings,
    Severity severity,
    std::string code,
    std::string message);

}  // namespace kernelscope::analysis

