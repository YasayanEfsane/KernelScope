#pragma once

#include <filesystem>
#include <string>

namespace kernelscope::analysis {

enum class SignatureStatus {
    Valid,
    Invalid,
    Unsigned,
    VerificationError,
    RevocationStatusUnknown
};

struct SignatureResult {
    SignatureStatus status{SignatureStatus::VerificationError};
    long trustStatus{};
    std::string detail;
};

[[nodiscard]] const char* SignatureStatusName(SignatureStatus status) noexcept;
[[nodiscard]] SignatureResult VerifyAuthenticode(
    const std::filesystem::path& path);

}  // namespace kernelscope::analysis
