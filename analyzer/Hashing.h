#pragma once

#include <filesystem>
#include <string>

namespace kernelscope::analysis {

struct HashResult {
    bool success{};
    std::string sha256;
    std::string error;
};

[[nodiscard]] HashResult ComputeSha256(const std::filesystem::path& path);

}  // namespace kernelscope::analysis
