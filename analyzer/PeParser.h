#pragma once

#include "Findings.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace kernelscope::analysis {

struct SectionInfo {
    std::string name;
    std::uint32_t virtualAddress{};
    std::uint32_t virtualSize{};
    std::uint32_t rawOffset{};
    std::uint32_t rawSize{};
    std::uint32_t characteristics{};
    double entropy{};
};

struct PeAnalysis {
    bool valid{};
    bool pe32Plus{};
    std::uint16_t machine{};
    std::uint16_t subsystem{};
    std::uint16_t dllCharacteristics{};
    std::uint64_t imageBase{};
    std::uint32_t entryPointRva{};
    std::uint32_t sizeOfImage{};
    std::uint32_t sizeOfHeaders{};
    std::size_t importDescriptorCount{};
    std::size_t exportCount{};
    bool hasRelocations{};
    bool hasTls{};
    bool hasDebugDirectory{};
    bool hasLoadConfiguration{};
    bool hasExceptionDirectory{};
    bool hasCertificateTable{};
    std::string pdbPath;
    std::vector<SectionInfo> sections;
    std::vector<Finding> findings;
};

class PeParser final {
public:
    [[nodiscard]] PeAnalysis ParseFile(
        const std::filesystem::path& path,
        std::string& error) const;

    [[nodiscard]] PeAnalysis ParseBytes(
        const std::vector<std::uint8_t>& bytes,
        std::string& error) const;
};

}  // namespace kernelscope::analysis
