#include "PeParser.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <utility>

namespace kernelscope::analysis {
namespace {

using Bytes = std::vector<std::uint8_t>;

[[nodiscard]] bool RangeWithin(
    const std::uint64_t offset,
    const std::uint64_t length,
    const std::size_t total) noexcept
{
    return offset <= total && length <= static_cast<std::uint64_t>(total) - offset;
}

[[nodiscard]] bool CheckedMultiply(
    const std::uint64_t left,
    const std::uint64_t right,
    std::uint64_t& result) noexcept
{
    if (left != 0u && right > std::numeric_limits<std::uint64_t>::max() / left) {
        return false;
    }
    result = left * right;
    return true;
}

template <typename T>
[[nodiscard]] bool ReadAt(const Bytes& bytes, const std::uint64_t offset, T& value) noexcept
{
    if (!RangeWithin(offset, sizeof(T), bytes.size())) {
        return false;
    }
    std::memcpy(&value, bytes.data() + static_cast<std::size_t>(offset), sizeof(T));
    return true;
}

struct ImageLayout {
    std::uint32_t sizeOfHeaders{};
    std::vector<IMAGE_SECTION_HEADER> sections;
};

[[nodiscard]] bool RvaToOffset(
    const ImageLayout& layout,
    const Bytes& bytes,
    const std::uint32_t rva,
    const std::uint32_t requiredSize,
    std::size_t& offset) noexcept
{
    if (rva < layout.sizeOfHeaders) {
        if (!RangeWithin(rva, requiredSize, bytes.size())) {
            return false;
        }
        offset = rva;
        return true;
    }

    for (const auto& section : layout.sections) {
        const std::uint64_t start = section.VirtualAddress;
        const std::uint64_t mappedSize =
            std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        const std::uint64_t end = start + mappedSize;
        if (end < start || rva < start || rva >= end) {
            continue;
        }
        const std::uint64_t delta = static_cast<std::uint64_t>(rva) - start;
        if (delta > section.SizeOfRawData || requiredSize > section.SizeOfRawData - delta) {
            return false;
        }
        const std::uint64_t raw = static_cast<std::uint64_t>(section.PointerToRawData) + delta;
        if (!RangeWithin(raw, requiredSize, bytes.size())) {
            return false;
        }
        offset = static_cast<std::size_t>(raw);
        return true;
    }
    return false;
}

[[nodiscard]] double CalculateEntropy(
    const Bytes& bytes,
    const std::uint32_t offset,
    const std::uint32_t size) noexcept
{
    if (size == 0u || !RangeWithin(offset, size, bytes.size())) {
        return 0.0;
    }
    std::array<std::uint64_t, 256> frequencies{};
    for (std::uint32_t index = 0u; index < size; ++index) {
        ++frequencies[bytes[static_cast<std::size_t>(offset) + index]];
    }
    double entropy = 0.0;
    for (const auto frequency : frequencies) {
        if (frequency == 0u) {
            continue;
        }
        const double probability = static_cast<double>(frequency) / size;
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

[[nodiscard]] std::string SectionName(const IMAGE_SECTION_HEADER& section)
{
    std::array<char, IMAGE_SIZEOF_SHORT_NAME + 1u> name{};
    std::memcpy(name.data(), section.Name, IMAGE_SIZEOF_SHORT_NAME);
    return std::string(name.data());
}

void AddMalformedDirectory(PeAnalysis& result, const char* name)
{
    AddFinding(result.findings, Severity::High, "PE_MALFORMED_DIRECTORY",
        std::string(name) + " directory is outside a valid file-backed region.");
}

[[nodiscard]] bool ValidateDirectoryRange(
    const char* name,
    const IMAGE_DATA_DIRECTORY& directory,
    const ImageLayout& layout,
    const Bytes& bytes,
    PeAnalysis& result,
    std::size_t& offset)
{
    if (directory.VirtualAddress == 0u && directory.Size == 0u) {
        return false;
    }
    if (directory.VirtualAddress == 0u || directory.Size == 0u ||
        !RvaToOffset(layout, bytes, directory.VirtualAddress, directory.Size, offset)) {
        AddMalformedDirectory(result, name);
        return false;
    }
    return true;
}

void AnalyzeImports(
    const IMAGE_DATA_DIRECTORY& directory,
    const ImageLayout& layout,
    const Bytes& bytes,
    PeAnalysis& result)
{
    std::size_t offset = 0u;
    if (!ValidateDirectoryRange("Import", directory, layout, bytes, result, offset)) {
        return;
    }
    const std::size_t maximumDescriptors = directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    bool terminated = false;
    for (std::size_t index = 0u; index < maximumDescriptors; ++index) {
        IMAGE_IMPORT_DESCRIPTOR descriptor{};
        if (!ReadAt(bytes, offset + index * sizeof(descriptor), descriptor)) {
            break;
        }
        if (descriptor.OriginalFirstThunk == 0u && descriptor.FirstThunk == 0u &&
            descriptor.Name == 0u) {
            terminated = true;
            break;
        }
        std::size_t nameOffset = 0u;
        if (descriptor.Name == 0u ||
            !RvaToOffset(layout, bytes, descriptor.Name, 1u, nameOffset)) {
            AddFinding(result.findings, Severity::High, "PE_MALFORMED_IMPORT",
                "An import descriptor contains an invalid DLL name RVA.");
            return;
        }
        const DWORD thunkRva = descriptor.OriginalFirstThunk != 0u
            ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
        const std::uint32_t thunkSize = result.pe32Plus
            ? static_cast<std::uint32_t>(sizeof(ULONGLONG))
            : static_cast<std::uint32_t>(sizeof(DWORD));
        std::size_t thunkOffset = 0u;
        if (thunkRva == 0u || descriptor.FirstThunk == 0u ||
            !RvaToOffset(layout, bytes, thunkRva, thunkSize, thunkOffset)) {
            AddFinding(result.findings, Severity::High, "PE_MALFORMED_IMPORT",
                "An import descriptor contains an invalid thunk RVA.");
            return;
        }
        ++result.importDescriptorCount;
    }
    if (!terminated) {
        AddFinding(result.findings, Severity::High, "PE_UNTERMINATED_IMPORTS",
            "The import descriptor table is not terminated within its declared size.");
    }
}

void AnalyzeExports(
    const IMAGE_DATA_DIRECTORY& directory,
    const ImageLayout& layout,
    const Bytes& bytes,
    PeAnalysis& result)
{
    std::size_t offset = 0u;
    if (!ValidateDirectoryRange("Export", directory, layout, bytes, result, offset)) {
        return;
    }
    IMAGE_EXPORT_DIRECTORY exports{};
    if (!ReadAt(bytes, offset, exports)) {
        AddMalformedDirectory(result, "Export");
        return;
    }
    std::uint64_t functionBytes = 0u;
    std::uint64_t nameBytes = 0u;
    std::uint64_t ordinalBytes = 0u;
    std::size_t unused = 0u;
    if (!CheckedMultiply(exports.NumberOfFunctions, sizeof(DWORD), functionBytes) ||
        !CheckedMultiply(exports.NumberOfNames, sizeof(DWORD), nameBytes) ||
        !CheckedMultiply(exports.NumberOfNames, sizeof(WORD), ordinalBytes) ||
        functionBytes > std::numeric_limits<std::uint32_t>::max() ||
        nameBytes > std::numeric_limits<std::uint32_t>::max() ||
        ordinalBytes > std::numeric_limits<std::uint32_t>::max() ||
        exports.NumberOfNames > exports.NumberOfFunctions ||
        (exports.NumberOfFunctions != 0u && !RvaToOffset(layout, bytes,
            exports.AddressOfFunctions, static_cast<std::uint32_t>(functionBytes), unused)) ||
        (exports.NumberOfNames != 0u && !RvaToOffset(layout, bytes,
            exports.AddressOfNames, static_cast<std::uint32_t>(nameBytes), unused)) ||
        (exports.NumberOfNames != 0u && !RvaToOffset(layout, bytes,
            exports.AddressOfNameOrdinals,
            static_cast<std::uint32_t>(ordinalBytes), unused))) {
        AddFinding(result.findings, Severity::High, "PE_MALFORMED_EXPORT",
            "The export table contains invalid counts or table RVAs.");
        return;
    }
    result.exportCount = exports.NumberOfFunctions;
}

void AnalyzeRelocations(
    const IMAGE_DATA_DIRECTORY& directory,
    const ImageLayout& layout,
    const Bytes& bytes,
    PeAnalysis& result)
{
    std::size_t offset = 0u;
    if (!ValidateDirectoryRange("Relocation", directory, layout, bytes, result, offset)) {
        return;
    }
    std::size_t consumed = 0u;
    while (consumed < directory.Size) {
        IMAGE_BASE_RELOCATION block{};
        if (!ReadAt(bytes, offset + consumed, block) ||
            block.SizeOfBlock < sizeof(block) ||
            block.SizeOfBlock > directory.Size - consumed ||
            ((block.SizeOfBlock - sizeof(block)) % sizeof(WORD)) != 0u) {
            AddFinding(result.findings, Severity::High, "PE_MALFORMED_RELOCATIONS",
                "A relocation block has an invalid or truncated size.");
            return;
        }
        consumed += block.SizeOfBlock;
    }
    result.hasRelocations = true;
}

void AnalyzeDebug(
    const IMAGE_DATA_DIRECTORY& directory,
    const ImageLayout& layout,
    const Bytes& bytes,
    PeAnalysis& result)
{
    std::size_t offset = 0u;
    if (!ValidateDirectoryRange("Debug", directory, layout, bytes, result, offset)) {
        return;
    }
    if ((directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY)) != 0u) {
        AddMalformedDirectory(result, "Debug");
        return;
    }
    result.hasDebugDirectory = true;
    const std::size_t count = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    for (std::size_t index = 0u; index < count; ++index) {
        IMAGE_DEBUG_DIRECTORY entry{};
        if (!ReadAt(bytes, offset + index * sizeof(entry), entry) ||
            !RangeWithin(entry.PointerToRawData, entry.SizeOfData, bytes.size())) {
            AddMalformedDirectory(result, "Debug");
            return;
        }
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData <= 24u) {
            continue;
        }
        const auto dataOffset = static_cast<std::size_t>(entry.PointerToRawData);
        const char* signature = reinterpret_cast<const char*>(bytes.data() + dataOffset);
        std::size_t pathStart = 0u;
        if (std::memcmp(signature, "RSDS", 4u) == 0) {
            pathStart = 24u;
        } else if (std::memcmp(signature, "NB10", 4u) == 0) {
            pathStart = 16u;
        }
        if (pathStart == 0u || pathStart >= entry.SizeOfData) {
            continue;
        }
        const char* begin = signature + pathStart;
        const std::size_t maximum = entry.SizeOfData - pathStart;
        const void* terminator = std::memchr(begin, '\0', maximum);
        if (terminator != nullptr) {
            result.pdbPath.assign(begin, static_cast<const char*>(terminator));
        }
    }
}

void AnalyzeCertificate(
    const IMAGE_DATA_DIRECTORY& directory,
    const Bytes& bytes,
    PeAnalysis& result)
{
    if (directory.VirtualAddress == 0u && directory.Size == 0u) {
        return;
    }
    if (directory.VirtualAddress == 0u || directory.Size < sizeof(WIN_CERTIFICATE) ||
        (directory.VirtualAddress % 8u) != 0u ||
        !RangeWithin(directory.VirtualAddress, directory.Size, bytes.size())) {
        AddMalformedDirectory(result, "Certificate");
        return;
    }
    WIN_CERTIFICATE certificate{};
    if (!ReadAt(bytes, directory.VirtualAddress, certificate) ||
        certificate.dwLength < sizeof(WIN_CERTIFICATE) ||
        certificate.dwLength > directory.Size) {
        AddMalformedDirectory(result, "Certificate");
        return;
    }
    result.hasCertificateTable = true;
}

}  // namespace

PeAnalysis PeParser::ParseFile(
    const std::filesystem::path& path,
    std::string& error) const
{
    error.clear();
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        error = "Could not open the file.";
        return {};
    }
    const auto end = input.tellg();
    if (end < 0) {
        error = "Could not determine the file size.";
        return {};
    }
    constexpr std::uint64_t maximumFileSize = 512ull * 1024ull * 1024ull;
    const auto fileSize = static_cast<std::uint64_t>(end);
    if (fileSize > maximumFileSize || fileSize > std::numeric_limits<std::size_t>::max()) {
        error = "The file exceeds the 512 MiB analysis limit.";
        return {};
    }
    Bytes bytes(static_cast<std::size_t>(fileSize));
    input.seekg(0, std::ios::beg);
    if (!bytes.empty() &&
        !input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) {
        error = "Could not read the complete file.";
        return {};
    }
    return ParseBytes(bytes, error);
}

PeAnalysis PeParser::ParseBytes(const Bytes& bytes, std::string& error) const
{
    PeAnalysis result;
    error.clear();
    IMAGE_DOS_HEADER dos{};
    if (!ReadAt(bytes, 0u, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
        error = "Missing or invalid DOS header.";
        AddFinding(result.findings, Severity::High, "PE_INVALID_DOS_HEADER", error);
        return result;
    }

    const std::uint64_t ntOffset = static_cast<std::uint32_t>(dos.e_lfanew);
    DWORD signature = 0u;
    IMAGE_FILE_HEADER fileHeader{};
    if (!ReadAt(bytes, ntOffset, signature) || signature != IMAGE_NT_SIGNATURE ||
        !ReadAt(bytes, ntOffset + sizeof(signature), fileHeader)) {
        error = "Missing or truncated NT headers.";
        AddFinding(result.findings, Severity::High, "PE_INVALID_NT_HEADERS", error);
        return result;
    }
    if (fileHeader.NumberOfSections == 0u || fileHeader.NumberOfSections > 96u) {
        error = "The section count is outside the supported safe range.";
        AddFinding(result.findings, Severity::High, "PE_INVALID_SECTION_COUNT", error);
        return result;
    }

    const std::uint64_t optionalOffset = ntOffset + sizeof(signature) + sizeof(fileHeader);
    if (!RangeWithin(optionalOffset, fileHeader.SizeOfOptionalHeader, bytes.size())) {
        error = "The optional header is truncated.";
        AddFinding(result.findings, Severity::High, "PE_TRUNCATED_OPTIONAL_HEADER", error);
        return result;
    }

    WORD magic = 0u;
    if (!ReadAt(bytes, optionalOffset, magic)) {
        error = "The optional header magic is truncated.";
        return result;
    }
    std::array<IMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> directories{};
    std::uint32_t directoryCount = 0u;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optional{};
        if (fileHeader.SizeOfOptionalHeader < sizeof(optional) || !ReadAt(bytes, optionalOffset, optional)) {
            error = "The PE32+ optional header is truncated.";
            AddFinding(result.findings, Severity::High, "PE_TRUNCATED_OPTIONAL_HEADER", error);
            return result;
        }
        result.pe32Plus = true;
        result.imageBase = optional.ImageBase;
        result.entryPointRva = optional.AddressOfEntryPoint;
        result.sizeOfImage = optional.SizeOfImage;
        result.sizeOfHeaders = optional.SizeOfHeaders;
        result.subsystem = optional.Subsystem;
        result.dllCharacteristics = optional.DllCharacteristics;
        directoryCount = std::min(optional.NumberOfRvaAndSizes,
            static_cast<DWORD>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
        std::copy_n(optional.DataDirectory, directoryCount, directories.begin());
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 optional{};
        if (fileHeader.SizeOfOptionalHeader < sizeof(optional) || !ReadAt(bytes, optionalOffset, optional)) {
            error = "The PE32 optional header is truncated.";
            AddFinding(result.findings, Severity::High, "PE_TRUNCATED_OPTIONAL_HEADER", error);
            return result;
        }
        result.imageBase = optional.ImageBase;
        result.entryPointRva = optional.AddressOfEntryPoint;
        result.sizeOfImage = optional.SizeOfImage;
        result.sizeOfHeaders = optional.SizeOfHeaders;
        result.subsystem = optional.Subsystem;
        result.dllCharacteristics = optional.DllCharacteristics;
        directoryCount = std::min(optional.NumberOfRvaAndSizes,
            static_cast<DWORD>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
        std::copy_n(optional.DataDirectory, directoryCount, directories.begin());
    } else {
        error = "Unknown optional header magic.";
        AddFinding(result.findings, Severity::High, "PE_UNKNOWN_OPTIONAL_MAGIC", error);
        return result;
    }

    result.machine = fileHeader.Machine;
    const std::uint64_t sectionOffset = optionalOffset + fileHeader.SizeOfOptionalHeader;
    std::uint64_t sectionBytes = 0u;
    if (!CheckedMultiply(fileHeader.NumberOfSections, sizeof(IMAGE_SECTION_HEADER), sectionBytes) ||
        !RangeWithin(sectionOffset, sectionBytes, bytes.size())) {
        error = "The section table is truncated or overflows the file.";
        AddFinding(result.findings, Severity::High, "PE_TRUNCATED_SECTION_TABLE", error);
        return result;
    }

    ImageLayout layout;
    layout.sizeOfHeaders = result.sizeOfHeaders;
    layout.sections.reserve(fileHeader.NumberOfSections);
    result.sections.reserve(fileHeader.NumberOfSections);
    bool entryInExecutableSection = result.entryPointRva == 0u;
    for (std::size_t index = 0u; index < fileHeader.NumberOfSections; ++index) {
        IMAGE_SECTION_HEADER section{};
        (void)ReadAt(bytes, sectionOffset + index * sizeof(section), section);
        layout.sections.push_back(section);

        SectionInfo sectionInfo;
        sectionInfo.name = SectionName(section);
        sectionInfo.virtualAddress = section.VirtualAddress;
        sectionInfo.virtualSize = section.Misc.VirtualSize;
        sectionInfo.rawOffset = section.PointerToRawData;
        sectionInfo.rawSize = section.SizeOfRawData;
        sectionInfo.characteristics = section.Characteristics;
        if (section.SizeOfRawData != 0u &&
            !RangeWithin(section.PointerToRawData, section.SizeOfRawData, bytes.size())) {
            AddFinding(result.findings, Severity::High, "PE_SECTION_OUT_OF_RANGE",
                "Section " + sectionInfo.name + " extends beyond the file.");
        } else {
            sectionInfo.entropy = CalculateEntropy(bytes,
                section.PointerToRawData, section.SizeOfRawData);
            if (section.SizeOfRawData >= 512u && sectionInfo.entropy >= 7.5) {
                AddFinding(result.findings, Severity::Medium, "PE_HIGH_SECTION_ENTROPY",
                    "Section " + sectionInfo.name + " has unusually high entropy.");
            }
        }
        const bool executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0u;
        const bool writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0u;
        if (executable && writable) {
            AddFinding(result.findings, Severity::High, "PE_WRITABLE_EXECUTABLE_SECTION",
                "Section " + sectionInfo.name + " is writable and executable.");
        }
        const std::uint64_t virtualEnd = static_cast<std::uint64_t>(section.VirtualAddress) +
            std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (virtualEnd < section.VirtualAddress || virtualEnd > result.sizeOfImage) {
            AddFinding(result.findings, Severity::High, "PE_SECTION_VIRTUAL_RANGE_INVALID",
                "Section " + sectionInfo.name + " has an invalid virtual range.");
        }
        if (executable && result.entryPointRva >= section.VirtualAddress &&
            result.entryPointRva < virtualEnd) {
            entryInExecutableSection = true;
        }
        result.sections.push_back(std::move(sectionInfo));
    }

    for (std::size_t left = 0u; left < layout.sections.size(); ++left) {
        for (std::size_t right = left + 1u; right < layout.sections.size(); ++right) {
            const auto& a = layout.sections[left];
            const auto& b = layout.sections[right];
            const std::uint64_t aRawEnd = static_cast<std::uint64_t>(a.PointerToRawData) + a.SizeOfRawData;
            const std::uint64_t bRawEnd = static_cast<std::uint64_t>(b.PointerToRawData) + b.SizeOfRawData;
            const bool rawOverlap = a.SizeOfRawData != 0u && b.SizeOfRawData != 0u &&
                a.PointerToRawData < bRawEnd && b.PointerToRawData < aRawEnd;
            const std::uint64_t aVirtualEnd = static_cast<std::uint64_t>(a.VirtualAddress) +
                std::max(a.Misc.VirtualSize, a.SizeOfRawData);
            const std::uint64_t bVirtualEnd = static_cast<std::uint64_t>(b.VirtualAddress) +
                std::max(b.Misc.VirtualSize, b.SizeOfRawData);
            const bool virtualOverlap = a.VirtualAddress < bVirtualEnd && b.VirtualAddress < aVirtualEnd;
            if (rawOverlap || virtualOverlap) {
                AddFinding(result.findings, Severity::High, "PE_OVERLAPPING_SECTIONS",
                    "Sections " + SectionName(a) + " and " + SectionName(b) + " overlap.");
            }
        }
    }

    if (!entryInExecutableSection) {
        AddFinding(result.findings, Severity::High, "PE_ENTRY_NOT_EXECUTABLE",
            "The entry point does not fall inside an executable section.");
    }
    if ((result.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) == 0u) {
        AddFinding(result.findings, Severity::Medium, "PE_NX_NOT_DECLARED",
            "The image does not declare NX compatibility.");
    }
    if ((result.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0u) {
        AddFinding(result.findings, Severity::Medium, "PE_ASLR_NOT_DECLARED",
            "The image does not declare dynamic-base support.");
    }

    if (directoryCount > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        AnalyzeExports(directories[IMAGE_DIRECTORY_ENTRY_EXPORT], layout, bytes, result);
    }
    if (directoryCount > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        AnalyzeImports(directories[IMAGE_DIRECTORY_ENTRY_IMPORT], layout, bytes, result);
    }
    if (directoryCount > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        AnalyzeRelocations(directories[IMAGE_DIRECTORY_ENTRY_BASERELOC], layout, bytes, result);
    }
    if (directoryCount > IMAGE_DIRECTORY_ENTRY_TLS) {
        std::size_t offset = 0u;
        if (ValidateDirectoryRange("TLS", directories[IMAGE_DIRECTORY_ENTRY_TLS],
                layout, bytes, result, offset)) {
            const std::size_t required = result.pe32Plus ? sizeof(IMAGE_TLS_DIRECTORY64) : sizeof(IMAGE_TLS_DIRECTORY32);
            if (directories[IMAGE_DIRECTORY_ENTRY_TLS].Size < required) {
                AddMalformedDirectory(result, "TLS");
            } else {
                result.hasTls = true;
            }
        }
    }
    if (directoryCount > IMAGE_DIRECTORY_ENTRY_DEBUG) {
        AnalyzeDebug(directories[IMAGE_DIRECTORY_ENTRY_DEBUG], layout, bytes, result);
    }
    if (directoryCount > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
        std::size_t offset = 0u;
        if (ValidateDirectoryRange("Load configuration",
                directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG], layout, bytes, result, offset)) {
            DWORD declaredSize = 0u;
            if (!ReadAt(bytes, offset, declaredSize) || declaredSize < sizeof(DWORD) ||
                declaredSize > directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size) {
                AddMalformedDirectory(result, "Load configuration");
            } else {
                result.hasLoadConfiguration = true;
            }
        }
    }
    if (directoryCount > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        std::size_t offset = 0u;
        const auto& directory = directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (ValidateDirectoryRange("Exception", directory, layout, bytes, result, offset)) {
            if (result.machine == IMAGE_FILE_MACHINE_AMD64 &&
                (directory.Size % sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) != 0u) {
                AddMalformedDirectory(result, "Exception");
            } else {
                result.hasExceptionDirectory = true;
            }
        }
    }
    if (directoryCount > IMAGE_DIRECTORY_ENTRY_SECURITY) {
        AnalyzeCertificate(directories[IMAGE_DIRECTORY_ENTRY_SECURITY], bytes, result);
    }

    result.valid = true;
    return result;
}

}  // namespace kernelscope::analysis
