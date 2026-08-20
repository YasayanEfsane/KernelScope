#include "TestHarness.h"

#include "../analyzer/PeParser.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

template <typename T>
void Write(std::vector<std::uint8_t>& bytes, const std::size_t offset, const T& value)
{
    KS_REQUIRE(offset <= bytes.size());
    KS_REQUIRE(sizeof(T) <= bytes.size() - offset);
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

std::vector<std::uint8_t> MinimalPe(const std::uint16_t sectionCount = 1u)
{
    std::vector<std::uint8_t> bytes(0x600u, 0u);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    Write(bytes, 0u, dos);
    const DWORD signature = IMAGE_NT_SIGNATURE;
    Write(bytes, 0x80u, signature);
    IMAGE_FILE_HEADER file{};
    file.Machine = IMAGE_FILE_MACHINE_AMD64;
    file.NumberOfSections = sectionCount;
    file.SizeOfOptionalHeader = static_cast<WORD>(sizeof(IMAGE_OPTIONAL_HEADER64));
    file.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    Write(bytes, 0x84u, file);
    IMAGE_OPTIONAL_HEADER64 optional{};
    optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    optional.AddressOfEntryPoint = 0x1000u;
    optional.ImageBase = 0x140000000ull;
    optional.SectionAlignment = 0x1000u;
    optional.FileAlignment = 0x200u;
    optional.SizeOfImage = sectionCount == 1u ? 0x2000u : 0x3000u;
    optional.SizeOfHeaders = 0x200u;
    optional.Subsystem = IMAGE_SUBSYSTEM_NATIVE;
    optional.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    Write(bytes, 0x98u, optional);
    const std::size_t sectionOffset = 0x98u + sizeof(optional);
    IMAGE_SECTION_HEADER text{};
    std::memcpy(text.Name, ".text", 5u);
    text.Misc.VirtualSize = 0x180u;
    text.VirtualAddress = 0x1000u;
    text.SizeOfRawData = 0x200u;
    text.PointerToRawData = 0x200u;
    text.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    Write(bytes, sectionOffset, text);
    if (sectionCount == 2u) {
        IMAGE_SECTION_HEADER data{};
        std::memcpy(data.Name, ".data", 5u);
        data.Misc.VirtualSize = 0x100u;
        data.VirtualAddress = 0x2000u;
        data.SizeOfRawData = 0x200u;
        data.PointerToRawData = 0x400u;
        data.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        Write(bytes, sectionOffset + sizeof(text), data);
    }
    return bytes;
}

bool HasFinding(const kernelscope::analysis::PeAnalysis& result, const std::string& code)
{
    return std::any_of(result.findings.begin(), result.findings.end(),
        [&](const auto& finding) { return finding.code == code; });
}

}  // namespace

KS_TEST_CASE("A bounds-valid minimal PE32+ image parses")
{
    std::string error;
    const auto result = kernelscope::analysis::PeParser{}.ParseBytes(MinimalPe(), error);
    KS_REQUIRE(result.valid);
    KS_REQUIRE(error.empty());
    KS_REQUIRE(result.pe32Plus);
    KS_REQUIRE(result.machine == IMAGE_FILE_MACHINE_AMD64);
    KS_REQUIRE(result.sections.size() == 1u);
}

KS_TEST_CASE("Malformed DOS and truncated section tables are rejected")
{
    std::string error;
    std::vector<std::uint8_t> malformed(64u, 0u);
    auto result = kernelscope::analysis::PeParser{}.ParseBytes(malformed, error);
    KS_REQUIRE(!result.valid);
    KS_REQUIRE(HasFinding(result, "PE_INVALID_DOS_HEADER"));

    auto truncated = MinimalPe();
    truncated.resize(0x180u);
    result = kernelscope::analysis::PeParser{}.ParseBytes(truncated, error);
    KS_REQUIRE(!result.valid);
}

KS_TEST_CASE("Invalid directory RVAs produce a high-confidence finding")
{
    auto bytes = MinimalPe();
    IMAGE_OPTIONAL_HEADER64 optional{};
    std::memcpy(&optional, bytes.data() + 0x98u, sizeof(optional));
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x50000000u;
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
        static_cast<DWORD>(sizeof(IMAGE_IMPORT_DESCRIPTOR));
    Write(bytes, 0x98u, optional);
    std::string error;
    const auto result = kernelscope::analysis::PeParser{}.ParseBytes(bytes, error);
    KS_REQUIRE(result.valid);
    KS_REQUIRE(HasFinding(result, "PE_MALFORMED_DIRECTORY"));
}

KS_TEST_CASE("Overlapping and overflowing section ranges are reported")
{
    auto overlapping = MinimalPe(2u);
    const std::size_t sectionOffset = 0x98u + sizeof(IMAGE_OPTIONAL_HEADER64);
    IMAGE_SECTION_HEADER second{};
    std::memcpy(&second, overlapping.data() + sectionOffset + sizeof(second), sizeof(second));
    second.PointerToRawData = 0x300u;
    second.VirtualAddress = 0x1100u;
    Write(overlapping, sectionOffset + sizeof(second), second);
    std::string error;
    auto result = kernelscope::analysis::PeParser{}.ParseBytes(overlapping, error);
    KS_REQUIRE(result.valid);
    KS_REQUIRE(HasFinding(result, "PE_OVERLAPPING_SECTIONS"));

    auto overflowing = MinimalPe();
    IMAGE_SECTION_HEADER first{};
    std::memcpy(&first, overflowing.data() + sectionOffset, sizeof(first));
    first.VirtualAddress = 0xfffffff0u;
    first.Misc.VirtualSize = 0x200u;
    Write(overflowing, sectionOffset, first);
    result = kernelscope::analysis::PeParser{}.ParseBytes(overflowing, error);
    KS_REQUIRE(HasFinding(result, "PE_SECTION_VIRTUAL_RANGE_INVALID"));
}
