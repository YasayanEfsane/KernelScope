#include "TestHarness.h"

#include "../analyzer/Hashing.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <string>

KS_TEST_CASE("SHA-256 matches the deterministic abc vector")
{
    const auto path = std::filesystem::temp_directory_path() /
        (L"kernelscope-hash-" + std::to_wstring(GetCurrentProcessId()) + L".bin");
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write("abc", 3);
        KS_REQUIRE(static_cast<bool>(output));
    }
    const auto result = kernelscope::analysis::ComputeSha256(path);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    KS_REQUIRE(result.success);
    KS_REQUIRE(result.sha256 ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

