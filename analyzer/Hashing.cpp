#include "Hashing.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

namespace kernelscope::analysis {
namespace {

class AlgorithmHandle final {
public:
    ~AlgorithmHandle() noexcept
    {
        if (value_ != nullptr) {
            (void)BCryptCloseAlgorithmProvider(value_, 0u);
        }
    }
    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;
    AlgorithmHandle() noexcept = default;
    [[nodiscard]] BCRYPT_ALG_HANDLE Get() const noexcept { return value_; }
    [[nodiscard]] BCRYPT_ALG_HANDLE* Put() noexcept { return &value_; }

private:
    BCRYPT_ALG_HANDLE value_{};
};

class HashHandle final {
public:
    ~HashHandle() noexcept
    {
        if (value_ != nullptr) {
            (void)BCryptDestroyHash(value_);
        }
    }
    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;
    HashHandle() noexcept = default;
    [[nodiscard]] BCRYPT_HASH_HANDLE Get() const noexcept { return value_; }
    [[nodiscard]] BCRYPT_HASH_HANDLE* Put() noexcept { return &value_; }

private:
    BCRYPT_HASH_HANDLE value_{};
};

}  // namespace

HashResult ComputeSha256(const std::filesystem::path& path)
{
    HashResult result;
    AlgorithmHandle algorithm;
    HashHandle hash;
    DWORD objectLength = 0u;
    DWORD hashLength = 0u;
    DWORD returned = 0u;
    std::vector<UCHAR> object;
    std::vector<UCHAR> digest;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        algorithm.Put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0u);
    if (!BCRYPT_SUCCESS(status)) {
        result.error = "BCryptOpenAlgorithmProvider failed.";
        return result;
    }

    status = BCryptGetProperty(algorithm.Get(), BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectLength), static_cast<ULONG>(sizeof(objectLength)), &returned, 0u);
    if (BCRYPT_SUCCESS(status)) {
        status = BCryptGetProperty(algorithm.Get(), BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashLength), static_cast<ULONG>(sizeof(hashLength)), &returned, 0u);
    }
    if (!BCRYPT_SUCCESS(status) || hashLength == 0u) {
        result.error = "BCryptGetProperty failed.";
        return result;
    }

    object.resize(objectLength);
    digest.resize(hashLength);
    status = BCryptCreateHash(algorithm.Get(), hash.Put(), object.data(), objectLength,
        nullptr, 0u, 0u);
    if (!BCRYPT_SUCCESS(status)) {
        result.error = "BCryptCreateHash failed.";
        return result;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        result.error = "Could not open the file for hashing.";
    } else {
        std::array<char, 64u * 1024u> buffer{};
        while (input) {
            input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const auto count = input.gcount();
            if (count > 0) {
                status = BCryptHashData(hash.Get(),
                    reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(count), 0u);
                if (!BCRYPT_SUCCESS(status)) {
                    result.error = "BCryptHashData failed.";
                    break;
                }
            }
        }
        if (result.error.empty() && input.bad()) {
            result.error = "A file read failed during hashing.";
        }
        if (result.error.empty()) {
            status = BCryptFinishHash(hash.Get(), digest.data(), hashLength, 0u);
            if (!BCRYPT_SUCCESS(status)) {
                result.error = "BCryptFinishHash failed.";
            } else {
                std::ostringstream stream;
                stream << std::hex << std::setfill('0');
                for (const auto value : digest) {
                    stream << std::setw(2) << static_cast<unsigned>(value);
                }
                result.sha256 = stream.str();
                result.success = true;
            }
        }
    }

    SecureZeroMemory(object.data(), object.size());
    SecureZeroMemory(digest.data(), digest.size());
    return result;
}

}  // namespace kernelscope::analysis
