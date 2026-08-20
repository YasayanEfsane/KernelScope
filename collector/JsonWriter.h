#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

namespace kernelscope {

class JsonWriter final {
public:
    JsonWriter(std::filesystem::path basePath, std::uint64_t maximumBytes);
    JsonWriter(const JsonWriter&) = delete;
    JsonWriter& operator=(const JsonWriter&) = delete;

    [[nodiscard]] bool Open(std::string& error);
    [[nodiscard]] bool WriteLine(const std::string& line, std::string& error);
    void Flush() noexcept;

private:
    [[nodiscard]] bool Rotate(std::string& error);
    [[nodiscard]] std::filesystem::path CurrentPath() const;

    std::filesystem::path basePath_;
    std::uint64_t maximumBytes_{};
    std::uint64_t currentBytes_{};
    std::uint32_t rotation_{};
    std::ofstream output_;
};

}  // namespace kernelscope

