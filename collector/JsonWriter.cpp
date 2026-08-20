#include "JsonWriter.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace kernelscope {

JsonWriter::JsonWriter(std::filesystem::path basePath, const std::uint64_t maximumBytes)
    : basePath_(std::move(basePath)), maximumBytes_(maximumBytes)
{
}

std::filesystem::path JsonWriter::CurrentPath() const
{
    if (rotation_ == 0u) {
        return basePath_;
    }
    return std::filesystem::path(basePath_.wstring() + L"." + std::to_wstring(rotation_));
}

bool JsonWriter::Open(std::string& error)
{
    error.clear();
    if (maximumBytes_ < 4096u) {
        error = "The rotation size must be at least 4096 bytes.";
        return false;
    }
    const auto parent = basePath_.parent_path();
    std::error_code filesystemError;
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, filesystemError);
        if (filesystemError) {
            error = "Could not create the output directory: " + filesystemError.message();
            return false;
        }
    }
    output_.open(CurrentPath(), std::ios::binary | std::ios::out | std::ios::trunc);
    if (!output_) {
        error = "Could not open the JSONL output file.";
        return false;
    }
    currentBytes_ = 0u;
    return true;
}

bool JsonWriter::Rotate(std::string& error)
{
    output_.flush();
    output_.close();
    if (rotation_ == std::numeric_limits<std::uint32_t>::max()) {
        error = "The output rotation counter is exhausted.";
        return false;
    }
    ++rotation_;
    output_.clear();
    output_.open(CurrentPath(), std::ios::binary | std::ios::out | std::ios::trunc);
    if (!output_) {
        error = "Could not open a rotated JSONL output file.";
        return false;
    }
    currentBytes_ = 0u;
    return true;
}

bool JsonWriter::WriteLine(const std::string& line, std::string& error)
{
    error.clear();
    const std::uint64_t required = static_cast<std::uint64_t>(line.size()) + 1u;
    if (currentBytes_ != 0u && required > maximumBytes_ -
        std::min(currentBytes_, maximumBytes_)) {
        if (!Rotate(error)) {
            return false;
        }
    }
    output_.write(line.data(), static_cast<std::streamsize>(line.size()));
    output_.put('\n');
    if (!output_) {
        error = "Writing the JSONL output failed.";
        return false;
    }
    currentBytes_ += required;
    return true;
}

void JsonWriter::Flush() noexcept
{
    output_.flush();
}

}  // namespace kernelscope
