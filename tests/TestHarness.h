#pragma once

#include <exception>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace kernelscope::tests {

struct TestCase {
    std::string name;
    std::function<void()> function;
};

inline std::vector<TestCase>& Registry()
{
    static std::vector<TestCase> tests;
    return tests;
}

class Registrar final {
public:
    Registrar(std::string name, std::function<void()> function)
    {
        Registry().push_back(TestCase{std::move(name), std::move(function)});
    }
};

[[noreturn]] inline void Fail(
    const char* expression,
    const char* file,
    const int line)
{
    std::ostringstream message;
    message << file << ':' << line << ": requirement failed: " << expression;
    throw std::runtime_error(message.str());
}

}  // namespace kernelscope::tests

#define KS_TEST_JOIN_INNER(A, B) A##B
#define KS_TEST_JOIN(A, B) KS_TEST_JOIN_INNER(A, B)
#define KS_TEST_CASE(Name) \
    static void KS_TEST_JOIN(KsTestFunction_, __LINE__)(); \
    static ::kernelscope::tests::Registrar KS_TEST_JOIN(KsTestRegistrar_, __LINE__)( \
        Name, KS_TEST_JOIN(KsTestFunction_, __LINE__)); \
    static void KS_TEST_JOIN(KsTestFunction_, __LINE__)()

#define KS_REQUIRE(Expression) \
    do { if (!(Expression)) ::kernelscope::tests::Fail(#Expression, __FILE__, __LINE__); } while (false)

