#include "TestHarness.h"

#include <iostream>

int main()
{
    std::size_t failures = 0u;
    for (const auto& test : kernelscope::tests::Registry()) {
        try {
            test.function();
            std::cout << "[PASS] " << test.name << '\n';
        } catch (const std::exception& exception) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << ": " << exception.what() << '\n';
        } catch (...) {
            ++failures;
            std::cerr << "[FAIL] " << test.name << ": unknown exception\n";
        }
    }
    std::cout << "Executed " << kernelscope::tests::Registry().size()
        << " tests; failures=" << failures << '\n';
    return failures == 0u ? 0 : 1;
}

