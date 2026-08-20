#include "TestHarness.h"

#include "../collector/EventProcessor.h"

KS_TEST_CASE("Sequence tracker detects gaps but not its first observation")
{
    kernelscope::SequenceTracker tracker;
    KS_REQUIRE(!tracker.Observe(10u).has_value());
    KS_REQUIRE(!tracker.Observe(11u).has_value());
    const auto gap = tracker.Observe(15u);
    KS_REQUIRE(gap.has_value());
    KS_REQUIRE(gap->expected == 12u);
    KS_REQUIRE(gap->actual == 15u);
    KS_REQUIRE(gap->missing == 3u);
}

KS_TEST_CASE("JSON escaping covers quotes controls and backslashes")
{
    const std::string input = std::string("quote=\" slash=\\ line=\n byte=") + char(1);
    const std::string expected = "quote=\\\" slash=\\\\ line=\\n byte=\\u0001";
    KS_REQUIRE(kernelscope::JsonEscape(input) == expected);
}

