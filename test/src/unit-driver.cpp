#include "Driver.hpp"
#include "catch2/catch.hpp"

CATCH_TEST_CASE("Driver tests")
{
    CATCH_SECTION("")
    {
        Driver analyzer = Driver(CATCH_INPUT_BIN);
        CATCH_REQUIRE(analyzer.analyze() == 0);

    }
}

