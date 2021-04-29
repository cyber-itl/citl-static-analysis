#include <cstdint>
#include "CfgRes.hpp"
#include "catch2/catch.hpp"

CATCH_TEST_CASE("CfgRes tests")
{
    CATCH_SECTION("err test")
    {
        auto res = CfgRes<uint64_t>(CfgErr::BAD_READ);
        CATCH_REQUIRE_FALSE(res);
    }
    CATCH_SECTION("value test")
    {
        uint64_t res_val = 0x100;
        auto res = CfgRes<uint64_t>(res_val);
        CATCH_REQUIRE(res);
        CATCH_REQUIRE(*res == res_val);
    }
    CATCH_SECTION("null test")
    {
        uint64_t res_val = 0x0;
        auto res = CfgRes<uint64_t>(res_val);
        CATCH_REQUIRE(res);
        CATCH_REQUIRE(*res == res_val);
    }
}
