#include <cstdint>
#include "CfgRes.hpp"
#include "RegCache.hpp"
#include "capstone/capstone.h"
#include "catch2/catch.hpp"

CATCH_TEST_CASE("RegCache tests")
{
    RegCache<uint64_t> reg_cache;
    uint64_t reg_val = 0x10;

    CATCH_SECTION("simple cache")
    {
        reg_cache.set_reg(X86_REG_EAX, reg_val);

        CATCH_REQUIRE(reg_cache.has_reg(X86_REG_EAX));

        CfgRes<uint64_t> reg_res = reg_cache.get_reg(X86_REG_EAX);
        CATCH_REQUIRE(reg_res);
        CATCH_REQUIRE(*reg_res == reg_val);

        reg_cache.remove_reg(X86_REG_EAX);

        CATCH_REQUIRE_FALSE(reg_cache.has_reg(X86_REG_EAX));
    }

    CATCH_SECTION("simple clear") {
        reg_cache.set_reg(X86_REG_EAX, reg_val);
        reg_cache.clear();
        CATCH_REQUIRE_FALSE(reg_cache.has_reg(X86_REG_EAX));
    }
}
