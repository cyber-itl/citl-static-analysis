#include "BlockQueueUniq.hpp"
#include "Block.hpp"
#include "catch2/catch.hpp"

CATCH_TEST_CASE("BlockQueueUniq tests")
{
    CATCH_SECTION("simple push")
    {
        auto value = Block(0x100);
        BlockQueueUniq queue;
        CATCH_REQUIRE(queue.push(value));
        CATCH_REQUIRE(queue.pop() == value);
    }
    CATCH_SECTION("duplicate push")
    {
        auto value = Block(0x100);
        BlockQueueUniq queue;
        CATCH_REQUIRE(queue.push(value));
        CATCH_REQUIRE_FALSE(queue.push(value));
    }
    CATCH_SECTION("check if exists")
    {
        auto value = Block(0x100);
        BlockQueueUniq queue;
        CATCH_REQUIRE(queue.push(value));
        CATCH_REQUIRE(queue.in_queue(value));
    }
    CATCH_SECTION("check delete")
    {
        auto value = Block(0x100);
        auto value2 = Block(0x200);

        BlockQueueUniq queue;
        CATCH_REQUIRE(queue.push(value));
        CATCH_REQUIRE(queue.push(value2));
        CATCH_REQUIRE(queue.del_elm(value));
        CATCH_REQUIRE_FALSE(queue.in_queue(value));
    }
}

// Catch currently can't handle SIGABRT sadly
//CATCH_TEST_CASE("unique_queue pop fail", "[!shouldfail]")
//{
//    CATCH_SECTION("pop test")
//    {
//        unique_queue<uint64_t> queue;
//        CATCH_FAIL(queue.pop());
//    }
//}
