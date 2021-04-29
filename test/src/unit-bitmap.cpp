#include "MemBitMap.hpp"
#include "catch2/catch.hpp"

CATCH_TEST_CASE("MemBitMap tests")
{
    auto bitmap = new MemBitMap();

    CATCH_SECTION("basic map")
    {
        bitmap->add_map(0x1000, 0x100);
        CATCH_REQUIRE(bitmap->has_addr(0x1000));

        bitmap->set_bit_range(0x1000, 0x10, MapFlag::BLOCK);
        CATCH_REQUIRE(bitmap->get_bit(0x1001, MapFlag::BLOCK));
        CATCH_REQUIRE_FALSE(bitmap->get_bit(0x1001, MapFlag::SCAN));
        CATCH_REQUIRE(bitmap->get_bit(0x1001, MapFlag::ANY));

        CATCH_REQUIRE(bitmap->get_bit(0x1001, (MapFlag::BLOCK | MapFlag::SCAN)));
        CATCH_REQUIRE(bitmap->get_bit(0x1001, (MapFlag::SCAN ^ MapFlag::ANY)));


        bitmap->set_bit_range(0x1020, 0x10, (MapFlag::BLOCK | MapFlag::SWITCH));
        CATCH_REQUIRE(bitmap->get_bit(0x1021, MapFlag::BLOCK));
        CATCH_REQUIRE(bitmap->get_bit(0x1021, MapFlag::SWITCH));

        CATCH_REQUIRE(bitmap->get_bit(0x1021, (MapFlag::BLOCK | MapFlag::SCAN)));

        CATCH_REQUIRE_FALSE(bitmap->get_bit(0x1021, MapFlag::SCAN));
    }

     CATCH_SECTION("overlapping maps") {
         bitmap->add_map(0x1000, 0x100);
         bitmap->set_bit_range(0x1000, 0x10, (MapFlag::BLOCK | MapFlag::SWITCH));
         CATCH_REQUIRE(bitmap->get_bit(0x1001, MapFlag::BLOCK));
         CATCH_REQUIRE(bitmap->get_bit(0x1001, MapFlag::SWITCH));

         CATCH_REQUIRE(bitmap->get_bit(0x1001, (MapFlag::BLOCK | MapFlag::SWITCH)));
         CATCH_REQUIRE(bitmap->get_flag(0x1001) == (MapFlag::BLOCK | MapFlag::SWITCH));
     }

     CATCH_SECTION("clearing ranges") {
         bitmap->add_map(0x1000, 0x100);
         bitmap->set_bit_range(0x1000, 0x10, MapFlag::BLOCK);
         CATCH_REQUIRE(bitmap->get_bit(0x1001, MapFlag::BLOCK));

         CATCH_REQUIRE(bitmap->clear_bit_range(0x1000, 0x5));

         CATCH_REQUIRE_FALSE(bitmap->get_bit(0x1000, MapFlag::BLOCK));
         CATCH_REQUIRE(bitmap->get_bit(0x1006, MapFlag::BLOCK));
     }

     delete bitmap;
}

