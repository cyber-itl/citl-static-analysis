#include <cstdint>
#include "Block.hpp"

block_range make_range(uint64_t lower, uint64_t upper) {
    return std::make_pair(lower,upper);
}
block_range make_range(uint64_t target) {
    return std::make_pair(target, target);
}
