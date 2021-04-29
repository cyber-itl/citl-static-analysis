#pragma once

#include <cstdint>

struct MemRange {
    MemRange() = default;
    MemRange(uint64_t addr, uint64_t size, const uint8_t *ptr) : addr(addr), size(size), ptr(ptr), cur_addr(addr) {};

    uint64_t addr {0};
    uint64_t size {0};
    const uint8_t *ptr {nullptr};
    uint64_t cur_addr {0};
};

inline bool operator==(const MemRange&lhs, const MemRange &rhs) {
    return lhs.addr == rhs.addr;
}
inline bool operator==(const uint64_t &lhs, const MemRange &rhs) {
    return lhs == rhs.addr;
}
inline bool operator==(const MemRange &lhs, const uint64_t &rhs) {
    return lhs.addr == rhs;
}
