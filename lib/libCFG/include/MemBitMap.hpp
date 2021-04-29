#pragma once

#include <cstdint>
#include <vector>

class MemoryMap;
struct MemRange;

enum class MapFlag : uint8_t {
    NONE = 0,           // 0000
    BLOCK = 1,          // 0001
    SWITCH = 1 << 1,    // 0010
    SCAN = 1 << 2,      // 0100
    READ = 1 << 3,
    ANY = 0xf           // 1111
};

inline bool operator & (uint8_t lhs, MapFlag rhs) {
    return static_cast<bool>(static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
}
inline MapFlag operator | (MapFlag lhs, MapFlag rhs) {
    return static_cast<MapFlag>(static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
}
inline MapFlag operator ^ (MapFlag lhs, MapFlag rhs) {
    return static_cast<MapFlag>(static_cast<uint8_t>(lhs) ^ static_cast<uint8_t>(rhs));
}
inline MapFlag operator & (MapFlag lhs, MapFlag rhs) {
    return static_cast<MapFlag>(static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
}
inline uint8_t& operator |= (uint8_t& lhs, MapFlag rhs) {
    lhs = static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs);
    return lhs;
}


class MemBitMap {
  public:

    MemBitMap() = default;

    bool add_map(uint64_t addr, uint64_t size);

    bool set_bit_range(uint64_t addr, uint64_t size, MapFlag flags);

    bool clear_bit_range(uint64_t addr, uint64_t size);

    bool has_addr(uint64_t addr) const;

    bool get_bit(uint64_t addr, MapFlag flags);
    MapFlag get_flag(uint64_t addr);

    std::vector<MemRange> get_unset_ranges(const MemoryMap *memmap, MapFlag flags);

    void clear();

    ~MemBitMap();

  private:
    bool get_bit(uint8_t *ptr, uint64_t pos, MapFlag flags);
    MapFlag get_flag(uint8_t *ptr, uint64_t pos);

    struct MapHolder {
        MapHolder() = default;
        MapHolder(uint64_t addr, uint64_t size, uint8_t *ptr) : addr(addr), size(size), ptr(ptr) {};
        uint64_t addr {0};
        uint64_t size {0};
        uint8_t *ptr {nullptr};
    };

    std::vector<MapHolder> m_maps;
};
