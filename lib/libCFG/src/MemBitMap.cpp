#include <cstdint>
#include <vector>
#include <algorithm>
#include <string.h>

#include <sys/mman.h>

#include "glog/logging.h"

#include "MemoryMap.hpp"
#include "MemRange.hpp"
#include "MemBitMap.hpp"

static const uint8_t shift_tab[2] = { 0, 4 };


bool MemBitMap::add_map(uint64_t addr, uint64_t size) {
    for (const auto &mapping : m_maps) {
        if (mapping.addr == addr && mapping.size == size) {
            return true;
        }
        else if (mapping.addr == addr && mapping.size != size) {
            LOG(FATAL) << "Tried to remap page: 0x" << std::hex << addr << " with different sizes";
        }
    }

    MapHolder mapping;
    mapping.addr = addr;
    mapping.size = size;
    mapping.ptr = static_cast<uint8_t *>(mmap(NULL, (mapping.size + 1) >> 1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    PCHECK(mapping.ptr) << "Failed to mmap range addr: 0x" << std::hex << addr << " size: 0x" << size;

    m_maps.emplace_back(mapping);

    return true;
}

bool MemBitMap::set_bit_range(uint64_t addr, uint64_t size, MapFlag flags) {
    uint8_t flagb = (uint8_t) flags;
    for (const auto &map : m_maps) {
        if (addr >= map.addr && addr < (map.addr + map.size)) {
            uint64_t pos = addr - map.addr;
            uint64_t max_pos = std::min(pos + size, map.size);

            if(pos & 1)
                map.ptr[(pos++) >> 1] |= (flagb << 4);
            memset(&map.ptr[pos >> 1], (flagb << 4) | flagb,
                (max_pos - pos) >> 1);
            if(max_pos & 1)
                map.ptr[max_pos >> 1] |= flagb;
            return true;
        }
    }
    return false;
}

bool MemBitMap::clear_bit_range(uint64_t addr, uint64_t size) {
    for (const auto &map : m_maps) {
        if (addr >= map.addr && addr < (map.addr + map.size)) {
            uint64_t pos = addr - map.addr;
            uint64_t max_pos = std::min(pos + size, map.size);

            if(pos & 1)
                map.ptr[(pos++) >> 1] &= 0xf;
            memset(&map.ptr[pos >> 1], 0x0, (max_pos - pos) >> 1);
            if(max_pos & 1)
                map.ptr[max_pos >> 1] &= 0xf0;

            return true;
        }
    }
    return false;

}

bool MemBitMap::has_addr(uint64_t addr) const {
    for (const auto &map : m_maps) {
        if (addr >= map.addr && addr < (map.addr + map.size)) {
            return true;
        }
    }
    return false;
}

// Private member
bool MemBitMap::get_bit(uint8_t *ptr, uint64_t pos, MapFlag flags) {
    return ptr[pos >> 1] & (((uint8_t) flags) << shift_tab[pos & 1]);
}

MapFlag MemBitMap::get_flag(uint8_t *ptr, uint64_t pos) {
    return static_cast<MapFlag>((ptr[pos >> 1] >> shift_tab[pos & 1]) & 0xf);
}


bool MemBitMap::get_bit(uint64_t addr, MapFlag flags) {
    for (const auto &map : m_maps) {
        if (addr >= map.addr && addr < (map.addr + map.size)) {
            uint64_t pos = addr - map.addr;
            return get_bit(map.ptr, pos, flags);
        }
    }
    return false;
}

MapFlag MemBitMap::get_flag(uint64_t addr) {
    for (const auto &map : m_maps) {
        if (addr >= map.addr && addr < (map.addr + map.size)) {
            uint64_t pos = addr - map.addr;
            return get_flag(map.ptr, pos);
        }
    }
    return MapFlag::NONE;
}

std::vector<MemRange> MemBitMap::get_unset_ranges(const MemoryMap *memmap, MapFlag flags) {
    std::vector<MemRange> ranges;

    for (auto &map : m_maps) {
        uint64_t last_null = 0;

        if (!map.size) {
            continue;
        }

        const MemPage *page_ptr = memmap->addr_to_page(map.addr);
        CHECK(page_ptr) << "Failed to get page for: 0x" << std::hex << map.addr;

        if (!page_ptr->data) {
            continue;
        }

        for (uint64_t i = 0; i < map.size; i++) {
            if (!last_null) {
                if (!this->get_bit(map.ptr, i, flags)) {
                    last_null = map.addr + i;
                }
            }
            else {
                if (this->get_bit(map.ptr, i, flags)) {
                    uint64_t hole_size = (map.addr + i) - last_null;
                    CHECK((last_null + hole_size) <= (page_ptr->address + page_ptr->size)) << "Invalid hole, past memory region";

                    ranges.emplace_back(last_null, hole_size, page_ptr->data + (last_null - map.addr));
//                    LOG(INFO) << "Hole at: 0x" << std::hex << last_null << " size: 0x" << hole_size;
                    last_null = 0;
                }
            }
//            LOG(INFO) << "Current addr: 0x" << std::hex << map.addr + i << " bit: " << this->get_bit(map.ptr, i);
        }

        if (last_null) {
            uint64_t hole_size = (map.addr + map.size) - last_null;
            CHECK((last_null + hole_size) <= (page_ptr->address + page_ptr->size)) << "Invalid hole, past memory region";

            ranges.emplace_back(last_null, hole_size, page_ptr->data + (last_null - map.addr));
//            LOG(INFO) << "Hole at: 0x" << std::hex << last_null << " size: 0x" << hole_size;
        }
    }
    return ranges;
}

void MemBitMap::clear() {
    for (const auto &map : m_maps) {
        memset(map.ptr, 0, map.size);
    }
}

MemBitMap::~MemBitMap() {
    if (m_maps.size()) {
        for (auto &map : m_maps) {
//            LOG(INFO) << "Unmapping: 0x" << std::hex <<  map.addr << " size: 0x" << map.size;
            if (munmap(map.ptr, (map.size + 1) >> 1) == -1) {
                PLOG(FATAL) << "Failed to munmap";
            }
            map.ptr = nullptr;
        }
        m_maps.clear();
    }
}
