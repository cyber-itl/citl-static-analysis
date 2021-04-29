#pragma once

#include <cstdint>
#include <cmath>
#include <map>

template <class MachHeader>
bool check_flags(const MachHeader &hdr, uint64_t flag_val) {
    if (hdr.flags & flag_val) {
        return true;
    }
    return false;
}

template <typename T>
float calc_entropy(T *data, uint64_t size) {
    float entropy = 0;
    std::map<T, uint64_t> counts;

    for (uint64_t dataidx = 0; dataidx < size; dataidx++) {
        counts[data[dataidx]]++;
    }

    for (const auto &kv : counts) {
        float p_x = static_cast<float>(kv.second) / size;
        if (p_x > 0) {
            entropy -= p_x * std::log(p_x) / std::log(2);
        }
    }

    return entropy;
}

template <typename T>
std::map<uint8_t, uint64_t> make_entropy_hist(T *data, uint64_t size) {
    std::map<uint8_t, uint64_t> counts;

    for (uint64_t dataidx = 0; dataidx < size; dataidx++) {
        counts[data[dataidx]]++;
    }

    return counts;
}
