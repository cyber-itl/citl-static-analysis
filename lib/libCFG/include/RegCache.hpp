#pragma once

#include <map>
#include <cstdint>

#include "CfgRes.hpp"

template<typename BITS>
class RegCache {
  public:
    RegCache() : m_last_removed(0) {};

    CfgRes<BITS> get_reg(uint32_t reg_numb) const {
        auto reg_val = m_reg_cache.find(reg_numb);
        if (reg_val == m_reg_cache.end()) {
            return CfgRes<BITS>(CfgErr::NO_REG);
        }

        return CfgRes<BITS>(reg_val->second);
    }

    bool has_reg(uint32_t reg_numb) const {
        if (m_reg_cache.find(reg_numb) != m_reg_cache.end()) {
            return true;
        }
        return false;
    }

    void set_reg(uint32_t reg_numb, BITS value) {
        m_reg_cache[reg_numb] = value;
    }

    void remove_reg(uint32_t reg_numb) {
        auto it = m_reg_cache.find(reg_numb);
        if (it != m_reg_cache.end()) {
            m_last_removed = it->second;
            m_reg_cache.erase(it);
        }
    }

    void clear() {
        m_reg_cache.clear();
        m_last_removed = 0;
    }

    CfgRes<BITS> get_last_removed() const {
        return CfgRes<BITS>(m_last_removed);
    }

  private:
    std::map<uint32_t, BITS> m_reg_cache;
    BITS m_last_removed;
};
