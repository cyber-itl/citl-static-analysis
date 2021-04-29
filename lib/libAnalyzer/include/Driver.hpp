#pragma once

#include <cstdint>
#include <string>
#include <utility>

#include "json.hpp"
using json = nlohmann::json;

class Driver {
  public:
    explicit Driver(std::string binpath) : m_binpath(std::move(binpath)) {};

    int analyze();
    void print() const;

    const json get_results() const;

  private:
    std::string m_binpath;
    json m_results;

    // Utils
    std::string sha256(const std::string &path) const;
    std::string md5(const std::string &path) const;

    template<typename T>
    std::string hexify(T data, uint64_t size) const;

    std::string cpu_type_str(uint32_t cpu_type, uint32_t sub_type) const;
};
