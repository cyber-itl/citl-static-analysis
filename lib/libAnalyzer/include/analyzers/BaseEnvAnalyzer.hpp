#pragma once

#include "json.hpp"

using json = nlohmann::json;

class BaseEnvAnalyzer {
  public:
    virtual ~BaseEnvAnalyzer() = default;
    virtual int run() = 0;

    json get_results() const {
        return m_results;
    }

    std::string get_analyzer_name() const {
        return m_analyzer_name;
    }

  protected:
    explicit BaseEnvAnalyzer(std::string name) : m_analyzer_name(std::move(name)) {};
    const std::string m_analyzer_name;
    json m_results;
};
