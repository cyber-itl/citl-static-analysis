#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "json.hpp"
#include "capstone/capstone.h"

class CpuState;
struct Block;
struct Symbol;


using json = nlohmann::json;

enum class event_type {
    NONE = 0,
    INSN,
    BLOCK,
    SYM_BRANCH,
    FUNC
};

class AnalyzerEvent {
  public:
    virtual ~AnalyzerEvent() = default;

    event_type get_type() const {
        return m_type;
    }

    std::string get_name() const {
        return m_analyzer_name;
    }

    virtual int run(CpuState *cpu, Block *block, cs_insn *insn, const Symbol *sym) = 0;

    virtual json get_results() const = 0;

  protected:
    AnalyzerEvent(std::string name, event_type type) : m_type(type), m_analyzer_name(std::move(name)) {};

    const std::string m_analyzer_name;
    event_type m_type;
};

class EventManager {
  public:
    EventManager() = default;

    void register_event(std::unique_ptr<AnalyzerEvent> event);
    void run_events(event_type type, CpuState *cpu, Block *block, cs_insn *insn);
    void run_events(event_type type, CpuState *cpu, Block *block, cs_insn *insn, const Symbol *sym);

    void clear();

    const std::vector<std::unique_ptr<AnalyzerEvent>> *get_events() const;

  private:
    std::vector<std::unique_ptr<AnalyzerEvent>> m_events;
};
