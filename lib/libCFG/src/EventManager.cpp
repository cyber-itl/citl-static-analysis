#include <vector>
#include <memory>

#include "capstone/capstone.h"
#include "glog/logging.h"

#include "EventManager.hpp"

class CpuState;
struct Block;
struct Symbol;

void EventManager::register_event(std::unique_ptr<AnalyzerEvent> event) {
    m_events.push_back(std::move(event));
}

void EventManager::run_events(event_type type, CpuState *cpu, Block *block, cs_insn *insn) {
    this->run_events(type, cpu, block, insn, nullptr);
}

void EventManager::run_events(event_type type, CpuState *cpu, Block *block, cs_insn *insn, const Symbol *sym) {
    for (const auto &event : m_events) {
        if (event->get_type() == type) {
            if (event->run(cpu, block, insn, sym)) {
                LOG(FATAL) << "Failed to run event analyzer: " << event->get_name();
            }
        }
    }
}

void EventManager::clear() {
    m_events.clear();
}

const std::vector<std::unique_ptr<AnalyzerEvent>> *EventManager::get_events() const {
    return &m_events;
}
