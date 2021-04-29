#include <cstdint>
#include <vector>
#include <utility>

#include "glog/logging.h"

#include "Block.hpp"
#include "BlockQueueUniq.hpp"

bool BlockQueueUniq::push(Block block) {
    if (m_set.insert(block.start).second) {
        m_queue.emplace(block);
        return true;
    }
    return false;
}

Block BlockQueueUniq::pop() {
    if (m_queue.empty()) {
        LOG(FATAL) << "popped from empty queue";
    }
    Block val = m_queue.front();

    auto it = m_set.find(val.start);
    if (it == m_set.end()) {
        LOG(FATAL) << "Tried to pop item that was missing from set";
    }
    if (*it != val.start) {
        LOG(FATAL) << "queue and set became mismatched, set != queue.start";
    }

    m_set.erase(it);
    m_queue.pop();

    return val;
}

// This should be a slow operation will all the copies,
// but in the context of the CFG it is called very rarely.

// Returns a copy of the deleted element
bool BlockQueueUniq::del_elm(Block block) {
    if (!m_set.count(block.start)) {
        return false;
    }
    m_set.erase(block.start);

    std::vector<Block> popped_elms;
    while (!m_queue.empty()) {
        Block cur_elm = m_queue.front();
        m_queue.pop();

        if (cur_elm == block) {
            continue;
        }
        popped_elms.emplace_back(cur_elm);
    }
    for (const auto &elm : popped_elms) {
        m_queue.emplace(elm);
    }

    return true;
}

bool BlockQueueUniq::in_queue(const Block &block) const {
    if (m_set.count(block.start)) {
        return true;
    }
    return false;
}

bool BlockQueueUniq::empty() const {
    return m_queue.empty();
}
