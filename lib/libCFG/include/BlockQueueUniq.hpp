#pragma once

#include <set>
#include <queue>
#include <cstdint>

#include "Block.hpp"

class BlockQueueUniq {
  private:
    std::set<uint64_t> m_set;
    std::queue<Block> m_queue;

  public:
    bool push(Block block);
    Block pop();

    bool del_elm(Block block);

    bool in_queue(const Block &block) const;
    bool empty() const;
};
