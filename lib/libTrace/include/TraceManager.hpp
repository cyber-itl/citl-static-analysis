#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <queue>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "TraceDefs.hpp"


class ThreadPool {
  public:
    ThreadPool(uint32_t thread_count, std::map<uint64_t, Module> *modmap, std::string analyzer_name);
    ~ThreadPool();

    void add_work(std::string item);
    void startup();
    void wait();
    void shutdown();

  private:
    // External sets
    uint32_t m_thread_count;
    std::string m_analyzer_name;

    // Internals
    std::vector<std::thread> m_pool;
    std::mutex m_mutex;
    std::condition_variable m_cond;
    std::condition_variable m_completed;
    uint32_t m_busy;
    bool m_terminate;
    std::queue<std::string> m_queue;

    // For the work:
    std::map<uint64_t, Module> *m_mod_map = nullptr;

    void wait_for_work();
};


class TraceManager {
  public:
    TraceManager(std::string bin_dir);
    bool create_mod_map();
    bool process_testcase(std::string trace_path, std::string analyzer);
    bool process_corpus(std::string corpus_dir, std::string analyzer, uint32_t thread_count);

  private:
    std::string m_bin_dir;
    std::map<uint64_t, Module> m_mod_map;
};

bool exists(std::string path, bool is_dir);