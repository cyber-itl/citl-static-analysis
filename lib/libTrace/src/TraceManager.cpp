#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>
#include <utility>

#include "llvm/Object/ObjectFile.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/Object/Error.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"

#include "glog/logging.h"

using namespace llvm;
using namespace object;

#include "TraceManager.hpp"
#include "TraceDefs.hpp"
#include "TraceAnalyzer.hpp"
#include "SymTraceAnalyzer.hpp"
#include "DisasmAnalyzer.hpp"
#include "EventManager.hpp"
// #include "LiftingAnalyzer.hpp"


#include "Cfg.hpp"
#include "MemoryMap.hpp"
#include "SymResolver.hpp"
#include "ElfSyms.hpp"


std::pair<bool, std::string> read_bin_str(uint8_t *&ptr) {
    // Should be std::optional<> instead of pair, update if switched to c++17
    uint32_t tmp = *(uint32_t *)ptr;
    std::string ret;
    ptr += sizeof(tmp);

    if (tmp == (uint32_t) -1) {
        return {false, ret};
    }

    ret.resize(tmp);
    ret.assign(reinterpret_cast<char *>(ptr), tmp);
    ptr += tmp;

    return {true, ret};
}

bool process_trace(TraceAnalyzer *analyzer, std::map<uint64_t, Module> *mod_map, std::string trace_path) {
    struct stat st;

    if (stat(trace_path.c_str(), &st) != 0) {
        LOG(ERROR) << "Failed to stat input path: " << trace_path << " err: " << strerror(errno);
        return false;
    }

    int fd = open(trace_path.c_str(), O_RDONLY);
    if (fd < 0) {
        LOG(ERROR) << "Failed to open input path: " << trace_path << " err: " << strerror(errno);
        return false;
    }

    uint8_t *map_file = static_cast<uint8_t *> (mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
    if (!map_file) {
        LOG(FATAL) << "Failed to mmap input path: " << trace_path << " err: " << strerror(errno);
    }
    uint8_t *ptr = map_file;

    TestCase tc;
    uint32_t tmp_32 = 0;
    uint64_t tmp_64 = 0;

    tc.lastmutated = *(decltype(tc.lastmutated) *)ptr;
    ptr += sizeof(tc.lastmutated);

    auto last_mut_res = read_bin_str(ptr);
    if (!last_mut_res.first) {
        LOG(ERROR) << "Failed to parse lastmutator";
        goto err;
    }
    tc.lastmutator = last_mut_res.second;

    tc.lastmut_offset = *(decltype(tc.lastmut_offset) *)ptr;
    ptr += sizeof(tc.lastmut_offset);

    tc.serial = *(decltype(tc.serial) *)ptr;
    ptr += sizeof(tc.serial);

    tc.parent_serial = *(decltype(tc.parent_serial) *)ptr;
    ptr += sizeof(tc.parent_serial);

    while (true) {
        auto arg = read_bin_str(ptr);
        if (!arg.first) {
            break;
        }
        tc.argv.push_back(arg.second);
    }

    while (true) {
        auto key = read_bin_str(ptr);
        if (!key.first) {
            break;
        }
        auto val = read_bin_str(ptr);
        if (!val.first) {
            break;
        }
        tc.envp.emplace_back(key.second, val.second);
    }

    tc.stdin_str = read_bin_str(ptr).second;

    while (true) {
        auto name = read_bin_str(ptr);
        if (!name.first) {
            break;
        }
        auto contents = read_bin_str(ptr);
        if (!contents.first) {
            break;
        }
        tc.files.emplace_back(name.second, contents.second);
    }

    tc.hasrun = *(decltype(tc.hasrun) *)ptr;
    ptr += sizeof(tc.hasrun);

    tc.hascrash = *(decltype(tc.hascrash) *)ptr;
    ptr += sizeof(tc.hascrash);

    tc.hitcnt = *(decltype(tc.hitcnt) *)ptr;
    ptr += sizeof(tc.hitcnt);

    tc.msec_delta = *(decltype(tc.msec_delta) *)ptr;
    ptr += sizeof(tc.msec_delta);

    tc.runs_total = *(decltype(tc.runs_total) *)ptr;
    ptr += sizeof(tc.runs_total);

    while (true) {
        tmp_64 = *(uint64_t *)ptr;
        ptr += sizeof(tmp_64);
        if (tmp_64 == 0ULL) {
            break;
        }
        if (mod_map->count(tmp_64) == 0) {
            LOG(ERROR) << "Missing module in mod map: " << tmp_64;
            goto err;
        }
        tc.mod_ids.push_back(tmp_64);
    }

    while (true) {
        auto opt = read_bin_str(ptr);
        if (!opt.first) {
            break;
        }
        tc.getopt_strs.push_back(opt.second);
    }

    while (true) {
        auto env = read_bin_str(ptr);
        if (!env.first) {
            break;
        }
        tc.unsat_envs.push_back(env.second);
    }

    while (true) {
        auto file = read_bin_str(ptr);
        if (!file.first) {
            break;
        }
        tc.unsat_files.push_back(file.second);
    }

    tc.uses_stdin = *(decltype(tc.uses_stdin) *)ptr;
    ptr += sizeof(tc.uses_stdin);

    tc.timed_out = *(decltype(tc.timed_out) *)ptr;
    ptr += sizeof(tc.timed_out);

    tc.bailed_out = *(decltype(tc.bailed_out) *)ptr;
    ptr += sizeof(tc.bailed_out);

    // trace
    tmp_32 = *(uint32_t *)ptr;
    ptr += sizeof(tmp_32);
    if (tmp_32 == (uint32_t) -1) {
        tc.trace_log = nullptr;
        tc.trace_size = 0;
    } else {
        tc.trace_log = ptr;
        tc.trace_size = tmp_32;
    }
    ptr += tmp_32;

    if (ptr >= (map_file + st.st_size)) {
        LOG(ERROR) << "Invalid trace size: 0x" << std::hex << tmp_32;
        goto err;
    }

    // call
    tmp_32 = *(uint32_t *)ptr;
    ptr += sizeof(tmp_32);
    if (tmp_32 == (uint32_t) -1) {
        tc.call_log = nullptr;
        tc.call_size = 0;
    } else {
        tc.call_log = ptr;
        tc.call_size = tmp_32;
    }
    ptr += tmp_32;

    // fault
    tmp_32 = *(uint32_t *)ptr;
    ptr += sizeof(tmp_32);
    if (tmp_32 == (uint32_t) -1) {
        tc.fault_log = nullptr;
        tc.fault_size = 0;
    } else {
        tc.fault_log = ptr;
        tc.fault_size = tmp_32;
    }
    ptr = nullptr;

    analyzer->set_testcase(&tc);
    if (!analyzer->init()) {
        LOG(ERROR) << "Failed to init analyzer";
        goto err;
    }

    if (!analyzer->run()) {
        LOG(ERROR) << "Failed to run analyzer: " << analyzer->m_name << " on: " << trace_path;
    }

err:
    if (munmap(map_file, st.st_size) == -1) {
        LOG(FATAL) << "Failed to munmap input path: " << trace_path << " err: " << strerror(errno);
    }
    close(fd);
    return true;
}

std::unique_ptr<TraceAnalyzer> create_analyzer(std::string analyzer, std::map<uint64_t, Module> *mod_map) {
    if (analyzer == "symtrace") {
        return std::make_unique<SymTraceAnalyzer>(mod_map);
    }
    else if (analyzer == "lift") {
        return std::make_unique<DisasmAnalyzer>(mod_map);
    }
    else {
        LOG(ERROR) << "Failed to find analyzer: " << analyzer;
        return nullptr;
    }
}

ThreadPool::ThreadPool(uint32_t thread_count, std::map<uint64_t, Module> *modmap, std::string analyzer_name) :
    m_thread_count(thread_count),
    m_terminate(false),
    m_mutex(),
    m_busy(m_thread_count),
    m_mod_map(modmap),
    m_analyzer_name(analyzer_name)
    {};

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::add_work(std::string item) {
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_queue.push(item);
    }
    m_cond.notify_one();
}

void ThreadPool::startup() {
    for (uint32_t i = 0; i < m_thread_count; i++) {
        m_pool.push_back(std::thread(&ThreadPool::wait_for_work, this));
    }
}

void ThreadPool::wait() {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_completed.wait(lock, [this]{ return m_queue.empty() && m_busy == 0; });
}

void ThreadPool::shutdown() {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_terminate = true;
    for (auto &thread : m_pool) {
        thread.join();
    }
    m_cond.notify_all();
    m_pool.clear();
}

void ThreadPool::wait_for_work() {
    auto analyzer = create_analyzer(m_analyzer_name, m_mod_map);
    if (!analyzer) {
        return;
    }
    while (true) {
        std::string work_arg;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cond.wait(lock, [this]{ return !m_queue.empty() || !m_terminate; });
            if (m_queue.empty() || m_terminate) {
                m_busy--;
                m_completed.notify_one();
                return;
            }
            work_arg = m_queue.front();
            m_queue.pop();
            LOG(INFO) << "starting work item: " << work_arg << " queue size: " << m_queue.size();

            lock.unlock();
            process_trace(analyzer.get(), m_mod_map, work_arg);
            lock.lock();
            analyzer->output_results();
        }
    }
}

TraceManager::TraceManager(std::string bin_dir) :
    m_bin_dir(bin_dir) {};

template <typename ELFT, typename ELFOBJ>
bool construct_elf_module(const ELFOBJ *obj, Module &mod, uint64_t &ep) {
    mod.resolver = std::make_shared<ElfSyms<ELFT>>(obj, mod.mem_map);
    if (mod.resolver->generate_symbols()) {
        LOG(ERROR) << "Failed to generate ELF symbols, most likely static binary";
        return false;
    }

    auto elf_file = obj->getELFFile();
    if (!elf_file) {
        LOG(ERROR) << "Failed to get elf file";
        return false;
    }

    const typename ELFT::Ehdr *hdr = elf_file->getHeader();
    if (!hdr) {
        LOG(ERROR) << "Failed to get elf header";
        return false;
    }
    ep = hdr->e_entry;

    return true;
}

bool TraceManager::create_mod_map() {
    struct dirent *dent;
    DIR *dir = opendir(m_bin_dir.c_str());
    if (!dir) {
        LOG(FATAL) << "Failed to open corpus dir: " << m_bin_dir << " err: " << strerror(errno);
    }

    do {
        dent = readdir(dir);
        if (!dent) {
            break;
        }
        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
            continue;
        }

        std::string filename(dent->d_name);
        auto idx = filename.find(".");
        if (idx == std::string::npos) {
            LOG(WARNING) << "Invalid filename format: '" << filename << "' should be <modid>.bin";
            continue;
        }
        uint64_t modid = std::stoull(filename.substr(0, idx));

        std::string path = m_bin_dir + "/" + dent->d_name;
        Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(path);
        if (!BinaryOrErr) {
            LOG(ERROR) << "Failed to create binary from: " << path;
            continue;
        }

        Module mod;
        mod.own_bin = std::move(BinaryOrErr.get());
        Binary *bin = mod.own_bin.getBinary();
        if (!bin) {
            LOG(ERROR) << "Failed to getBinary()";
            continue;
        }

        if (const ObjectFile *obj = dyn_cast<ObjectFile>(bin)) {
            mod.obj = obj;
            mod.mem_map = std::make_shared<MemoryMap>(obj);

            uint64_t ep = 0;
            if (const auto *ELFObj = dyn_cast<ELF32LEObjectFile>(obj)) {
                if (!construct_elf_module<ELFType<support::little, false>>(ELFObj, mod, ep)) {
                    continue;
                }
            }
            else if (const auto *ELFObj = dyn_cast<ELF32BEObjectFile>(obj)) {
                if (!construct_elf_module<ELFType<support::big, false>>(ELFObj, mod, ep)) {
                    continue;
                }
            }
            else if (const auto *ELFObj = dyn_cast<ELF64LEObjectFile>(obj)) {
                if (!construct_elf_module<ELFType<support::little, true>>(ELFObj, mod, ep)) {
                    continue;
                }
            }
            else if (const auto *ELFObj = dyn_cast<ELF64BEObjectFile>(obj)) {
                if (!construct_elf_module<ELFType<support::big, true>>(ELFObj, mod, ep)) {
                    continue;
                }
            }

            mod.cfg = std::unique_ptr<Cfg>(new Cfg(obj, mod.resolver, mod.mem_map, std::make_shared<EventManager>()));
            if (mod.cfg->create_cfg(ep)) {
                LOG(FATAL) << "Failed to create CFG";
            }

            mod.block_map = mod.cfg->get_cfg_map();

            if (!mod.block_map) {
                LOG(FATAL) << "Failed to get CFG block map";
            }

            LOG(INFO) << "Processed mod: " << modid;
            m_mod_map[modid] = std::move(mod);
        }
        else {
            LOG(ERROR) << "Failed to cast bin to ObjectFile, invalid format?";
            continue;
        }

    } while (true);
    closedir(dir);
    return true;
}

bool TraceManager::process_testcase(std::string trace_path, std::string analyzer) {
    auto selected_analyzer = create_analyzer(analyzer, &m_mod_map);
    if (!process_trace(selected_analyzer.get(), &m_mod_map, trace_path)) {
        LOG(ERROR) << "Failed to process trace: " << trace_path;
        return false;
    }

    selected_analyzer->output_header();
    selected_analyzer->output_results();
    return true;
}


bool TraceManager::process_corpus(std::string corpus_dir, std::string analyzer, uint32_t thread_count) {
    // TODO: avoid creating temp analyzer just for the header
    auto tmp_analyzer = create_analyzer(analyzer, &m_mod_map);
    if (!tmp_analyzer) {
        return false;
    }
    tmp_analyzer->output_header();


    ThreadPool pool(thread_count, &m_mod_map, analyzer);

    struct dirent *dent;
    DIR *dir = opendir(corpus_dir.c_str());
    if (!dir) {
        LOG(FATAL) << "Failed to open corpus dir: " << corpus_dir << " err: " << strerror(errno);
    }

    do {
        dent = readdir(dir);
        if (!dent) {
            break;
        }
        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
            continue;
        }

        std::string path = corpus_dir + "/" + dent->d_name;
        pool.add_work(path);
    } while (true);

    pool.startup();
    pool.wait();
    closedir(dir);

    return true;
}

bool exists(std::string path, bool is_dir) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }

    if (is_dir && !S_ISDIR(st.st_mode)) {
        return false;
    }

    return true;
}
