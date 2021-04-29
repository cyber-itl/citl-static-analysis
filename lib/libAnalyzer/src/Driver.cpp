#include <stdio.h>
#include <cstdint>
#include <string>
#include <utility>
#include <iostream>
#include <iomanip>
#include <memory>
#include <vector>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "llvm/Object/Binary.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/MachOUniversal.h"
#include "llvm/Object/Archive.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/fallible_iterator.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Error.h"

#include "gflags/gflags.h"
#include "glog/logging.h"

#include "Driver.hpp"
#include "ArchHandler.hpp"
#include "meta.hpp"

using namespace llvm;
using namespace object;

DEFINE_bool(pretty_print, true, "Pretty print the json output");
DEFINE_bool(omit_git, false, "Omit the git commit hash, used for test data");

DEFINE_string(metadata, "", "Adds key values to metadata json field, format: 'key:value,' ");

// Publics
int Driver::analyze() {
    Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(m_binpath);
    if (!BinaryOrErr) {
        std::string err_msg;
        // std::string("Failed to process binary " + m_binpath + ": ")
        raw_string_ostream ErrStream(err_msg);
        auto err = BinaryOrErr.takeError();

        logAllUnhandledErrors(std::move(err), ErrStream, "");
        LOG(ERROR) << ErrStream.str();
        return 1;
    }

    struct stat stat_buf;
    if (stat(m_binpath.c_str(), &stat_buf)) {
        PLOG(ERROR) << "Unable to stat file";
        return 1;
    }
    m_results["filesize"] = stat_buf.st_size;

    std::string hash = this->sha256(m_binpath);
    if (hash.empty()) {
        LOG(ERROR) << "Failed to create hash for file: " << m_binpath;
        return 1;
    }
    m_results["sha256"] = hash;

    std::string md5_hash = this->md5(m_binpath);
    if (md5_hash.empty()) {
        LOG(ERROR) << "Failed to create md5 hash for file: " << m_binpath;
        return 1;
    }
    m_results["md5"] = md5_hash;
    if (!FLAGS_omit_git) {
        m_results["git_commit"] = git_commit_sha1;
    }

    std::size_t filename_pos = m_binpath.find_last_of('/');
    std::string filename = m_binpath.substr(filename_pos + 1, m_binpath.length());

    m_results["filename"] = filename;

    auto owning_bin = std::move(BinaryOrErr.get());
    Binary *bin = owning_bin.getBinary();
    if (!bin) {
        LOG(ERROR) << "Failed to getBinary()";
        return 1;
    }

    std::string magic = this->hexify(bin->getMemoryBufferRef().getBufferStart(), 4);
    if (magic.empty()) {
        LOG(ERROR) << "Failed to get magic from Binary data";
        return 1;
    }
    m_results["magic"] = magic;

    if (FLAGS_metadata.size() != 0) {
        auto metadata_json = json::parse(FLAGS_metadata);

        m_results["metadata"] = metadata_json;
    }

    m_results["binaries"] = std::vector<json>();

    if (const Archive *arc = dyn_cast<Archive>(bin)) {
        Error err = Error::success();
        LOG(INFO) << "Processing archive file";

        for (auto &child : arc->children(err)) {
            Expected<std::unique_ptr<Binary>> childOrErr = child.getAsBinary();
            if (!childOrErr) {
                LOG(ERROR) << "Failed to process archive child";
                continue;
            }

            if (const ObjectFile *obj = dyn_cast<ObjectFile>(&*childOrErr.get())) {
                std::unique_ptr<ArchHandler> analyzer = handler_factory(obj);
                if (!analyzer) {
                    return 1;
                }
                Expected<StringRef> nameOrErr = child.getName();
                if (!nameOrErr) {
                    LOG(ERROR) << "Failed to get archive name";
                    return 1;
                }
                StringRef name = nameOrErr.get();

                json analyzer_result = analyzer->analyze();
                if (!analyzer_result.size()) {
                    LOG(ERROR) << "Failed to analyze binary";
                    continue;
                }

                analyzer_result["bin_name"] = name.str();
                m_results["binaries"].push_back(analyzer_result);
            }
            else {
                LOG(ERROR) << "Failed to cast archive child to Binary";
                continue;
            }
        }
    }
    else if (auto *mach = dyn_cast<MachOUniversalBinary>(bin)) {
        LOG(INFO) << "Processing FAT object file";

        for (MachOUniversalBinary::object_iterator I = mach->begin_objects(), E = mach->end_objects(); I != E; ++I) {
            Expected<std::unique_ptr<ObjectFile>> objOrErr = I->getAsObjectFile();
            if (!objOrErr) {
                LOG(ERROR) << "Failed to process MachOFat child";
                continue;
            }
            if (const ObjectFile *obj = dyn_cast<ObjectFile>(&*objOrErr.get())) {
                std::unique_ptr<ArchHandler> analyzer = handler_factory(obj);
                if (!analyzer) {
                    return 1;
                }

                json analyzer_result = analyzer->analyze();
                if (!analyzer_result.size()) {
                    LOG(ERROR) << "Failed to analyze binary";
                    continue;
                }

                analyzer_result["bin_name"] = this->cpu_type_str(I->getCPUType(), I->getCPUSubType());
                m_results["binaries"].push_back(analyzer_result);
            }
            else {
                LOG(ERROR) << "Failed to cast FAT child to Binary";
                continue;
            }
        }
    }
    else if (const ObjectFile *obj = dyn_cast<ObjectFile>(bin)) {
        std::unique_ptr<ArchHandler> analyzer = handler_factory(obj);
        if (!analyzer) {
            return 1;
        }
        json analyzer_result = analyzer->analyze();
        if (!analyzer_result.size()) {
            LOG(ERROR) << "Failed to analyze binary";
            return 1;
        }
        analyzer_result["bin_name"] = "";

        m_results["binaries"].push_back(analyzer_result);
    }
    else {
        LOG(ERROR) << "Failed to find a top level type: " << bin->getType();
        return 1;
    }

    return 0;
}


void Driver::print() const {
    if (FLAGS_pretty_print) {
        std::cout << m_results.dump(4) << std::endl << std::flush;
    }
    else {
        std::cout << m_results.dump() << std::endl << std::flush;
    }
}

const json Driver::get_results() const {
    return m_results;
}

// Privates

std::string Driver::sha256(const std::string &path) const {
    FILE *file = fopen(path.c_str(), "rb");
    if (!file) {
        LOG(ERROR) << "Failed to open file: " << path << " to create hash";
        return std::string();
    }

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    const uint32_t bufSize = 0x2000;
    uint8_t buffer[bufSize];

    uint32_t bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    std::string ret = this->hexify(hash, SHA256_DIGEST_LENGTH);

    fclose(file);

    return ret;
}

std::string Driver::md5(const std::string &path) const {
    FILE *file = fopen(path.c_str(), "rb");
    if (!file) {
        LOG(ERROR) << "Failed to open file: " << path << " to create hash";
        return std::string();
    }

    uint8_t hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);

    const uint32_t bufSize = 0x2000;
    uint8_t buffer[bufSize];

    uint32_t bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        MD5_Update(&md5, buffer, bytesRead);
    }
    MD5_Final(hash, &md5);

    std::string ret = this->hexify(hash, MD5_DIGEST_LENGTH);

    fclose(file);

    return ret;
}

template<typename T>
std::string Driver::hexify(T data, uint64_t size) const {
    auto data_cast = reinterpret_cast<const unsigned char *>(data);
    std::stringstream ss;
    for(uint32_t i = 0; i < size; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(data_cast[i]);
    }
    return ss.str();
}

std::string Driver::cpu_type_str(uint32_t cpu_type, uint32_t sub_type) const {
    std::stringstream ss;

    switch (cpu_type) {
    case MachO::CPU_TYPE_ARM:
        ss << "CPU_TYPE_ARM";
        break;
    case MachO::CPU_TYPE_ARM64:
        ss << "CPU_TYPE_ARM64";
        break;
    case MachO::CPU_TYPE_I386:
        ss << "CPU_TYPE_I386";
        break;
    case MachO::CPU_TYPE_X86_64:
        ss << "CPU_TYPE_X86_64";
        break;
    case MachO::CPU_TYPE_MC98000:
        ss << "CPU_TYPE_MC98000";
        break;
    case MachO::CPU_TYPE_SPARC:
        ss << "CPU_TYPE_SPARC";
        break;
    case MachO::CPU_TYPE_POWERPC:
        ss << "CPU_TYPE_POWERPC";
        break;
    case MachO::CPU_TYPE_POWERPC64:
        ss << "CPU_TYPE_POWERPC64";
        break;
    default:
        ss << "CPU_TYPE_" << std::to_string(cpu_type);
        break;
    }

    switch (sub_type) {
    case MachO::CPU_SUBTYPE_386:
        ss << "_SUBTYPE_" << "386";
        break;
    case MachO::CPU_SUBTYPE_486:
        ss << "_SUBTYPE_" << "486";
        break;
    case MachO::CPU_SUBTYPE_486SX:
        ss << "_SUBTYPE_" << "486SX";
        break;
    case MachO::CPU_SUBTYPE_586:
        ss << "_SUBTYPE_" << "586";
        break;
    case MachO::CPU_SUBTYPE_PENTPRO:
        ss << "_SUBTYPE_" << "PENTPRO";
        break;
    case MachO::CPU_SUBTYPE_PENTII_M3:
        ss << "_SUBTYPE_" << "PENTII_M3";
        break;
    case MachO::CPU_SUBTYPE_PENTII_M5:
        ss << "_SUBTYPE_" << "PENTII_M5";
        break;
    case MachO::CPU_SUBTYPE_CELERON:
        ss << "_SUBTYPE_" << "CELERON";
        break;
    case MachO::CPU_SUBTYPE_CELERON_MOBILE:
        ss << "_SUBTYPE_" << "CELERON_MOBILE";
        break;
    case MachO::CPU_SUBTYPE_PENTIUM_3:
        ss << "_SUBTYPE_" << "PENTIUM_3";
        break;
    case MachO::CPU_SUBTYPE_PENTIUM_3_M:
        ss << "_SUBTYPE_" << "PENTIUM_3_M";
        break;
    case MachO::CPU_SUBTYPE_PENTIUM_3_XEON:
        ss << "_SUBTYPE_" << "PENTIUM_3_XEON";
        break;
    case MachO::CPU_SUBTYPE_PENTIUM_M:
        ss << "_SUBTYPE_" << "PENTIUM_M";
        break;
    case MachO::CPU_SUBTYPE_PENTIUM_4:
        ss << "_SUBTYPE_" << "PENTIUM_4";
        break;
    case MachO::CPU_SUBTYPE_PENTIUM_4_M:
        ss << "_SUBTYPE_" << "PENTIUM_4_M";
        break;
    case MachO::CPU_SUBTYPE_ITANIUM:
        ss << "_SUBTYPE_" << "ITANIUM";
        break;
    case MachO::CPU_SUBTYPE_ITANIUM_2:
        ss << "_SUBTYPE_" << "ITANIUM_2";
        break;
    case MachO::CPU_SUBTYPE_XEON:
        ss << "_SUBTYPE_" << "XEON";
        break;
    case MachO::CPU_SUBTYPE_XEON_MP:
        ss << "_SUBTYPE_" << "XEON_MP";
        break;
    default:
        ss << "CPU_TYPE_" << std::to_string(sub_type);
        break;
    }

    return ss.str();
}
