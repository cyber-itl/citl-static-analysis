#pragma once

#include <cstdint>

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/COFF.h"

using namespace llvm;
using namespace object;

enum class bin_type {
    COFF,
    MACHO,
    ELF,
    UNKNOWN
};

uint16_t get_dllChars(const COFFObjectFile *obj);

bin_type get_bin_type(const ObjectFile *obj);
