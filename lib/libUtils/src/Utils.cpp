#include <cstdint>

#include "Utils.hpp"

#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/COFF.h"
#include <llvm/Support/Endian.h>

#include "glog/logging.h"


uint16_t get_dllChars(const COFFObjectFile *obj) {
    const pe32_header *hdr = obj->getPE32Header();
    if (!hdr) {
        const pe32plus_header *hdrPlus = obj->getPE32PlusHeader();
        if (!hdrPlus) {
            LOG(WARNING) << "Failed to get DllCharacteristics from header";
            return 0;
        }
        return hdrPlus->DLLCharacteristics;
    }
    else {
        return hdr->DLLCharacteristics;
    }

    return 0;
}

bin_type get_bin_type(const ObjectFile *obj) {
    if (obj->isCOFF() || obj->isCOFFImportFile()) {
        return bin_type::COFF;
    }
    else if (obj->isELF()) {
        return bin_type::ELF;
    }
    else if (obj->isMachO() || obj->isMachOUniversalBinary()) {
        return bin_type::MACHO;
    }
    else {
        LOG(FATAL) << "Unknown bin type: " << obj->getType();
        return bin_type::UNKNOWN;
    }
}
