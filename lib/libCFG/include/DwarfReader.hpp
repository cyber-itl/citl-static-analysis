#pragma once

#include <cstdint>

#include "glog/logging.h"

#include "llvm/Support/Endian.h"
#include "llvm/Object/ELFTypes.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/Support/LEB128.h"


template<llvm::support::endianness E, bool BITS64>
class DwarfReader {
  public:
    DwarfReader(uint64_t addr, uint64_t size, const char *data) :
        m_addr(addr),
        m_size(size),
        m_data(reinterpret_cast<const uint8_t *>(data)) {

        m_cursor = m_data;
        m_end = m_data + m_size;
    }

    template<typename T>
    T readNext() {
        CHECK(m_cursor + sizeof(T) <= m_end) << "Invalid readNext on Dwarf object";
        auto result = llvm::support::endian::read<T, E, llvm::support::unaligned>(m_cursor);
        m_cursor += sizeof(T);
        return result;
    }

    uint64_t readPtr(uint32_t encoding) {
        CHECK((encoding & ~(0x70 | 0x0f | llvm::dwarf::DW_EH_PE_indirect)) == 0) << "Invalid encoding: 0x" << std::hex << encoding;

        uint64_t base = 0;
        if ((encoding & 0x70) == llvm::dwarf::DW_EH_PE_pcrel) {
            base = m_addr + (m_cursor - m_data);
        }

        if (encoding == llvm::dwarf::DW_EH_PE_omit) {
            return 0;
        }

        unsigned format = encoding & 0x0F;

        switch (format) {
        case llvm::dwarf::DW_EH_PE_uleb128:
            return readInternalPtr(llvm::decodeULEB128(m_cursor, nullptr, m_end, nullptr), encoding, base);
        case llvm::dwarf::DW_EH_PE_sleb128:
            return readInternalPtr(llvm::decodeSLEB128(m_cursor, nullptr, m_end, nullptr), encoding, base);
        case llvm::dwarf::DW_EH_PE_absptr:
            if (BITS64) {
                return readInternalPtr(readNext<uint64_t>(), encoding, base);
            }
            else {
                return readInternalPtr(readNext<uint32_t>(), encoding, base);
            }
        case llvm::dwarf::DW_EH_PE_signed:
            if (BITS64) {
                return readInternalPtr(readNext<int64_t>(), encoding, base);
            }
            else {
                return readInternalPtr(readNext<int32_t>(), encoding, base);
            }
        case llvm::dwarf::DW_EH_PE_udata2:
            return readInternalPtr(readNext<uint16_t>(), encoding, base);
        case llvm::dwarf::DW_EH_PE_sdata2:
            return readInternalPtr(readNext<int16_t>(), encoding, base);
        case llvm::dwarf::DW_EH_PE_udata4:
            return readInternalPtr(readNext<uint32_t>(), encoding, base);
        case llvm::dwarf::DW_EH_PE_sdata4:
            return readInternalPtr(readNext<int32_t>(), encoding, base);
        case llvm::dwarf::DW_EH_PE_udata8:
            return readInternalPtr(readNext<uint64_t>(), encoding, base);
        case llvm::dwarf::DW_EH_PE_sdata8:
            return readInternalPtr(readNext<int64_t>(), encoding, base);
        default:
            LOG(FATAL) << "Unknown encoding: " << format;
        }

        return 0;
    }

    uint8_t readU8() {
        return readNext<uint8_t>();
    }
    uint16_t readU16() {
        return readNext<uint16_t>();
    }
    uint32_t readU32() {
        return readNext<uint32_t>();
    }
    uint64_t readU64() {
        return readNext<uint64_t>();
    }

    uint64_t readULEB128() {
        uint32_t length;
        uint64_t results = llvm::decodeULEB128(m_cursor, &length, m_end, nullptr);
        m_cursor += length;
        CHECK(m_cursor <= m_end) << "Invalid readULEB128";
        return results;
    }

    int64_t readSLEB128() {
        uint32_t length;
        uint64_t results = llvm::decodeSLEB128(m_cursor, &length, m_end, nullptr);
        m_cursor += length;
        CHECK(m_cursor <= m_end) << "Invalid readSLEB128";
        return results;
    }

    bool eof() const {
        return m_cursor >= m_end;
    }

    uint64_t offset() const {
        return m_cursor - m_data;
    }

    void moveTo(uint64_t offset) {
        const uint8_t *NewCursor = m_data + offset;
        CHECK(NewCursor >= m_cursor && NewCursor <= m_end) << "Invalid moveTo: 0x" << std::hex << offset;
        m_cursor = NewCursor;
    }


  private:

    template<typename T>
    uint64_t readInternalPtr(T val, unsigned encoding, uint64_t base) {
        uint64_t result = val;

        if (val != 0) {
            int encoding_relative = encoding & 0x70;
            CHECK(encoding_relative == 0 || encoding_relative == 0x10) << "Invalid relative encoding";

            result = base;
            if (std::numeric_limits<T>::is_signed) {
                result += static_cast<int64_t>(val);
            }
            else {
                result += static_cast<uint64_t>(val);
            }
        }

        return result;
    }


    const uint8_t *m_cursor;
    const uint8_t *m_end;
    const uint8_t *m_data;
    uint64_t m_addr;
    uint64_t m_size;
};
