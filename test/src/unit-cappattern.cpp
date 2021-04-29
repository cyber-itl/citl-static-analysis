#include <cstdint>
#include <vector>
#include "capstone/capstone.h"
#include "CapPattern.hpp"
#include "catch2/catch.hpp"

CapPattern create_matcher(std::vector<uint8_t> data, uint32_t insn_cnt, cs_arch arch, cs_mode mode, cs_insn **insn_out) {
    uint32_t count = 0;
    csh cs_handle;

    cs_err err = cs_open(arch, mode, &cs_handle);
    CATCH_REQUIRE(err == CS_ERR_OK);

    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(cs_handle, &data.front(), data.size(), 0x1000, insn_cnt, insn_out);

    CATCH_REQUIRE(count == insn_cnt);

    cs_close(&cs_handle);

    return CapPattern(*insn_out, count, arch, mode);
}

CATCH_TEST_CASE("Basic match")
{
    cs_arch arch = cs_arch::CS_ARCH_X86;
    cs_mode mode = cs_mode::CS_MODE_32;

    // push esi
    // mov esi, ecx
    // mov eax, [esi]
    uint32_t insn_cnt = 3;
    std::vector<uint8_t> raw_data = {0x56, 0x89, 0xce, 0x8b, 0x06};

    cs_insn *insns;
    auto matcher = create_matcher(raw_data, insn_cnt, arch, mode, &insns);

    Pattern pat = { {
        {X86_INS_PUSH, {{op_type::REG, X86_REG_ESI}} },
        {X86_INS_MOV, {{op_type::REG, X86_REG_ESI}, {op_type::REG}} },
        {X86_INS_MOV, {{op_type::REG}, {op_type::MEM, X86_REG_ESI}} }
    } };

    CATCH_REQUIRE(matcher.check_pattern(pat));


    Pattern pat_2 = { {
        {X86_INS_PUSH, {{op_type::REG, {X86_REG_ESI, X86_REG_EAX} }} },
        {X86_INS_MOV, {{op_type::REG, X86_REG_ESI}, {op_type::REG}} },
        {X86_INS_MOV, {{op_type::REG}, {op_type::MEM, X86_REG_ESI}} }
    } };

    CATCH_REQUIRE(matcher.check_pattern(pat_2));

    cs_free(insns, insn_cnt);
}

CATCH_TEST_CASE("Validate order") {
    cs_arch arch = cs_arch::CS_ARCH_X86;
    cs_mode mode = cs_mode::CS_MODE_64;

    // push rax
    // sub rsp, 0x10
    uint32_t insn_cnt = 2;
    std::vector<uint8_t> raw_data = {0x50, 0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00};

    cs_insn *insns;
    auto matcher = create_matcher(raw_data, insn_cnt, arch, mode, &insns);

    Pattern pat = { {
        {X86_INS_SUB, {{op_type::REG, X86_REG_RSP}, {op_type::IMM}} }
    } };

    CATCH_REQUIRE_FALSE(matcher.check_pattern(pat));
    cs_free(insns, insn_cnt);
}

CATCH_TEST_CASE("Wildcard reg with memory") {
    cs_arch arch = cs_arch::CS_ARCH_X86;
    cs_mode mode = cs_mode::CS_MODE_32;


    // mov ecx, [ebp-0x14]
    // mov eax, [ecx]
    uint32_t insn_cnt = 2;
    std::vector<uint8_t> raw_data = {0x8b, 0x4d, 0xec, 0x8b, 0x01};

    cs_insn *insns;
    auto matcher = create_matcher(raw_data, insn_cnt, arch, mode, &insns);

    Pattern pat = { {
        {X86_INS_MOV, {{op_type::REG}, {op_type::MEM, X86_REG_EBP}} },
        {X86_INS_MOV, {{op_type::REG}, {op_type::MEM}} }
    } };

    CATCH_REQUIRE(matcher.check_pattern(pat));
    cs_free(insns, insn_cnt);
}

CATCH_TEST_CASE("Check mem pattern with multiple regs") {
    cs_arch arch = cs_arch::CS_ARCH_X86;
    cs_mode mode = cs_mode::CS_MODE_32;

    // push esi
    // lea eax, [esp+0x8]
    uint32_t insn_cnt = 2;
    std::vector<uint8_t> raw_data = {0x56, 0x8d, 0x44, 0x24, 0x08};

    cs_insn *insns;
    auto matcher = create_matcher(raw_data, insn_cnt, arch, mode, &insns);

    Pattern pat = { {
        {X86_INS_PUSH,  {{op_type::REG, X86_REG_ESI}} },
        {X86_INS_LEA, {{op_type::REG}, {op_type::MEM, {X86_REG_ECX, X86_REG_ESP} }} }
    } };

    CATCH_REQUIRE(matcher.check_pattern(pat));

    cs_free(insns, insn_cnt);


    // push esi
    // lea esi, [ecx+0x8]
    std::vector<uint8_t> raw_data2 = {0x56, 0x8d, 0x71, 0x08};

    cs_insn *insns2;
    auto matcher2 = create_matcher(raw_data2, insn_cnt, arch, mode, &insns2);

    CATCH_REQUIRE(matcher2.check_pattern(pat));
    cs_free(insns2, insn_cnt);
}

CATCH_TEST_CASE("Reg Placeholder test") {
    cs_arch arch = cs_arch::CS_ARCH_X86;
    cs_mode mode = cs_mode::CS_MODE_32;

    // mov ecx, [ebp-0x14]
    // mov eax, [ecx]
    uint32_t insn_cnt = 2;
    std::vector<uint8_t> raw_data = {0x8b, 0x4d, 0xec, 0x8b, 0x01};

    cs_insn *insns;
    auto matcher = create_matcher(raw_data, insn_cnt, arch, mode, &insns);

    Pattern pat = { {
        {X86_INS_MOV,  {{op_type::REG_PLACEHOLDER, 0}, {op_type::MEM}} },
        {X86_INS_MOV, {{op_type::REG}, {op_type::REG_PLACEHOLDER, 0}} }
    } };

    CATCH_REQUIRE(matcher.check_pattern(pat));

    Pattern anti_pat = { {
        {X86_INS_MOV,  {{op_type::REG}, {op_type::REG_PLACEHOLDER, 0}} },
        {X86_INS_MOV, {{op_type::REG}, {op_type::REG_PLACEHOLDER, 0}} }
    } };

    CATCH_REQUIRE_FALSE(matcher.check_pattern(anti_pat));

    cs_free(insns, insn_cnt);
}

CATCH_TEST_CASE("Unordered test") {
    cs_arch arch = cs_arch::CS_ARCH_X86;
    cs_mode mode = cs_mode::CS_MODE_32;

    // push esi
    // int3
    // ret
    uint32_t insn_cnt = 3;
    std::vector<uint8_t> raw_data = {0x56, 0xcc, 0xc3};

    cs_insn *insns;
    auto matcher = create_matcher(raw_data, insn_cnt, arch, mode, &insns);

    Pattern pat = { pat_type::UNORDERED, {
        {X86_INS_PUSH,  {{op_type::REG}} },
        {X86_INS_RET},
        {X86_INS_INT3}
    } };

    CATCH_REQUIRE(matcher.check_pattern(pat));

    cs_free(insns, insn_cnt);
}

CATCH_TEST_CASE("Unordered and placeholder test") {
    cs_arch arch = cs_arch::CS_ARCH_X86;
    cs_mode mode = cs_mode::CS_MODE_32;

    // mov eax, [esp+0x4]
    // mov eax, [eax]
    // push esi
    uint32_t insn_cnt = 3;
    std::vector<uint8_t> raw_data = {0x8b, 0x44, 0x24, 0x04, 0x8b, 0x00, 0x56};

    cs_insn *insns;
    auto matcher = create_matcher(raw_data, insn_cnt, arch, mode, &insns);

    Pattern pat = { pat_type::UNORDERED, {
        {X86_INS_PUSH, {{op_type::REG, X86_REG_ESI}} },
        {X86_INS_MOV, {{op_type::REG_PLACEHOLDER, 0}, {op_type::MEM, X86_REG_ESP}} },
        {X86_INS_MOV, {{op_type::REG}, {op_type::REG_PLACEHOLDER, 0}} }
    } };

    CATCH_REQUIRE(matcher.check_pattern(pat));

    cs_free(insns, insn_cnt);
}

CATCH_TEST_CASE("Unordered repeat match bug") {
    cs_arch arch = cs_arch::CS_ARCH_X86;
    cs_mode mode = cs_mode::CS_MODE_32;

    // mov ecx, [data_446e50]
    // mov eax, [esp+0x12050]
    // push ebx
    // mov ebx, [USER32!SendMessageA@IAT]
    uint32_t insn_cnt = 4;
    std::vector<uint8_t> raw_data = {0x8b, 0x0d, 0x50, 0x6e, 0x44, 0x00,
                                     0x8b, 0x84, 0x24, 0x50, 0x20, 0x01, 0x00,
                                     0x53,
                                     0x8b, 0x1d, 0x20, 0xb4, 0x43, 0x00};

    cs_insn *insns;
    auto matcher = create_matcher(raw_data, insn_cnt, arch, mode, &insns);

    Pattern pat = { pat_type::UNORDERED, {
        {X86_INS_MOV, {{op_type::REG}, {op_type::MEM, X86_REG_ESP}} },
        {X86_INS_MOV, {{op_type::REG}, {op_type::MEM}} },
        {X86_INS_PUSH, {{op_type::WILDCARD}} },
        {X86_INS_PUSH, {{op_type::WILDCARD}} }
    } };

    CATCH_REQUIRE_FALSE(matcher.check_pattern(pat));

    cs_free(insns, insn_cnt);
}

