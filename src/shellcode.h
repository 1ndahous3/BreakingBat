#pragma once

#include <vector>
#include "sysapi.h"

namespace shellcode {

PVOID find_rop_gadget_inf_loop();

}

namespace shellcode::x64 {

PVOID find_rop_gadget_pop_values_and_ret(size_t count);

}

namespace shellcode::x64::LdrpHandleInvalidUserCallTarget {

PVOID find_rop_gadget_pop_values_and_jmp();
PVOID find_rop_gadget_setup_reg_values_and_ret();
PVOID find_rop_gadget_pop_values_and_ret8(size_t count);

std::vector<UINT64> build_stack_for_gadget(
    PVOID RetAddr, PVOID FunctionAddress, UINT64 Arg1, UINT64 Arg2, UINT64 Arg3, UINT64 Arg4,
    const std::initializer_list<uint64_t>& args, bool sp_aligned
);
std::vector<uint8_t> build_shellcode_for_gadget(
    PVOID RetAddr, PVOID FunctionAddress, UINT64 Arg1, UINT64 Arg2, UINT64 Arg3, UINT64 Arg4,
    const std::initializer_list<uint64_t>& args, bool sp_aligned
);

} // namespace shellcode::x64::LdrpHandleInvalidUserCallTarget
