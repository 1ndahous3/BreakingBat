#include <cstdio>

#include "sysapi.h"
#include "scripts.h"
#include "shellcode.h"
#include "logging.h"


extern "C"
int __stdcall test_func(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8) {
    bblog::info("test_func({}, {}, {}, {}, {}, {}, {}, {})", a1, a2, a3, a4, a5, a6, a7, a8);
    return 10;
}


namespace scripts {

void execute_rop_gadget_local() {

    bblog::info("[*] Executing shellcode in the current thread");

    //auto shellcode = shellcode::x64::LdrpHandleInvalidUserCallTarget::build_shellcode_for_gadget(0, MessageBoxW, 0, 0, 0, MB_ICONEXCLAMATION | MB_OK, {}, true);
    auto shellcode = shellcode::x64::LdrpHandleInvalidUserCallTarget::build_shellcode_for_gadget(
        0, //shellcode::find_rop_gadget_inf_loop(),
        test_func,
        1, 2, 3, 4, {5, 6, 7, 8},
        false // aligned stack + ret address
    );

    RemoteProcessMemoryContext ctx;
    bool res = process_init_memory(ctx, RemoteProcessMemoryMethod::AllocateInAddr, GetCurrentProcess(), 0);
    if (!res) {
        return;
    }

    ctx.Size = (ULONG)shellcode.size();

    res = process_memory_create_write(ctx, shellcode.data(), shellcode.size());
    if (!res) {
        return;
    }

    ((void(*)())ctx.RemoteBaseAddress)();

    bblog::info("[+] Success");
}

}