#pragma once

#include <cstdint>

#include "phnt_windows.h"
#include "phnt.h"

namespace scripts {

extern char* default_shellcode_data;
extern size_t default_shellcode_size;

enum class RemoteProcessMemoryMethod {
    AllocateInAddr,
    CreateSectionMap,
    CreateSectionMapLocalMap
};


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

//

bool inject_create_remote_thread(uint32_t pid, RemoteProcessMemoryMethod method);
bool inject_create_process_hollow(const std::wstring& original_image,
                                  const std::wstring& injected_image,
                                  RemoteProcessMemoryMethod method);
bool inject_create_process_doppel(const std::wstring& original_image,
                                  const std::wstring& injected_image,
                                  RemoteProcessMemoryMethod method);
bool inject_queue_apc(uint32_t pid, uint32_t tid, RemoteProcessMemoryMethod method);
}