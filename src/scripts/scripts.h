#pragma once

#include <cstdint>

#include "phnt_windows.h"

namespace scripts {

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
bool process_write_memory(const RemoteProcessMemoryContext& ctx, size_t offset, PVOID Data, SIZE_T Size);
bool process_read_memory(const RemoteProcessMemoryContext& ctx, size_t offset, PVOID Data, SIZE_T Size);
bool process_pe_image_relocate(const RemoteProcessMemoryContext& ctx, PVOID ImageBuffer);

//

bool inject_create_remote_thread(uint32_t pid, RemoteProcessMemoryMethod method);
bool inject_create_process_hollowed(const std::wstring& original_image,
                                    const std::wstring& injected_image,
                                    RemoteProcessMemoryMethod method);

}