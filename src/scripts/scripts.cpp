#include <cstdint>

#include "phnt_windows.h"

#include "common.h"
#include "sysapi.h"
#include "scripts.h"

namespace scripts {

bool process_create_memory(RemoteProcessMemoryContext& ctx) {

    switch (ctx.method) {
    case RemoteProcessMemoryMethod::AllocateInAddr:

        wprintf(L"  [*] allocating memory (%lu bytes)...\n", ctx.Size);

        ctx.RemoteBaseAddress = sysapi::VirtualMemoryAllocate(ctx.Size, PAGE_EXECUTE_READWRITE, ctx.ProcessHandle, ctx.RemoteBaseAddress);
        if (ctx.RemoteBaseAddress == nullptr) {
            return false;
        }

        return true;

    case RemoteProcessMemoryMethod::CreateSectionMap:
    case RemoteProcessMemoryMethod::CreateSectionMapLocalMap:

        wprintf(L"  [*] creating section (%lu bytes)...\n", ctx.Size);

        ctx.Section = sysapi::SectionCreate(ctx.Size);
        if (ctx.Section == NULL) {
            return false;
        }

        wprintf(L"  [*] mapping section for process (HANDLE = 0x%p)...\n", ctx.ProcessHandle);

        ctx.RemoteBaseAddress = sysapi::SectionMapView(ctx.Section, ctx.Size, PAGE_EXECUTE_READWRITE, ctx.ProcessHandle, ctx.RemoteBaseAddress);
        if (ctx.RemoteBaseAddress == nullptr) {
            return false;
        }

        if (ctx.method == RemoteProcessMemoryMethod::CreateSectionMapLocalMap) {

            wprintf(L"  [*] mapping section for current process...\n");

            ctx.LocalBaseAddress = sysapi::SectionMapView(ctx.Section, ctx.Size, PAGE_READWRITE);
            if (ctx.LocalBaseAddress == nullptr) {
                return false;
            }
        }

        return true;
    }

    return false;
}

bool process_read_memory(const RemoteProcessMemoryContext& ctx, size_t offset, PVOID Data, SIZE_T Size) {

    bool res;

    if (ctx.LocalBaseAddress == nullptr) {
        res = sysapi::VirtualMemoryRead(Data, Size, PTR_ADD(ctx.RemoteBaseAddress, offset), ctx.ProcessHandle);
    }
    else {
        memcpy(Data, PTR_ADD(ctx.LocalBaseAddress, offset), Size);
        res = true;
    }

    return res;
}

bool process_write_memory(const RemoteProcessMemoryContext& ctx, size_t offset, PVOID Data, SIZE_T Size) {

    bool res;

    if (ctx.LocalBaseAddress == nullptr) {
        res = sysapi::VirtualMemoryWrite(Data, Size, PTR_ADD(ctx.RemoteBaseAddress, offset), ctx.ProcessHandle);
    }
    else {
        memcpy(PTR_ADD(ctx.LocalBaseAddress, offset), Data, Size);
        res = true;
    }

    return res;
}

bool process_memory_create_write(RemoteProcessMemoryContext& ctx, PVOID Data, SIZE_T Size) {

    bool res = process_create_memory(ctx);
    if (!res) {
        return false;
    }

    res = process_write_memory(ctx, 0, Data, Size);
    if (!res) {
        return false;
    }

    return true;
}

bool process_memory_create_write_fixup_addr(RemoteProcessMemoryContext& ctx, PVOID Data, SIZE_T Size, RemoteProcessMemoryContext& ctx_fixup, size_t offset_fixup) {

    bool res = process_memory_create_write(ctx, Data, Size);
    if (!res) {
        return false;
    }

    res = process_write_memory(ctx_fixup, offset_fixup, &ctx.RemoteBaseAddress, sizeof(ctx.RemoteBaseAddress));
    if (!res) {
        return false;
    }

    return true;
}

bool process_pe_image_relocate(const RemoteProcessMemoryContext& ctx, PVOID ImageBuffer) {

    auto* pDOSHeader = (PIMAGE_DOS_HEADER)ImageBuffer;

    auto* pNT32Header = (PIMAGE_NT_HEADERS32)PTR_ADD(ImageBuffer, pDOSHeader->e_lfanew);
    auto* pNT64Header = (PIMAGE_NT_HEADERS64)pNT32Header;

    bool is_64 = pNT32Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    size_t ImageBaseOffset = pDOSHeader->e_lfanew + (is_64 ?
        offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase) :
        offsetof(IMAGE_NT_HEADERS32, OptionalHeader.ImageBase));

    wprintf(L"  [*] writing new image base at 0x%p...\n", ctx.RemoteBaseAddress);

    bool res;
    if (is_64) {
        auto ImageBaseAddress = (UINT64)(UINT_PTR)ctx.RemoteBaseAddress;
        res = process_write_memory(ctx, ImageBaseOffset, &ImageBaseAddress, sizeof(ImageBaseAddress));
    }
    else {
        auto ImageBaseAddress = (UINT32)(UINT_PTR)ctx.RemoteBaseAddress;
        res = process_write_memory(ctx, ImageBaseOffset, &ImageBaseAddress, sizeof(ImageBaseAddress));
    }

    if (!res) {
        return false;
    }

    ptrdiff_t delta = PTR_DIFF(ctx.RemoteBaseAddress, is_64 ? pNT64Header->OptionalHeader.ImageBase : pNT32Header->OptionalHeader.ImageBase);
    if (delta == 0) {
        wprintf(L"  [!] image base is already at the base address = 0x%p\n", ctx.RemoteBaseAddress);
        return true;
    }

    wprintf(L"  [*] rebasing relocation entries...\n");

    auto *pSection = (PIMAGE_SECTION_HEADER)PTR_ADD(ImageBuffer, pDOSHeader->e_lfanew + (is_64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32)));

    DWORD RelocAddr = 0;

    for (WORD i = 0; i < pNT32Header->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".reloc") == 0) {
            pSection = &pSection[i];
            RelocAddr = pSection->PointerToRawData;
            break;
        }
    }

    if (RelocAddr == 0) {
        wprintf(L"  [-] unable to find \".reloc\" section...\n");
        return false;
    }

    IMAGE_DATA_DIRECTORY relocData = is_64 ?
        pNT64Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] :
        pNT32Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    for (DWORD dwOffset = 0; dwOffset < relocData.Size;) {

        auto* pBlockheader = (PBASE_RELOCATION_BLOCK)PTR_ADD(ImageBuffer, RelocAddr + dwOffset);
        dwOffset += sizeof(BASE_RELOCATION_BLOCK);

        DWORD dwEntryCount = (pBlockheader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);

        auto* pBlocks = (PBASE_RELOCATION_ENTRY)PTR_ADD(ImageBuffer, RelocAddr + dwOffset);

        for (DWORD j = 0; j < dwEntryCount; j++) {

            dwOffset += sizeof(BASE_RELOCATION_ENTRY);

            if (pBlocks[j].Type == 0) {
                continue;
            }

            DWORD FieldAddress = pBlockheader->PageAddress + pBlocks[j].Offset;

            if (is_64) {
                DWORD64 Field = 0;
                res = process_read_memory(ctx, FieldAddress, &Field, sizeof(Field));
                if (!res) {
                    return false;
                }

                Field += (DWORD64)delta;

                res = process_write_memory(ctx, FieldAddress, &Field, sizeof(Field));
                if (!res) {
                    return false;
                }
            }
            else {
                DWORD32 Field = 0;
                res = process_read_memory(ctx, FieldAddress, &Field, sizeof(Field));
                if (!res) {
                    return false;
                }

                Field += (DWORD32)delta;

                res = process_write_memory(ctx, FieldAddress, &Field, sizeof(Field));
                if (!res) {
                    return false;
                }
            }
        }
    }

    return true;
}

//

bool process_write_params(HANDLE ProcessHandle, PRTL_USER_PROCESS_PARAMETERS Params, PVOID PebBaseAddress, RemoteProcessMemoryMethod method) {

    RemoteProcessMemoryContext ctx_params;
    ctx_params.method = method;
    ctx_params.ProcessHandle = ProcessHandle;
    ctx_params.Size = Params->Length;

    RemoteProcessMemoryContext ctx_peb;
    ctx_peb.ProcessHandle = ProcessHandle;
    ctx_peb.RemoteBaseAddress = PebBaseAddress;
    // TODO: add another methods

    bool res = process_memory_create_write_fixup_addr(ctx_params, Params, Params->Length, ctx_peb, offsetof(PEB, ProcessParameters));
    if (!res) {
        return false;
    }

    if (Params->Environment) {

        RemoteProcessMemoryContext ctx_env;
        ctx_env.method = method;
        ctx_env.ProcessHandle = ProcessHandle;
        ctx_env.Size = (ULONG)Params->EnvironmentSize;

        res = process_memory_create_write_fixup_addr(ctx_env, Params->Environment, Params->EnvironmentSize, ctx_params, offsetof(RTL_USER_PROCESS_PARAMETERS, Environment));
        if (!res) {
            return false;
        }
    }

    return true;
}
}
