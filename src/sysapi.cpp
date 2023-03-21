#include "..\deps\phnt\phnt_windows.h"
#include "..\deps\phnt\phnt.h"

#include "ntapi_dynamic.h"

#include <cstdio>
#include <cstdint>
#include <cassert>

#include <string>

#include "sysapi.h"

#include <tlhelp32.h>

#include "common.h"

#pragma comment(lib, "ntdll.lib")

HMODULE hNtdll = GetModuleHandleA("ntdll");;

sysapi::options_t sysapi_opts;

namespace sysapi {

process_t ProcessCreate(const std::wstring& name, bool suspended) {

    auto nt_name = L"\\??\\" + name;

    UNICODE_STRING NtImagePath;
    RtlInitUnicodeString(&NtImagePath, nt_name.c_str());

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    auto status = RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to create process paremeters, status = 0x%x\n", status);
        return {};
    }

    PS_CREATE_INFO CreateInfo = {};
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    PS_ATTRIBUTE_LIST AttributeList = {};
    AttributeList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    AttributeList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList.Attributes[0].Size = NtImagePath.Length;
    AttributeList.Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

    process_t process;
    status = NtCreateUserProcess(process.hProcess.reset(), process.hThread.reset(), PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
                                 NULL, NULL, NULL, suspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0, ProcessParameters, &CreateInfo, &AttributeList);

    RtlDestroyProcessParameters(ProcessParameters);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to create process, status = 0x%x\n", status);
        return {};
    }

    return process;
}

PVOID ProcessGetPEBAddress(HANDLE hProcess) {

    PROCESS_BASIC_INFORMATION BasicInfo;

    DWORD dwReturnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to get basic process information (HANDLE = 0x%p), status = 0x%x\n", hProcess, status);
        return nullptr;
    }

	return BasicInfo.PebBaseAddress;
}

uint32_t ProcessFind(const wchar_t *name) {

    uint32_t pid = 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == NULL) {
        wprintf(L"[-] unable to create snapshot of processes\n");
        return 0;
    }

    if (Process32FirstW(snapshot, &entry) != TRUE) {
        wprintf(L"[-] unable to get first process, error = %d\n", GetLastError());
        CloseHandle(snapshot);
        return 0;
    }

    while (Process32NextW(snapshot, &entry) == TRUE) {

        if (_wcsicmp(entry.szExeFile, name) != 0) {
            continue;
        }

        wprintf(L"[+] process found (name = %s), PID = %d\n", name, entry.th32ProcessID);

        if (pid != 0) {
            wprintf(L"[-] there are multiple processes with the same name\n");
            pid = 0;
            break;
        }

        pid = entry.th32ProcessID;
    }

    CloseHandle(snapshot);
    return pid;
}

HANDLE ProcessOpen(uint32_t pid, ACCESS_MASK AccessMask) {

    HANDLE ProcessHandle = 0;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID Cid{ .UniqueProcess = ULongToHandle(pid), .UniqueThread = NULL };
    NTSTATUS status = NtOpenProcess(&ProcessHandle, AccessMask, &ObjectAttributes, &Cid);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to open process (PID = %d), status = 0x%x\n", pid, status);
        return NULL;
    }

    wprintf(L"[+] process (PID = %d) opened, HANDLE = 0x%p\n", pid, ProcessHandle);
    return ProcessHandle;
}

HANDLE ThreadCreate(HANDLE ProcessHandle, PVOID StartAddress) {

    HANDLE ThreadHandle;
    // TODO: NtCreateThreadEx
    NTSTATUS status = RtlCreateUserThread(ProcessHandle, NULL, FALSE, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)StartAddress, NULL, &ThreadHandle, NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to create process thread (HANDLE = 0x%p), status = 0x%x\n", ProcessHandle, status);
        return NULL;
    }

    wprintf(L"[+] thread created, HANDLE = 0x%p\n", ThreadHandle);
    return ThreadHandle;
}

bool ThreadResume(HANDLE ThreadHandle) {

    NTSTATUS status = NtResumeThread(ThreadHandle, NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to resume thread (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    wprintf(L"[+] thread resumed, HANDLE = 0x%p\n", ThreadHandle);
    return true;
}

bool ThreadGetContext(HANDLE ThreadHandle, CONTEXT* ctx) {

    NTSTATUS status = NtGetContextThread(ThreadHandle, ctx);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to get thread context (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    //wprintf(L"[+] thread context get");
    return true;
}

bool ThreadGetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT* ctx) {

    NTSTATUS status = NtQueryInformationThread(ThreadHandle, ThreadWow64Context, ctx, sizeof(WOW64_CONTEXT), NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to get WOW64 thread context (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    //wprintf(L"[+] thread WOW64 context get\n");
    return true;
}

bool ThreadSetContext(HANDLE ThreadHandle, CONTEXT* ctx) {

    NTSTATUS status = NtSetContextThread(ThreadHandle, ctx);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to set thread context (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    wprintf(L"[+] thread context set, HANDLE = 0x%p\n", ThreadHandle);
    return true;
}

bool ThreadSetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT* ctx) {

    NTSTATUS status = NtSetInformationThread(ThreadHandle, ThreadWow64Context, ctx, sizeof(WOW64_CONTEXT));

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to set WOW64 thread context (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    wprintf(L"[+] thread WOW64 context set, HANDLE = 0x%p\n", ThreadHandle);
    return true;
}

HANDLE SectionCreate(size_t Size) {

    HANDLE SectionHandle;
    NTSTATUS status;

    LARGE_INTEGER sectionSize{ .QuadPart = (LONGLONG)Size };

    if (sysapi_opts.ntdll_ex) {

        assert(hNtdll != NULL);
        static auto NtCreateSectionEx = (_NtCreateSectionEx)GetProcAddress(hNtdll, "NtCreateSectionEx");
        if (NtCreateSectionEx == nullptr) {
            wprintf(L"[-] unable to get address of \"%hs\" from ntdll.dll", "NtCreateSectionEx");
            return NULL;
        }

        status = NtCreateSectionEx(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL, NULL, 0);
    }
    else {
        status = NtCreateSection(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to create section, status = 0x%x\n", status);
        return 0;
    }

    wprintf(L"[+] section created, HANDLE = 0x%p\n", SectionHandle);
    return SectionHandle;
}

HANDLE SectionFileCreate(HANDLE FileHandle) {

    HANDLE SectionHandle;

    NTSTATUS status;

    if (sysapi_opts.ntdll_ex) {

        assert(hNtdll != NULL);
        static auto NtCreateSectionEx = (_NtCreateSectionEx)GetProcAddress(hNtdll, "NtCreateSectionEx");
        if (NtCreateSectionEx == nullptr) {
            wprintf(L"[-] unable to get address of \"%hs\" from ntdll.dll", "NtCreateSectionEx");
            return NULL;
        }

        status = NtCreateSectionEx(&SectionHandle, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, FileHandle, NULL, 0);
    }
    else {
        status = NtCreateSection(&SectionHandle, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, FileHandle);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to create file section, status = 0x%x\n", status);
        return 0;
    }

    wprintf(L"[+] file section created, HANDLE = 0x%p\n", SectionHandle);
    return SectionHandle;
}

PVOID SectionMapView(HANDLE SectionHandle, SIZE_T Size, ULONG Win32Protect, HANDLE ProcessHandle) {

    PVOID BaseAddress = nullptr;

    NTSTATUS status;

    if (sysapi_opts.ntdll_ex) {

        assert(hNtdll != NULL);
        static auto NtMapViewOfSectionEx = (_NtMapViewOfSectionEx)GetProcAddress(hNtdll, "NtMapViewOfSectionEx");
        if (NtMapViewOfSectionEx == nullptr) {
            wprintf(L"[-] unable to get address of \"%hs\" from ntdll.dll", "NtMapViewOfSectionEx");
            return nullptr;
        }

        status = NtMapViewOfSectionEx(SectionHandle, ProcessHandle, &BaseAddress, NULL, &Size, 0, Win32Protect, NULL, 0);
    }
    else {
        status = NtMapViewOfSection(SectionHandle, ProcessHandle, &BaseAddress, NULL, 0, NULL, &Size, ViewUnmap, 0, Win32Protect);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to map section, status = 0x%x\n", status);
        return nullptr;
    }

    wprintf(L"[+] section mapped, address = 0x%p\n", BaseAddress);
    return BaseAddress;
}

bool SectionUnmapView(PVOID BaseAddress, HANDLE ProcessHandle) {

    NTSTATUS status;

    if (sysapi_opts.ntdll_ex) {
        assert(hNtdll != NULL);
        static auto NtUnmapViewOfSectionEx = (_NtUnmapViewOfSectionEx)GetProcAddress(hNtdll, "NtUnmapViewOfSectionEx");
        if (NtUnmapViewOfSectionEx == nullptr) {
            wprintf(L"[-] unable to get address of \"%hs\" from ntdll.dll", "NtUnmapViewOfSectionEx");
            return false;
        }

        status = NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, 0);
    }
    else {
        status = NtUnmapViewOfSection(ProcessHandle, BaseAddress);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to unmap section, status = 0x%x\n", status);
        return false;
    }

    wprintf(L"[+] section unmapped\n");
    return true;
}

bool HandleClose(HANDLE Handle) {

    NTSTATUS status = NtClose(Handle);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to close handle (0x%p), status = 0x%x\n", Handle, status);
        return false;
    }

    //wprintf(L"[+] handle closed\n");
    return true;
}

PVOID VirtualMemoryAllocate(SIZE_T Size, ULONG Protect, HANDLE ProcessHandle, PVOID BaseAddress) {

    NTSTATUS status = NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &Size, MEM_RESERVE | MEM_COMMIT, Protect);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to allocate virtual memory (0x%zu bytes), status = 0x%x\n", Size, status);
        return nullptr;
    }

    return BaseAddress;
}

bool VirtualMemoryProtect(PVOID BaseAddress, SIZE_T Size, ULONG& Protect, HANDLE ProcessHandle) {

    NTSTATUS status = NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &Size, Protect, &Protect);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to protect virtual memory (0x%zu bytes), status = 0x%x\n", Size, status);
        return false;
    }

    return true;
}

bool VirtualMemoryWrite(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle) {

    SIZE_T NumberOfBytesWritten;
    NTSTATUS status = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Data, Size, &NumberOfBytesWritten);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to write virtual memory (0x%zu bytes), status = 0x%x\n", Size, status);
        return false;
    }

    return true;
}

size_t VirtualMemoryRead(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle) {

    SIZE_T NumberOfBytesRead;
    NTSTATUS status = NtReadVirtualMemory(ProcessHandle, BaseAddress, Data, Size, &NumberOfBytesRead);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to read virtual memory (0x%zu bytes), status = 0x%x\n", Size, status);
        return 0;
    }

    return NumberOfBytesRead;
}

HANDLE FileOpen(const wchar_t* path) {

    auto nt_path = L"\\??\\" + std::wstring(path);

    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, nt_path.c_str());

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatus = {};

    HANDLE hFile;

    NTSTATUS status = NtCreateFile(&hFile, FILE_GENERIC_READ, &ObjectAttributes, &IoStatus, NULL,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to open file (%s), status = 0x%x\n", path, status);
        return NULL;
    }

    return hFile;
}

size_t FileGetSize(HANDLE FileHandle) {

    IO_STATUS_BLOCK IoStatus = {};

    FILE_STANDARD_INFORMATION FileInformation;

    NTSTATUS status = NtQueryInformationFile(FileHandle, &IoStatus, &FileInformation, sizeof(FileInformation), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to get basic file information (HANDLE = 0x%p), status = 0x%x\n", FileHandle, status);
        return 0;
    }

    return FileInformation.EndOfFile.QuadPart;
}

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

bool PeImageRelocate(PVOID ImageBuffer, PVOID NewBaseAddress, HANDLE ProcessHandle) {

    auto* pDOSHeader = (PIMAGE_DOS_HEADER)ImageBuffer;

    auto* pNT32Header = (PIMAGE_NT_HEADERS32)PTR_ADD(ImageBuffer, pDOSHeader->e_lfanew);
    auto* pNT64Header = (PIMAGE_NT_HEADERS64)pNT32Header;

    bool is_64 = pNT32Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    size_t ImageBaseOffset = pDOSHeader->e_lfanew + (is_64 ?
        offsetof(IMAGE_NT_HEADERS64, OptionalHeader.ImageBase) :
        offsetof(IMAGE_NT_HEADERS32, OptionalHeader.ImageBase));

    bool res;
    if (is_64) {
        auto ImageBaseAddress = (UINT64)(UINT_PTR)NewBaseAddress;
        res = sysapi::VirtualMemoryWrite(&ImageBaseAddress, sizeof(ImageBaseAddress), PTR_ADD(NewBaseAddress, ImageBaseOffset), ProcessHandle);
    }
    else {
        auto ImageBaseAddress = (UINT32)(UINT_PTR)NewBaseAddress;
        res = sysapi::VirtualMemoryWrite(&ImageBaseAddress, sizeof(ImageBaseAddress), PTR_ADD(NewBaseAddress, ImageBaseOffset), ProcessHandle);
    }

    if (!res) {
        return false;
    }

    ptrdiff_t delta = PTR_DIFF(NewBaseAddress, is_64 ? pNT64Header->OptionalHeader.ImageBase : pNT32Header->OptionalHeader.ImageBase);
    if (delta == 0) {
        wprintf(L"[+] image base is already at the base address = 0x%p\n", NewBaseAddress);
        return true;
    }

    wprintf(L"Rebasing...\n");

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
        wprintf(L"Unable to find \".reloc\" section...\n");
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
                res = sysapi::VirtualMemoryRead(&Field, sizeof(Field), PTR_ADD(NewBaseAddress, FieldAddress), ProcessHandle);
                if (!res) {
                    return false;
                }

                Field += (DWORD64)delta;

                res = sysapi::VirtualMemoryWrite(&Field, sizeof(Field), PTR_ADD(NewBaseAddress, FieldAddress), ProcessHandle);
                if (!res) {
                    return false;
                }
            }
            else {
                DWORD32 Field = 0;
                res = sysapi::VirtualMemoryRead(&Field, sizeof(Field), PTR_ADD(NewBaseAddress, FieldAddress), ProcessHandle);
                if (!res) {
                    return false;
                }

                Field += (DWORD32)delta;

                res = sysapi::VirtualMemoryWrite(&Field, sizeof(Field), PTR_ADD(NewBaseAddress, FieldAddress), ProcessHandle);
                if (!res) {
                    return false;
                }
            }
        }
    }

    wprintf(L"[+] image relocated, new base address = 0x%p\n", NewBaseAddress);
    return true;
}

}