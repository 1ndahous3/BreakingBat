#pragma once

#include <cstdint>
#include <string>

#include "phnt_windows.h"
#include "phnt.h"

#include "unique_memory.h"

typedef struct BASE_RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;


namespace sysapi {

struct options_t {
    bool ntdll_ex = false;
};

using unique_handle = unique_resource<HANDLE, decltype(CloseHandle)>;

struct process_t {
    unique_handle hProcess;
    unique_handle hThread;
};

void init(const options_t& sysapi_opts);

process_t ProcessCreate(const std::wstring& name, bool suspended = false);

bool ProcessGetBasicInfo(HANDLE ProcessHandle, PROCESS_BASIC_INFORMATION& BasicInfo);

uint32_t ProcessFind(const wchar_t* name);
HANDLE ProcessOpen(uint32_t pid, ACCESS_MASK AccessMask = PROCESS_ALL_ACCESS);

HANDLE ThreadCreateEx(HANDLE ProcessHandle, PVOID StartAddress);
HANDLE ThreadCreate(HANDLE ProcessHandle, PVOID StartAddress);
bool ThreadResume(HANDLE ThreadHandle);
bool ThreadGetContext(HANDLE ThreadHandle, CONTEXT *ctx);
bool ThreadGetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT *ctx);
bool ThreadSetContext(HANDLE ThreadHandle, CONTEXT *ctx);
bool ThreadSetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT *ctx);
bool ThreadCreateStack(HANDLE ProcessHandle, PINITIAL_TEB InitialTeb);

HANDLE SectionCreate(size_t Size);
HANDLE SectionFileCreate(HANDLE FileHandle);
PVOID SectionMapView(HANDLE SectionHandle, SIZE_T Size, ULONG Protect, HANDLE ProcessHandle = GetCurrentProcess(), PVOID BaseAddress = nullptr);
bool SectionUnmapView(PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());

bool HandleClose(HANDLE Handle);

PVOID VirtualMemoryAllocate(SIZE_T Size, ULONG Protect, HANDLE ProcessHandle = GetCurrentProcess(), PVOID BaseAddress = nullptr, ULONG AllocationType = MEM_RESERVE | MEM_COMMIT);
bool VirtualMemoryProtect(PVOID BaseAddress, SIZE_T Size, ULONG& Protect, HANDLE ProcessHandle = GetCurrentProcess());
bool VirtualMemoryWrite(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());
size_t VirtualMemoryRead(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());

HANDLE FileOpen(const wchar_t* path);
size_t FileGetSize(HANDLE FileHandle);

}