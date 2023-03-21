#pragma once

#include <cstdint>
#include <string>

#include "..\phnt\phnt_windows.h"
#include "..\phnt\phnt.h"

#include "unique_memory.h"

namespace sysapi {

struct options_t {
    bool ntdll_ex;
};

using unique_handle = unique_resource<HANDLE, decltype(CloseHandle)>;

struct process_t {
    unique_handle hProcess;
    unique_handle hThread;
};

process_t ProcessCreate(const std::wstring& name, bool suspended = false);

PVOID ProcessGetPEBAddress(HANDLE hProcess);

uint32_t ProcessFind(const wchar_t* name);
HANDLE ProcessOpen(uint32_t pid, ACCESS_MASK AccessMask = PROCESS_ALL_ACCESS);

HANDLE ThreadCreate(HANDLE ProcessHandle, PVOID StartAddress);
bool ThreadResume(HANDLE ThreadHandle);
bool ThreadGetContext(HANDLE ThreadHandle, CONTEXT *ctx);
bool ThreadGetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT *ctx);
bool ThreadSetContext(HANDLE ThreadHandle, CONTEXT *ctx);
bool ThreadSetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT *ctx);

HANDLE SectionCreate(size_t Size);
HANDLE SectionFileCreate(HANDLE FileHandle);
PVOID SectionMapView(HANDLE SectionHandle, SIZE_T Size, ULONG Win32Protect, HANDLE ProcessHandle = GetCurrentProcess());
bool SectionUnmapView(PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());

bool HandleClose(HANDLE Handle);

PVOID VirtualMemoryAllocate(SIZE_T Size, ULONG Protect, HANDLE ProcessHandle = GetCurrentProcess(), PVOID BaseAddress = nullptr);
bool VirtualMemoryProtect(PVOID BaseAddress, SIZE_T Size, ULONG& Protect, HANDLE ProcessHandle = GetCurrentProcess());
bool VirtualMemoryWrite(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());
size_t VirtualMemoryRead(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());

HANDLE FileOpen(const wchar_t* path);
size_t FileGetSize(HANDLE FileHandle);

bool PeImageRelocate(PVOID ImageBuffer, PVOID NewBaseAddress, HANDLE ProcessHandle);

}