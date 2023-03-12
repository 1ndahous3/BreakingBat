#pragma once

#include <cstdint>

#include "winapi.h"

namespace sysapi {

struct options_t {
    bool ntdll_ex;
};

uint32_t FindProcess(const wchar_t* name);
HANDLE OpenProcess(uint32_t pid, ACCESS_MASK AccessMask = PROCESS_ALL_ACCESS);
HANDLE CreateThread(HANDLE ProcessHandle, PVOID StartAddress);

HANDLE CreateSection(size_t Size);
PVOID MapViewOfSection(HANDLE SectionHandle, SIZE_T Size, ULONG Win32Protect, HANDLE ProcessHandle = GetCurrentProcess());
bool UnmapViewOfSection(PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());

bool CloseHandle(HANDLE Handle);

}