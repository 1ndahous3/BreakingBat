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
    bool ntdll_copy = false;
    bool ntdll_alt_api = false;
};

void HandleClose(HANDLE Handle);
HANDLE HandleDuplicate(HANDLE TargetProcessHandle, HANDLE SourceHandle, HANDLE SourceProcessHandle = GetCurrentProcess());

using unique_handle = unique_resource<HANDLE, HandleClose>;

struct process_t {
    unique_handle hProcess;
    unique_handle hThread;
};

void init(const options_t& sysapi_opts);

PPEB GetPeb();

PRTL_USER_PROCESS_PARAMETERS ProcessParametersCreate(const std::wstring& name);
void ProcessParametersDestroy(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

process_t ProcessCreateUser(const std::wstring& name, bool suspended = false);
HANDLE ProcessCreate(HANDLE SectionHandle);
bool ProcessGetBasicInfo(HANDLE ProcessHandle, PROCESS_BASIC_INFORMATION& BasicInfo);
bool ProcessGetWow64Info(HANDLE ProcessHandle, bool& is_64);

uint32_t ProcessFind(const wchar_t *name);
HANDLE ProcessOpen(uint32_t pid, ACCESS_MASK AccessMask);
HANDLE ProcessOpenByHwnd(HWND hWnd, ACCESS_MASK AccessMask);

HANDLE ThreadOpenNext(HANDLE ProcessHandle, HANDLE ThreadHandle = NULL, ACCESS_MASK AccessMask = THREAD_ALL_ACCESS);
HANDLE ThreadOpen(uint32_t pid, uint32_t tid, ACCESS_MASK AccessMask = THREAD_ALL_ACCESS);
HANDLE ThreadCreate(HANDLE ProcessHandle, PVOID StartAddress);
bool ThreadSuspend(HANDLE ThreadHandle);
bool ThreadResume(HANDLE ThreadHandle);
bool ThreadGetBasicInfo(HANDLE ThreadHandle, THREAD_BASIC_INFORMATION& BasicInfo);
bool ThreadGetContext(HANDLE ThreadHandle, CONTEXT *ctx);
bool ThreadGetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT *ctx);
bool ThreadSetContext(HANDLE ThreadHandle, CONTEXT *ctx);
bool ThreadSetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT *ctx);
bool ThreadCreateStack(HANDLE ProcessHandle, PINITIAL_TEB InitialTeb);

bool ThreadQueueUserApc(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1 = NULL, PVOID ApcArgument2 = NULL, PVOID ApcArgument3 = NULL);

HANDLE SectionCreate(size_t Size);
HANDLE SectionFileCreate(HANDLE FileHandle, ACCESS_MASK DesiredAccess, ULONG Protection, bool AsImage = false, SIZE_T Size = 0);
PVOID SectionMapView(HANDLE SectionHandle, SIZE_T Size, ULONG Protect, HANDLE ProcessHandle = GetCurrentProcess(), PVOID BaseAddress = nullptr);
bool SectionUnmapView(PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());

PVOID VirtualMemoryAllocate(SIZE_T Size, ULONG Protect, HANDLE ProcessHandle = GetCurrentProcess(), PVOID BaseAddress = nullptr, ULONG AllocationType = MEM_RESERVE | MEM_COMMIT);
bool VirtualMemoryProtect(PVOID BaseAddress, SIZE_T Size, ULONG& Protect, HANDLE ProcessHandle = GetCurrentProcess());
bool VirtualMemoryWrite(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());
size_t VirtualMemoryRead(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle = GetCurrentProcess());

HANDLE TransactionCreate(const wchar_t *path);
bool TransactionRollback(HANDLE hTransaction);
bool TransactionSet(HANDLE hTransaction);

HANDLE EventCreate();

HANDLE FileOpen(const wchar_t *path);
HANDLE FileCreate(const wchar_t *path, ACCESS_MASK DesiredAccess, ULONG ShareAccess, size_t Size);
bool FileWrite(HANDLE FileHandle, PVOID Data, SIZE_T Size);
size_t FileGetSize(HANDLE FileHandle);

bool AdjustPrivilege(ULONG Privilege);

bool DumpLiveSystem(HANDLE FileHandle);

HMODULE LoadLibraryCopyW(const wchar_t *ModuleName);

} // namespace sysapi
