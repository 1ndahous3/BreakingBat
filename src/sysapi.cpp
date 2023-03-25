#include "phnt_windows.h"
#include "phnt.h"

#include <cstdio>
#include <cstdint>

#include <string>

#include "sysapi.h"

#include <tlhelp32.h>

#include "common.h"

#pragma comment(lib, "ntdll.lib")

HMODULE hNtdll = GetModuleHandleA("ntdll");

namespace sysapi {

decltype(::RtlInitializeContext) *RtlInitializeContext = nullptr;
decltype(::NtCreateSectionEx) *NtCreateSectionEx = nullptr;
decltype(::NtMapViewOfSectionEx) *NtMapViewOfSectionEx = nullptr;
decltype(::NtUnmapViewOfSectionEx) *NtUnmapViewOfSectionEx = nullptr;
decltype(::NtAllocateVirtualMemoryEx) *NtAllocateVirtualMemoryEx = nullptr;
decltype(::NtReadVirtualMemoryEx) *NtReadVirtualMemoryEx = nullptr;

void init(const options_t &sysapi_opts) {

#define NTDLL_RESOLVE(F) \
    F = (decltype(::F)*)GetProcAddress(hNtdll, #F);                            \
    if (F == nullptr) {                                                        \
        wprintf(L"  [!] unable to get address of \"%hs\" from ntdll.dll\n", #F); \
    }

    NTDLL_RESOLVE(RtlInitializeContext);

    if (sysapi_opts.ntdll_ex) {
        NTDLL_RESOLVE(NtCreateSectionEx);
        NTDLL_RESOLVE(NtMapViewOfSectionEx);
        NTDLL_RESOLVE(NtUnmapViewOfSectionEx);
        NTDLL_RESOLVE(NtAllocateVirtualMemoryEx);
        NTDLL_RESOLVE(NtReadVirtualMemoryEx);
    }
#undef NTDLL_RESOLVE

    wprintf(L"\n");
}

process_t ProcessCreate(const std::wstring& name, bool suspended) {

    auto nt_name = L"\\??\\" + name;

    UNICODE_STRING NtImagePath;
    RtlInitUnicodeString(&NtImagePath, nt_name.c_str());

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    NTSTATUS status = RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to create process parameters, status = 0x%x\n", status);
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
        wprintf(L"  [-] unable to create process, status = 0x%x\n", status);
        return {};
    }

    return process;
}

bool ProcessGetBasicInfo(HANDLE ProcessHandle, PROCESS_BASIC_INFORMATION& BasicInfo) {

    NTSTATUS status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to get basic process information (HANDLE = 0x%p), status = 0x%x\n", ProcessHandle, status);
        return false;
    }

    return true;
}

uint32_t ProcessFind(const wchar_t *name) {

    uint32_t pid = 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == NULL) {
        wprintf(L"  [-] unable to create snapshot of processes\n");
        return 0;
    }

    if (Process32FirstW(snapshot, &entry) != TRUE) {
        wprintf(L"  [-] unable to get first process, error = %d\n", GetLastError());
        CloseHandle(snapshot);
        return 0;
    }

    while (Process32NextW(snapshot, &entry) == TRUE) {

        if (_wcsicmp(entry.szExeFile, name) != 0) {
            continue;
        }

        //wprintf(L"  [+] process found (name = %s), PID = %d\n", name, entry.th32ProcessID);

        if (pid != 0) {
            wprintf(L"  [-] there are multiple processes with the same name\n");
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
        wprintf(L"  [-] unable to open process (PID = %d), status = 0x%x\n", pid, status);
        return NULL;
    }

    //wprintf(L"  [+] process (PID = %d) opened, HANDLE = 0x%p\n", pid, ProcessHandle);
    return ProcessHandle;
}

HANDLE ThreadCreateEx(HANDLE ProcessHandle, PVOID StartAddress) {

    HANDLE ThreadHandle;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    NTSTATUS status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, ProcessHandle, StartAddress, NULL, 0, 0, 0, 0, NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to create process thread (HANDLE = 0x%p), status = 0x%x\n", ProcessHandle, status);
        return NULL;
    }

    //wprintf(L"  [+] thread created, HANDLE = 0x%p\n", ThreadHandle);
    return ThreadHandle;
}

HANDLE ThreadCreate(HANDLE ProcessHandle, PVOID StartAddress) {

    HANDLE ThreadHandle;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    auto *Cid = (PCLIENT_ID)VirtualMemoryAllocate(sizeof(CLIENT_ID), PAGE_READWRITE);
    auto *InitialTeb = (PINITIAL_TEB)VirtualMemoryAllocate(sizeof(INITIAL_TEB), PAGE_READWRITE);
    auto *Context = (PCONTEXT)VirtualMemoryAllocate(sizeof(CONTEXT), PAGE_READWRITE);

    bool res = ThreadCreateStack(ProcessHandle, InitialTeb);
    if (!res) {
        return NULL;
    }

    RtlInitializeContext(ProcessHandle, Context, NULL, StartAddress, InitialTeb->StackBase);
    NTSTATUS status = NtCreateThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, ProcessHandle, Cid, Context, InitialTeb, FALSE);

    if (!NT_SUCCESS(status)) {

        wprintf(L"  [-] unable to create process thread (HANDLE = 0x%p), status = 0x%x\n", ProcessHandle, status);
        if (status == STATUS_ACCESS_DENIED) {
            wprintf(L"  [!] the target process probably has a 'ControlFlowGuard' protection\n");
        }

        return NULL;
    }

    //wprintf(L"  [+] thread created, HANDLE = 0x%p\n", ThreadHandle);
    return ThreadHandle;
}

bool ThreadResume(HANDLE ThreadHandle) {

    NTSTATUS status = NtResumeThread(ThreadHandle, NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to resume thread (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    //wprintf(L"  [+] thread resumed, HANDLE = 0x%p\n", ThreadHandle);
    return true;
}

bool ThreadGetContext(HANDLE ThreadHandle, CONTEXT* ctx) {

    NTSTATUS status = NtGetContextThread(ThreadHandle, ctx);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to get thread context (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    ////wprintf(L"  [+] thread context get");
    return true;
}

bool ThreadGetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT* ctx) {

    NTSTATUS status = NtQueryInformationThread(ThreadHandle, ThreadWow64Context, ctx, sizeof(WOW64_CONTEXT), NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to get WOW64 thread context (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    ////wprintf(L"  [+] thread WOW64 context get\n");
    return true;
}

bool ThreadSetContext(HANDLE ThreadHandle, CONTEXT* ctx) {

    NTSTATUS status = NtSetContextThread(ThreadHandle, ctx);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to set thread context (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    //wprintf(L"  [+] thread context set, HANDLE = 0x%p\n", ThreadHandle);
    return true;
}

bool ThreadSetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT* ctx) {

    NTSTATUS status = NtSetInformationThread(ThreadHandle, ThreadWow64Context, ctx, sizeof(WOW64_CONTEXT));

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to set WOW64 thread context (HANDLE = 0x%p), status = 0x%x\n", ThreadHandle, status);
        return false;
    }

    //wprintf(L"  [+] thread WOW64 context set, HANDLE = 0x%p\n", ThreadHandle);
    return true;
}

// see RtlpCreateStack() (base/ntos/rtl/rtlexec.c)
bool ThreadCreateStack(HANDLE ProcessHandle, PINITIAL_TEB InitialTeb) {

    SYSTEM_BASIC_INFORMATION SysInfo;
    auto status = NtQuerySystemInformation(SystemBasicInformation, &SysInfo, sizeof(SysInfo), NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to get system basic information, status = 0x%x\n", status);
        return false;
    }

    //
    // if stack is in the current process, then default to
    // the parameters from the image
    //

    SIZE_T MaximumStackSize = SysInfo.AllocationGranularity;
    SIZE_T CommittedStackSize = SysInfo.PageSize;

    //
    // Enforce a minimal stack commit if there is a PEB setting
    // for this.
    //

    if (CommittedStackSize >= MaximumStackSize) {
        MaximumStackSize = ROUND_UP(CommittedStackSize, (1024 * 1024));
    }

    CommittedStackSize = ROUND_UP(CommittedStackSize, SysInfo.PageSize);
    MaximumStackSize = ROUND_UP(MaximumStackSize, SysInfo.AllocationGranularity);

    PVOID Stack = VirtualMemoryAllocate(MaximumStackSize, PAGE_READWRITE, ProcessHandle, NULL, MEM_RESERVE);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    InitialTeb->OldInitialTeb.OldStackBase = NULL;
    InitialTeb->OldInitialTeb.OldStackLimit = NULL;
    InitialTeb->StackAllocationBase = Stack;
    InitialTeb->StackBase = PTR_ADD(Stack, MaximumStackSize);

    bool GuardPage = false;

    Stack = PTR_ADD(Stack, MaximumStackSize - CommittedStackSize);
    if (MaximumStackSize > CommittedStackSize) {
        Stack = PTR_SUB(Stack, SysInfo.PageSize);
        CommittedStackSize += SysInfo.PageSize;
        GuardPage = true;
    }

    Stack = VirtualMemoryAllocate(CommittedStackSize, PAGE_READWRITE, ProcessHandle, Stack, MEM_COMMIT);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    InitialTeb->StackLimit = Stack;

    //
    // if we have space, create a guard page.
    //

    if (GuardPage) {

        SIZE_T RegionSize =  SysInfo.PageSize;
        ULONG Protect = PAGE_READWRITE | PAGE_GUARD;

        bool res = VirtualMemoryProtect(Stack, RegionSize, Protect, ProcessHandle);
        if (!res) {
            return false;
        }

        InitialTeb->StackLimit = PTR_ADD(InitialTeb->StackLimit, RegionSize);
    }

    return true;
}

HANDLE SectionCreate(size_t Size) {

    HANDLE SectionHandle;
    LARGE_INTEGER sectionSize{ .QuadPart = (LONGLONG)Size };

    NTSTATUS status;

    if (NtCreateSectionEx) {
        status = NtCreateSectionEx(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL, NULL, 0);
    }
    else {
        status = NtCreateSection(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to create section, status = 0x%x\n", status);
        return NULL;
    }

    //wprintf(L"  [+] section created, HANDLE = 0x%p\n", SectionHandle);
    return SectionHandle;
}

HANDLE SectionFileCreate(HANDLE FileHandle) {

    HANDLE SectionHandle;

    NTSTATUS status;

    if (NtCreateSectionEx) {
        status = NtCreateSectionEx(&SectionHandle, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, FileHandle, NULL, 0);
    }
    else {
        status = NtCreateSection(&SectionHandle, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT, FileHandle);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to create file section, status = 0x%x\n", status);
        return NULL;
    }

    //wprintf(L"  [+] file section created, HANDLE = 0x%p\n", SectionHandle);
    return SectionHandle;
}

PVOID SectionMapView(HANDLE SectionHandle, SIZE_T Size, ULONG Protect, HANDLE ProcessHandle, PVOID BaseAddress) {

    NTSTATUS status;

    if (NtMapViewOfSectionEx) {
        status = NtMapViewOfSectionEx(SectionHandle, ProcessHandle, &BaseAddress, NULL, &Size, 0, Protect, NULL, 0);
    }
    else {
        status = NtMapViewOfSection(SectionHandle, ProcessHandle, &BaseAddress, NULL, 0, NULL, &Size, ViewUnmap, 0, Protect);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to map section, status = 0x%x\n", status);
        return nullptr;
    }

    //wprintf(L"  [+] section mapped, address = 0x%p\n", BaseAddress);
    return BaseAddress;
}

bool SectionUnmapView(PVOID BaseAddress, HANDLE ProcessHandle) {

    NTSTATUS status;

    if (NtUnmapViewOfSectionEx) {
        status = NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, 0);
    }
    else {
        status = NtUnmapViewOfSection(ProcessHandle, BaseAddress);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to unmap section, status = 0x%x\n", status);
        return false;
    }

    //wprintf(L"  [+] section unmapped\n");
    return true;
}

bool HandleClose(HANDLE Handle) {

    NTSTATUS status = NtClose(Handle);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to close handle (0x%p), status = 0x%x\n", Handle, status);
        return false;
    }

    ////wprintf(L"  [+] handle closed\n");
    return true;
}

PVOID VirtualMemoryAllocate(SIZE_T Size, ULONG Protect, HANDLE ProcessHandle, PVOID BaseAddress, ULONG AllocationType) {

    NTSTATUS status;

    if (NtAllocateVirtualMemoryEx) {
        status = NtAllocateVirtualMemoryEx(ProcessHandle, &BaseAddress, &Size, AllocationType, Protect, NULL, 0);
    }
    else {
        status = NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &Size, AllocationType, Protect);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to allocate virtual memory (0x%zu bytes), status = 0x%x\n", Size, status);
        return nullptr;
    }

    return BaseAddress;
}

bool VirtualMemoryProtect(PVOID BaseAddress, SIZE_T Size, ULONG& Protect, HANDLE ProcessHandle) {

    NTSTATUS status = NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &Size, Protect, &Protect);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to protect virtual memory (0x%zu bytes), status = 0x%x\n", Size, status);
        return false;
    }

    return true;
}

bool VirtualMemoryWrite(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle) {

    SIZE_T NumberOfBytesWritten;
    NTSTATUS status = NtWriteVirtualMemory(ProcessHandle, BaseAddress, Data, Size, &NumberOfBytesWritten);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to write virtual memory (0x%zu bytes), status = 0x%x\n", Size, status);
        return false;
    }

    return true;
}

size_t VirtualMemoryRead(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle) {

    SIZE_T NumberOfBytesRead;

    NTSTATUS status;

    if (NtReadVirtualMemoryEx) {
        status = NtReadVirtualMemoryEx(ProcessHandle, BaseAddress, Data, Size, &NumberOfBytesRead, 0);
    }
    else {
        status = NtReadVirtualMemory(ProcessHandle, BaseAddress, Data, Size, &NumberOfBytesRead);
    }

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to read virtual memory (0x%zu bytes), status = 0x%x\n", Size, status);
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
        wprintf(L"  [-] unable to open file (%s), status = 0x%x\n", path, status);
        return NULL;
    }

    return hFile;
}

size_t FileGetSize(HANDLE FileHandle) {

    IO_STATUS_BLOCK IoStatus = {};

    FILE_STANDARD_INFORMATION FileInformation;
    NTSTATUS status = NtQueryInformationFile(FileHandle, &IoStatus, &FileInformation, sizeof(FileInformation), FileStandardInformation);

    if (!NT_SUCCESS(status)) {
        wprintf(L"  [-] unable to get basic file information (HANDLE = 0x%p), status = 0x%x\n", FileHandle, status);
        return 0;
    }

    return FileInformation.EndOfFile.QuadPart;
}

}