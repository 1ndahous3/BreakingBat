#include "phnt_windows.h"
#include "phnt.h"
#include <tlhelp32.h>
#include <userenv.h>

#include <cstdio>
#include <cstdint>
#include <string>

#include "common.h"
#include "fs.h"
#include "sysapi.h"
#include "logging.h"


extern "C" {

NTSYSCALLAPI
HANDLE
NTAPI
NtUserGetWindowProcessHandle(
    _In_ HWND hWnd,
    _In_ ACCESS_MASK DesiredAccess
);
}

struct ntdll_api_t {

    HMODULE NtDllModule = NULL;

    decltype(::NtQuerySystemInformation) *NtQuerySystemInformation = nullptr;
    decltype(::NtAllocateVirtualMemory) *NtAllocateVirtualMemory = nullptr;
    decltype(::NtReadVirtualMemory) *NtReadVirtualMemory = nullptr;
    decltype(::NtWriteVirtualMemory) *NtWriteVirtualMemory = nullptr;
    decltype(::NtProtectVirtualMemory) *NtProtectVirtualMemory = nullptr;
    decltype(::NtCreateSection) *NtCreateSection = nullptr;
    decltype(::NtMapViewOfSection) *NtMapViewOfSection = nullptr;
    decltype(::NtUnmapViewOfSection) *NtUnmapViewOfSection = nullptr;
    decltype(::NtClose) *NtClose = nullptr;
    decltype(::NtDuplicateObject) *NtDuplicateObject = nullptr;
    decltype(::NtOpenProcess) *NtOpenProcess = nullptr;
    decltype(::NtQueryInformationProcess) *NtQueryInformationProcess = nullptr;
    decltype(::NtSuspendThread) *NtSuspendThread = nullptr;
    decltype(::NtResumeThread) *NtResumeThread = nullptr;
    decltype(::NtGetContextThread) *NtGetContextThread = nullptr;
    decltype(::NtSetContextThread) *NtSetContextThread = nullptr;
    decltype(::NtQueryInformationThread) *NtQueryInformationThread = nullptr;
    decltype(::NtSetInformationThread) *NtSetInformationThread = nullptr;
    decltype(::NtCreateUserProcess) *NtCreateUserProcess = nullptr;
    decltype(::NtCreateProcessEx) *NtCreateProcessEx = nullptr;
    decltype(::NtCreateThreadEx) *NtCreateThreadEx = nullptr;
    decltype(::NtOpenThread) *NtOpenThread = nullptr;
    decltype(::NtGetNextThread) *NtGetNextThread = nullptr;
    decltype(::NtCreateFile) *NtCreateFile = nullptr;
    decltype(::NtWriteFile) *NtWriteFile = nullptr;
    decltype(::NtCreateTransaction) *NtCreateTransaction = nullptr;
    decltype(::NtRollbackTransaction) *NtRollbackTransaction = nullptr;
    decltype(::NtQueryInformationFile) *NtQueryInformationFile = nullptr;
    decltype(::NtQueueApcThread) *NtQueueApcThread = nullptr;
    decltype(::NtQueueApcThreadEx) *NtQueueApcThreadEx = nullptr;
    decltype(::NtCreateEvent) *NtCreateEvent = nullptr;
    decltype(::NtSystemDebugControl) *NtSystemDebugControl = nullptr;
    decltype(::RtlAdjustPrivilege) *RtlAdjustPrivilege = nullptr;
    decltype(::RtlCreateProcessParametersEx) *RtlCreateProcessParametersEx = nullptr;
    decltype(::RtlDestroyProcessParameters) *RtlDestroyProcessParameters = nullptr;
    decltype(::RtlInitializeContext) *RtlInitializeContext = nullptr;
    decltype(::RtlCreateEnvironmentEx) *RtlCreateEnvironmentEx = nullptr;
    decltype(::RtlDestroyEnvironment) *RtlDestroyEnvironment = nullptr;
    decltype(::RtlSetCurrentTransaction) *RtlSetCurrentTransaction = nullptr;
    // alternative API
    decltype(::NtCreateProcess) *NtCreateProcess = nullptr;
    decltype(::NtCreateThread) *NtCreateThread = nullptr;
    decltype(::NtCreateSectionEx) *NtCreateSectionEx = nullptr;
    decltype(::NtMapViewOfSectionEx) *NtMapViewOfSectionEx = nullptr;
    decltype(::NtUnmapViewOfSectionEx) *NtUnmapViewOfSectionEx = nullptr;
    decltype(::NtAllocateVirtualMemoryEx) *NtAllocateVirtualMemoryEx = nullptr;
    decltype(::NtReadVirtualMemoryEx) *NtReadVirtualMemoryEx = nullptr;
};


struct win32u_api_t {

    HMODULE Win32uDllModule = NULL;

    decltype(::NtUserGetWindowProcessHandle) *NtUserGetWindowProcessHandle = nullptr;
};


namespace sysapi {

ntdll_api_t ntdll;
win32u_api_t win32u;

void init(const options_t& sysapi_opts) {

#define NTDLL_RESOLVE(F)                                                   \
    ntdll.F = (decltype(::F) *)GetProcAddress(ntdll.NtDllModule, #F);      \
    if (ntdll.F == nullptr) {                                              \
        bblog::warn("unable to get address of \"{}\" from ntdll.dll", #F); \
    }

    ntdll.NtDllModule = GetModuleHandleW(L"ntdll.dll");

    NTDLL_RESOLVE(NtQuerySystemInformation);
    NTDLL_RESOLVE(NtAllocateVirtualMemory);
    NTDLL_RESOLVE(NtReadVirtualMemory);
    NTDLL_RESOLVE(NtWriteVirtualMemory);
    NTDLL_RESOLVE(NtProtectVirtualMemory);
    NTDLL_RESOLVE(NtCreateSection);
    NTDLL_RESOLVE(NtMapViewOfSection);
    NTDLL_RESOLVE(NtUnmapViewOfSection);
    NTDLL_RESOLVE(NtClose);
    NTDLL_RESOLVE(NtDuplicateObject);
    NTDLL_RESOLVE(NtOpenProcess);
    NTDLL_RESOLVE(NtQueryInformationProcess);
    NTDLL_RESOLVE(NtSuspendThread);
    NTDLL_RESOLVE(NtResumeThread);
    NTDLL_RESOLVE(NtGetContextThread);
    NTDLL_RESOLVE(NtSetContextThread);
    NTDLL_RESOLVE(NtQueryInformationThread);
    NTDLL_RESOLVE(NtSetInformationThread);
    NTDLL_RESOLVE(NtCreateUserProcess);
    NTDLL_RESOLVE(NtCreateProcessEx);
    NTDLL_RESOLVE(NtCreateThreadEx);
    NTDLL_RESOLVE(NtOpenThread);
    NTDLL_RESOLVE(NtGetNextThread);
    NTDLL_RESOLVE(NtCreateFile);
    NTDLL_RESOLVE(NtWriteFile);
    NTDLL_RESOLVE(NtCreateTransaction);
    NTDLL_RESOLVE(NtRollbackTransaction);
    NTDLL_RESOLVE(NtQueryInformationFile);
    NTDLL_RESOLVE(NtQueueApcThread);
    NTDLL_RESOLVE(NtQueueApcThreadEx);
    NTDLL_RESOLVE(NtCreateEvent);
    NTDLL_RESOLVE(NtSystemDebugControl);
    NTDLL_RESOLVE(RtlAdjustPrivilege);
    NTDLL_RESOLVE(RtlCreateProcessParametersEx);
    NTDLL_RESOLVE(RtlDestroyProcessParameters);
    NTDLL_RESOLVE(RtlInitializeContext);
    NTDLL_RESOLVE(RtlCreateEnvironmentEx);
    NTDLL_RESOLVE(RtlDestroyEnvironment);
    NTDLL_RESOLVE(RtlSetCurrentTransaction);

    if (sysapi_opts.ntdll_alt_api) {
        NTDLL_RESOLVE(NtCreateProcess);
        NTDLL_RESOLVE(NtCreateThread);
        NTDLL_RESOLVE(NtCreateSectionEx);
        NTDLL_RESOLVE(NtMapViewOfSectionEx);
        NTDLL_RESOLVE(NtUnmapViewOfSectionEx);
        NTDLL_RESOLVE(NtAllocateVirtualMemoryEx);
        NTDLL_RESOLVE(NtReadVirtualMemoryEx);
    }
#undef NTDLL_RESOLVE

    if (sysapi_opts.ntdll_copy) {

#define NTDLL_RESOLVE(F)                                                           \
    ntdll.F = (decltype(::F) *)GetProcAddress(ntdll.NtDllModule, #F);              \
    if (ntdll.F == nullptr) {                                                      \
        bblog::info("unable to get address of \"{}\" from copy of ntdll.dll", #F); \
    }

        // we had to initialize the original API first to use it in this function
        ntdll.NtDllModule = LoadLibraryCopyW(L"c:\\windows\\system32\\ntdll.dll");

        NTDLL_RESOLVE(NtQuerySystemInformation);
        NTDLL_RESOLVE(NtAllocateVirtualMemory);
        NTDLL_RESOLVE(NtReadVirtualMemory);
        NTDLL_RESOLVE(NtWriteVirtualMemory);
        NTDLL_RESOLVE(NtProtectVirtualMemory);
        NTDLL_RESOLVE(NtCreateSection);
        NTDLL_RESOLVE(NtMapViewOfSection);
        NTDLL_RESOLVE(NtUnmapViewOfSection);
        NTDLL_RESOLVE(NtClose);
        NTDLL_RESOLVE(NtDuplicateObject);
        NTDLL_RESOLVE(NtOpenProcess);
        NTDLL_RESOLVE(NtQueryInformationProcess);
        NTDLL_RESOLVE(NtSuspendThread);
        NTDLL_RESOLVE(NtResumeThread);
        NTDLL_RESOLVE(NtGetContextThread);
        NTDLL_RESOLVE(NtSetContextThread);
        NTDLL_RESOLVE(NtQueryInformationThread);
        NTDLL_RESOLVE(NtSetInformationThread);
        NTDLL_RESOLVE(NtCreateUserProcess);
        NTDLL_RESOLVE(NtCreateProcessEx);
        NTDLL_RESOLVE(NtCreateThreadEx);
        NTDLL_RESOLVE(NtOpenThread);
        NTDLL_RESOLVE(NtGetNextThread);
        NTDLL_RESOLVE(NtCreateFile);
        NTDLL_RESOLVE(NtWriteFile);
        NTDLL_RESOLVE(NtCreateTransaction);
        NTDLL_RESOLVE(NtRollbackTransaction);
        NTDLL_RESOLVE(NtQueryInformationFile);
        NTDLL_RESOLVE(NtQueueApcThread);
        NTDLL_RESOLVE(NtQueueApcThreadEx);
        NTDLL_RESOLVE(NtCreateEvent);
        NTDLL_RESOLVE(NtSystemDebugControl);
        // these functions crash inside guard_dispatch_icall_nop() if called from copy of ntdll.dll
        // NTDLL_RESOLVE(RtlAdjustPrivilege);
        // NTDLL_RESOLVE(RtlCreateProcessParametersEx);
        // NTDLL_RESOLVE(RtlDestroyProcessParameters);
        // NTDLL_RESOLVE(RtlInitializeContext);
        NTDLL_RESOLVE(RtlCreateEnvironmentEx);
        NTDLL_RESOLVE(RtlDestroyEnvironment);
        NTDLL_RESOLVE(RtlSetCurrentTransaction);

        if (sysapi_opts.ntdll_alt_api) {
            NTDLL_RESOLVE(NtCreateProcess);
            NTDLL_RESOLVE(NtCreateThread);
            NTDLL_RESOLVE(NtCreateSectionEx);
            NTDLL_RESOLVE(NtMapViewOfSectionEx);
            NTDLL_RESOLVE(NtUnmapViewOfSectionEx);
            NTDLL_RESOLVE(NtAllocateVirtualMemoryEx);
            NTDLL_RESOLVE(NtReadVirtualMemoryEx);
        }
#undef NTDLL_RESOLVE
    }

#define WIN32U_RESOLVE(F)                                                   \
    win32u.F = (decltype(::F) *)GetProcAddress(win32u.Win32uDllModule, #F); \
    if (win32u.F == nullptr) {                                              \
        bblog::warn("unable to get address of \"{}\" from win32u.dll", #F); \
    }

    win32u.Win32uDllModule = GetModuleHandleW(L"win32u.dll");

    WIN32U_RESOLVE(NtUserGetWindowProcessHandle);
#undef WIN32U_RESOLVE
}

PPEB GetPeb() {
#if defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#elif defined(_WIN32)
    return (PPEB)__readfsdword(0x30);
#endif
}

PRTL_USER_PROCESS_PARAMETERS ProcessParametersCreate(const std::wstring& name) {

    auto nt_name = L"\\??\\" + name;

    UNICODE_STRING NtImagePath;
    RtlInitUnicodeString(&NtImagePath, nt_name.c_str());

    wchar_t dirPath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, dirPath);

    UNICODE_STRING uCurrentDir;
    RtlInitUnicodeString(&uCurrentDir, dirPath);

    UNICODE_STRING uDllDir = sysapi::GetPeb()->ProcessParameters->DllPath;

    LPVOID ProcessEnvironment = sysapi::GetPeb()->ProcessParameters->Environment;

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    NTSTATUS status = ntdll.RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, &uDllDir, &uCurrentDir, &NtImagePath, ProcessEnvironment, NULL, NULL, NULL, NULL, 0);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to create process parameters, status = 0x{:x}", status);
        return NULL;
    }

    return ProcessParameters;
}

void ProcessParametersDestroy(PRTL_USER_PROCESS_PARAMETERS ProcessParameters) {
    ntdll.RtlDestroyProcessParameters(ProcessParameters);
}

process_t ProcessCreateUser(const std::wstring& name, bool suspended) {

    auto nt_name = L"\\??\\" + name;

    UNICODE_STRING NtImagePath;
    RtlInitUnicodeString(&NtImagePath, nt_name.c_str());

    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    NTSTATUS status = ntdll.RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to create process parameters, status = 0x{:x}", status);
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
    status = ntdll.NtCreateUserProcess(
        process.hProcess.reset(), process.hThread.reset(),
        PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL,
        suspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0,
        ProcessParameters, &CreateInfo, &AttributeList
    );

    ntdll.RtlDestroyProcessParameters(ProcessParameters);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to create process, status = 0x{:x}", status);
        return {};
    }

    return process;
}

HANDLE ProcessCreate(HANDLE SectionHandle) {

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    HANDLE ProcessHandle;
    NTSTATUS status;

    if (ntdll.NtCreateProcess) {
        status = ntdll.NtCreateProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, NtCurrentProcess(), TRUE, SectionHandle, NULL, NULL);
    }
    else {
        status = ntdll.NtCreateProcessEx(&ProcessHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, NtCurrentProcess(), PROCESS_CREATE_FLAGS_INHERIT_HANDLES, SectionHandle, NULL, NULL, 0);
    }

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to create process, status = 0x{:x}", status);
        return NULL;
    }

    return ProcessHandle;
}

bool ProcessGetBasicInfo(HANDLE ProcessHandle, PROCESS_BASIC_INFORMATION& BasicInfo) {

    NTSTATUS status = ntdll.NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &BasicInfo, sizeof(PROCESS_BASIC_INFORMATION), NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to get basic process information (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ProcessHandle, status);
        return false;
    }

    return true;
}

bool ProcessGetWow64Info(HANDLE ProcessHandle, bool& is_64) {

    ULONG_PTR Wow64Info;
    NTSTATUS status = ntdll.NtQueryInformationProcess(ProcessHandle, ProcessWow64Information, &Wow64Info, sizeof(ULONG_PTR), NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to get WOW64 process information (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ProcessHandle, status);
        return false;
    }

    is_64 = Wow64Info == NULL;
    return true;
}

uint32_t ProcessFind(const wchar_t *name) {

    uint32_t pid = 0;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == NULL) {
        bblog::error("unable to create snapshot of processes");
        return 0;
    }

    if (Process32FirstW(snapshot, &entry) != TRUE) {
        bblog::error("unable to get first process, error = {}", GetLastError());
        CloseHandle(snapshot);
        return 0;
    }

    while (Process32NextW(snapshot, &entry) == TRUE) {

        if (_wcsicmp(entry.szExeFile, name) != 0) {
            continue;
        }

        bblog::debug(L"process found (name = {}), PID = {}", name, entry.th32ProcessID);

        if (pid != 0) {
            bblog::error("there are multiple processes with the same name");
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
    NTSTATUS status = ntdll.NtOpenProcess(&ProcessHandle, AccessMask, &ObjectAttributes, &Cid);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to open process (PID = {}), status = 0x{:x}", pid, status);
        return NULL;
    }

    bblog::debug("process (PID = {}) opened, HANDLE = 0x{:x}", pid, (uintptr_t)ProcessHandle);
    return ProcessHandle;
}

HANDLE ProcessOpenByHwnd(HWND hWnd, ACCESS_MASK AccessMask) {

    HANDLE ProcessHandle = win32u.NtUserGetWindowProcessHandle(hWnd, AccessMask);
    if (ProcessHandle == NULL) {
        bblog::error("unable to open process (HWND = 0x{:x})", (uintptr_t)hWnd);
        return NULL;
    }

    bblog::debug("process (HWND = 0x{:x}) opened, HANDLE = 0x{:x}", (uintptr_t)hWnd, (uintptr_t)ProcessHandle);
    return ProcessHandle;
}

HANDLE ThreadOpenNext(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK AccessMask) {

    HANDLE NewThreadHandle;

    NTSTATUS status = ntdll.NtGetNextThread(
        ProcessHandle,
        ThreadHandle,
        AccessMask,
        0,
        0,
        &NewThreadHandle
    );

    if (!NT_SUCCESS(status)) {
        if (status != STATUS_NO_MORE_ENTRIES) {
            bblog::error("unable to open thread (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ProcessHandle, status);
        }

        return NULL;
    }

    bblog::debug("thread opened (HANDLE = 0x{:x}), HANDLE = 0x{:x}", (uintptr_t)ProcessHandle, (uintptr_t)NewThreadHandle);
    return NewThreadHandle;
}

HANDLE ThreadOpen(uint32_t pid, uint32_t tid, ACCESS_MASK AccessMask) {

    HANDLE ThreadHandle;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID Cid{ .UniqueProcess = ULongToHandle(pid), .UniqueThread = ULongToHandle(tid) };
    NTSTATUS status = ntdll.NtOpenThread(&ThreadHandle, AccessMask, &ObjectAttributes, &Cid);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to open thread (PID = {}, TID = {}), status = 0x{:x}", pid, tid, status);
        return NULL;
    }

    bblog::debug("thread (PID = {}, TID = {}) opened, HANDLE = 0x{:x}", pid, tid, (uintptr_t)ThreadHandle);
    return ThreadHandle;
}

HANDLE ThreadCreate(HANDLE ProcessHandle, PVOID StartAddress) {

    HANDLE ThreadHandle;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    NTSTATUS status;

    if (ntdll.NtCreateThread) {

        auto *Cid = (PCLIENT_ID)VirtualMemoryAllocate(sizeof(CLIENT_ID), PAGE_READWRITE);
        auto *InitialTeb = (PINITIAL_TEB)VirtualMemoryAllocate(sizeof(INITIAL_TEB), PAGE_READWRITE);
        auto *Context = (PCONTEXT)VirtualMemoryAllocate(sizeof(CONTEXT), PAGE_READWRITE);

        bool res = ThreadCreateStack(ProcessHandle, InitialTeb);
        if (!res) {
            return NULL;
        }

        ntdll.RtlInitializeContext(ProcessHandle, Context, NULL, StartAddress, InitialTeb->StackBase);
        status = ntdll.NtCreateThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, ProcessHandle, Cid, Context, InitialTeb, FALSE);
    }
    else {
        status = ntdll.NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, ProcessHandle, (PUSER_THREAD_START_ROUTINE)StartAddress, NULL, 0, 0, 0, 0, NULL);
    }

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to create process thread (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ProcessHandle, status);
        if (status == STATUS_ACCESS_DENIED) {
            bblog::warn("the target process probably has a 'ControlFlowGuard' protection");
        }

        return NULL;
    }

    bblog::debug("thread created, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle);
    return ThreadHandle;
}

bool ThreadSuspend(HANDLE ThreadHandle) {

    NTSTATUS status = ntdll.NtSuspendThread(ThreadHandle, NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to suspend thread (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ThreadHandle, status);
        return false;
    }

    bblog::debug("thread suspended, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle);
    return true;
}

bool ThreadResume(HANDLE ThreadHandle) {

    NTSTATUS status = ntdll.NtResumeThread(ThreadHandle, NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to resume thread (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ThreadHandle, status);
        return false;
    }

    bblog::debug("thread resumed, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle);
    return true;
}

bool ThreadGetBasicInfo(HANDLE ThreadHandle, THREAD_BASIC_INFORMATION& BasicInfo) {

    NTSTATUS status = ntdll.NtQueryInformationThread(ThreadHandle, ThreadBasicInformation, &BasicInfo, sizeof(THREAD_BASIC_INFORMATION), NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to get basic thread information (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ThreadHandle, status);
        return false;
    }

    return true;
}

bool ThreadGetContext(HANDLE ThreadHandle, CONTEXT *ctx) {

    NTSTATUS status = ntdll.NtGetContextThread(ThreadHandle, ctx);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to get thread context (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ThreadHandle, status);
        return false;
    }

    bblog::debug("thread context got");
    return true;
}

bool ThreadGetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT *ctx) {

    NTSTATUS status = ntdll.NtQueryInformationThread(ThreadHandle, ThreadWow64Context, ctx, sizeof(WOW64_CONTEXT), NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to get WOW64 thread context (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ThreadHandle, status);
        return false;
    }

    bblog::debug("thread WOW64 context got");
    return true;
}

bool ThreadSetContext(HANDLE ThreadHandle, CONTEXT *ctx) {

    NTSTATUS status = ntdll.NtSetContextThread(ThreadHandle, ctx);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to set thread context (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ThreadHandle, status);
        return false;
    }

    bblog::debug("thread context set, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle);
    return true;
}

bool ThreadSetWow64Context(HANDLE ThreadHandle, WOW64_CONTEXT *ctx) {

    NTSTATUS status = ntdll.NtSetInformationThread(ThreadHandle, ThreadWow64Context, ctx, sizeof(WOW64_CONTEXT));

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to set WOW64 thread context (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ThreadHandle, status);
        return false;
    }

    bblog::debug("thread WOW64 context set, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle);
    return true;
}

// see RtlpCreateStack() (base/ntos/rtl/rtlexec.c)
bool ThreadCreateStack(HANDLE ProcessHandle, PINITIAL_TEB InitialTeb) {

    SYSTEM_BASIC_INFORMATION SysInfo;
    auto status = ntdll.NtQuerySystemInformation(SystemBasicInformation, &SysInfo, sizeof(SysInfo), NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to get system basic information, status = 0x{:x}", status);
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

        SIZE_T RegionSize = SysInfo.PageSize;
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
    LARGE_INTEGER MaximumSize{ .QuadPart = (LONGLONG)Size };

    NTSTATUS status;

    if (ntdll.NtCreateSectionEx) {
        status = ntdll.NtCreateSectionEx(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL, NULL, 0);
    }
    else {
        status = ntdll.NtCreateSection(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    }

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to create section, status = 0x{:x}", status);
        return NULL;
    }

    bblog::debug("section created, HANDLE = 0x{:x}", (uintptr_t)SectionHandle);
    return SectionHandle;
}

HANDLE SectionFileCreate(HANDLE FileHandle, ACCESS_MASK DesiredAccess, ULONG Protection, bool AsImage, SIZE_T Size) {

    HANDLE SectionHandle;

    NTSTATUS status;

    LARGE_INTEGER MaximumSize{ .QuadPart = (LONGLONG)Size };

    if (ntdll.NtCreateSectionEx) {
        status = ntdll.NtCreateSectionEx(&SectionHandle, DesiredAccess, NULL, &MaximumSize, Protection, AsImage ? SEC_IMAGE : SEC_COMMIT, FileHandle, NULL, 0);
    }
    else {
        status = ntdll.NtCreateSection(&SectionHandle, DesiredAccess, NULL, &MaximumSize, Protection, AsImage ? SEC_IMAGE : SEC_COMMIT, FileHandle);
    }

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to create file section, status = 0x{:x}", status);
        return NULL;
    }

    bblog::debug("file section created, HANDLE = 0x{:x}", (uintptr_t)SectionHandle);
    return SectionHandle;
}

PVOID SectionMapView(HANDLE SectionHandle, SIZE_T Size, ULONG Protect, HANDLE ProcessHandle, PVOID BaseAddress) {

    NTSTATUS status;

    if (ntdll.NtMapViewOfSectionEx) {
        status = ntdll.NtMapViewOfSectionEx(SectionHandle, ProcessHandle, &BaseAddress, NULL, &Size, 0, Protect, NULL, 0);
    }
    else {
        status = ntdll.NtMapViewOfSection(SectionHandle, ProcessHandle, &BaseAddress, NULL, 0, NULL, &Size, ViewUnmap, 0, Protect);
    }

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to map section, status = 0x{:x}", status);
        return nullptr;
    }

    bblog::debug("section mapped, address = 0x{:x}", (uintptr_t)BaseAddress);
    return BaseAddress;
}

bool SectionUnmapView(PVOID BaseAddress, HANDLE ProcessHandle) {

    NTSTATUS status;

    if (ntdll.NtUnmapViewOfSectionEx) {
        status = ntdll.NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, 0);
    }
    else {
        status = ntdll.NtUnmapViewOfSection(ProcessHandle, BaseAddress);
    }

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to unmap section, status = 0x{:x}", status);
        return false;
    }

    bblog::debug("section unmapped");
    return true;
}

void HandleClose(HANDLE Handle) {

    NTSTATUS status = ntdll.NtClose(Handle);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to close handle (0x{:x}), status = 0x{:x}", (uintptr_t)Handle, status);
    }

    bblog::debug("handle closed");
}

HANDLE HandleDuplicate(HANDLE TargetProcessHandle, HANDLE SourceHandle, HANDLE SourceProcessHandle) {

    HANDLE TargetHandle;

    NTSTATUS status = ntdll.NtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, &TargetHandle, 0, 0, DUPLICATE_SAME_ACCESS);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to duplicate handle (0x{:x}), status = 0x{:x}", (uintptr_t)SourceHandle, status);
        return NULL;
    }

    bblog::debug("handle duplicated, HANDLE = 0x{:x}", (uintptr_t)TargetHandle);
    return TargetHandle;
}

PVOID VirtualMemoryAllocate(SIZE_T Size, ULONG Protect, HANDLE ProcessHandle, PVOID BaseAddress, ULONG AllocationType) {

    NTSTATUS status;

    if (ntdll.NtAllocateVirtualMemoryEx) {
        status = ntdll.NtAllocateVirtualMemoryEx(ProcessHandle, &BaseAddress, &Size, AllocationType, Protect, NULL, 0);
    }
    else {
        status = ntdll.NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &Size, AllocationType, Protect);
    }

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to allocate virtual memory (0x{:x} bytes), status = 0x{:x}", Size, status);
        return nullptr;
    }

    return BaseAddress;
}

bool VirtualMemoryProtect(PVOID BaseAddress, SIZE_T Size, ULONG& Protect, HANDLE ProcessHandle) {

    NTSTATUS status = ntdll.NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &Size, Protect, &Protect);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to protect virtual memory (0x{:x} bytes), status = 0x{:x}", Size, status);
        return false;
    }

    return true;
}

bool VirtualMemoryWrite(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle) {

    SIZE_T NumberOfBytesWritten;
    NTSTATUS status = ntdll.NtWriteVirtualMemory(ProcessHandle, BaseAddress, Data, Size, &NumberOfBytesWritten);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to write virtual memory (0x{:x} bytes), status = 0x{:x}", Size, status);
        return false;
    }

    return true;
}

size_t VirtualMemoryRead(PVOID Data, SIZE_T Size, PVOID BaseAddress, HANDLE ProcessHandle) {

    SIZE_T NumberOfBytesRead;

    NTSTATUS status;

    if (ntdll.NtReadVirtualMemoryEx) {
        status = ntdll.NtReadVirtualMemoryEx(ProcessHandle, BaseAddress, Data, Size, &NumberOfBytesRead, 0);
    }
    else {
        status = ntdll.NtReadVirtualMemory(ProcessHandle, BaseAddress, Data, Size, &NumberOfBytesRead);
    }

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to read virtual memory (0x{:x} bytes), status = 0x{:x}", Size, status);
        return 0;
    }

    return NumberOfBytesRead;
}

HANDLE TransactionCreate(const wchar_t *path) {

    auto nt_path = L"\\??\\" + std::wstring(path);

    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, nt_path.c_str());

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hTransaction;

    NTSTATUS status = ntdll.NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &ObjectAttributes, NULL, NULL, 0, 0, 0, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error(L"unable to create transaction ({}), status = 0x{:x}", path, status);
        return NULL;
    }

    return hTransaction;
}

bool TransactionRollback(HANDLE hTransaction) {

    NTSTATUS status = ntdll.NtRollbackTransaction(hTransaction, TRUE);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to rollback transaction (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)hTransaction, status);
        return false;
    }

    return true;
}

bool TransactionSet(HANDLE hTransaction) {

    auto res = ntdll.RtlSetCurrentTransaction(hTransaction);

    if (!res) {
        bblog::error("unable to set current transaction (HANDLE = 0x{:x})", (uintptr_t)hTransaction);
        return false;
    }

    return true;
}

bool ThreadQueueUserApc(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3) {

    NTSTATUS status = ntdll.NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    if (!NT_SUCCESS(status)) {
        bblog::error("unable to queue user APC (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)ThreadHandle, status);
        return false;
    }

    bblog::debug("user APC queued, HANDLE = 0x{:x}", (uintptr_t)ThreadHandle);
    return true;
}

HANDLE EventCreate() {

    HANDLE hEvent;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    NTSTATUS status = ntdll.NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, &ObjectAttributes, NotificationEvent, FALSE);
    if (!NT_SUCCESS(status)) {
        bblog::error("unable to create event, status = 0x{:x}", status);
        return NULL;
    }

    return hEvent;
}

HANDLE FileOpen(const wchar_t *path) {

    auto nt_path = L"\\??\\" + std::wstring(path);

    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, nt_path.c_str());

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatus = {};

    HANDLE hFile;

    NTSTATUS status = ntdll.NtCreateFile(
        &hFile, FILE_GENERIC_READ, &ObjectAttributes, &IoStatus, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0
    );

    if (!NT_SUCCESS(status)) {
        bblog::error(L"unable to open file ({}), status = 0x{:x}", path, status);
        return NULL;
    }

    return hFile;
}

HANDLE FileCreate(const wchar_t *path, ACCESS_MASK DesiredAccess, ULONG ShareAccess, size_t Size) {

    auto nt_path = L"\\??\\" + std::wstring(path);

    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, nt_path.c_str());

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatus = {};

    HANDLE hFile;

    LARGE_INTEGER AllocationSize{ .QuadPart = (LONGLONG)Size };

    NTSTATUS status = ntdll.NtCreateFile(
        &hFile, DesiredAccess, &ObjectAttributes, &IoStatus, &AllocationSize,
        FILE_ATTRIBUTE_NORMAL, ShareAccess, FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0
    );

    if (!NT_SUCCESS(status)) {
        bblog::error(L"unable to create file ({}), status = 0x{:x}", path, status);
        return NULL;
    }

    return hFile;
}

bool FileWrite(HANDLE FileHandle, PVOID Data, SIZE_T Size) {

    IO_STATUS_BLOCK IoStatus = {};

    NTSTATUS status = ntdll.NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatus, Data, (ULONG)Size, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to write file (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)FileHandle, status);
        return false;
    }

    return IoStatus.Information == Size;
}

size_t FileGetSize(HANDLE FileHandle) {

    IO_STATUS_BLOCK IoStatus = {};

    FILE_STANDARD_INFORMATION FileInformation;
    NTSTATUS status = ntdll.NtQueryInformationFile(FileHandle, &IoStatus, &FileInformation, sizeof(FileInformation), FileStandardInformation);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to get basic file information (HANDLE = 0x{:x}), status = 0x{:x}", (uintptr_t)FileHandle, status);
        return 0;
    }

    return (size_t)FileInformation.EndOfFile.QuadPart;
}

bool AdjustPrivilege(ULONG Privilege) {

    BOOLEAN WasEnabled = FALSE;
    NTSTATUS status = ntdll.RtlAdjustPrivilege(Privilege, TRUE, FALSE, &WasEnabled);
    if (!NT_SUCCESS(status)) {
        bblog::error("unable to adjust debug privilege, status = 0x{:x}", status);
        return false;
    }

    if (!WasEnabled) {
        bblog::info("debug privilege adjusted");
    }

    return true;
}

bool DumpLiveSystem(HANDLE FileHandle) {

    if (!AdjustPrivilege(SE_DEBUG_PRIVILEGE)) {
        return false;
    }

    SYSDBG_LIVEDUMP_CONTROL LiveDumpControl = { 0 };
    LiveDumpControl.Version = 1;
    LiveDumpControl.BugCheckCode = 0x161;
    LiveDumpControl.DumpFileHandle = FileHandle;

    LiveDumpControl.Flags.CompressMemoryPagesData = 1;
    LiveDumpControl.Flags.IncludeUserSpaceMemoryPages = 1;

    NTSTATUS status = ntdll.NtSystemDebugControl(SysDbgGetLiveKernelDump, &LiveDumpControl, offsetof(SYSDBG_LIVEDUMP_CONTROL, SelectiveControl), NULL, 0, NULL);

    if (!NT_SUCCESS(status)) {
        bblog::error("unable to get live system dump, status = 0x{:x}", status);
        if (status == STATUS_DEBUGGER_INACTIVE) {
            bblog::warn("the system is probably virtualized");
        }
        return false;
    }

    return true;
}


HMODULE LoadLibraryCopyW(const wchar_t *ModulePath) {

    std::wstring TempModulePath = {
        GetPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer,
        GetPeb()->ProcessParameters->CurrentDirectory.DosPath.Length / sizeof(wchar_t)
    };

    std::wstring ModuleName = ModulePath;
    ModuleName.erase(ModuleName.begin(), ModuleName.begin() + ModuleName.rfind('\\') + 1);

    TempModulePath += ModuleName;

    {
        auto module_mapping = fs::map_file(ModulePath);
        if (module_mapping.handle == NULL) {
            return NULL;
        }

        sysapi::unique_handle ModuleCopyHandle = sysapi::FileCreate(TempModulePath.c_str(), FILE_GENERIC_READ | FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, module_mapping.size);
        if (ModuleCopyHandle == nullptr) {
            return NULL;
        }

        sysapi::unique_handle ModuleCopySectionHandle = SectionFileCreate(ModuleCopyHandle.get(), SECTION_ALL_ACCESS, PAGE_READWRITE, false, module_mapping.size);
        if (ModuleCopySectionHandle == NULL) {
            return NULL;
        }

        PVOID ModuleCopyImage = SectionMapView(ModuleCopySectionHandle.get(), module_mapping.size, PAGE_READWRITE);
        if (ModuleCopyImage == nullptr) {
            return NULL;
        }

        memcpy(ModuleCopyImage, module_mapping.data, module_mapping.size);
        SectionUnmapView(module_mapping.data);
        SectionUnmapView(ModuleCopyImage);
    }

    return LoadLibraryW(TempModulePath.c_str());
}

} // namespace sysapi
