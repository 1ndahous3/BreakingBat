#include <cstdio>
#include <cstdint>
#include <cassert>

#include "ntapi.h"
#include "sysapi.h"

#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")

HMODULE hNtdll = GetModuleHandleA("ntdll");;

sysapi::options_t sysapi_opts;

namespace sysapi {

uint32_t FindProcess(const wchar_t *name) {

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

HANDLE OpenProcess(uint32_t pid, ACCESS_MASK AccessMask) {

    HANDLE ProcessHandle = 0;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID Cid{ .UniqueProcess = ULongToHandle(pid), .UniqueThread = 0 };
    NTSTATUS status = NtOpenProcess(&ProcessHandle, AccessMask, &ObjectAttributes, &Cid);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to open process (PID = %d), status = 0x%x\n", pid, status);
        return NULL;
    }

    wprintf(L"[+] process (PID = %d) opened, HANDLE = 0x%p\n", pid, ProcessHandle);
    return ProcessHandle;
}

HANDLE CreateThread(HANDLE ProcessHandle, PVOID StartAddress) {

    HANDLE ThreadHandle;

    NTSTATUS status = RtlCreateUserThread(ProcessHandle, NULL, FALSE, 0, 0, 0, StartAddress, NULL, &ThreadHandle, NULL);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to create process thread (HANDLE = 0x%p), status = 0x%x\n", ProcessHandle, status);
        return NULL;
    }

    wprintf(L"[+] thread created, HANDLE = 0x%p\n", ThreadHandle);
    return ThreadHandle;
}

HANDLE CreateSection(size_t Size) {

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

PVOID MapViewOfSection(HANDLE SectionHandle, SIZE_T Size, ULONG Win32Protect, HANDLE ProcessHandle) {

    PVOID BaseAddress = nullptr;

    NTSTATUS status;

    if (sysapi_opts.ntdll_ex) {

        assert(hNtdll != NULL);
        static auto NtMapViewOfSectionEx = (_NtMapViewOfSectionEx)GetProcAddress(hNtdll, "NtMapViewOfSectionEx");
        status = NtMapViewOfSectionEx(SectionHandle, ProcessHandle, &BaseAddress, NULL, &Size, 0, Win32Protect, NULL, 0);

        if (NtMapViewOfSectionEx == nullptr) {
            wprintf(L"[-] unable to get address of \"%hs\" from ntdll.dll", "NtMapViewOfSectionEx");
            return nullptr;
        }
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

bool UnmapViewOfSection(PVOID BaseAddress, HANDLE ProcessHandle) {

    NTSTATUS status;

    if (sysapi_opts.ntdll_ex) {
        assert(hNtdll != NULL);
        static auto NtUnmapViewOfSectionEx = (_NtUnmapViewOfSectionEx)GetProcAddress(hNtdll, "NtUnmapViewOfSectionEx");
        status = NtUnmapViewOfSectionEx(ProcessHandle, BaseAddress, 0);

        if (NtUnmapViewOfSectionEx == nullptr) {
            wprintf(L"[-] unable to get address of \"%hs\" from ntdll.dll", "NtUnmapViewOfSectionEx");
            return false;
        }

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

bool CloseHandle(HANDLE Handle) {

    NTSTATUS status = NtClose(Handle);

    if (!NT_SUCCESS(status)) {
        wprintf(L"[-] unable to close handle (0x%p), status = 0x%x\n", Handle, status);
        return false;
    }

    //wprintf(L"[+] handle closed\n");
    return true;
}

}