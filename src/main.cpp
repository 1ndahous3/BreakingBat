﻿#include <cstdio>
#include <string>
#include <fcntl.h>
#include <io.h>

#include "SimpleOpt.h"

#include "sysapi.h"
#include "scripts/scripts.h"

enum {
    OPT_HELP,
    // optional options
    OPT_NTDLL_LOAD_COPY,
    OPT_NTDLL_ALTERNATIVE_API,
    // scripts
    OPT_INJECT_HIJACK_REMOTE_THREAD,
    OPT_INJECT_CREATE_REMOTE_THREAD,
    OPT_INJECT_CREATE_HOLLOW_PROCESS,
    OPT_INJECT_CREATE_DOPPEL_PROCESS,
    OPT_INJECT_QUEUE_APC,
    OPT_INJECT_QUEUE_APC_EARLY_BIRD,
    OPT_INJECT_COM_IRUNDOWN_DOCALLBACK,
    OPT_EXECUTE_ROP_GADGET_LOCAL,
    // script options
    OPT_PROCESS,
    OPT_THREAD,
    OPT_ORIGINAL_IMAGE,
    OPT_INJECTED_IMAGE,
    OPT_PROCESS_OPEN,
    OPT_PROCESS_MEMORY_INIT
};

CSimpleOptW::SOption g_cli_opts[] = {
    { OPT_HELP, L"-?",     SO_NONE },
    { OPT_HELP, L"--help", SO_NONE },
    // optional options
    { OPT_NTDLL_LOAD_COPY,        L"--ntdll-load-copy",       SO_NONE },
    { OPT_NTDLL_ALTERNATIVE_API,  L"--ntdll-alternative-api", SO_NONE },
    // scripts
    { OPT_INJECT_HIJACK_REMOTE_THREAD,    L"inject_hijack_remote_thread",    SO_NONE },
    { OPT_INJECT_CREATE_REMOTE_THREAD,    L"inject_create_remote_thread",    SO_NONE },
    { OPT_INJECT_CREATE_HOLLOW_PROCESS,   L"inject_create_hollow_process",   SO_NONE },
    { OPT_INJECT_CREATE_DOPPEL_PROCESS,   L"inject_create_doppel_process",   SO_NONE },
    { OPT_INJECT_QUEUE_APC,               L"inject_queue_apc",               SO_NONE },
    { OPT_INJECT_QUEUE_APC_EARLY_BIRD,    L"inject_queue_apc_early_bird",    SO_NONE },
    { OPT_INJECT_COM_IRUNDOWN_DOCALLBACK, L"inject_com_irundown_docallback", SO_NONE },
    { OPT_EXECUTE_ROP_GADGET_LOCAL,       L"execute_rop_gadget_local",       SO_NONE },
    // script options
    { OPT_PROCESS,             L"--process",             SO_REQ_SEP},
    { OPT_THREAD,              L"--thread",              SO_REQ_SEP},
    { OPT_ORIGINAL_IMAGE,      L"--original-image",      SO_REQ_SEP},
    { OPT_INJECTED_IMAGE,      L"--injected-image",      SO_REQ_SEP},
    { OPT_PROCESS_OPEN,        L"--process-open",        SO_REQ_SEP},
    { OPT_PROCESS_MEMORY_INIT, L"--process-memory-init", SO_REQ_SEP},
    SO_END_OF_OPTIONS
};

void print_usage(wchar_t *binary) {
    wprintf(L"Usage: %s <script> <script_options>\n", binary);
    wprintf(L"\n");
    wprintf(L"Global options:\n");
    wprintf(L"  --ntdll-load-copy (load and use copy of ntdll.dll)\n");
    wprintf(L"  --ntdll-alternative-api (use alternative versions of some NT functions, if available)\n");
    wprintf(L"  --process-memory-init <method> (default: 1)\n");
    wprintf(L"    1 - %hs\n", scripts::decode(scripts::RemoteProcessMemoryMethod::AllocateInAddr));
    wprintf(L"    2 - %hs\n", scripts::decode(scripts::RemoteProcessMemoryMethod::CreateSectionMap));
    wprintf(L"    3 - %hs\n", scripts::decode(scripts::RemoteProcessMemoryMethod::CreateSectionMapLocalMap));
    wprintf(L"  --process-open <method> (default: 1)\n");
    wprintf(L"    1 - %hs\n", scripts::decode(scripts::RemoteProcessOpenMethod::OpenProcess));
    wprintf(L"    2 - %hs\n", scripts::decode(scripts::RemoteProcessOpenMethod::OpenProcessByHwnd));
    wprintf(L"\n");
    wprintf(L"Scripts:\n");

    wprintf(L"inject_hijack_remote_thread\n");
    wprintf(L"  --process (PID or process name)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"inject_create_remote_thread\n");
    wprintf(L"  --process (PID or process name)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"inject_create_hollow_process\n");
    wprintf(L"  --original-image (filepath)\n");
    wprintf(L"  --injected-image (filepath)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"inject_create_doppel_process\n");
    wprintf(L"  --original-image (filepath)\n");
    wprintf(L"  --injected-image (filepath)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"inject_queue_apc\n");
    wprintf(L"  --process (PID or process name)\n");
    wprintf(L"  --thread (TID), optional\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"inject_queue_apc_early_bird\n");
    wprintf(L"  --original-image (filepath)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"inject_com_irundown_docallback\n");
    wprintf(L"  --process (PID or process name)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"execute_rop_gadget_local\n");
    wprintf(L"\n");
}

bool process_args_inject_hijack_remote_thread(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via hijack remote thread\n");

    sysapi::options_t opts;
    std::wstring process;

    auto open_method = scripts::RemoteProcessOpenMethod::OpenProcess;
    auto memory_method = scripts::RemoteProcessMemoryMethod::AllocateInAddr;

    while (args.Next()) {

        if (args.LastError() != SO_SUCCESS) {
            print_usage(binary);
            return false;
        }

        switch (args.OptionId()) {

        case OPT_PROCESS: {
            process = args.OptionArg();
            break;
        }

        case OPT_NTDLL_LOAD_COPY:
            opts.ntdll_copy = true;
            break;

        case OPT_NTDLL_ALTERNATIVE_API:
            opts.ntdll_alt_api = true;
            break;

        case OPT_PROCESS_OPEN: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessOpenMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            open_method = (scripts::RemoteProcessOpenMethod)(m - 1);
            break;
        }

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessMemoryMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            memory_method = (scripts::RemoteProcessMemoryMethod)(m - 1);
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (process.empty() ||
        open_method > scripts::RemoteProcessOpenMethod::MaxValue ||
        memory_method > scripts::RemoteProcessMemoryMethod::MaxValue) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Process: %s\n", process.c_str());
    wprintf(L"|   Remote process open method: %lu (%hs)\n", (uint32_t)open_method + 1, scripts::decode(open_method));
    wprintf(L"|   Remote process memory method: %lu (%hs)\n", (uint32_t)memory_method + 1, scripts::decode(memory_method));
    wprintf(L"|   Load and use copy of ntdll.dll: %hs\n", opts.ntdll_copy ? "true" : "false");
    wprintf(L"|   Use NT alternative API: %hs\n", opts.ntdll_alt_api ? "true" : "false");
    wprintf(L"\n");

    uint32_t pid = 0;

    {
        wchar_t* end;
        pid = wcstoul(process.c_str(), &end, 10);
        if (errno == ERANGE) {
            wprintf(L"  [-] invalid PID\n");
            return false;
        }

        if (pid == 0) {
            pid = sysapi::ProcessFind(process.c_str());
        }

        if (pid == 0) {
            wprintf(L"  [-] unable to find process\n");
            return false;
        }
    }

    sysapi::init(opts);
    return scripts::inject_hijack_remote_thread(pid, open_method, memory_method);
}


bool process_args_inject_create_remote_thread(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via NtCreateThread()\n");

    sysapi::options_t opts;
    std::wstring process;

    auto open_method = scripts::RemoteProcessOpenMethod::OpenProcess;
    auto memory_method = scripts::RemoteProcessMemoryMethod::AllocateInAddr;

    while (args.Next()) {

        if (args.LastError() != SO_SUCCESS) {
            print_usage(binary);
            return false;
        }

        switch (args.OptionId()) {

        case OPT_PROCESS: {
            process = args.OptionArg();
            break;
        }

        case OPT_NTDLL_LOAD_COPY:
            opts.ntdll_copy = true;
            break;

        case OPT_NTDLL_ALTERNATIVE_API:
            opts.ntdll_alt_api = true;
            break;

        case OPT_PROCESS_OPEN: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessOpenMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            open_method = (scripts::RemoteProcessOpenMethod)(m - 1);
            break;
        }

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessMemoryMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            memory_method = (scripts::RemoteProcessMemoryMethod)(m - 1);
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (process.empty() ||
        open_method > scripts::RemoteProcessOpenMethod::MaxValue ||
        memory_method > scripts::RemoteProcessMemoryMethod::MaxValue) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Process: %s\n", process.c_str());
    wprintf(L"|   Remote process open method: %lu (%hs)\n", (uint32_t)open_method + 1, scripts::decode(open_method));
    wprintf(L"|   Remote process memory method: %lu (%hs)\n", (uint32_t)memory_method + 1, scripts::decode(memory_method));
    wprintf(L"|   Load and use copy of ntdll.dll: %hs\n", opts.ntdll_copy ? "true" : "false");
    wprintf(L"|   Use NT alternative API: %hs\n", opts.ntdll_alt_api ? "true" : "false");
    wprintf(L"\n");

    uint32_t pid = 0;

    {
        wchar_t* end;
        pid = wcstoul(process.c_str(), &end, 10);
        if (errno == ERANGE) {
            wprintf(L"  [-] invalid PID\n");
            return false;
        }

        if (pid == 0) {
            pid = sysapi::ProcessFind(process.c_str());
        }

        if (pid == 0) {
            wprintf(L"  [-] unable to find process\n");
            return false;
        }
    }

    sysapi::init(opts);
    return scripts::inject_create_remote_thread(pid, open_method, memory_method);
}


bool process_args_inject_create_hollow_process(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via process hollowing\n");

    sysapi::options_t opts;
    std::wstring original_image, injected_image;

    auto memory_method = scripts::RemoteProcessMemoryMethod::AllocateInAddr;

    while (args.Next()) {

        if (args.LastError() != SO_SUCCESS) {
            print_usage(binary);
            return false;
        }

        switch (args.OptionId()) {

        case OPT_ORIGINAL_IMAGE:
            original_image = args.OptionArg();
            break;

        case OPT_INJECTED_IMAGE:
            injected_image = args.OptionArg();
            break;

        case OPT_NTDLL_LOAD_COPY:
            opts.ntdll_copy = true;
            break;

        case OPT_NTDLL_ALTERNATIVE_API:
            opts.ntdll_alt_api = true;
            break;

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessMemoryMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            memory_method = (scripts::RemoteProcessMemoryMethod)(m - 1);
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (original_image.empty() ||
        injected_image.empty() ||
        memory_method > scripts::RemoteProcessMemoryMethod::MaxValue) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Original image: %s\n", original_image.c_str());
    wprintf(L"|   Injected image: %s\n", injected_image.c_str());
    wprintf(L"|   Remote process memory method: %lu (%hs)\n", (uint32_t)memory_method + 1, scripts::decode(memory_method));
    wprintf(L"|   Load and use copy of ntdll.dll: %hs\n", opts.ntdll_copy ? "true" : "false");
    wprintf(L"|   Use NT alternative API: %hs\n", opts.ntdll_alt_api ? "true" : "false");
    wprintf(L"\n");

    sysapi::init(opts);
    return scripts::inject_create_process_hollow(original_image, injected_image, memory_method);
}


bool process_args_inject_create_doppel_process(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via process doppelganging\n");

    sysapi::options_t opts;
    std::wstring original_image, injected_image;

    auto memory_method = scripts::RemoteProcessMemoryMethod::AllocateInAddr;

    while (args.Next()) {

        if (args.LastError() != SO_SUCCESS) {
            print_usage(binary);
            return false;
        }

        switch (args.OptionId()) {

        case OPT_ORIGINAL_IMAGE:
            original_image = args.OptionArg();
            break;

        case OPT_INJECTED_IMAGE:
            injected_image = args.OptionArg();
            break;

        case OPT_NTDLL_LOAD_COPY:
            opts.ntdll_copy = true;
            break;

        case OPT_NTDLL_ALTERNATIVE_API:
            opts.ntdll_alt_api = true;
            break;

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessMemoryMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            memory_method = (scripts::RemoteProcessMemoryMethod)(m - 1);
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (original_image.empty() ||
        injected_image.empty() ||
        memory_method > scripts::RemoteProcessMemoryMethod::MaxValue) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Original image: %s\n", original_image.c_str());
    wprintf(L"|   Injected image: %s\n", injected_image.c_str());
    wprintf(L"|   Remote process memory method: %lu (%hs)\n", (uint32_t)memory_method + 1, scripts::decode(memory_method));
    wprintf(L"|   Load and use copy of ntdll.dll: %hs\n", opts.ntdll_copy ? "true" : "false");
    wprintf(L"|   Use NT alternative API: %hs\n", opts.ntdll_alt_api ? "true" : "false");
    wprintf(L"\n");

    sysapi::init(opts);
    return scripts::inject_create_process_doppel(original_image, injected_image, memory_method);
}


bool process_args_inject_queue_apc(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via queue user APC\n");

    sysapi::options_t opts;
    std::wstring process;
    std::wstring thread;

    auto open_method = scripts::RemoteProcessOpenMethod::OpenProcess;
    auto memory_method = scripts::RemoteProcessMemoryMethod::AllocateInAddr;

    while (args.Next()) {

        if (args.LastError() != SO_SUCCESS) {
            print_usage(binary);
            return false;
        }

        switch (args.OptionId()) {

        case OPT_PROCESS: {
            process = args.OptionArg();
            break;
        }

        case OPT_THREAD: {
            thread = args.OptionArg();
            break;
        }

        case OPT_NTDLL_LOAD_COPY:
            opts.ntdll_copy = true;
            break;

        case OPT_NTDLL_ALTERNATIVE_API:
            opts.ntdll_alt_api = true;
            break;

        case OPT_PROCESS_OPEN: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessOpenMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            open_method = (scripts::RemoteProcessOpenMethod)(m - 1);
            break;
        }

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessMemoryMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            memory_method = (scripts::RemoteProcessMemoryMethod)(m - 1);
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (process.empty() ||
        open_method > scripts::RemoteProcessOpenMethod::MaxValue ||
        memory_method > scripts::RemoteProcessMemoryMethod::MaxValue) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Process: %s\n", process.c_str());
    wprintf(L"|   Threads: %s\n", thread.empty() ? L"all" : thread.c_str());
    wprintf(L"|   Remote process open method: %lu (%hs)\n", (uint32_t)open_method + 1, scripts::decode(open_method));
    wprintf(L"|   Remote process memory method: %lu (%hs)\n", (uint32_t)memory_method + 1, scripts::decode(memory_method));
    wprintf(L"|   Load and use copy of ntdll.dll: %hs\n", opts.ntdll_copy ? "true" : "false");
    wprintf(L"|   Use NT alternative API: %hs\n", opts.ntdll_alt_api ? "true" : "false");
    wprintf(L"\n");

    uint32_t pid = 0;

    {
        wchar_t* end;
        pid = wcstoul(process.c_str(), &end, 10);
        if (errno == ERANGE) {
            wprintf(L"  [-] invalid PID\n");
            return false;
        }

        if (pid == 0) {
            pid = sysapi::ProcessFind(process.c_str());
        }

        if (pid == 0) {
            wprintf(L"  [-] unable to find process\n");
            return false;
        }
    }

    uint32_t tid = 0;

    if (!thread.empty()) {

        wchar_t* end;
        tid = wcstoul(thread.c_str(), &end, 10);
        if (errno == ERANGE || tid == 0) {
            wprintf(L"  [-] invalid TID\n");
            return false;
        }
    }

    sysapi::init(opts);
    return scripts::inject_queue_apc(pid, tid, open_method, memory_method);
}


bool process_args_inject_queue_apc_early_bird(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via queue user APC (early bird)\n");

    sysapi::options_t opts;
    std::wstring original_image;

    auto memory_method = scripts::RemoteProcessMemoryMethod::AllocateInAddr;

    while (args.Next()) {

        if (args.LastError() != SO_SUCCESS) {
            print_usage(binary);
            return false;
        }

        switch (args.OptionId()) {

        case OPT_ORIGINAL_IMAGE:
            original_image = args.OptionArg();
            break;

        case OPT_NTDLL_LOAD_COPY:
            opts.ntdll_copy = true;
            break;

        case OPT_NTDLL_ALTERNATIVE_API:
            opts.ntdll_alt_api = true;
            break;

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessMemoryMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            memory_method = (scripts::RemoteProcessMemoryMethod)(m - 1);
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (memory_method > scripts::RemoteProcessMemoryMethod::MaxValue) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Original image: %s\n", original_image.c_str());
    wprintf(L"|   Remote process memory method: %lu (%hs)\n", (uint32_t)memory_method + 1, scripts::decode(memory_method));
    wprintf(L"|   Load and use copy of ntdll.dll: %hs\n", opts.ntdll_copy ? "true" : "false");
    wprintf(L"|   Use NT alternative API: %hs\n", opts.ntdll_alt_api ? "true" : "false");
    wprintf(L"\n");

    sysapi::init(opts);
    return scripts::inject_queue_apc_early_bird(original_image, memory_method);
}


bool process_args_inject_com_irundown_docallback(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via COM IRundown::DoCallback()\n");

    sysapi::options_t opts;
    std::wstring process;

    auto open_method = scripts::RemoteProcessOpenMethod::OpenProcess;
    auto memory_method = scripts::RemoteProcessMemoryMethod::AllocateInAddr;

    while (args.Next()) {

        if (args.LastError() != SO_SUCCESS) {
            print_usage(binary);
            return false;
        }

        switch (args.OptionId()) {

        case OPT_PROCESS: {
            process = args.OptionArg();
            break;
        }

        case OPT_NTDLL_LOAD_COPY:
            opts.ntdll_copy = true;
            break;

        case OPT_NTDLL_ALTERNATIVE_API:
            opts.ntdll_alt_api = true;
            break;

        case OPT_PROCESS_OPEN: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessOpenMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            open_method = (scripts::RemoteProcessOpenMethod)(m - 1);
            break;
        }

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > (uint32_t)scripts::RemoteProcessMemoryMethod::MaxValue + 1) {
                print_usage(binary);
                return false;
            }

            memory_method = (scripts::RemoteProcessMemoryMethod)(m - 1);
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (process.empty() ||
        open_method > scripts::RemoteProcessOpenMethod::MaxValue ||
        memory_method > scripts::RemoteProcessMemoryMethod::MaxValue) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Process: %s\n", process.c_str());
    wprintf(L"|   Remote process open method: %lu (%hs)\n", (uint32_t)open_method + 1, scripts::decode(open_method));
    wprintf(L"|   Remote process memory method: %lu (%hs)\n", (uint32_t)memory_method + 1, scripts::decode(memory_method));
    wprintf(L"|   Load and use copy of ntdll.dll: %hs\n", opts.ntdll_copy ? "true" : "false");
    wprintf(L"|   Use NT alternative API: %hs\n", opts.ntdll_alt_api ? "true" : "false");
    wprintf(L"\n");

    uint32_t pid = 0;

    {
        wchar_t* end;
        pid = wcstoul(process.c_str(), &end, 10);
        if (errno == ERANGE) {
            wprintf(L"  [-] invalid PID\n");
            return false;
        }

        if (pid == 0) {
            pid = sysapi::ProcessFind(process.c_str());
        }

        if (pid == 0) {
            wprintf(L"  [-] unable to find process\n");
            return false;
        }
    }

    sysapi::init(opts);
    return scripts::inject_com_irundown_docallback(pid, open_method, memory_method);
}

int wmain(int argc, wchar_t *argv[]) {

    _setmode(_fileno(stdout), _O_U16TEXT);

    wprintf(L"\n");
    wprintf(L" ╔═══════════════════════╗\n");
    wprintf(L" ║ BreakingBat tool v0.1 ║\n");
    wprintf(L" ╟───────────────────────╢\n");
    wprintf(L" ║      _   ,_,   _      ║\n");
    wprintf(L" ║     / `'=) (='` \\     ║\n");
    wprintf(L" ║    /.-.-.\\ /.-.-.\\    ║\n");
    wprintf(L" ║    `      \"      `    ║\n");
    wprintf(L" ╚═══════════════════════╝\n");
    wprintf(L"\n");

    if (argc == 1) {
        print_usage(argv[0]);
        return -1;
    }

    CSimpleOptW args(argc, argv, g_cli_opts);

    if (!args.Next() || args.LastError() != SO_SUCCESS) {
        print_usage(argv[0]);
        return -1;
    }

    switch (args.OptionId()) {

    case OPT_HELP:
        print_usage(argv[0]);
        return 0;

    case OPT_INJECT_HIJACK_REMOTE_THREAD:
        if (!process_args_inject_hijack_remote_thread(argv[0], args)) {
            return -1;
        }

        return 0;

    case OPT_INJECT_CREATE_REMOTE_THREAD:
        if (!process_args_inject_create_remote_thread(argv[0], args)) {
            return -1;
        }

        return 0;

    case OPT_INJECT_CREATE_HOLLOW_PROCESS:
        if (!process_args_inject_create_hollow_process(argv[0], args)) {
            return -1;
        }

        return 0;

    case OPT_INJECT_CREATE_DOPPEL_PROCESS:
        if (!process_args_inject_create_doppel_process(argv[0], args)) {
            return -1;
        }

        return 0;

    case OPT_INJECT_QUEUE_APC:
        if (!process_args_inject_queue_apc(argv[0], args)) {
            return -1;
        }

        return 0;

    case OPT_INJECT_QUEUE_APC_EARLY_BIRD:
        if (!process_args_inject_queue_apc_early_bird(argv[0], args)) {
            return -1;
        }

        return 0;

    case OPT_INJECT_COM_IRUNDOWN_DOCALLBACK:
        if (!process_args_inject_com_irundown_docallback(argv[0], args)) {
            return -1;
        }

        return 0;

    case OPT_EXECUTE_ROP_GADGET_LOCAL: {
        sysapi::options_t opts;
        sysapi::init(opts);
        scripts::execute_rop_gadget_local();
        return 0;
    }

    default:
        print_usage(argv[0]);
        return -1;
    }
}