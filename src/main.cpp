#include <cstdio>
#include <string>
#include <fcntl.h>
#include <io.h>

#include "SimpleOpt.h"

#include "sysapi.h"
#include "scripts/scripts.h"

enum {
    OPT_HELP,
    // optional options
    OPT_NT_EX_FUNCS,
    // scripts
    OPT_INJECT_CREATE_REMOTE_THREAD,
    OPT_INJECT_CREATE_HOLLOWED_PROCESS,
    // script options
    OPT_PROCESS,
    OPT_ORIGINAL_IMAGE,
    OPT_INJECTED_IMAGE,
    OPT_PROCESS_MEMORY_INIT
};

CSimpleOptW::SOption g_cli_opts[] = {
    { OPT_HELP, L"-?",     SO_NONE },
    { OPT_HELP, L"--help", SO_NONE },
    // optional options
    { OPT_NT_EX_FUNCS,   L"--nt-ex-functions", SO_NONE },
    // scripts
    { OPT_INJECT_CREATE_REMOTE_THREAD,    L"inject_create_remote_thread",    SO_NONE },
    { OPT_INJECT_CREATE_HOLLOWED_PROCESS, L"inject_create_hollowed_process", SO_NONE },
    // script options
    { OPT_PROCESS,             L"--process",             SO_REQ_SEP},
    { OPT_ORIGINAL_IMAGE,      L"--original-image",      SO_REQ_SEP},
    { OPT_INJECTED_IMAGE,      L"--injected-image",      SO_REQ_SEP},
    { OPT_PROCESS_MEMORY_INIT, L"--process-memory-init", SO_REQ_SEP},
    SO_END_OF_OPTIONS
};

void print_usage(wchar_t *binary) {
    wprintf(L"Usage: %s <script> <script_options>\n", binary);
    wprintf(L"\n");
    wprintf(L"Global options:\n");
    wprintf(L"  --nt-ex-functions (use Ex versions of NT functions, if available)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"    1 - allocate memory in remote process and write via virtual memory routines\n");
    wprintf(L"    2 - create new section, map view for remote process and write via virtual memory routines\n");
    wprintf(L"    3 - create new section, map view for remote and local processes and write directly\n");
    wprintf(L"\n");
    wprintf(L"Scripts:\n");

    wprintf(L"inject_create_remote_thread:\n");
    wprintf(L"  --process (PID or process name)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"inject_create_hollowed_process:\n");
    wprintf(L"  --original-image (filepath)\n");
    wprintf(L"  --injected-image (filepath)\n");
    wprintf(L"  --process-memory-init <method>\n");
    wprintf(L"\n");
}

bool process_args_inject_create_remote_thread(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via RtlCreateUserThread()\n");

    sysapi::options_t opts;
    std::wstring process;

    uint8_t method = 0;

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

        case OPT_NT_EX_FUNCS:
            opts.ntdll_ex = true;
            break;

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > 3) {
                print_usage(binary);
                return false;
            }

            method = (uint8_t)m;
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (process.empty() || method == 0) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Process: %s\n", process.c_str());
    wprintf(L"|   Remote process memory method: %lu\n", method);
    wprintf(L"|   Use NT Extended API: %hs\n", opts.ntdll_ex ? "true" : "false");
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
    return scripts::inject_create_remote_thread(pid, (scripts::RemoteProcessMemoryMethod)(method - 1));
}


bool process_args_inject_create_hollowed_process(wchar_t *binary, CSimpleOptW& args) {

    wprintf(L"| Script: Inject via process hollowing\n");

    sysapi::options_t opts;
    std::wstring original_image, injected_image;

    uint8_t method = 0;

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

        case OPT_NT_EX_FUNCS:
            opts.ntdll_ex = true;
            break;

        case OPT_PROCESS_MEMORY_INIT: {

            wchar_t* end;
            uint32_t m = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE || m == 0 || m > 3) {
                print_usage(binary);
                return false;
            }

            method = (uint8_t)m;
            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (original_image.empty() || injected_image.empty() || method == 0) {
        print_usage(binary);
        return false;
    }

    wprintf(L"| Options:\n");
    wprintf(L"|   Original image: %s\n", original_image.c_str());
    wprintf(L"|   Injected image: %s\n", injected_image.c_str());
    wprintf(L"|   Remote process memory method: %lu\n", method);
    wprintf(L"|   Use NT Extended API: %hs\n", opts.ntdll_ex ? "true" : "false");
    wprintf(L"\n");

    sysapi::init(opts);
    return scripts::inject_create_process_hollowed(original_image, injected_image, (scripts::RemoteProcessMemoryMethod)(method - 1));
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

    if (!args.Next() || args.LastError() != SO_SUCCESS){
        print_usage(argv[0]);
        return -1;
    }

    switch (args.OptionId()) {

    case OPT_HELP:
        print_usage(argv[0]);
        return 0;

    case OPT_INJECT_CREATE_REMOTE_THREAD:
        if (!process_args_inject_create_remote_thread(argv[0], args)) {
            return -1;
        }

        return 0;

    case OPT_INJECT_CREATE_HOLLOWED_PROCESS:
        if (!process_args_inject_create_hollowed_process(argv[0], args)) {
            return -1;
        }

        return 0;

    default:
        print_usage(argv[0]);
        return -1;
    }
}