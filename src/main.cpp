#include <cstdio>

#include <string>

#include "sysapi.h"

extern sysapi::options_t sysapi_opts;

#include <fcntl.h>
#include <io.h>

#include "SimpleOpt.h"

#include <scripts/scripts.h>

enum {
    OPT_HELP,
    // scripts
    OPT_INJECT_CREATE_REMOTE_THREAD,
    OPT_INJECT_CREATE_HOLLOWED_PROCESS,
    // script options
    OPT_PROCESS,
    OPT_ORIGINAL_IMAGE,
    OPT_INJECTED_IMAGE
};

CSimpleOptW::SOption g_cli_opts[] = {
    { OPT_HELP,   L"-?",       SO_NONE },
    { OPT_HELP,   L"--help",   SO_NONE },
    // scripts
    { OPT_INJECT_CREATE_REMOTE_THREAD, L"inject_create_remote_thread", SO_NONE },
    { OPT_INJECT_CREATE_HOLLOWED_PROCESS, L"inject_create_hollowed_process", SO_NONE },
    // script options
    { OPT_PROCESS, L"--process",               SO_REQ_SEP},
    { OPT_ORIGINAL_IMAGE, L"--original_image", SO_REQ_SEP},
    { OPT_INJECTED_IMAGE, L"--injected_image", SO_REQ_SEP},
    SO_END_OF_OPTIONS
};

void print_usage(wchar_t *binary) {
    wprintf(L"Usage: %s <script> <script_options>\n", binary);
    wprintf(L"\n");
    wprintf(L"Scripts:\n");
    wprintf(L"  inject_create_remote_thread: pid | process_name\n");
    wprintf(L"  inject_create_hollowed_process: original_image injected_image\n");
    wprintf(L"\n");
}

bool process_args_inject_create_remote_thread(wchar_t *binary, CSimpleOptW& args) {

    uint32_t pid = 0;

    while (args.Next()) {

        if (args.LastError() != SO_SUCCESS) {
            print_usage(binary);
            return false;
        }

        switch (args.OptionId()) {

        case OPT_PROCESS: {

            wchar_t* end;
            pid = wcstoul(args.OptionArg(), &end, 10);
            if (errno == ERANGE) {
                print_usage(binary);
                return false;
            }

            if (pid == 0) {
                pid = sysapi::ProcessFind(args.OptionArg());
            }

            if (pid == 0) {
                return false;
            }

            break;
        }

        default:
            print_usage(binary);
            return false;
        }
    }

    if (pid == 0) {
        print_usage(binary);
        return false;
    }

    wprintf(L"[Inject via RtlCreateUserThread()]\n\n");
    return scripts::inject_create_remote_thread(pid);
}


bool process_args_inject_create_hollowed_process(wchar_t *binary, CSimpleOptW& args) {

    std::wstring original_image, injected_image;

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


        default:
            print_usage(binary);
            return false;
        }
    }

    if (original_image.empty() || injected_image.empty()) {
        print_usage(binary);
        return false;
    }

    wprintf(L"[Inject via process hollowing]\n\n");
    return scripts::inject_create_process_hollowed(original_image, injected_image);
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


    sysapi_opts.ntdll_ex = true;

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