#include <cstdio>
#include <string>
#include <fcntl.h>
#include <io.h>

#include <sstream>
#include <fstream>

#include "SimpleOpt.h"

#include "python_core.h"
#include "logging.h"

enum {
    OPT_HELP,
    OPT_SCRIPT
};

CSimpleOptW::SOption g_cli_opts[] = {
    { OPT_HELP,   L"-?",       SO_NONE    },
    { OPT_HELP,   L"--help",   SO_NONE    },
    { OPT_SCRIPT, L"--script", SO_REQ_SEP },
    SO_END_OF_OPTIONS
};

void print_usage(wchar_t *binary) {
    wprintf(L"Usage: %s --script <script_path>\n", binary);
    wprintf(L"\n");
}

int wmain(int argc, wchar_t *argv[]) {

    _setmode(_fileno(stdout), _O_U16TEXT);

    bblog::set_pattern("[%^%l%$] %v");

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

    case OPT_SCRIPT: {

        auto script_path = args.OptionArg();

        std::ifstream ifs(script_path);
        if (!ifs) {
            wprintf(L"[error] unable to open script: %s\n", script_path);
            return -1;
        }

        std::ostringstream oss;
        oss << ifs.rdbuf();
        auto script_data = oss.str();

        python::initialize();
        python::execute_script(script_data);
        python::finalize();

        return 0;
    }

    default:
        print_usage(argv[0]);
        return -1;
    }
}
