#include "python_core.h"

#include "sysapi.h"
#include "common.h"
#include "logging.h"
#include "magic_enum.hpp"

#include "python_modules.h"

extern script_context_t *script_context;

static PyObject *py_init_sysapi(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "ntdll_alt_api", "ntdll_load_copy", NULL };

    int ntdll_alt_api = 0;
    int ntdll_copy = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "|O&O&", (char **)kwlist,
            PyObject_IsTrue, &ntdll_alt_api,
            PyObject_IsTrue, &ntdll_copy
        )) {
        return NULL;
    }

    bblog::info("| System API options:");
    bblog::info("|   Load and use copy of ntdll.dll: {}", ntdll_copy ? "true" : "false");
    bblog::info("|   Use NT alternative API: {}", ntdll_alt_api ? "true" : "false");
    bblog::info("");

    sysapi::init(sysapi::options_t{
        .ntdll_copy = ntdll_copy != 0,
        .ntdll_alt_api = ntdll_alt_api != 0,
    });

    Py_RETURN_NONE;
}

static PyMethodDef module_methods[] = {
    { "init_sysapi",                    (PyCFunction)py_init_sysapi,                    METH_VARARGS | METH_KEYWORDS, "Initial method to init system API"      },
    { "script_success",                 (PyCFunction)py_script_success,                 METH_VARARGS | METH_KEYWORDS, "Set script success result"              },
    { "set_default_options",            (PyCFunction)py_set_default_options,            METH_VARARGS | METH_KEYWORDS, "Set default options for future calls"   },
    { "inject_queue_apc",               (PyCFunction)py_inject_queue_apc,               METH_VARARGS | METH_KEYWORDS, "inject_queue_apc"                       },
    { "inject_queue_apc_early_bird",    (PyCFunction)py_inject_queue_apc_early_bird,    METH_VARARGS | METH_KEYWORDS, "inject_queue_apc_early_bird"            },
    { "inject_create_process_hollow",   (PyCFunction)py_inject_create_process_hollow,   METH_VARARGS | METH_KEYWORDS, "inject_create_process_hollow"           },
    { "inject_create_process_doppel",   (PyCFunction)py_inject_create_process_doppel,   METH_VARARGS | METH_KEYWORDS, "inject_create_process_doppel"           },
    { "inject_com_irundown_docallback", (PyCFunction)py_inject_com_irundown_docallback, METH_VARARGS | METH_KEYWORDS, "inject_com_irundown_docallback"         },
    { "execute_rop_gadget_local",       (PyCFunction)py_execute_rop_gadget_local,       METH_VARARGS | METH_KEYWORDS, "execute_rop_gadget_local"               },
    { "process_find",                   (PyCFunction)py_process_find,                   METH_VARARGS | METH_KEYWORDS, "Find process by name"                   },
    { "process_open",                   (PyCFunction)py_process_open,                   METH_VARARGS | METH_KEYWORDS, "Open process"                           },
    { "process_init_memory",            (PyCFunction)py_process_init_memory,            METH_VARARGS | METH_KEYWORDS, "Init memory context for the process"    },
    { "process_create_memory",          (PyCFunction)py_process_create_memory,          METH_VARARGS | METH_KEYWORDS, "Create memory in the process"           },
    { "process_write_memory",           (PyCFunction)py_process_write_memory,           METH_VARARGS | METH_KEYWORDS, "Write memory in the process"            },
    { "process_thread_set_execute",     (PyCFunction)py_process_thread_set_execute,     METH_VARARGS | METH_KEYWORDS, "Set thread execute"                     },
    { "process_thread_create",          (PyCFunction)py_process_thread_create,          METH_VARARGS | METH_KEYWORDS, "Create thread in the process"           },
    { "process_thread_open",            (PyCFunction)py_process_thread_open,            METH_VARARGS | METH_KEYWORDS, "Open thread in the process"             },
    { "process_thread_suspend",         (PyCFunction)py_process_thread_suspend,         METH_VARARGS | METH_KEYWORDS, "Suspend thread in the process"          },
    { "process_thread_resume",          (PyCFunction)py_process_thread_resume,          METH_VARARGS | METH_KEYWORDS, "Resume thread in the process"           },
    { "process_is_x64",                 (PyCFunction)py_process_is_x64,                 METH_VARARGS | METH_KEYWORDS, "Check if process is x64"                },
    { "memory_get_remote_address",      (PyCFunction)py_memory_get_remote_address,      METH_VARARGS | METH_KEYWORDS, "Get remote address from memory context" },
    { "memory_set_size",                (PyCFunction)py_memory_set_size,                METH_VARARGS | METH_KEYWORDS, "Set size of data in memory context"     },
    { "shellcode_get_messageboxw",      (PyCFunction)py_shellcode_get_messageboxw,      METH_VARARGS | METH_KEYWORDS, "Get call MessageBoxW shellcode"         },
    { NULL,                             NULL,                                           0,                            NULL                                     }
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "breaking_bat",
    NULL,
    -1,
    module_methods
};


PyMODINIT_FUNC PyInit_breaking_bat(void) {

    auto *m = PyModule_Create(&module_def);
    if (m == NULL) {
        return NULL;
    }

    py_init_enums(m);


    return m;
}


namespace python {

void initialize() {

    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.use_frozen_modules = 1;
    config.isolated = 1;
    config.site_import = 0;

    auto status = PyConfig_SetBytesString(&config, &config.program_name, "breaking_bat");
    if (PyStatus_Exception(status)) {
        goto exception;
    }

    PyImport_AppendInittab("breaking_bat", &PyInit_breaking_bat);

    status = Py_InitializeFromConfig(&config);
    if (PyStatus_Exception(status)) {
        goto exception;
    }

    PyConfig_Clear(&config);

    PyModule_Create(&module_def);
    return;

exception:
    PyConfig_Clear(&config);
    Py_ExitStatusException(status);
}

void execute_script(const std::string& script) {
    script_context_t ctx;
    script_context = &ctx;
    PyRun_SimpleString(script.c_str());
    script_context = nullptr;
}

bool finalize() {

    if (Py_FinalizeEx() < 0) {
        return false;
    }

    return true;
}

} // namespace python
