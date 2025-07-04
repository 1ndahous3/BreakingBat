#include "python_core.h"

#include "sysapi.h"
#include "common.h"
#include "logging.h"
#include "magic_enum.hpp"

#include "python_modules.h"

static PyObject *py_init_sysapi(PyObject * /*self*/, PyObject *args, PyObject *kwargs) {

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
    { "init_sysapi",                    (PyCFunction)py_init_sysapi,                    METH_VARARGS | METH_KEYWORDS, "Initial method to init system API" },
    { "inject_queue_apc",               (PyCFunction)py_inject_queue_apc,               METH_VARARGS | METH_KEYWORDS, "inject_queue_apc"                  },
    { "inject_queue_apc_early_bird",    (PyCFunction)py_inject_queue_apc_early_bird,    METH_VARARGS | METH_KEYWORDS, "inject_queue_apc_early_bird"       },
    { "inject_hijack_remote_thread",    (PyCFunction)py_inject_hijack_remote_thread,    METH_VARARGS | METH_KEYWORDS, "inject_hijack_remote_thread"       },
    { "inject_create_remote_thread",    (PyCFunction)py_inject_create_remote_thread,    METH_VARARGS | METH_KEYWORDS, "inject_create_remote_thread"       },
    { "inject_create_process_hollow",   (PyCFunction)py_inject_create_process_hollow,   METH_VARARGS | METH_KEYWORDS, "inject_create_process_hollow"      },
    { "inject_create_process_doppel",   (PyCFunction)py_inject_create_process_doppel,   METH_VARARGS | METH_KEYWORDS, "inject_create_process_doppel"      },
    { "inject_com_irundown_docallback", (PyCFunction)py_inject_com_irundown_docallback, METH_VARARGS | METH_KEYWORDS, "inject_com_irundown_docallback"    },
    { "execute_rop_gadget_local",       (PyCFunction)py_execute_rop_gadget_local,       METH_VARARGS | METH_KEYWORDS, "execute_rop_gadget_local"          },
    { NULL,                             NULL,                                           0,                            NULL                                }
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
    PyRun_SimpleString(script.c_str());
}

bool finalize() {

    if (Py_FinalizeEx() < 0) {
        return false;
    }

    return true;
}

} // namespace python
