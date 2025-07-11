#pragma once

#include "modules/modules.h"
#include "python_core.h"

struct script_context_t {
    std::unordered_map<HANDLE, sysapi::unique_handle> module_resources;
    std::unordered_map<uintptr_t, std::unique_ptr<modules::RemoteProcessMemoryContext>> module_memory_ctxs;

    modules::RemoteProcessMemoryMethod current_process_memory_method = modules::RemoteProcessMemoryMethod::Unknown;
    modules::RemoteProcessOpenMethod current_process_open_method = modules::RemoteProcessOpenMethod::Unknown;
    HANDLE current_process;
    HANDLE current_thread;

    bool result = false;
};

void py_init_enums(PyObject *m);
PyObject *py_script_success(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_set_default_options(PyObject *m, PyObject *args, PyObject *kwargs);

PyObject *py_inject_queue_apc_early_bird(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_inject_create_process_hollow(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_inject_create_process_doppel(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_inject_com_irundown_docallback(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_execute_rop_gadget_local(PyObject *m, PyObject *args, PyObject *kwargs);

PyObject *py_process_find(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_open(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_init_memory(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_create_memory(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_write_memory(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_thread_set_execute(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_thread_create(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_thread_open(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_thread_open_alertable(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_thread_suspend(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_thread_resume(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_thread_queue_user_apc(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_process_is_x64(PyObject *m, PyObject *args, PyObject *kwargs);

PyObject *py_memory_get_remote_address(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_memory_set_size(PyObject *m, PyObject *args, PyObject *kwargs);

PyObject *py_shellcode_get_messageboxw(PyObject *m, PyObject *args, PyObject *kwargs);
