#pragma once

#include "python_core.h"

void py_init_enums(PyObject *m);

PyObject *py_inject_queue_apc(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_inject_queue_apc_early_bird(PyObject *, PyObject *args, PyObject *kwargs);
PyObject *py_inject_hijack_remote_thread(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_inject_create_remote_thread(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_inject_create_process_hollow(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_inject_create_process_doppel(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_inject_com_irundown_docallback(PyObject *m, PyObject *args, PyObject *kwargs);
PyObject *py_execute_rop_gadget_local(PyObject *m, PyObject *args, PyObject *kwargs);
