#include "python_core.h"
#include "common.h"
#include "logging.h"
#include "magic_enum.hpp"

#include "modules/modules.h"
#include "python_modules.h"

script_context_t *script_context;

uint32_t get_pid(const std::wstring& process) {

    uint32_t pid = 0;

    wchar_t *end;
    pid = wcstoul(process.c_str(), &end, 10);
    if (errno == ERANGE) {
        bblog::error(L"invalid PID: {}", process.c_str());
        return pid;
    }

    if (pid == 0) {
        pid = sysapi::ProcessFind(process.c_str());
    }

    if (pid == 0) {
        bblog::error(L"unable to find process: {}", process.c_str());
        return pid;
    }

    return pid;
}

template<typename T>
void init_enums(PyObject *m) {

    static const auto enum_name_s = std::string(magic_enum::enum_type_name<T>());
    constexpr const auto enum_names = magic_enum::enum_names<T>();

    PyObject *enum_name = PyUnicode_FromString(enum_name_s.c_str());
    PyObject *enum_dict = PyDict_New();

    for (size_t i = 0; i < enum_names.size(); i++) {
        PyDict_SetItemString(enum_dict, std::string(enum_names[i]).c_str(), PyLong_FromSize_t(i));
    }

    PyObject *args = PyTuple_Pack(3, enum_name, PyTuple_New(0), enum_dict);
    PyObject *enum_class = PyObject_CallObject((PyObject *)&PyType_Type, args);

    Py_DECREF(enum_dict);
    Py_DECREF(args);

    PyModule_AddObject(m, enum_name_s.c_str(), enum_class);
}

//

void py_init_enums(PyObject *m) {
    init_enums<modules::RemoteProcessOpenMethod>(m);
    init_enums<modules::RemoteProcessMemoryMethod>(m);
}

PyObject *py_script_success(PyObject *, PyObject *, PyObject *) {
    script_context->result = true;
    bblog::info("[+] Success");
    Py_RETURN_NONE;
}

PyObject *py_set_default_options(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "open_method", "memory_method", NULL };

    int open_method_i = -1;
    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "|ii", (char **)kwlist,
            &open_method_i,
            &memory_method_i
        )) {
        return NULL;
    }

    bblog::info("| Setting default options:");

    if (open_method_i != -1) {
        auto open_method = magic_enum::enum_cast<modules::RemoteProcessOpenMethod>((uint8_t)open_method_i);
        if (!open_method.has_value()) {
            bblog::error("invalid RemoteProcessOpenMethod");
            PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessOpenMethod");
            return NULL;
        }

        script_context->current_process_open_method = *open_method;
        bblog::info("|   Remote process open method: {}", magic_enum::enum_name(*open_method));
    }

    if (memory_method_i != -1) {
        auto memory_method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
        if (!memory_method.has_value()) {
            bblog::error("invalid RemoteProcessMemoryMethod");
            PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryMethod");
            return NULL;
        }

        script_context->current_process_memory_method = *memory_method;
        bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(*memory_method));
    }

    bblog::info("");
    Py_RETURN_NONE;
}

PyObject *py_inject_queue_apc(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "process", "thread", "open_method", "memory_method", NULL };

    const char *process_s = NULL;
    int thread = 0;

    int open_method_i = -1;
    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "s|iii", (char **)kwlist,
            &process_s,
            &thread,
            &open_method_i,
            &memory_method_i
        )) {
        return NULL;
    }

    auto process_ws = str::to_wstring(process_s);

    uint32_t pid = get_pid(process_ws);
    if (pid == 0) {
        Py_RETURN_NONE;
    }

    auto open_method = script_context->current_process_open_method;
    if (open_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessOpenMethod>((uint8_t)open_method_i);
        open_method = method.has_value() ? *method : modules::RemoteProcessOpenMethod::Unknown;
    }

    if (open_method == modules::RemoteProcessOpenMethod::Unknown) {
        bblog::error("invalid RemoteProcessOpenMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessOpenMethod");
        return NULL;
    }

    auto memory_method = script_context->current_process_memory_method;
    if (memory_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
        memory_method = method.has_value() ? *method : modules::RemoteProcessMemoryMethod::Unknown;
    }

    if (memory_method == modules::RemoteProcessMemoryMethod::Unknown) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryMethod");
        return NULL;
    }

    bblog::info("| Script options:");
    bblog::info("|   Process: {}", process_s);
    bblog::info("|   Thread: {}", thread ? std::to_string(thread) : "alertable");
    bblog::info("|   Remote process open method: {}", magic_enum::enum_name(open_method));
    bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(memory_method));
    bblog::info("");

    modules::inject_queue_apc(pid, thread, open_method, memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_queue_apc_early_bird(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "original_image", "memory_method", NULL };

    const char *original_image_s = NULL;

    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "s|i", (char **)kwlist,
            &original_image_s,
            &memory_method_i
        )) {
        return NULL;
    }

    auto original_image_ws = str::to_wstring(original_image_s);

    auto memory_method = script_context->current_process_memory_method;
    if (memory_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
        memory_method = method.has_value() ? *method : modules::RemoteProcessMemoryMethod::Unknown;
    }

    if (memory_method == modules::RemoteProcessMemoryMethod::Unknown) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryMethod");
        return NULL;
    }

    bblog::info("| Script options:");
    bblog::info("|   Original image: {}", original_image_s);
    if (memory_method_i != -1) {
        bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(memory_method));
    }
    bblog::info("");

    modules::inject_queue_apc_early_bird(original_image_ws, memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_create_process_hollow(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "original_image", "injected_image", "memory_method", NULL };

    const char *original_image_s = NULL;
    const char *injected_image_s = NULL;

    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "ss|i", (char **)kwlist,
            &original_image_s,
            &injected_image_s,
            &memory_method_i
        )) {
        return NULL;
    }

    auto original_image_ws = str::to_wstring(original_image_s);
    auto injected_image_ws = str::to_wstring(injected_image_s);

    auto memory_method = script_context->current_process_memory_method;
    if (memory_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
        memory_method = method.has_value() ? *method : modules::RemoteProcessMemoryMethod::Unknown;
    }

    if (memory_method == modules::RemoteProcessMemoryMethod::Unknown) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryMethod");
        return NULL;
    }

    bblog::info("| Script options:");
    bblog::info("|   Original image: {}", original_image_s);
    bblog::info("|   Injected image: {}", injected_image_s);
    if (memory_method_i != -1) {
        bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(memory_method));
    }
    bblog::info("");

    modules::inject_create_process_hollow(original_image_ws, injected_image_ws, memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_create_process_doppel(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "original_image", "injected_image", "memory_method", NULL };

    const char *original_image_s = NULL;
    const char *injected_image_s = NULL;

    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "ss|i", (char **)kwlist,
            &original_image_s,
            &injected_image_s,
            &memory_method_i
        )) {
        return NULL;
    }

    auto original_image_ws = str::to_wstring(original_image_s);
    auto injected_image_ws = str::to_wstring(injected_image_s);

    auto memory_method = script_context->current_process_memory_method;
    if (memory_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
        memory_method = method.has_value() ? *method : modules::RemoteProcessMemoryMethod::Unknown;
    }

    if (memory_method == modules::RemoteProcessMemoryMethod::Unknown) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryMethod");
        return NULL;
    }

    bblog::info("| Script options:");
    bblog::info("|   Original image: {}", original_image_s);
    bblog::info("|   Injected image: {}", injected_image_s);
    if (memory_method_i != -1) {
        bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(memory_method));
    }
    bblog::info("");

    modules::inject_create_process_doppel(original_image_ws, injected_image_ws, memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_com_irundown_docallback(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "process", "open_method", "memory_method", NULL };

    const char *process_s = NULL;

    int open_method_i = -1;
    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "s|ii", (char **)kwlist,
            &process_s,
            &open_method_i,
            &memory_method_i
        )) {
        return NULL;
    }

    auto process_ws = str::to_wstring(process_s);

    uint32_t pid = get_pid(process_ws);
    if (pid == 0) {
        Py_RETURN_NONE;
    }

    auto open_method = script_context->current_process_open_method;
    if (open_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessOpenMethod>((uint8_t)open_method_i);
        open_method = method.has_value() ? *method : modules::RemoteProcessOpenMethod::Unknown;
    }

    if (open_method == modules::RemoteProcessOpenMethod::Unknown) {
        bblog::error("invalid RemoteProcessOpenMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessOpenMethod");
        return NULL;
    }

    auto memory_method = script_context->current_process_memory_method;
    if (memory_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
        memory_method = method.has_value() ? *method : modules::RemoteProcessMemoryMethod::Unknown;
    }

    if (memory_method == modules::RemoteProcessMemoryMethod::Unknown) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryMethod");
        return NULL;
    }

    bblog::info("| Script options:");
    bblog::info("|   Process: {}", process_s);
    if (open_method_i != -1) {
        bblog::info("|   Remote process open method: {}", magic_enum::enum_name(open_method));
    }
    if (memory_method_i != -1) {
        bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(memory_method));
    }
    bblog::info("");

    modules::inject_com_irundown_docallback(pid, open_method, memory_method);
    Py_RETURN_NONE;
}

PyObject *py_execute_rop_gadget_local(PyObject *, PyObject *, PyObject *) {
    modules::execute_rop_gadget_local();
    Py_RETURN_NONE;
}

// API

PyObject *py_process_find(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "process", NULL };

    const char *process_s = NULL;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "s", (char **)kwlist,
            &process_s
        )) {
        return NULL;
    }

    auto process_ws = str::to_wstring(process_s);

    uint32_t pid = get_pid(process_ws);
    if (pid == 0) {
        PyErr_SetString(PyExc_ValueError, "Invalid process");
        return NULL;
    }

    /*PyObject *c_int_type = PyObject_GetAttrString(PyImport_ImportModule("ctypes"), "c_uint");
    return PyObject_CallFunction(c_int_type, "i", pid);*/

    return PyLong_FromUnsignedLong(pid);
}

PyObject *py_process_open(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "pid", "open_method", NULL };

    int pid_i = -1;
    int open_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "i|i", (char **)kwlist,
            &pid_i,
            &open_method_i
        )) {
        return NULL;
    }

    auto open_method = script_context->current_process_open_method;
    if (open_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessOpenMethod>((uint8_t)open_method_i);
        open_method = method.has_value() ? *method : modules::RemoteProcessOpenMethod::Unknown;
    }

    if (open_method == modules::RemoteProcessOpenMethod::Unknown) {
        bblog::error("invalid RemoteProcessOpenMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessOpenMethod");
        return NULL;
    }

    uint32_t pid = (uint32_t)pid_i;

    sysapi::unique_handle ProcessHandle = modules::process_open(open_method, pid);
    if (ProcessHandle == NULL) {
        PyErr_SetString(PyExc_SystemError, "Unable to open process");
        return NULL;
    }

    script_context->current_process = ProcessHandle.get();
    script_context->module_resources.emplace(ProcessHandle.get(), std::move(ProcessHandle));

    return PyLong_FromVoidPtr(script_context->current_process);
}

PyObject *py_process_init_memory(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "pid", "handle", "memory_method", NULL };

    int pid_i = -1;
    uint64_t handle_u = 0;
    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "i|Ki", (char **)kwlist,
            &pid_i,
            &handle_u,
            &memory_method_i
        )) {
        return NULL;
    }

    uint32_t pid = (uint32_t)pid_i;

    auto handle = script_context->current_process;
    if (handle_u) {
        handle = (HANDLE)handle_u;
    }

    if (handle == 0) {
        bblog::error("invalid HANDLE");
        PyErr_SetString(PyExc_ValueError, "Invalid HANDLE");
        return NULL;
    }

    auto memory_method = script_context->current_process_memory_method;
    if (memory_method_i != -1) {
        auto method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
        memory_method = method.has_value() ? *method : modules::RemoteProcessMemoryMethod::Unknown;
    }

    if (memory_method == modules::RemoteProcessMemoryMethod::Unknown) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryMethod");
        return NULL;
    }

    auto ctx_ptr = std::make_unique<modules::RemoteProcessMemoryContext>();
    auto ctx = ctx_ptr.get();
    script_context->module_memory_ctxs.emplace((uintptr_t)ctx, std::move(ctx_ptr));

    if (!modules::process_init_memory(*ctx, memory_method, handle, pid)) {
        PyErr_SetString(PyExc_SystemError, "Unable to open process");
        return NULL;
    }

    return PyLong_FromVoidPtr(ctx);
}

PyObject *py_process_create_memory(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "ctx", NULL };

    uint64_t ctx_u = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "K", (char **)kwlist,
            &ctx_u
        )) {
        return NULL;
    }

    auto it = script_context->module_memory_ctxs.find(ctx_u);
    if (it == script_context->module_memory_ctxs.end()) {
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryContext");
        return NULL;
    }

    auto ctx = it->second.get();

    if (!modules::process_create_memory(*ctx)) {
        PyErr_SetString(PyExc_SystemError, "Unable to create memory");
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *py_process_write_memory(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "ctx", "data", NULL };

    uint64_t ctx_u = 0;
    const char *buffer = NULL;
    Py_ssize_t size_s = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "Ky#", (char **)kwlist,
            &ctx_u,
            &buffer,
            &size_s
        )) {
        return NULL;
    }

    auto it = script_context->module_memory_ctxs.find(ctx_u);
    if (it == script_context->module_memory_ctxs.end()) {
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryContext");
        return NULL;
    }

    auto ctx = it->second.get();

    if (!modules::process_write_memory(*ctx, 0, (PVOID)buffer, (SIZE_T)size_s)) {
        PyErr_SetString(PyExc_SystemError, "Unable to write memory");
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *py_process_thread_set_execute(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "new_thread", "is_x64", "ep", "handle", NULL };

    int new_thread = 0;
    int is_x64 = 0;

    uint64_t ep_u = 0;
    uint64_t handle_u = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "ppK|K", (char **)kwlist,
            &new_thread,
            &is_x64,
            &ep_u,
            &handle_u
        )) {
        return NULL;
    }

    auto handle = script_context->current_thread;
    if (handle_u) {
        handle = (HANDLE)handle_u;
    }

    if (handle == 0) {
        bblog::error("invalid HANDLE");
        PyErr_SetString(PyExc_ValueError, "Invalid HANDLE");
        return NULL;
    }

    bool res;

    if (new_thread) {
        if (is_x64) {
            res = modules::new_thread_set_execute_x64(handle, (PVOID)ep_u);
        }
        else {
            res = modules::new_thread_set_execute_x86(handle, (PVOID)ep_u);
        }
    }
    else {
        if (is_x64) {
            res = modules::thread_set_execute_x64(handle, (PVOID)ep_u);
        }
        else {
            res = modules::thread_set_execute_x86(handle, (PVOID)ep_u);
        }
    }

    if (!res) {
        PyErr_SetString(PyExc_SystemError, "Unable to set thread execute");
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *py_process_thread_create(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "ep", "handle", NULL };

    uint64_t ep_u = 0;
    uint64_t handle_u = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "K|K", (char **)kwlist,
            &ep_u,
            &handle_u
        )) {
        return NULL;
    }

    auto handle = script_context->current_process;
    if (handle_u) {
        handle = (HANDLE)handle_u;
    }

    if (handle == 0) {
        bblog::error("invalid HANDLE");
        PyErr_SetString(PyExc_ValueError, "Invalid HANDLE");
        return NULL;
    }

    auto ctx_ptr = std::make_unique<modules::RemoteProcessMemoryContext>();
    auto ctx = ctx_ptr.get();
    script_context->module_memory_ctxs.emplace((uintptr_t)ctx, std::move(ctx_ptr));

    sysapi::unique_handle ThreadHandle = sysapi::ThreadCreate(handle, (PVOID)ep_u);
    if (ThreadHandle == NULL) {
        PyErr_SetString(PyExc_SystemError, "Unable to create thread");
        return NULL;
    }

    script_context->current_thread = ThreadHandle.get();
    script_context->module_resources.emplace(ThreadHandle.get(), std::move(ThreadHandle));

    return PyLong_FromVoidPtr(script_context->current_process);
}

PyObject *py_process_thread_open(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "handle", "tid", NULL };

    uint64_t handle_u = 0;

    int tid_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "|Ki", (char **)kwlist,
            &handle_u,
            &tid_i
        )) {
        return NULL;
    }

    auto handle = script_context->current_process;
    if (handle_u) {
        handle = (HANDLE)handle_u;
    }

    if (handle == 0) {
        bblog::error("invalid HANDLE");
        PyErr_SetString(PyExc_ValueError, "Invalid HANDLE");
        return NULL;
    }

    sysapi::unique_handle ThreadHandle;

    if (tid_i == -1) {
        ThreadHandle = sysapi::ThreadOpenNext(handle);
    }
    else {
        // TODO: capture PID
        // ThreadHandle = sysapi::ThreadOpen();
    }

    if (ThreadHandle == NULL) {
        PyErr_SetString(PyExc_SystemError, "Unable to open thread");
        return NULL;
    }

    script_context->current_thread = ThreadHandle.get();
    script_context->module_resources.emplace(ThreadHandle.get(), std::move(ThreadHandle));

    return PyLong_FromVoidPtr(script_context->current_process);
}

PyObject *py_process_thread_suspend(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "handle", NULL };

    uint64_t handle_u = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "|K", (char **)kwlist,
            &handle_u
        )) {
        return NULL;
    }

    auto handle = script_context->current_thread;
    if (handle_u) {
        handle = (HANDLE)handle_u;
    }

    if (handle == 0) {
        bblog::error("invalid HANDLE");
        PyErr_SetString(PyExc_ValueError, "Invalid HANDLE");
        return NULL;
    }

    auto ctx_ptr = std::make_unique<modules::RemoteProcessMemoryContext>();
    auto ctx = ctx_ptr.get();
    script_context->module_memory_ctxs.emplace((uintptr_t)ctx, std::move(ctx_ptr));

    if (!sysapi::ThreadSuspend(handle)) {
        PyErr_SetString(PyExc_SystemError, "Unable to suspend thread");
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *py_process_thread_resume(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "handle", NULL };

    uint64_t handle_u = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "|K", (char **)kwlist,
            &handle_u
        )) {
        return NULL;
    }

    auto handle = script_context->current_thread;
    if (handle_u) {
        handle = (HANDLE)handle_u;
    }

    if (handle == 0) {
        bblog::error("invalid HANDLE");
        PyErr_SetString(PyExc_ValueError, "Invalid HANDLE");
        return NULL;
    }

    auto ctx_ptr = std::make_unique<modules::RemoteProcessMemoryContext>();
    auto ctx = ctx_ptr.get();
    script_context->module_memory_ctxs.emplace((uintptr_t)ctx, std::move(ctx_ptr));

    if (!sysapi::ThreadResume(handle)) {
        PyErr_SetString(PyExc_SystemError, "Unable to resume thread");
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject *py_process_is_x64(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "handle", NULL };

    uint64_t ep_u = 0;
    uint64_t handle_u = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "|K", (char **)kwlist,
            &ep_u,
            &handle_u
        )) {
        return NULL;
    }

    auto handle = script_context->current_process;
    if (handle_u) {
        handle = (HANDLE)handle_u;
    }

    if (handle == 0) {
        bblog::error("invalid HANDLE");
        PyErr_SetString(PyExc_ValueError, "Invalid HANDLE");
        return NULL;
    }

    bool is_64;
    bool res = sysapi::ProcessGetWow64Info(handle, is_64);
    if (!res) {
        PyErr_SetString(PyExc_SystemError, "Unable to get Wow64 info");
        return NULL;
    }

    return is_64 ? Py_True : Py_False;
}

PyObject *py_memory_get_remote_address(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "ctx", NULL };

    uint64_t ctx_u = 0;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "K", (char **)kwlist,
            &ctx_u
        )) {
        return NULL;
    }

    auto it = script_context->module_memory_ctxs.find(ctx_u);
    if (it == script_context->module_memory_ctxs.end()) {
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryContext");
        return NULL;
    }

    auto ctx = it->second.get();
    return PyLong_FromVoidPtr(ctx->RemoteBaseAddress);
}

PyObject *py_memory_set_size(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "ctx", "size", NULL };

    uint64_t ctx_u = 0;
    int size_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "Ki", (char **)kwlist,
            &ctx_u,
            &size_i
        )) {
        return NULL;
    }

    auto it = script_context->module_memory_ctxs.find(ctx_u);
    if (it == script_context->module_memory_ctxs.end()) {
        PyErr_SetString(PyExc_ValueError, "Invalid RemoteProcessMemoryContext");
        return NULL;
    }

    auto ctx = it->second.get();
    ctx->Size = (ULONG)size_i;

    Py_RETURN_NONE;
}

PyObject *py_shellcode_get_messageboxw(PyObject *, PyObject *, PyObject *) {
    return PyBytes_FromStringAndSize(modules::default_shellcode_data, modules::default_shellcode_size);
}
