#include "python_core.h"
#include "common.h"
#include "logging.h"
#include "magic_enum.hpp"

#include "modules/modules.h"


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
        Py_RETURN_NONE;
    }

    auto process_ws = str::to_wstring(process_s);

    uint32_t pid = get_pid(process_ws);
    if (pid == 0) {
        Py_RETURN_NONE;
    }

    auto open_method = magic_enum::enum_cast<modules::RemoteProcessOpenMethod>((uint8_t)open_method_i);
    if (!open_method.has_value()) {
        bblog::error("invalid RemoteProcessOpenMethod");
        Py_RETURN_NONE;
    }

    auto memory_method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
    if (!memory_method.has_value()) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        Py_RETURN_NONE;
    }

    bblog::info("| Script options:");
    bblog::info("|   Process: {}", process_s);
    bblog::info("|   Thread: {}", thread ? std::to_string(thread) : "alertable");
    bblog::info("|   Remote process open method: {}", magic_enum::enum_name(*open_method));
    bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(*memory_method));
    bblog::info("");

    modules::inject_queue_apc(pid, thread, *open_method, *memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_queue_apc_early_bird(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "original_image", "memory_method", NULL };

    const char *original_image_s = NULL;

    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "si", (char **)kwlist,
            &original_image_s,
            &memory_method_i
        )) {
        Py_RETURN_NONE;
    }

    auto original_image_ws = str::to_wstring(original_image_s);

    auto memory_method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
    if (!memory_method.has_value()) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        Py_RETURN_NONE;
    }

    bblog::info("| Script options:");
    bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(*memory_method));
    bblog::info("|   Original image: {}", original_image_s);
    bblog::info("");

    modules::inject_queue_apc_early_bird(original_image_ws, *memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_hijack_remote_thread(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "process", "open_method", "memory_method", NULL };

    const char *process_s = NULL;

    int open_method_i = -1;
    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "sii", (char **)kwlist,
            &process_s,
            &open_method_i,
            &memory_method_i
        )) {
        Py_RETURN_NONE;
    }

    auto process_ws = str::to_wstring(process_s);

    uint32_t pid = get_pid(process_ws);
    if (pid == 0) {
        Py_RETURN_NONE;
    }

    auto open_method = magic_enum::enum_cast<modules::RemoteProcessOpenMethod>((uint8_t)open_method_i);
    if (!open_method.has_value()) {
        bblog::error("invalid RemoteProcessOpenMethod");
        Py_RETURN_NONE;
    }

    auto memory_method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
    if (!memory_method.has_value()) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        Py_RETURN_NONE;
    }

    bblog::info("| Script options:");
    bblog::info("|   Process: {}", process_s);
    bblog::info("|   Remote process open method: {}", magic_enum::enum_name(*open_method));
    bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(*memory_method));
    bblog::info("");

    modules::inject_hijack_remote_thread(pid, *open_method, *memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_create_remote_thread(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "process", "open_method", "memory_method", NULL };

    const char *process_s = NULL;

    int open_method_i = -1;
    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "sii", (char **)kwlist,
            &process_s,
            &open_method_i,
            &memory_method_i
        )) {
        Py_RETURN_NONE;
    }

    auto process_ws = str::to_wstring(process_s);

    uint32_t pid = get_pid(process_ws);
    if (pid == 0) {
        Py_RETURN_NONE;
    }

    auto open_method = magic_enum::enum_cast<modules::RemoteProcessOpenMethod>((uint8_t)open_method_i);
    if (!open_method.has_value()) {
        bblog::error("invalid RemoteProcessOpenMethod");
        Py_RETURN_NONE;
    }

    auto memory_method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
    if (!memory_method.has_value()) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        Py_RETURN_NONE;
    }

    bblog::info("| Script options:");
    bblog::info("|   Process: {}", process_s);
    bblog::info("|   Remote process open method: {}", magic_enum::enum_name(*open_method));
    bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(*memory_method));
    bblog::info("");

    modules::inject_create_remote_thread(pid, *open_method, *memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_create_process_hollow(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "original_image", "injected_image", "memory_method", NULL };

    const char *original_image_s = NULL;
    const char *injected_image_s = NULL;

    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "ssi", (char **)kwlist,
            &original_image_s,
            &injected_image_s,
            &memory_method_i
        )) {
        Py_RETURN_NONE;
    }

    auto original_image_ws = str::to_wstring(original_image_s);
    auto injected_image_ws = str::to_wstring(injected_image_s);

    auto memory_method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
    if (!memory_method.has_value()) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        Py_RETURN_NONE;
    }

    bblog::info("| Script options:");
    bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(*memory_method));
    bblog::info("|   Original image: {}", original_image_s);
    bblog::info("|   Injected image: {}", injected_image_s);
    bblog::info("");

    modules::inject_create_process_hollow(original_image_ws, injected_image_ws, *memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_create_process_doppel(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "original_image", "injected_image", "memory_method", NULL };

    const char *original_image_s = NULL;
    const char *injected_image_s = NULL;

    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "ssi", (char **)kwlist,
            &original_image_s,
            &injected_image_s,
            &memory_method_i
        )) {
        Py_RETURN_NONE;
    }

    auto original_image_ws = str::to_wstring(original_image_s);
    auto injected_image_ws = str::to_wstring(injected_image_s);

    auto memory_method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
    if (!memory_method.has_value()) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        Py_RETURN_NONE;
    }

    bblog::info("| Script options:");
    bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(*memory_method));
    bblog::info("|   Original image: {}", original_image_s);
    bblog::info("|   Injected image: {}", injected_image_s);
    bblog::info("");

    modules::inject_create_process_doppel(original_image_ws, injected_image_ws, *memory_method);
    Py_RETURN_NONE;
}

PyObject *py_inject_com_irundown_docallback(PyObject *, PyObject *args, PyObject *kwargs) {

    static const char *kwlist[] = { "process", "open_method", "memory_method", NULL };

    const char *process_s = NULL;

    int open_method_i = -1;
    int memory_method_i = -1;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs,
            "sii", (char **)kwlist,
            &process_s,
            &open_method_i,
            &memory_method_i
        )) {
        Py_RETURN_NONE;
    }

    auto process_ws = str::to_wstring(process_s);

    uint32_t pid = get_pid(process_ws);
    if (pid == 0) {
        Py_RETURN_NONE;
    }

    auto open_method = magic_enum::enum_cast<modules::RemoteProcessOpenMethod>((uint8_t)open_method_i);
    if (!open_method.has_value()) {
        bblog::error("invalid RemoteProcessOpenMethod");
        Py_RETURN_NONE;
    }

    auto memory_method = magic_enum::enum_cast<modules::RemoteProcessMemoryMethod>((uint8_t)memory_method_i);
    if (!memory_method.has_value()) {
        bblog::error("invalid RemoteProcessMemoryMethod");
        Py_RETURN_NONE;
    }

    bblog::info("| Script options:");
    bblog::info("|   Process: {}", process_s);
    bblog::info("|   Remote process open method: {}", magic_enum::enum_name(*open_method));
    bblog::info("|   Remote process memory method: {}", magic_enum::enum_name(*memory_method));
    bblog::info("");

    modules::inject_com_irundown_docallback(pid, *open_method, *memory_method);
    Py_RETURN_NONE;
}

PyObject *py_execute_rop_gadget_local(PyObject *, PyObject *, PyObject *) {
    modules::execute_rop_gadget_local();
    Py_RETURN_NONE;
}
