#pragma once

#include "sysapi.h"

#define PY_SSIZE_T_CLEAN

#ifdef _DEBUG
#undef _DEBUG
#include <python.h>
#define _DEBUG
#else
#include <python.h>
#endif

#include <string>

namespace python {

void initialize();
void execute_script(const std::string& script);
bool finalize();

} // namespace python
