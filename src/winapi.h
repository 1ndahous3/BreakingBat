#pragma once

#define NTDDI_VERSION NTDDI_WIN7

#define NOMINMAX
#define WIN32_NO_STATUS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#undef WIN32_LEAN_AND_MEAN
#undef WIN32_NO_STATUS
#undef NOMINMAX

#include <ntstatus.h>

#ifndef _NTDEF_
typedef long NTSTATUS;
#endif
