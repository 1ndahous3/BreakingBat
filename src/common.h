#pragma once

#define PTR_ADD(PTR, OFFSET) (void *)((uint8_t *)(PTR) + (size_t)(OFFSET))
#define PTR_SUB(PTR, OFFSET) (void *)((uint8_t *)(PTR) - (size_t)(OFFSET))
#define PTR_DIFF(PTR1, PTR2) (ptrdiff_t)((uint8_t *)(PTR1) - (uint8_t *)(PTR2))

#define IS_ALIGNED(X, BITS) (((size_t)(X) & ((1 << (BITS)) - 1)) == 0)
#define ROUND_UP(x, y) ((ULONG)(x) + ((y) - 1) & ~((y) - 1))

#include "sysapi.h"
#include <guiddef.h>

#include <format>
#include <string>


namespace str {

inline std::wstring to_wstring(GUID guid) {
    return std::format(
        L"{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]
    );
}

inline std::string to_string(GUID guid) {
    return std::format(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]
    );
}

inline std::wstring to_wstring(std::string_view str) {
    std::wstring wstr(str.size(), L' ');
    wstr.resize(mbstowcs(wstr.data(), str.data(), str.size()));

    return wstr;
}

inline std::string to_string(std::wstring_view wstr) {
    std::string str(wstr.size(), ' ');
    str.resize(wcstombs(str.data(), wstr.data(), wstr.size()));

    return str;
}

std::string decode_ntstatus(NTSTATUS status);
std::string decode_hresult(HRESULT hr);

} // namespace str
