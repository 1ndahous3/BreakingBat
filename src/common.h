#pragma once

#define PTR_ADD(PTR, OFFSET) (void*)((uint8_t*)(PTR) + (size_t)(OFFSET))
#define PTR_SUB(PTR, OFFSET) (void*)((uint8_t*)(PTR) - (size_t)(OFFSET))
#define PTR_DIFF(PTR1, PTR2) (ptrdiff_t)((uint8_t*)(PTR1) - (uint8_t*)(PTR2))

#define ROUND_UP( x, y )  ((ULONG)(x) + ((y)-1) & ~((y)-1))

#include <format>
#include <string>

#include <guiddef.h>

namespace str {

inline
std::wstring to_wstring(GUID guid) {
    return std::format(L"{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
}

inline
std::wstring to_wstring(std::string_view str) {
    std::wstring wstr(str.size(), L' ');
    wstr.resize(mbstowcs(wstr.data(), str.data(), str.size()));

    return wstr;
}

}