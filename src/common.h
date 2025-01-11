#pragma once

#define PTR_ADD(PTR, OFFSET) (void*)((uint8_t*)(PTR) + (size_t)(OFFSET))
#define PTR_SUB(PTR, OFFSET) (void*)((uint8_t*)(PTR) - (size_t)(OFFSET))
#define PTR_DIFF(PTR1, PTR2) (ptrdiff_t)((uint8_t*)(PTR1) - (uint8_t*)(PTR2))

#define ROUND_UP( x, y )  ((ULONG)(x) + ((y)-1) & ~((y)-1))

#include <string>


namespace str {

inline
std::wstring to_wstring(std::string_view str) {
    std::wstring wstr(str.size(), L' ');
    wstr.resize(mbstowcs(wstr.data(), str.data(), str.size()));

    return wstr;
}

}