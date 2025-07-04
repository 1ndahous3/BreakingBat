#include "sysapi.h"
#include "common.h"

#include <string>
#include <format>
#include <unordered_map>
#include <cassert>

#include "errcodes.cpp"

namespace str {

std::string decode_ntstatus(NTSTATUS status) {

    if (status == STATUS_SUCCESS) {
        return std::format("status = 0x{:x}", (uint32_t)status);
    }

    const char *str;

    if (auto it = ntstatus_str.find(status);
        it != ntstatus_str.end()) {
        str = it->second;
    }
    else {
        assert(false);
        str = "unknown NTSTATUS";
    }

    return std::format("status = 0x{:x} ({})", (uint32_t)status, str);
}

std::string decode_hresult(HRESULT hr) {

    if (hr == S_OK) {
        return std::format("hr = 0x{:x}", (uint32_t)hr);
    }

    const char *str;

    if (auto it = hresult_str.find(hr);
        it != hresult_str.end()) {
        str = it->second;
    }
    else {
        assert(false);
        str = "unknown HRESULT";
    }

    return std::format("hr = 0x{:x} ({})", (uint32_t)hr, str);
}

} // namespace str
