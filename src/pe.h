#pragma once

#include <cstdint>

namespace pe {

uintptr_t rva_to_offset(PVOID image, uintptr_t rva);

}