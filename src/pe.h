#pragma once

#include <cstdint>

namespace pe {

uintptr_t rva_to_offset(PVOID image, uintptr_t rva);

PIMAGE_SECTION_HEADER find_module_section_header(const char* module_name, const char* section);

std::string_view get_module_section(const char* module_name, const char* section_name);
PVOID find_code_in_module(const char* module_name, const std::vector<uint8_t>& code);

}