#pragma once

#include <string>
#include <windows.h>

namespace pdb {

std::wstring download_pdb(std::wstring folder_path, PVOID image, bool is_file);

bool get_symbol_rva(size_t& rva, PVOID pdb_data, const std::string& symbol_name);
bool get_field_offset(size_t& offset, PVOID pdb_data, const std::string& class_name, const std::string& field_name);

}