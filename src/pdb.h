#include <string>
#include <windows.h>

namespace pdb {

std::wstring download_pdb(PVOID image, std::wstring folder_path);

size_t get_symbol_rva(const std::wstring& pdb_filepath, const std::wstring& symbol_name);
size_t get_field_offset(const std::wstring& pdb_filepath, const std::wstring& struct_name, const std::wstring& field_name);

}