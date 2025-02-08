#include "sysapi.h"

namespace fs {

struct file_mapping_t {
    PVOID data; // TODO: RAII with sysapi::SectionUnmapView()
    size_t size;

    sysapi::unique_handle section_handle;
    sysapi::unique_handle handle;
};

file_mapping_t map_file(const wchar_t *file_path);

}