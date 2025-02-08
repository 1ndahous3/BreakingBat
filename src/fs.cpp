#include "sysapi.h"
#include "fs.h"

namespace fs {

file_mapping_t map_file(const wchar_t *file_path) {

    file_mapping_t file_mapping;

    file_mapping.handle = sysapi::FileOpen(file_path);
    if (file_mapping.handle == NULL) {
        return {};
    }

    file_mapping.size = sysapi::FileGetSize(file_mapping.handle.get());
    if (file_mapping.size == 0) {
        return {};
    }

    file_mapping.section_handle = sysapi::SectionFileCreate(file_mapping.handle.get(), SECTION_MAP_READ, PAGE_READONLY);
    if (file_mapping.section_handle == NULL) {
        return {};
    }

    file_mapping.data = sysapi::SectionMapView(file_mapping.section_handle.get(), file_mapping.size, PAGE_READONLY);
    if (file_mapping.data == nullptr) {
        return {};
    }

    return file_mapping;
}

}