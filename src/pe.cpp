#include "sysapi.h"
#include "common.h"
#include "pe.h"

namespace pe {

uintptr_t rva_to_offset(PVOID image, uintptr_t rva) {

    auto *pDOSHeader = (PIMAGE_DOS_HEADER)image;
    auto *pNTHeader = (PIMAGE_NT_HEADERS32)PTR_ADD(image, pDOSHeader->e_lfanew);

    auto *section_header = IMAGE_FIRST_SECTION(pNTHeader);

    for (size_t i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section_header++) {
        if (rva >= section_header->VirtualAddress && rva < section_header->VirtualAddress + section_header->Misc.VirtualSize) {
            return rva - section_header->VirtualAddress + section_header->PointerToRawData;
        }
    }

    return 0;
}

}