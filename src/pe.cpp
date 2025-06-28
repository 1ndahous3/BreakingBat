#include <algorithm>
#include <vector>

#include "sysapi.h"
#include "common.h"
#include "pe.h"
#include "logging.h"

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

PIMAGE_SECTION_HEADER find_module_section_header(const char* module_name, const char* section) {

    HMODULE hModule = GetModuleHandleA(module_name);
    if (hModule == NULL) {
        return NULL;
    }

    auto *pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    auto *pNtHeader = (PIMAGE_NT_HEADERS)PTR_ADD(hModule, pDosHeader->e_lfanew);
    auto *pSectionHeader = (PIMAGE_SECTION_HEADER)PTR_ADD(&pNtHeader->OptionalHeader, pNtHeader->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSectionHeader[i].Name, section) == 0) {
            return &pSectionHeader[i];
        }
    }

    bblog::error("unable to find {} section in {}", section, module_name);
    return NULL;
}

std::string_view get_module_section(const char* module_name, const char* section_name) {

    PIMAGE_SECTION_HEADER text_section_header = find_module_section_header(module_name, section_name);
    if (text_section_header == NULL) {
        return {};
    }

    auto* pTextSection = PTR_ADD(GetModuleHandleA(module_name), text_section_header->VirtualAddress);

    return { (char*)pTextSection, text_section_header->SizeOfRawData };
}

PVOID find_code_in_module(const char* module_name, const std::vector<uint8_t>& code) {

    PIMAGE_SECTION_HEADER text_section_header = find_module_section_header(module_name, ".text");
    if (text_section_header == NULL) {
        return NULL;
    }

    auto *pTextSection = PTR_ADD(GetModuleHandleA(module_name), text_section_header->VirtualAddress);
    auto *pTextSectionEnd = PTR_ADD(pTextSection, text_section_header->SizeOfRawData);

    auto *pGadget = std::search((uint8_t*)pTextSection, (uint8_t*)pTextSectionEnd, code.begin(), code.end());
    if (pGadget == pTextSectionEnd) {
        bblog::error("unable to find gadget in {}", module_name);
        return NULL;
    }

    return pGadget;
}

}