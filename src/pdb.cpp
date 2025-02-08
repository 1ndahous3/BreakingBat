#include <urlmon.h>

#include <string>
#include <format>
#include <vector>
#include <cassert>

#include "common.h"
#include "pe.h"

#include "PDB_RawFile.h"
#include "PDB_DBIStream.h"
#include "PDB_TPIStream.h"

#pragma comment(lib, "urlmon.lib")

struct pdb_symbol_t {
    std::string name;
    uint32_t rva;
};

namespace raw_pdb {

typedef void (*pfn_symbol_callback_t)(pdb_symbol_t *current_symbol, PVOID ctx);

bool get_symbol(PVOID pdb_data, const std::string& symbol_name, pfn_symbol_callback_t pfn_symbol_callback, PVOID ctx) {

    auto raw_file = PDB::RawFile(pdb_data);

    auto dbi_stream = PDB::CreateDBIStream(raw_file);

    auto image_section_stream = dbi_stream.CreateImageSectionStream(raw_file);

    auto symbol_record_stream = dbi_stream.CreateSymbolRecordStream(raw_file);

    // public symbols
    {
        auto publicSymbolStream = dbi_stream.CreatePublicSymbolStream(raw_file);

        for (const auto& hashRecord : publicSymbolStream.GetRecords()) {

            auto *record = publicSymbolStream.GetRecord(symbol_record_stream, hashRecord);
            if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32) {
                continue;
            }

            if (strcmp(record->data.S_PUB32.name, symbol_name.c_str())) {
                continue;
            }

            uint32_t rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_PUB32.section, record->data.S_PUB32.offset);
            if (rva == 0) {
                continue;
            }

            pdb_symbol_t symbol{ .name = record->data.S_PUB32.name, .rva = rva };

            pfn_symbol_callback(&symbol, ctx);
            return true;
        }
    }

    // global symbols
    {
        auto global_symbol_stream = dbi_stream.CreateGlobalSymbolStream(raw_file);

        for (const auto& hash_record : global_symbol_stream.GetRecords()) {

            auto *record = global_symbol_stream.GetRecord(symbol_record_stream, hash_record);

            const char *name = nullptr;
            uint32_t rva = 0u;
            if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GDATA32) {
                name = record->data.S_GDATA32.name;
                rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_GDATA32.section, record->data.S_GDATA32.offset);
            }
            else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GTHREAD32) {
                name = record->data.S_GTHREAD32.name;
                rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_GTHREAD32.section, record->data.S_GTHREAD32.offset);
            }
            else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32) {
                name = record->data.S_LDATA32.name;
                rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_LDATA32.section, record->data.S_LDATA32.offset);
            }
            else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LTHREAD32) {
                name = record->data.S_LTHREAD32.name;
                rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_LTHREAD32.section, record->data.S_LTHREAD32.offset);
            }
            else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_UDT) {
                name = record->data.S_UDT.name;
            }
            else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_UDT_ST) {
                name = record->data.S_UDT_ST.name;
            }

            if (!name || strcmp(name, symbol_name.c_str())) {
                continue;
            }

            if (rva == 0) {
                continue;
            }

            pdb_symbol_t symbol{ .name = name, .rva = rva };

            pfn_symbol_callback(&symbol, ctx);
            return true;
        }
    }


    // module symbols
    {
        auto module_info_stream = dbi_stream.CreateModuleInfoStream(raw_file);

        for (const auto& module : module_info_stream.GetModules()) {

            if (!module.HasSymbolStream()) {
                continue;
            }

            auto module_symbol_stream = module.CreateSymbolStream(raw_file);

            pdb_symbol_t symbol;

            module_symbol_stream.ForEachSymbol([&](const PDB::CodeView::DBI::Record *record){

                const char *name = nullptr;
                uint32_t rva = 0;
                if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_THUNK32) {
                    if (record->data.S_THUNK32.thunk == PDB::CodeView::DBI::ThunkOrdinal::TrampolineIncremental) {
                        name = "ILT";
                        rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_THUNK32.section, record->data.S_THUNK32.offset);
                    }
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_TRAMPOLINE) {
                    name = "ILT";
                    rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_TRAMPOLINE.thunkSection, record->data.S_TRAMPOLINE.thunkOffset);
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_BLOCK32) {
                    // blocks never store a name and are only stored for indicating whether other symbols are children of this block
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LABEL32) {
                    // labels don't have a name
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32) {
                    name = record->data.S_LPROC32.name;
                    rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_LPROC32.section, record->data.S_LPROC32.offset);
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32) {
                    name = record->data.S_GPROC32.name;
                    rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_GPROC32.section, record->data.S_GPROC32.offset);
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID) {
                    name = record->data.S_LPROC32_ID.name;
                    rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_LPROC32_ID.section, record->data.S_LPROC32_ID.offset);
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID) {
                    name = record->data.S_GPROC32_ID.name;
                    rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_GPROC32_ID.section, record->data.S_GPROC32_ID.offset);
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_REGREL32) {
                    name = record->data.S_REGREL32.name;
                    // You can only get the address while running the program by checking the register value and adding the offset
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LDATA32) {
                    name = record->data.S_LDATA32.name;
                    rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_LDATA32.section, record->data.S_LDATA32.offset);
                }
                else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LTHREAD32) {
                    name = record->data.S_LTHREAD32.name;
                    rva = image_section_stream.ConvertSectionOffsetToRVA(record->data.S_LTHREAD32.section, record->data.S_LTHREAD32.offset);
                }

                if (!name || strcmp(name, symbol_name.c_str())) {
                    return;
                }

                if (rva == 0) {
                    return;
                }

                symbol.name = name;
                symbol.rva = rva;
            });

            if (!symbol.name.empty()) {
                pfn_symbol_callback(&symbol, ctx);
                return true;
            }
        }
    }

    wprintf(L"  [-] unable to find symbol = %hs\n", symbol_name.c_str());
    return false;
}


uint8_t get_leaf_size(PDB::CodeView::TPI::TypeRecordKind kind) {

    if (kind < PDB::CodeView::TPI::TypeRecordKind::LF_NUMERIC) {
        return sizeof(PDB::CodeView::TPI::TypeRecordKind);
    }

    switch (kind) {
    case PDB::CodeView::TPI::TypeRecordKind::LF_CHAR:
        return sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(uint8_t);
    case PDB::CodeView::TPI::TypeRecordKind::LF_USHORT:
    case PDB::CodeView::TPI::TypeRecordKind::LF_SHORT:
        return sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(uint16_t);
    case PDB::CodeView::TPI::TypeRecordKind::LF_LONG:
    case PDB::CodeView::TPI::TypeRecordKind::LF_ULONG:
        return sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(uint32_t);
    case PDB::CodeView::TPI::TypeRecordKind::LF_QUADWORD:
    case PDB::CodeView::TPI::TypeRecordKind::LF_UQUADWORD:
        return sizeof(PDB::CodeView::TPI::TypeRecordKind) + sizeof(uint64_t);
    default:
        return 0;
    }
}

const char *get_leaf_name(const char *data, PDB::CodeView::TPI::TypeRecordKind kind) {
    return &data[get_leaf_size(kind)];
}

const char *get_field_name(const PDB::CodeView::TPI::FieldList *field_record) {
    switch (field_record->kind) {
    case PDB::CodeView::TPI::TypeRecordKind::LF_NESTTYPE:
        return field_record->data.LF_NESTTYPE.name;
    case PDB::CodeView::TPI::TypeRecordKind::LF_STMEMBER:
        return field_record->data.LF_STMEMBER.name;
    case PDB::CodeView::TPI::TypeRecordKind::LF_METHOD:
        return field_record->data.LF_METHOD.name;
    case PDB::CodeView::TPI::TypeRecordKind::LF_ONEMETHOD:
        switch ((PDB::CodeView::TPI::MethodProperty)field_record->data.LF_ONEMETHOD.attributes.mprop) {
        case PDB::CodeView::TPI::MethodProperty::Intro:
        case PDB::CodeView::TPI::MethodProperty::PureIntro:
            return (const char *)&field_record->data.LF_ONEMETHOD.vbaseoff[sizeof(uint32_t)];
        default:
            return (const char *)&field_record->data.LF_ONEMETHOD.vbaseoff[0];
        }
    case PDB::CodeView::TPI::TypeRecordKind::LF_BCLASS:
        return get_leaf_name(field_record->data.LF_BCLASS.offset, field_record->data.LF_BCLASS.lfEasy.kind);
    case PDB::CodeView::TPI::TypeRecordKind::LF_ENUMERATE:
        return get_leaf_name(field_record->data.LF_ENUMERATE.value, field_record->data.LF_ENUMERATE.lfEasy.kind);
    case PDB::CodeView::TPI::TypeRecordKind::LF_MEMBER:
        return get_leaf_name(field_record->data.LF_MEMBER.offset, field_record->data.LF_MEMBER.lfEasy.kind);
    default:
        return nullptr;
    }
}

bool get_field_offset(size_t& offset, PVOID pdb_data, const std::string& class_name, const std::string& field_name) {

    auto raw_file = PDB::RawFile(pdb_data);

    auto tpi_stream = PDB::CreateTPIStream(raw_file);

    auto& directStream = tpi_stream.GetDirectMSFStream();
    auto stream = PDB::CoalescedMSFStream(directStream, directStream.GetSize(), 0);

    // some tricky indexing: store all records continuously
    // but to get the actual record data we need to shift left to the first index in the stream
    std::vector<const PDB::CodeView::TPI::Record*> records;
    records.resize(tpi_stream.GetTypeRecordCount());
    {
        uint32_t typeIndex = 0;
        tpi_stream.ForEachTypeRecordHeaderAndOffset([&](const PDB::CodeView::TPI::RecordHeader& /*header*/, size_t offset) {
            records[typeIndex] = stream.GetDataAtOffset<PDB::CodeView::TPI::Record>(offset);
            ++typeIndex;
        });
    }

    const PDB::CodeView::TPI::Record *class_record = nullptr;

    for (size_t i = 0; i < records.size(); i++) {

        auto record = records[i];

        if (record->data.LF_CLASS.property.fwdref) {
            continue;
        }

        const char *name;

        switch (record->header.kind) {
        case PDB::CodeView::TPI::TypeRecordKind::LF_STRUCTURE:
        case PDB::CodeView::TPI::TypeRecordKind::LF_CLASS:
            name = raw_pdb::get_leaf_name(record->data.LF_CLASS.data, record->data.LF_CLASS.lfEasy.kind);
            break;
        default:
            continue;
        }

        if (strcmp(name, class_name.c_str()) == 0) {
            class_record = records[record->data.LF_CLASS.field - tpi_stream.GetFirstTypeIndex()];
            break;
        }
    }

    if (class_record == nullptr) {
        wprintf(L"  [-] unable to find TPI record\n");
        return false;
    }

    auto size_max = class_record->header.size - sizeof(uint16_t);

    for (size_t i = 0; i < size_max;) {

        auto *field_record = (PDB::CodeView::TPI::FieldList *)PTR_ADD(&class_record->data.LF_FIELD.list, i);
        const char *name = get_field_name(field_record);

        if (field_record->kind == PDB::CodeView::TPI::TypeRecordKind::LF_MEMBER) {
            if (name && strcmp(name, field_name.c_str()) == 0) {

                if (field_record->data.LF_MEMBER.lfEasy.kind < PDB::CodeView::TPI::TypeRecordKind::LF_NUMERIC) {
                    offset = *(uint16_t *)&field_record->data.LF_MEMBER.offset[0];
                }
                else {
                    offset = *(uint16_t *)(&field_record->data.LF_MEMBER.offset[sizeof(PDB::CodeView::TPI::TypeRecordKind)]);
                }

                return true;
            }
        }

        // skip other types

        switch (field_record->kind) {
        case PDB::CodeView::TPI::TypeRecordKind::LF_BCLASS:
            i += (size_t)PTR_DIFF(name, field_record);
            i = (i + (sizeof(uint32_t) - 1)) & (0 - sizeof(uint32_t));
            continue;
        case PDB::CodeView::TPI::TypeRecordKind::LF_VBCLASS:
        case PDB::CodeView::TPI::TypeRecordKind::LF_IVBCLASS: {

            auto offset_address_point_kind = *(PDB::CodeView::TPI::TypeRecordKind*)(field_record->data.LF_IVBCLASS.vbpOffset);
            uint8_t offset_address_point_size = get_leaf_size(offset_address_point_kind);

            auto offset_vbtable_kind = *(PDB::CodeView::TPI::TypeRecordKind*)(field_record->data.LF_IVBCLASS.vbpOffset + offset_address_point_size);
            uint8_t offset_vbtable_size = get_leaf_size(offset_vbtable_kind);

            i += sizeof(PDB::CodeView::TPI::FieldList::Data::LF_VBCLASS);
            i += offset_address_point_size + offset_vbtable_size;
            i = (i + (sizeof(uint32_t) - 1)) & (0 - sizeof(uint32_t));
            continue;
        }
        case PDB::CodeView::TPI::TypeRecordKind::LF_INDEX:
            i += sizeof(PDB::CodeView::TPI::FieldList::Data::LF_INDEX);
            i = (i + (sizeof(uint32_t) - 1)) & (0 - sizeof(uint32_t));
            continue;
        case PDB::CodeView::TPI::TypeRecordKind::LF_VFUNCTAB:
            i += sizeof(PDB::CodeView::TPI::FieldList::Data::LF_VFUNCTAB);
            i = (i + (sizeof(uint32_t) - 1)) & (0 - sizeof(uint32_t));
            continue;
        default:
            if (!name) {
                assert(name && "fields with names must be implemented");
                wprintf(L"  [-] unable to interate over all fields of the record\n");
                return false;
            }

            i += (size_t)PTR_DIFF(name, field_record);
            i += strnlen(name, size_max - i - 1) + 1;
            i = (i + (sizeof(uint32_t) - 1)) & (0 - sizeof(uint32_t));
        }
    }

    wprintf(L"  [-] unable to find field in the record\n");
    return false;
}

}

namespace pdb {

const DWORD CV_SIGNATURE_RSDS = 0x53445352; // 'SDSR'

struct CV_INFO_PDB70 {
    DWORD CvSignature;
    GUID Signature;
    DWORD Age;
    BYTE PdbFileName[ANYSIZE_ARRAY];
};

std::wstring download_pdb(std::wstring folder_path, PVOID image, bool is_file) {

    constexpr auto symbol_server = L"http://msdl.microsoft.com/download/symbols/";

    auto *pDOSHeader = (PIMAGE_DOS_HEADER)image;

    auto *pNT32Header = (PIMAGE_NT_HEADERS32)PTR_ADD(image, pDOSHeader->e_lfanew);
    auto *pNT64Header = (PIMAGE_NT_HEADERS64)pNT32Header;

    bool is_64 = pNT32Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    uintptr_t debug_directory_rva =
        is_64 ?
        pNT64Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress :
        pNT32Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;

    if (!debug_directory_rva) {
        wprintf(L"  [-] unable to get PE debug directory VA\n");
        return {};
    }

    uintptr_t debug_directory_offset =
        is_file ?
        pe::rva_to_offset(image, debug_directory_rva) :
        debug_directory_rva;

    if (!debug_directory_offset) {
        wprintf(L"  [-] unable to get PE debug directory offset\n");
        return {};
    }

    for (auto *current_debug_dir = (IMAGE_DEBUG_DIRECTORY *)PTR_ADD(image, debug_directory_offset);
        current_debug_dir->SizeOfData;
        current_debug_dir++) {

        if (current_debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
            continue;
        }

        auto *codeview_info = (CV_INFO_PDB70 *)PTR_ADD(image,
            is_file ?
            current_debug_dir->PointerToRawData :
            current_debug_dir->AddressOfRawData
        );

        if (codeview_info->CvSignature != CV_SIGNATURE_RSDS) {
            continue;
        }

        auto GUID = std::format(L"{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            codeview_info->Signature.Data1,
            codeview_info->Signature.Data2,
            codeview_info->Signature.Data3,
            codeview_info->Signature.Data4[0],
            codeview_info->Signature.Data4[1],
            codeview_info->Signature.Data4[2],
            codeview_info->Signature.Data4[3],
            codeview_info->Signature.Data4[4],
            codeview_info->Signature.Data4[5],
            codeview_info->Signature.Data4[6],
            codeview_info->Signature.Data4[7]
        );

        auto pdb_filename = str::to_wstring((char*)codeview_info->PdbFileName);
        auto pdb_extention_path = std::format(L"{}/{}{}/{}", pdb_filename, GUID, codeview_info->Age, pdb_filename);
        auto pdb_filepath = std::format(L"{}{}", folder_path, pdb_filename);

        auto url = symbol_server + pdb_extention_path;

        wprintf(L"  [*] PDB URL: %s\n", url.c_str());
        wprintf(L"  [*] downloading, it can take a while...\n");

        HRESULT hr = URLDownloadToFileW(nullptr, url.c_str(), pdb_filepath.c_str(), 0, nullptr);
        if (FAILED(hr)) {
            wprintf(L"  [-] unable to download PDB, HRESULT = 0x%x, \n", hr);
            return {};
        }

        return pdb_filepath;
    }

    wprintf(L"  [-] unable to get PE CodeView debug directory\n");
    return {};
}


bool get_symbol_rva(size_t& rva, PVOID pdb_data, const std::string& symbol_name) {

    DWORD RVA = 0;

    auto callback = +[](pdb_symbol_t *current_symbol, void* ctx) {
        *(DWORD*)ctx = current_symbol->rva;
    };

    if (!raw_pdb::get_symbol(pdb_data, symbol_name, callback, &RVA)) {
        wprintf(L"  [-] unable to get RVA of %hs\n", symbol_name.c_str());
        return false;
    }

    rva = RVA;
    return true;
}


bool get_field_offset(size_t& offset, PVOID pdb_data, const std::string& class_name, const std::string& field_name) {

    if (!raw_pdb::get_field_offset(offset, pdb_data, class_name, field_name)) {
        wprintf(L"  [-] unable to get offset of %hs field in %hs\n", class_name.c_str(), field_name.c_str());
        return false;
    }

    return true;
}

}
