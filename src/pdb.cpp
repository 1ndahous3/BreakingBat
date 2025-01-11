#include <urlmon.h>
#include <dia2.h>
#include <diacreate.h>
#include <comdef.h>

#include <format>

#include <common.h>

#pragma comment(lib, "urlmon.lib")


_COM_SMARTPTR_TYPEDEF(IDiaDataSource, __uuidof(IDiaDataSource));
_COM_SMARTPTR_TYPEDEF(IDiaSession, __uuidof(IDiaSession));
_COM_SMARTPTR_TYPEDEF(IDiaSymbol, __uuidof(IDiaSymbol));
_COM_SMARTPTR_TYPEDEF(IDiaEnumSymbols, __uuidof(IDiaEnumSymbols));


// https://chromium.googlesource.com/breakpad/breakpad/+/1e24e66fbbc8855b93932988769c5267c265fc8d%5E!/
IDiaDataSourcePtr CreateDiaDataSourceInstance() {

    IDiaDataSourcePtr data_source;
    HRESULT hr = data_source.CreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER);
    if (SUCCEEDED(hr)) {
        return data_source;
    }

    if (hr != REGDB_E_CLASSNOTREG) {
        wprintf(L"  [-] unable to initialize DIA Source, HRESULT = 0x%x\n", hr);
        return NULL;
    }

    class DECLSPEC_UUID("B86AE24D-BF2F-4ac9-B5A2-34B14E4CE11D") DiaSource100;
    class DECLSPEC_UUID("761D3BCD-1304-41D5-94E8-EAC54E4AC172") DiaSource110;
    class DECLSPEC_UUID("3BFCEA48-620F-4B6B-81F7-B9AF75454C7D") DiaSource120;
    class DECLSPEC_UUID("E6756135-1E65-4D17-8576-610761398C3C") DiaSource140;

    // If the CoCreateInstance call above failed, msdia*.dll is not registered.
    // We can try loading the DLL corresponding to the #included DIA SDK, but
    // the DIA headers don't provide a version. Lets try to figure out which DIA
    // version we're compiling against by comparing CLSIDs.
    const wchar_t *msdia_dll = nullptr;
    if (CLSID_DiaSource == _uuidof(DiaSource100)) {
        msdia_dll = L"msdia100.dll";
    } else if (CLSID_DiaSource == _uuidof(DiaSource110)) {
        msdia_dll = L"msdia110.dll";
    } else if (CLSID_DiaSource == _uuidof(DiaSource120)) {
        msdia_dll = L"msdia120.dll";
    } else if (CLSID_DiaSource == _uuidof(DiaSource140)) {
        msdia_dll = L"msdia140.dll";
    }

    hr = NoRegCoCreate(msdia_dll, CLSID_DiaSource, IID_IDiaDataSource, (void**)&data_source);
    if (FAILED(hr)) {
        wprintf(L"  [-] unable to initialize DIA Source, HRESULT = 0x%x\n", hr);
        return NULL;
    }

    return data_source;
}

namespace pdb {

struct codeviewInfo_t {
    ULONG CvSignature;
    GUID Signature;
    ULONG Age;
    char PdbFileName[ANYSIZE_ARRAY];
};


std::wstring download_pdb(PVOID image, std::wstring folder_path) {

    constexpr auto symbol_server = L"http://msdl.microsoft.com/download/symbols/";

    auto* pDOSHeader = (PIMAGE_DOS_HEADER)image;

    auto* pNT32Header = (PIMAGE_NT_HEADERS32)PTR_ADD(image, pDOSHeader->e_lfanew);
    auto* pNT64Header = (PIMAGE_NT_HEADERS64)pNT32Header;

    bool is_64 = pNT32Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    const uintptr_t debug_directory =
        is_64 ?
        pNT64Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress :
        pNT32Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;

    if (!debug_directory) {
        wprintf(L"  [-] unable to get PE debug directory\n");
        return {};
    }

    for (auto *current_debug_dir = (IMAGE_DEBUG_DIRECTORY *)PTR_ADD(image, debug_directory);
        current_debug_dir->SizeOfData;
        current_debug_dir++) {

        if (current_debug_dir->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
            continue;
        }

        auto *codeview_info = (codeviewInfo_t *)PTR_ADD(image, current_debug_dir->PointerToRawData);

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
        auto pdb_extention_path = std::format(L"{}\\{}1\\{}", pdb_filename, GUID, pdb_filename);
        auto pdb_filepath = std::format(L"{}\\{}", folder_path, pdb_filename);

        wprintf(L"  [*] downloading PDB from the server, it can take a while...\n");

        HRESULT hr = URLDownloadToFileW(nullptr, (symbol_server + pdb_extention_path).c_str(), pdb_filepath.c_str(), 0, nullptr);
        if (FAILED(hr)) {
            wprintf(L"  [-] unable to download PDB, HRESULT = 0x%x\n", hr);
            return {};
        }

        return pdb_filepath;
    }

    wprintf(L"  [-] unable to get PE CodeView debug directory\n");
    return {};
}

typedef void (*pfn_symbol_callback_t)(IDiaSymbol* current_symbol, void* ctx);

bool get_symbol_internal(const std::wstring& pdb_filepath, const std::wstring& symbol_name, pfn_symbol_callback_t pfn_symbol_callback, void *ctx) {

    HRESULT hr;

    static bool com_initialized = false;
    if (!com_initialized) {

        hr = CoInitialize(nullptr);
        if (FAILED(hr)) {
            wprintf(L"  [-] unable to initialize COM, HRESULT = 0x%x\n", hr);
            return false;
        }

        com_initialized = true;
    }

    IDiaDataSourcePtr source = CreateDiaDataSourceInstance();
    if (!source) {
        return false;
    }

    hr = source->loadDataFromPdb(pdb_filepath.c_str());
    if (FAILED(hr)) {
        wprintf(L"  [-] unable to load data from PDB, HRESULT = 0x%x\n", hr);
        return false;
    }

    IDiaSessionPtr session;
    hr = source->openSession(&session);
    if (FAILED(hr)) {
        wprintf(L"  [-] unable to open DIA session, HRESULT = 0x%x\n", hr);
        return false;
    }

    IDiaSymbolPtr global;
    hr = session->get_globalScope(&global);
    if (FAILED(hr)) {
        wprintf(L"  [-] unable to get DIA global scope, HRESULT = 0x%x\n", hr);
        return false;
    }

    IDiaEnumSymbolsPtr enum_symbols;
    hr = global->findChildren(SymTagNull, symbol_name.c_str(), nsNone, &enum_symbols);
    if (FAILED(hr)) {
        wprintf(L"  [-] unable to get DIA enum symbols, HRESULT = 0x%x\n", hr);
        return false;
    }

    IDiaSymbolPtr current_symbol;
    ULONG celt = 0;
    while (SUCCEEDED(enum_symbols->Next(1, &current_symbol, &celt)) && celt == 1) {
        pfn_symbol_callback(current_symbol, ctx);
        return true;
    }

    wprintf(L"  [-] unable to find symbol = %s\n", symbol_name.c_str());
    return false;
}

size_t get_symbol_rva(const std::wstring& pdb_filepath, const std::wstring& symbol_name) {

    DWORD RVA = 0;

    auto callback = +[](IDiaSymbol* current_symbol, void* ctx) {
        if (FAILED(current_symbol->get_relativeVirtualAddress((DWORD*)ctx))) {
            wprintf(L"  [-] unable to get symbol RVA\n");
        }
    };

    if (!get_symbol_internal(pdb_filepath, symbol_name, callback, &RVA)) {
        return 0;
    }

    return RVA;
}

size_t get_field_offset(const std::wstring& pdb_filepath, const std::wstring& struct_name, const std::wstring& field_name) {

    struct callback_ctx_t {
        const wchar_t *field;
        LONG offset;
    } callback_ctx {
        .field = field_name.c_str(),
        .offset = 0
    };

    auto callback = +[](IDiaSymbol* type_symbol, void* ctx) {

        auto callback_ctx = (callback_ctx_t*)ctx;

        IDiaEnumSymbolsPtr enum_symbols;
        HRESULT hr = type_symbol->findChildren(SymTagData, callback_ctx->field, nsNone, &enum_symbols);
        if (FAILED(hr)) {
            wprintf(L"  [-] unable to get DIA enum symbols, HRESULT = 0x%x\n", hr);
            return;
        }

        IDiaSymbolPtr field_symbol;
        ULONG celt = 0;
        while (SUCCEEDED(enum_symbols->Next(1, &field_symbol, &celt)) && celt == 1) {

            hr = field_symbol->get_offset(&callback_ctx->offset);
            if (FAILED(hr)) {
                wprintf(L"  [-] unable to get field offset, HRESULT = 0x%x\n", hr);
            }

            return;
        }

        wprintf(L"  [-] unable to find field\n");
        return;
    };

    if (!get_symbol_internal(pdb_filepath, struct_name, callback, &callback_ctx)) {
        return 0;
    }

    return callback_ctx.offset;
}

}