#include "sysapi.h"
#include "common.h"
#include "logging.h"

#include <iostream>
#include <stack>

#include "pdb.h"
#include "fs.h"

#include "kernel_dump.h"

typedef enum _MI_VAD_TYPE
{
    VadNone = 0,
    VadDevicePhysicalMemory = 1,
    VadImageMap = 2,
    VadAwe = 3,
    VadWriteWatch = 4,
    VadLargePages = 5,
    VadRotatePhysical = 6,
    VadLargePageSection = 7
} MI_VAD_TYPE;

namespace kernel_dump {

bool init_parser(const char *filepath, const wchar_t *pdb_path, kernel_dump_context_t& ctx) {

    auto pdb = fs::map_file(pdb_path);
    if (!pdb.data) {
        return false;
    }

    if (
        // _MMVAD_SHORT
        !pdb::get_field_offset(ctx.kernel_offsets.MMVAD_STARTING_VPN, pdb.data, "_MMVAD_SHORT", "StartingVpn") ||
        !pdb::get_field_offset(ctx.kernel_offsets.MMVAD_ENDING_VPN, pdb.data, "_MMVAD_SHORT", "EndingVpn") ||
        !pdb::get_field_offset(ctx.kernel_offsets.MMVAD_U_VAD_FLAGS, pdb.data, "_MMVAD_SHORT", "u") ||
        // _MMVAD_SHORT::VadNode
        !pdb::get_field_offset(ctx.kernel_offsets.MMVAD_LEFT_CHILD, pdb.data, "_RTL_BALANCED_NODE", "Left") ||
        !pdb::get_field_offset(ctx.kernel_offsets.MMVAD_RIGHT_CHILD, pdb.data, "_RTL_BALANCED_NODE", "Right") ||
        // _EPROCESS
        !pdb::get_field_offset(ctx.kernel_offsets.EPROCESS_ACTIVE_PROCESS_LINKS, pdb.data, "_EPROCESS", "ActiveProcessLinks") ||
        !pdb::get_field_offset(ctx.kernel_offsets.EPROCESS_UNIQUE_PROCESS_ID, pdb.data, "_EPROCESS", "UniqueProcessId") ||
        !pdb::get_field_offset(ctx.kernel_offsets.EPROCESS_IMAGE_FILE_NAME, pdb.data, "_EPROCESS", "ImageFileName") ||
        !pdb::get_field_offset(ctx.kernel_offsets.EPROCESS_VAD_ROOT, pdb.data, "_EPROCESS", "VadRoot") ||
        // _KPROCESS
        !pdb::get_field_offset(ctx.kernel_offsets.KPROCESS_DTB, pdb.data, "_KPROCESS", "DirectoryTableBase")) {
        return false;
    }

    if (!ctx.parser.Parse(filepath)) {
        bblog::error("unable to parse kernel dump");
        return false;
    }

    return true;
}

bool read_data(const kdmpparser::KernelDumpParser& dmp, uint64_t VirtualAddress, PVOID data, SIZE_T size, uint64_t dtb) {

    while (size) {
        uint64_t pte_base_vaddr = kdmpparser::Page::Align(VirtualAddress);
        uint64_t pte_offset = kdmpparser::Page::Offset(VirtualAddress);

        auto pte_base_paddr = dmp.VirtTranslate(pte_base_vaddr, dtb);
        if (!pte_base_paddr.has_value()) {
            bblog::error("unable to find physical address for PT base, vaddr = 0x{:016x}", pte_base_vaddr);
            return false;
        }

        const uint8_t* pte_base_data = dmp.GetPhysicalPage(*pte_base_paddr);
        if (!pte_base_data) {
            bblog::error("unable to get page for PT base, paddr = 0x{:016x}", *pte_base_paddr);
            return false;
        }

        size_t read_size = std::min(kdmpparser::Page::Size - pte_offset, size);
        std::memcpy(data, PTR_ADD(pte_base_data, pte_offset), read_size);

        size -= read_size;
        data = PTR_ADD(data, read_size);
        VirtualAddress += read_size;
    }

    return true;
}

std::vector<process_t> get_processes(const kernel_dump_context_t& ctx) {

    auto& header = ctx.parser.GetDumpHeader();

    LIST_ENTRY PsActiveProcessHead;
    if (!read_value(ctx.parser, header.PsActiveProcessHead, PsActiveProcessHead)) {
        return {};
    }

    std::vector<process_t> processes;

    for (uint64_t va_current_process = (uint64_t)PsActiveProcessHead.Flink; va_current_process != header.PsActiveProcessHead;) {

        process_t process = {};

        uint64_t va_eprocess = va_current_process - ctx.kernel_offsets.EPROCESS_ACTIVE_PROCESS_LINKS;

        if (!read_value(ctx.parser, va_eprocess + ctx.kernel_offsets.KPROCESS_DTB, process.dtb)) {
            return processes;
        }

        if (!read_value(ctx.parser, va_eprocess + ctx.kernel_offsets.EPROCESS_UNIQUE_PROCESS_ID, process.pid)) {
            return processes;
        }

        if (!read_value(ctx.parser, va_eprocess + ctx.kernel_offsets.EPROCESS_IMAGE_FILE_NAME, process.image_file_name)) {
            return processes;
        }

        if (!read_value(ctx.parser, va_eprocess + ctx.kernel_offsets.EPROCESS_VAD_ROOT, process.vad_root)) {
            return processes;
        }

        processes.emplace_back(std::move(process));

        LIST_ENTRY next_process;
        if (!read_value(ctx.parser, va_current_process, next_process)) {
            return processes;
        }

        va_current_process = (uint64_t)next_process.Flink;
    }

    return processes;
}

std::vector<vad_image_t> get_process_image_maps(const kernel_dump_context_t& ctx, uint64_t va_vad_root) {

    std::stack<uint64_t> vads;
    if (va_vad_root) {
        vads.push(va_vad_root);
    }

    std::vector<vad_image_t> vad_images;

    while (!vads.empty()) {

        uint64_t va_vad_current = vads.top();
        vads.pop();


        uint32_t vad_flags;
        if (!read_value(ctx.parser, va_vad_current + ctx.kernel_offsets.MMVAD_U_VAD_FLAGS, vad_flags)) {
            continue;
        }

        uint8_t VadType = (vad_flags >> 4) & 7; // TODO: get bit offset from pdb
        if (VadType != VadImageMap) {
            continue;
        }

        ULONG StartingVpn, EndingVpn;
        if (!read_value(ctx.parser, va_vad_current + ctx.kernel_offsets.MMVAD_STARTING_VPN, StartingVpn) ||
            !read_value(ctx.parser, va_vad_current + ctx.kernel_offsets.MMVAD_ENDING_VPN, EndingVpn)) {
            continue;
        }

        vad_image_t mmvad;
        mmvad.VA_start = (uint64_t)StartingVpn << 12;
        mmvad.VA_end = ((uint64_t)EndingVpn + 1) << 12;

        vad_images.push_back(mmvad);

        for (auto child_offset: { ctx.kernel_offsets.MMVAD_LEFT_CHILD, ctx.kernel_offsets.MMVAD_RIGHT_CHILD }) {

            uint64_t va_vad_leaf;
            if (!read_value(ctx.parser, va_vad_current + child_offset, va_vad_leaf)) {
                continue;
            }

            if (va_vad_leaf) {
                vads.push(va_vad_leaf);
            }
        }
    }

    return vad_images;
}

}