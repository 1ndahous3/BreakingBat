#pragma once

#include <vector>

#include "kdmp-parser.h"

namespace kernel_dump {

struct kernel_offsets_t {
    size_t MMVAD_STARTING_VPN;
    size_t MMVAD_ENDING_VPN;
    size_t MMVAD_U_VAD_FLAGS;
    size_t MMVAD_LEFT_CHILD;
    size_t MMVAD_RIGHT_CHILD;
    size_t EPROCESS_ACTIVE_PROCESS_LINKS;
    size_t EPROCESS_UNIQUE_PROCESS_ID;
    size_t EPROCESS_IMAGE_FILE_NAME;
    size_t EPROCESS_VAD_ROOT;
    size_t KPROCESS_DTB;
};

struct kernel_dump_context_t {
    kernel_offsets_t kernel_offsets;
    kdmpparser::KernelDumpParser parser;
};

struct process_t {
    uint64_t dtb;
    uint64_t vad_root; // _RTL_AVL_TREE.Root
    uint64_t pid;
    char image_file_name[16];
};

struct vad_image_t {
    uint64_t VA_start;
    uint64_t VA_end;
};


bool init_parser(const char *filepath, const wchar_t *pdb_path, kernel_dump_context_t& ctx);

bool read_data(const kdmpparser::KernelDumpParser& dmp, uint64_t VirtualAddress, PVOID data, SIZE_T size, uint64_t dtb = 0);
template<typename T>
bool read_value(const kdmpparser::KernelDumpParser& dmp, uint64_t VirtualAddress, T& value, uint64_t dtb = 0) {
    return read_data(dmp, VirtualAddress, &value, sizeof(T), dtb);
}

std::vector<process_t> get_processes(const kernel_dump_context_t& ctx);
std::vector<vad_image_t> get_process_image_maps(const kernel_dump_context_t& ctx, uint64_t va_vad_root);

} // namespace kernel_dump
