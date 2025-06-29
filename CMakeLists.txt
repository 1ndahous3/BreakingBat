cmake_minimum_required(VERSION 3.15)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(breaking_bat
    LANGUAGES C CXX
    VERSION "0.1.0"
)

add_executable(breaking_bat)

target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/deps")
target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/deps/phnt")
target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/deps/spdlog/include")
target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/deps/raw_pdb/src")
target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/deps/kdmp-parser/src/lib")

target_compile_definitions(breaking_bat PUBLIC
                           _CRT_SECURE_NO_WARNINGS
                           PHNT_VERSION=PHNT_WIN11_24H2
                           SPDLOG_WCHAR_TO_UTF8_SUPPORT SPDLOG_USE_STD_FORMAT)

# RAW PDB

file(GLOB RAW_PDB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/deps/raw_pdb/src/*.cpp")

# IDL

file(GLOB IDL_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/*.idl")

foreach(IDL_FILE ${IDL_FILES})
    add_custom_command(
        TARGET breaking_bat PRE_BUILD
        COMMAND midl /notlb /target NT60 /I "${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/" /out "${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/" ${IDL_FILE}
    )
endforeach()

file(GLOB IDL_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/*_i.c")

target_sources(breaking_bat PRIVATE
    src/sysapi.cpp
    src/shellcode.cpp
    src/fs.cpp
    src/pe.cpp
    src/pdb.cpp
    src/hash.cpp
    src/kernel_dump.cpp
    src/main.cpp
    src/scripts/scripts.cpp
    src/scripts/inject_hijack_remote_thread.cpp
    src/scripts/inject_create_remote_thread.cpp
    src/scripts/inject_create_process_hollow.cpp
    src/scripts/inject_create_process_doppel.cpp
    src/scripts/inject_queue_apc.cpp
    src/scripts/inject_queue_apc_early_bird.cpp
    src/scripts/inject_com_irundown_docallback.cpp
    src/scripts/execute_rop_gadget_local.cpp
    ${RAW_PDB_SOURCES}
    ${IDL_SOURCES}
)

foreach(CompilerFlag CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
                     CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE)
    string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /DEBUG:FULL /OPT:REF /OPT:ICF")

target_compile_features(breaking_bat PRIVATE cxx_std_23)
target_compile_options(breaking_bat PRIVATE /W4 /WX
    /wd4201 # nonstandard extension used: nameless struct/union
    /wd4324 # structure was padded due to alignment specifier
    /wd4471 # a forward declaration of an unscoped enumeration must have an underlying type
    /guard:cf- # because of 'ControlFlowGuardEnabled' flag checks of caller process in some kernel functions (i.e. 'PspCreateThread()')
)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/deps/spdlog")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/deps/kdmp-parser/src/lib")

target_link_libraries(breaking_bat PRIVATE spdlog::spdlog_header_only)