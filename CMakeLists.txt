cmake_minimum_required(VERSION 3.15)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(breaking_bat CXX)
add_executable(breaking_bat)

target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/deps/phnt")

target_compile_definitions(breaking_bat PUBLIC PHNT_VERSION=PHNT_WIN11_22H2)

target_sources(breaking_bat PRIVATE
    src/sysapi.cpp
    src/main.cpp
    src/scripts/scripts.cpp
    src/scripts/inject_create_remote_thread.cpp
    src/scripts/inject_create_process_hollow.cpp
    src/scripts/inject_create_process_doppel.cpp
    src/scripts/inject_queue_apc.cpp
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
