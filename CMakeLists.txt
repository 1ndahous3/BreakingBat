cmake_minimum_required(VERSION 3.15)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(breaking_bat CXX)
add_executable(breaking_bat)

target_include_directories(breaking_bat PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_sources(breaking_bat PRIVATE
    src/sysapi.cpp
    src/main.cpp
    src/scripts/inject_remote_thread.cpp
)

foreach(CompilerFlag CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
                     CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE)
    string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /Zi")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /DEBUG:FULL /OPT:REF /OPT:ICF")

target_compile_features(breaking_bat PRIVATE cxx_std_23)
target_compile_options(breaking_bat PRIVATE /W4 /WX)
