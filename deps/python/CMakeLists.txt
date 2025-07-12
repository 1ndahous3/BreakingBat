# =============================================================================
# Auxiliary CMakeLists.txt to build Python runtime with static and isolated 
# configuration (prepare CPython sources, configure python-cmake-buildsystem)
# =============================================================================

set(CPYTHON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cpython")
set(PYTHON_CMAKE_BUILDSYSTEM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/python-cmake-buildsystem")

find_package(Git REQUIRED)

function(apply_patch)
    set(oneValueArgs PATCH_FILE TARGET_FILE)
    cmake_parse_arguments(PARSE_ARGV 0 ARG "" "${oneValueArgs}" "")

    if(NOT ARG_PATCH_FILE OR NOT ARG_TARGET_FILE)
        message(FATAL_ERROR "apply_patch() requires PATCH_FILE and TARGET_FILE arguments")
    endif()

    message(STATUS "Attempting to apply patch: ${ARG_PATCH_FILE} to ${ARG_TARGET_FILE}")

    execute_process(
        COMMAND patch -N -l "${ARG_TARGET_FILE}" "${ARG_PATCH_FILE}"
        RESULT_VARIABLE ret
    )

    if(ret EQUAL 0)
        message(STATUS "Patch applied successfully: ${ARG_PATCH_FILE}")
        return()
    endif()
    
    execute_process(
        COMMAND patch -N -l -R --dry-run "${ARG_TARGET_FILE}" "${ARG_PATCH_FILE}"
        RESULT_VARIABLE ret
    )

    if(NOT ret EQUAL 0)
        message(FATAL_ERROR "Failed to apply patch ${ARG_PATCH_FILE} (ret=${ret})")
    endif()

    message(STATUS "Patch already applied: ${ARG_PATCH_FILE}")
endfunction()

function(replace_in_file)
    set(oneValueArgs TARGET_FILE STR_FIND STR_REPLACE)
    cmake_parse_arguments(PARSE_ARGV 0 ARG "" "${oneValueArgs}" "")

    if(NOT ARG_TARGET_FILE OR NOT ARG_STR_FIND OR NOT ARG_STR_REPLACE)
        message(FATAL_ERROR "replace_in_file() requires TARGET_FILE, STR_FIND and STR_REPLACE arguments")
    endif()

    message(STATUS "Replace content in file: ${ARG_TARGET_FILE}")

    file(READ "${ARG_TARGET_FILE}" FILE_CONTENT)
    string(REPLACE "${ARG_STR_FIND}" "${ARG_STR_REPLACE}" FILE_CONTENT "${FILE_CONTENT}")
    file(WRITE "${ARG_TARGET_FILE}" "${FILE_CONTENT}")
endfunction()

# -----------------------------------------------------------------------------
# Freeze the "encoding" module in CPython since it's not the default
# Reference: https://github.com/python/cpython/pull/28398#pullrequestreview-756856469
# -----------------------------------------------------------------------------

# Keep only minimal set of encodings
set(ENCODING_MODULE_BASE_SRC
    "__init__.py" 
    "aliases.py" 
    "utf_8.py" 
    "cp1252.py"
)

file(GLOB ENCODING_MODULE_SRC "${CPYTHON_DIR}/Lib/encodings/*")
foreach(FILE ${ENCODING_MODULE_SRC})
    get_filename_component(FILENAME ${FILE} NAME)
    
    list(FIND ENCODING_MODULE_BASE_SRC ${FILENAME} INDEX)
    if(${INDEX} EQUAL -1)
        message(STATUS "Removing unnecessary encoding: ${FILE}")
        file(REMOVE ${FILE})
    endif()
endforeach()

# Patch freeze_modules.py to include encodings in frozen stdlib
# Reference: https://github.com/python/cpython/blob/8ac7613dc8b8f82253d7c0e2b6ef6ed703a0a1ee/Tools/build/freeze_modules.py#L56
replace_in_file(
    TARGET_FILE "${CPYTHON_DIR}/Tools/build/freeze_modules.py"
    STR_FIND "#'<encodings.*>',"
    STR_REPLACE "'<encodings.*>',"
)

find_package(Python COMPONENTS Interpreter REQUIRED)

# Regenerate frozen.c to update _PyImport_FrozenStdlib
execute_process(
    COMMAND python "${CPYTHON_DIR}/Tools/build/freeze_modules.py" --frozen-modules
)

# -----------------------------------------------------------------------------
# Remove os.getppid() as it uses PssCaptureSnapshot() which is not available in Windows 7
# Reference: https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot
# Reference: https://github.com/python/cpython/blob/8ac7613dc8b8f82253d7c0e2b6ef6ed703a0a1ee/Modules/posixmodule.c#L9501
# -----------------------------------------------------------------------------

replace_in_file(
    TARGET_FILE "${CPYTHON_DIR}/Modules/posixmodule.c"
    STR_FIND "#    define HAVE_GETPPID    1"
    STR_REPLACE " "
)

# -----------------------------------------------------------------------------
# Remove CopyFile2() as it's not available in Windows 7
# Reference: https://learn.microsoft.com/ru-ru/windows/win32/api/winbase/nf-winbase-copyfile2
# Reference: https://github.com/python/cpython/pull/105055
# -----------------------------------------------------------------------------

replace_in_file(
    TARGET_FILE "${CPYTHON_DIR}/Modules/clinic/posixmodule.c.h"
    STR_FIND "_WINAPI_COPYFILE2_METHODDEF"
    STR_REPLACE " "
)

replace_in_file(
    TARGET_FILE "${CPYTHON_DIR}/Modules/_winapi.c"
    STR_FIND "_WINAPI_COPYFILE2_METHODDEF"
    STR_REPLACE " "
)

# -----------------------------------------------------------------------------
# Don't link with pathcch.lib since it's not available on Windows 7, use own implementation
# Reference: https://github.com/python/cpython/issues/84917
# Reference: https://github.com/nalexandru/api-ms-win-core-path-HACK
# -----------------------------------------------------------------------------

file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/api-ms-win-core-path.c" DESTINATION "${CPYTHON_DIR}/Python/")

apply_patch(
    PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/python_cmake_replace_pathcch_libpython.patch"
    TARGET_FILE "${PYTHON_CMAKE_BUILDSYSTEM_DIR}/cmake/libpython/CMakeLists.txt"
)

apply_patch(
    PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/python_cmake_replace_pathcch_extensions.patch"
    TARGET_FILE "${PYTHON_CMAKE_BUILDSYSTEM_DIR}/cmake/extensions/CMakeLists.txt"
)

# -----------------------------------------------------------------------------
# Include encodings in deepfreeze.c generation
# -----------------------------------------------------------------------------

apply_patch(
    PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/python_cmake_freeze_encodings.patch"
    TARGET_FILE "${PYTHON_CMAKE_BUILDSYSTEM_DIR}/cmake/libpython/CMakeLists.txt"
)

# -----------------------------------------------------------------------------
# Configure and build
# -----------------------------------------------------------------------------

set(DOWNLOAD_SOURCES "OFF")
set(SRC_DIR "${CPYTHON_DIR}")

set(BUILD_TESTING "OFF")
set(INSTALL_MANUAL "OFF")
set(INSTALL_TEST "OFF")
set(WITH_STATIC_DEPENDENCIES "ON")
set(BUILD_EXTENSIONS_AS_BUILTIN "ON")

add_subdirectory(${PYTHON_CMAKE_BUILDSYSTEM_DIR})
