# =============================================================================
# Auxiliary CMakeLists.txt to build Python runtime with static and isolated 
# configuration (prepare CPython sources, configure python-cmake-buildsystem)
# =============================================================================

set(CPYTHON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cpython")
set(PYTHON_CMAKE_BUILDSYSTEM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/python-cmake-buildsystem")

# -----------------------------------------------------------------------------
# Freeze the "encoding" module in CPython since it's not the default
# Reference: https://github.com/python/cpython/pull/28398#pullrequestreview-756856469
# -----------------------------------------------------------------------------

find_package(Python COMPONENTS Interpreter REQUIRED)

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
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/cpython/Tools/build/freeze_modules.py" FREEZE_SCRIPT)
string(REPLACE "#'<encodings.*>'," "'<encodings.*>'," FREEZE_SCRIPT "${FREEZE_SCRIPT}")
file(WRITE "${CMAKE_CURRENT_SOURCE_DIR}/cpython/Tools/build/freeze_modules.py" "${FREEZE_SCRIPT}")

# Regenerate frozen.c to update _PyImport_FrozenStdlib
execute_process(
    COMMAND python "${CMAKE_CURRENT_SOURCE_DIR}/cpython/Tools/build/freeze_modules.py" --frozen-modules
)

# -----------------------------------------------------------------------------
# Configure python-cmake-buildsystem
# -----------------------------------------------------------------------------

# Apply patch to include encodings in deepfreeze.c generation
find_package(Git REQUIRED)
set(PYTHON_CMAKE_PATCH "python_cmake_freeze_encodings.patch")

execute_process(
    COMMAND patch -N -l "${PYTHON_CMAKE_BUILDSYSTEM_DIR}/cmake/libpython/CMakeLists.txt"
            "${CMAKE_CURRENT_SOURCE_DIR}/${PYTHON_CMAKE_PATCH}"
    RESULT_VARIABLE ret
)

if(ret EQUAL 0)
    message(STATUS "python-cmake patch applied successfully")
else()
    execute_process(
        COMMAND patch -N -l -R --dry-run
                "${PYTHON_CMAKE_BUILDSYSTEM_DIR}/cmake/libpython/CMakeLists.txt"
                "${CMAKE_CURRENT_SOURCE_DIR}/${PYTHON_CMAKE_PATCH}"
        RESULT_VARIABLE ret
    )

    if(NOT ret EQUAL 0)
        message(FATAL_ERROR "Failed to apply ${PYTHON_CMAKE_PATCH} (ret=${ret})")
    endif()
    
    message(STATUS "python-cmake patch already applied")
endif()

# -----------------------------------------------------------------------------
# Configure and build
# -----------------------------------------------------------------------------

set(DOWNLOAD_SOURCES "OFF")
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cpython")

set(BUILD_TESTING "OFF")
set(INSTALL_MANUAL "OFF")
set(INSTALL_TEST "OFF")
set(WITH_STATIC_DEPENDENCIES "ON")
set(BUILD_EXTENSIONS_AS_BUILTIN "ON")

add_subdirectory(${PYTHON_CMAKE_BUILDSYSTEM_DIR})
