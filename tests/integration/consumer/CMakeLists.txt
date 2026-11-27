# A project that uses secure-buffer the way a downstream project does: either
# as an installed package (find_package) or as a subdirectory. Driven by
# tests/integration/run.sh.
cmake_minimum_required(VERSION 3.28)
project(secure_buffer_consumer LANGUAGES CXX)

set(SB_CONSUMER_MODE "package" CACHE STRING "How secure-buffer is brought in: package or subdirectory")
set(SB_SOURCE_DIR "" CACHE PATH "secure-buffer source tree (subdirectory mode)")
set(SB_CONSUMER_CXX_STANDARD "" CACHE STRING
    "If set, CMAKE_CXX_STANDARD is set to it as a normal variable before add_subdirectory()")
option(SB_CONSUMER_ENABLE_TESTS
    "Set SECURE_BUFFER_BUILD_TESTS to ON as a normal variable before add_subdirectory()" OFF)

enable_testing()

if(SB_CONSUMER_MODE STREQUAL "package")
    find_package(secure-buffer 0.11.0 REQUIRED)
elseif(SB_CONSUMER_MODE STREQUAL "subdirectory")
    if(NOT SB_CONSUMER_CXX_STANDARD STREQUAL "")
        set(CMAKE_CXX_STANDARD ${SB_CONSUMER_CXX_STANDARD})
    endif()
    if(SB_CONSUMER_ENABLE_TESTS)
        set(SECURE_BUFFER_BUILD_TESTS ON)
    endif()
    add_subdirectory("${SB_SOURCE_DIR}" secure-buffer)
    # Reported for run.sh: the library has no C++20 modules to scan.
    get_target_property(sb_scan_for_modules secure-buffer CXX_SCAN_FOR_MODULES)
    message(STATUS "secure-buffer CXX_SCAN_FOR_MODULES: ${sb_scan_for_modules}")
else()
    message(FATAL_ERROR "SB_CONSUMER_MODE must be package or subdirectory, got '${SB_CONSUMER_MODE}'")
endif()

# An executable that calls secure_memzero directly.
add_executable(consumer_static main.cpp)
target_link_libraries(consumer_static PRIVATE safeheron::secure-buffer)
add_test(NAME consumer_static COMMAND consumer_static)

# A shared library that links the static library, and an executable using it.
add_library(consumer_shared SHARED wipe.cpp)
target_link_libraries(consumer_shared PRIVATE safeheron::secure-buffer)
add_executable(consumer_via_shared shared_main.cpp)
target_link_libraries(consumer_via_shared PRIVATE consumer_shared)
add_test(NAME consumer_via_shared COMMAND consumer_via_shared)

# The consumer's own code, with a warning: it must build even though
# secure-buffer treats warnings as errors in some builds.
add_library(consumer_own_warning STATIC own_warning.cpp)
target_link_libraries(consumer_own_warning PRIVATE safeheron::secure-buffer)
target_compile_options(consumer_own_warning PRIVATE -Wall)
