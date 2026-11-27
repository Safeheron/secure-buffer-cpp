cmake_minimum_required(VERSION 3.28)
project(secure-buffer
    VERSION 0.10.1
    LANGUAGES CXX
    DESCRIPTION "C++17 secure-buffer base library (header-first API + tiny compiled core)"
)

# Defaults to ON only when this is the top-level project. With it OFF,
# GoogleTest is not downloaded, built or installed.
option(SECURE_BUFFER_BUILD_TESTS "Build the tests (downloads GoogleTest)" ${PROJECT_IS_TOP_LEVEL})

# GNUInstallDirs must precede the target: CMAKE_INSTALL_INCLUDEDIR is used in
# its INSTALL_INTERFACE and must match install(DIRECTORY ...) below, or a
# custom -DCMAKE_INSTALL_INCLUDEDIR breaks the exported package.
include(GNUInstallDirs)

add_library(secure-buffer STATIC src/secure_memzero.cpp)
add_library(safeheron::secure-buffer ALIAS secure-buffer)

# A value set by the user, a toolchain file or a parent project wins;
# otherwise the library's default. Only this target is affected.
if(NOT DEFINED CMAKE_CXX_STANDARD)
    set_target_properties(secure-buffer PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
endif()
if(NOT DEFINED CMAKE_CXX_EXTENSIONS)
    set_target_properties(secure-buffer PROPERTIES CXX_EXTENSIONS OFF)
endif()
if(NOT DEFINED CMAKE_POSITION_INDEPENDENT_CODE)
    set_target_properties(secure-buffer PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()
# The library has no C++20 modules. Scanning its source for them (done for
# C++20 under Ninja) would need a tool such as clang-scan-deps, which a parent
# project building in C++20 may not have.
if(NOT DEFINED CMAKE_CXX_SCAN_FOR_MODULES)
    set_target_properties(secure-buffer PROPERTIES CXX_SCAN_FOR_MODULES OFF)
endif()
# Warnings are errors only in a build with the tests (development and CI), so
# a build that installs or embeds the library does not fail when a newer
# compiler adds a warning. CMAKE_COMPILE_WARNING_AS_ERROR and
# cmake --compile-no-warning-as-error override it.
if(NOT DEFINED CMAKE_COMPILE_WARNING_AS_ERROR)
    set_target_properties(secure-buffer PROPERTIES COMPILE_WARNING_AS_ERROR ${SECURE_BUFFER_BUILD_TESTS})
endif()

# Warnings on the library itself (PRIVATE: never propagated to consumers).
if(MSVC)
    target_compile_options(secure-buffer PRIVATE /W4)
else()
    target_compile_options(secure-buffer PRIVATE -Wall -Wextra)
endif()

target_include_directories(secure-buffer PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(secure-buffer PUBLIC cxx_std_17)

# --- install / export (config-file package) ---
include(CMakePackageConfigHelpers)

install(TARGETS secure-buffer EXPORT secure-bufferTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT secure-bufferTargets
    NAMESPACE safeheron::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/secure-buffer
)

configure_package_config_file(
    cmake/secure-bufferConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/secure-bufferConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/secure-buffer
)
# Before 1.0.0 a minor release may break the public API, so a 0.x package is
# compatible only within its minor release; from 1.0.0 within its major release.
if(PROJECT_VERSION_MAJOR EQUAL 0)
    set(_sb_version_compatibility SameMinorVersion)
else()
    set(_sb_version_compatibility SameMajorVersion)
endif()
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/secure-bufferConfigVersion.cmake"
    COMPATIBILITY ${_sb_version_compatibility}
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/secure-bufferConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/secure-bufferConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/secure-buffer
)

if(SECURE_BUFFER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
