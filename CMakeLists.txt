cmake_minimum_required(VERSION 3.28)
project(secure-buffer
    VERSION 0.10.0
    LANGUAGES CXX
    DESCRIPTION "C++17 secure-buffer base library (header-first API + tiny compiled core)"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# GNUInstallDirs must precede the target: CMAKE_INSTALL_INCLUDEDIR is used in
# its INSTALL_INTERFACE and must match install(DIRECTORY ...) below, or a
# custom -DCMAKE_INSTALL_INCLUDEDIR breaks the exported package.
include(GNUInstallDirs)

add_library(secure-buffer STATIC src/secure_memzero.cpp)
add_library(safeheron::secure-buffer ALIAS secure-buffer)

# Warnings on the library itself (PRIVATE: never propagated to consumers).
# -Werror only when built top-level: this library is source-distributed
# (FetchContent/subdirectory), and an unconditional -Werror would break
# downstream builds whenever a future compiler adds a new warning.
if(MSVC)
    target_compile_options(secure-buffer PRIVATE /W4)
    if(PROJECT_IS_TOP_LEVEL)
        target_compile_options(secure-buffer PRIVATE /WX)
    endif()
else()
    target_compile_options(secure-buffer PRIVATE -Wall -Wextra)
    if(PROJECT_IS_TOP_LEVEL)
        target_compile_options(secure-buffer PRIVATE -Werror)
    endif()
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

if(PROJECT_IS_TOP_LEVEL)
    enable_testing()
    add_subdirectory(tests)
endif()
