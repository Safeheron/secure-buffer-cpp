# Fails if any public header references a platform macro/header.
# Platform code must live only in src/*.cpp.
file(GLOB_RECURSE PUBLIC_HEADERS "${PROJECT_SOURCE_DIR}/include/*.h")

set(FORBIDDEN "_WIN32|__GNUC__|__clang__|__APPLE__|__GLIBC__|__STDC_LIB_EXT1__|explicit_bzero|memset_s|windows\\.h")

set(VIOLATIONS "")
foreach(header ${PUBLIC_HEADERS})
    file(STRINGS "${header}" HITS REGEX "${FORBIDDEN}")
    if(HITS)
        list(APPEND VIOLATIONS "${header}: ${HITS}")
    endif()
endforeach()

if(VIOLATIONS)
    message(FATAL_ERROR "Platform macros leaked into public headers:\n${VIOLATIONS}")
endif()
message(STATUS "test_no_platform_macros: OK")
