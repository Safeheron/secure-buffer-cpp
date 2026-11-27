include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
    SYSTEM
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(googletest)

if(MSVC)
    # /permissive- is standard-conformance mode (not a warning switch): the
    # overload-resolution pins in the tests assert standard C++ behavior.
    set(TEST_COMPILE_OPTIONS /W4 /WX /permissive-)
else()
    set(TEST_COMPILE_OPTIONS -Wall -Wextra -Werror)
endif()

function(add_secure_buffer_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_link_libraries(${TEST_NAME} PRIVATE safeheron::secure-buffer GTest::gtest_main)
    target_compile_options(${TEST_NAME} PRIVATE ${TEST_COMPILE_OPTIONS})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

add_secure_buffer_test(test_secure_memzero test_secure_memzero.cpp)
add_secure_buffer_test(test_secure_cleanse test_secure_cleanse.cpp)
add_secure_buffer_test(test_secure_bytes test_secure_bytes.cpp)
add_secure_buffer_test(test_secure_array test_secure_array.cpp)
add_secure_buffer_test(test_secure_string test_secure_string.cpp)
add_secure_buffer_test(test_secure_utils_compare test_secure_utils_compare.cpp)
add_secure_buffer_test(test_secure_utils_convert test_secure_utils_convert.cpp)
add_secure_buffer_test(test_compat_span test_compat_span.cpp)
# C++20-only targets: test_compat_span_std builds the span tests against
# std::span (compat::span must be a strict subset of it); test_comparison_cxx20
# and the *_cxx20 compile-fail cases (tests/compile_fail) pin the rewritten
# comparison operators. A compiler with C++20 support may still use a standard
# library without std::span or a usable <compare>, so probe each in C++20 mode
# (the checks honour CMAKE_CXX_STANDARD, which the block overrides) and skip
# the targets whose probe fails.
if("cxx_std_20" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
    include(CheckCXXSourceCompiles)
    block(SCOPE_FOR VARIABLES)
        set(CMAKE_CXX_STANDARD 20)
        set(CMAKE_CXX_STANDARD_REQUIRED ON)
        check_cxx_source_compiles([[
#include <span>
#if !defined(__cpp_lib_span) || __cpp_lib_span < 202002L
#error "std::span is not available"
#endif
int main() {
    int a[2] = {0, 1};
    std::span<int> s(a);
    return s[0];
}
]] SB_HAS_CXX20_STD_SPAN)
        # Functional check only: some standard libraries ship a usable <compare>
        # before they define __cpp_lib_three_way_comparison.
        check_cxx_source_compiles([[
#include <compare>
#if !defined(__cpp_impl_three_way_comparison)
#error "three-way comparison is not available"
#endif
int main() {
    int a = 0;
    int b = 1;
    std::strong_ordering r = a <=> b;
    return r < 0 ? 0 : 1;
}
]] SB_HAS_CXX20_THREE_WAY)
    endblock()
endif()
if(SB_HAS_CXX20_STD_SPAN)
    add_secure_buffer_test(test_compat_span_std test_compat_span.cpp)
    set_target_properties(test_compat_span_std PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
    target_compile_definitions(test_compat_span_std PRIVATE SB_TEST_STD_SPAN)
else()
    message(STATUS "C++20 std::span not available: skipping test_compat_span_std")
endif()

# Replaces global operator new/delete: needs its own executable
add_secure_buffer_test(test_secure_allocator_zeroing test_secure_allocator_zeroing.cpp)

# Replaces global operator new/delete: needs its own executable
add_secure_buffer_test(test_secure_array_zeroing test_secure_array_zeroing.cpp)

# Fault injection through global operator new/delete: needs its own executable
add_secure_buffer_test(test_secure_string_exception_safety test_secure_string_exception_safety.cpp)

add_secure_buffer_test(test_secure_array_returns test_secure_array_returns.cpp)
if(NOT MSVC)
    # Same tests with optional copy elision disabled, so returns take the copy path.
    add_secure_buffer_test(test_secure_array_returns_no_elide test_secure_array_returns.cpp)
    target_compile_options(test_secure_array_returns_no_elide PRIVATE -fno-elide-constructors)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # Optimized GCC builds report false positives in std::vector internals
    # (stringop-overflow/overread, worst in the SIZE_MAX tests) and flag the
    # malloc/free new/delete replacement as mismatched-new-delete. Demote these
    # to warnings on the test targets only; the library stays -Werror-clean.
    # The flags need GCC 7 or 11, so probe the positive form of each (GCC
    # accepts any -Wno-* silently) and add only the supported ones.
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-Wstringop-overflow"     SB_HAS_WSTRINGOP_OVERFLOW)
    check_cxx_compiler_flag("-Wstringop-overread"     SB_HAS_WSTRINGOP_OVERREAD)
    check_cxx_compiler_flag("-Wmismatched-new-delete" SB_HAS_WMISMATCHED_NEW_DELETE)

    set(SB_STR_DEMOTE "")
    if(SB_HAS_WSTRINGOP_OVERFLOW)
        list(APPEND SB_STR_DEMOTE -Wno-error=stringop-overflow)
    endif()
    if(SB_HAS_WSTRINGOP_OVERREAD)
        list(APPEND SB_STR_DEMOTE -Wno-error=stringop-overread)
    endif()
    set(SB_EXC_DEMOTE ${SB_STR_DEMOTE})
    if(SB_HAS_WMISMATCHED_NEW_DELETE)
        list(APPEND SB_EXC_DEMOTE -Wno-error=mismatched-new-delete)
    endif()

    if(SB_STR_DEMOTE)
        target_compile_options(test_secure_string PRIVATE ${SB_STR_DEMOTE})
    endif()
    if(SB_EXC_DEMOTE)
        target_compile_options(test_secure_string_exception_safety PRIVATE ${SB_EXC_DEMOTE})
        target_compile_options(test_secure_array_zeroing PRIVATE ${SB_EXC_DEMOTE})
    endif()
endif()

# C++20 rewritten comparisons are only checkable in C++20 mode with a usable <compare>
if(SB_HAS_CXX20_THREE_WAY)
    add_executable(test_comparison_cxx20 test_comparison_cxx20.cpp)
    target_link_libraries(test_comparison_cxx20 PRIVATE safeheron::secure-buffer)
    target_compile_options(test_comparison_cxx20 PRIVATE ${TEST_COMPILE_OPTIONS})
    set_target_properties(test_comparison_cxx20 PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
    add_test(NAME test_comparison_cxx20 COMMAND test_comparison_cxx20)
else()
    message(STATUS "C++20 three-way comparison not available: skipping test_comparison_cxx20 and the *_cxx20 compile-fail cases")
endif()

# Header-hygiene: no platform macros in public headers
add_test(
    NAME test_no_platform_macros
    COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/test_no_platform_macros.cmake
)

# Header-hygiene: each public header compiles standalone
add_subdirectory(test_header_selfcontained)

# Compile-fail tests: invalid uses must be rejected with the documented message
add_subdirectory(compile_fail)
