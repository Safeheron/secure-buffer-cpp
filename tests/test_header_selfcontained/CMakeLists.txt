# Compile each public header as the first-and-only include of a generated TU,
# including it twice to exercise the include guard. Discover headers by glob
# so a future public header cannot silently miss this coverage (re-run cmake
# after adding one).
file(GLOB_RECURSE PUBLIC_HEADERS
    RELATIVE "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/include/*.h")

foreach(hdr ${PUBLIC_HEADERS})
    string(MAKE_C_IDENTIFIER "${hdr}" stub_id)
    set(stub "${CMAKE_CURRENT_BINARY_DIR}/selfcontained_${stub_id}.cpp")
    file(WRITE "${stub}"
        "#include <${hdr}>\n#include <${hdr}>\nint main() { return 0; }\n")
    add_executable(selfcontained_${stub_id} "${stub}")
    target_link_libraries(selfcontained_${stub_id} PRIVATE safeheron::secure-buffer)
    secure_buffer_test_options(selfcontained_${stub_id})
    add_test(NAME selfcontained_${stub_id} COMMAND selfcontained_${stub_id})
endforeach()

# Windows consumers often include <windows.h>, which defines function-like
# min/max macros, before these headers. Check that the public headers still
# compile with such macros in effect. The standard headers they use are
# included first (by then a consumer has pulled them in already, and
# libstdc++'s own headers are not written to survive these macros).
set(minmax_stub "${CMAKE_CURRENT_BINARY_DIR}/header_tolerates_minmax_macros.cpp")
file(WRITE "${minmax_stub}"
    "#include <algorithm>\n#include <array>\n#include <cassert>\n#include <cstddef>\n#include <cstdint>\n"
    "#include <cstring>\n#include <iterator>\n#include <memory>\n#include <stdexcept>\n"
    "#include <string>\n#include <string_view>\n#include <type_traits>\n#include <vector>\n"
    "#define min(a, b) (((a) < (b)) ? (a) : (b))\n"
    "#define max(a, b) (((a) > (b)) ? (a) : (b))\n"
    "#include <secure-buffer/secure_buffer.h>\n"
    "int main() {\n"
    "  safeheron::sbuf::SecureString s(\"ab\"); s.append(s.view());\n"
    "  unsigned char k[4] = {1, 2, 3, 4}; safeheron::sbuf::secure_cleanse(k);\n"
    "  if (k[0] != 0) return 1;\n"
    "  safeheron::sbuf::SecureArray<unsigned char, 4> a; a[0] = 1;\n"
    "  safeheron::sbuf::secure_cleanse(a);\n"
    "  if (a[0] != 0) return 1;\n"
    "  if (safeheron::sbuf::as_span(a).first<1>()[0] != 0) return 1;\n"
    "  safeheron::sbuf::span<const unsigned char> v(k, 4);\n"
    "  if (v.subspan(1).size() != 3) return 1;\n"
    "  if (v.first<2>().size() != 2) return 1;\n"
    "  if (!safeheron::sbuf::constant_time_equal(v, v)) return 1;\n"
    "  return static_cast<int>(s.size()) - 4;\n"
    "}\n")
add_executable(header_tolerates_minmax_macros "${minmax_stub}")
target_link_libraries(header_tolerates_minmax_macros PRIVATE safeheron::secure-buffer)
secure_buffer_test_options(header_tolerates_minmax_macros)
add_test(NAME header_tolerates_minmax_macros COMMAND header_tolerates_minmax_macros)

# Consumers sometimes write `using namespace std;` before including these
# headers. In C++20 that brings std::span into scope, and the headers' own
# unqualified span must still mean this library's span: the stub checks the
# types as_span and as_writable_span return.
if(SB_HAS_CXX20_STD_SPAN)
    set(using_std_stub "${CMAKE_CURRENT_BINARY_DIR}/header_tolerates_using_namespace_std.cpp")
    file(WRITE "${using_std_stub}"
        "#include <span>\n"
        "using namespace std;\n"
        "#include <secure-buffer/secure_buffer.h>\n"
        "#include <type_traits>\n"
        "int main() {\n"
        "  safeheron::sbuf::SecureArray<unsigned char, 4> a; a[0] = 1;\n"
        "  static_assert(std::is_same<decltype(safeheron::sbuf::as_span(a)),\n"
        "                             safeheron::sbuf::span<const unsigned char, 4>>::value &&\n"
        "                std::is_same<decltype(safeheron::sbuf::as_writable_span(a)),\n"
        "                             safeheron::sbuf::span<unsigned char, 4>>::value,\n"
        "                \"as_span and as_writable_span return this library's span\");\n"
        "  if (safeheron::sbuf::as_span(a).first<2>()[0] != 1) return 1;\n"
        "  unsigned char k[4] = {1, 2, 3, 4};\n"
        "  safeheron::sbuf::span<const unsigned char> v(k, 4);\n"
        "  return safeheron::sbuf::constant_time_equal(v, v) ? 0 : 1;\n"
        "}\n")
    add_executable(header_tolerates_using_namespace_std "${using_std_stub}")
    target_link_libraries(header_tolerates_using_namespace_std PRIVATE safeheron::secure-buffer)
    set_target_properties(header_tolerates_using_namespace_std
        PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
    secure_buffer_test_options(header_tolerates_using_namespace_std)
    add_test(NAME header_tolerates_using_namespace_std COMMAND header_tolerates_using_namespace_std)
endif()

# Downstream code often builds with conversion warnings as errors; keep the public
# headers clean under them (MSVC's /W4 already covers its narrowing checks).
# The check is that this compiles without a warning, so it keeps -Werror even
# when warnings-as-errors is turned off.
if(NOT MSVC)
    add_executable(header_conversion_clean header_conversion_clean.cpp)
    target_link_libraries(header_conversion_clean PRIVATE safeheron::secure-buffer)
    secure_buffer_test_options(header_conversion_clean)
    target_compile_options(header_conversion_clean PRIVATE -Werror -Wconversion -Wsign-conversion)
    add_test(NAME header_conversion_clean COMMAND header_conversion_clean)
endif()
