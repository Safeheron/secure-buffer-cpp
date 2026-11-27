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
    target_compile_options(selfcontained_${stub_id} PRIVATE ${TEST_COMPILE_OPTIONS})
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
    "  safeheron::secure_buffer::SecureString s(\"ab\"); s.append(s.view());\n"
    "  unsigned char k[4] = {1, 2, 3, 4}; safeheron::secure_buffer::secure_cleanse(k);\n"
    "  if (k[0] != 0) return 1;\n"
    "  safeheron::secure_buffer::SecureArray<unsigned char, 4> a; a[0] = 1;\n"
    "  safeheron::secure_buffer::secure_cleanse(a);\n"
    "  if (a[0] != 0) return 1;\n"
    "  if (safeheron::secure_buffer::as_span(a).first<1>()[0] != 0) return 1;\n"
    "  safeheron::secure_buffer::compat::span<const unsigned char> v(k, 4);\n"
    "  if (v.subspan(1).size() != 3) return 1;\n"
    "  if (v.first<2>().size() != 2) return 1;\n"
    "  if (!safeheron::secure_buffer::constant_time_equal(v, v)) return 1;\n"
    "  return static_cast<int>(s.size()) - 4;\n"
    "}\n")
add_executable(header_tolerates_minmax_macros "${minmax_stub}")
target_link_libraries(header_tolerates_minmax_macros PRIVATE safeheron::secure-buffer)
target_compile_options(header_tolerates_minmax_macros PRIVATE ${TEST_COMPILE_OPTIONS})
add_test(NAME header_tolerates_minmax_macros COMMAND header_tolerates_minmax_macros)

# Downstream code often builds with conversion warnings as errors; keep the public
# headers clean under them (MSVC's /W4 already covers its narrowing checks).
if(NOT MSVC)
    add_executable(header_conversion_clean header_conversion_clean.cpp)
    target_link_libraries(header_conversion_clean PRIVATE safeheron::secure-buffer)
    target_compile_options(header_conversion_clean PRIVATE
        ${TEST_COMPILE_OPTIONS} -Wconversion -Wsign-conversion)
    add_test(NAME header_conversion_clean COMMAND header_conversion_clean)
endif()
