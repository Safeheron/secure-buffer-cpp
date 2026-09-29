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
    "#include <algorithm>\n#include <cassert>\n#include <cstddef>\n#include <cstdint>\n"
    "#include <cstring>\n#include <iterator>\n#include <memory>\n#include <stdexcept>\n"
    "#include <string>\n#include <string_view>\n#include <type_traits>\n#include <vector>\n"
    "#define min(a, b) (((a) < (b)) ? (a) : (b))\n"
    "#define max(a, b) (((a) > (b)) ? (a) : (b))\n"
    "#include <secure-buffer/secure_buffer.h>\n"
    "int main() { safeheron::secure_buffer::SecureString s(\"ab\"); s.append(s.view()); return static_cast<int>(s.size()) - 4; }\n")
add_executable(header_tolerates_minmax_macros "${minmax_stub}")
target_link_libraries(header_tolerates_minmax_macros PRIVATE safeheron::secure-buffer)
target_compile_options(header_tolerates_minmax_macros PRIVATE ${TEST_COMPILE_OPTIONS})
add_test(NAME header_tolerates_minmax_macros COMMAND header_tolerates_minmax_macros)
