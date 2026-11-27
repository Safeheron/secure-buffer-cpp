#include <secure-buffer/version.h>

#include <gtest/gtest.h>
#include <type_traits>

// SECURE_BUFFER_EXPECTED_* come from tests/CMakeLists.txt (PROJECT_VERSION*,
// which cmake/version.cmake read from the same header).
#if !defined(SECURE_BUFFER_VERSION_MAJOR) || !defined(SECURE_BUFFER_VERSION_MINOR) || \
    !defined(SECURE_BUFFER_VERSION_PATCH)
#error "version.h must define the three version numbers"
#endif
// The numbers are usable in #if, and the preprocessor reads the same values as CMake.
#if SECURE_BUFFER_VERSION_MAJOR != SECURE_BUFFER_EXPECTED_MAJOR || \
    SECURE_BUFFER_VERSION_MINOR != SECURE_BUFFER_EXPECTED_MINOR || \
    SECURE_BUFFER_VERSION_PATCH != SECURE_BUFFER_EXPECTED_PATCH
#error "the version numbers in #if differ from PROJECT_VERSION"
#endif

static_assert(std::is_same<decltype(safeheron::sbuf::version()), const char*>::value,
              "version() returns const char*");
static_assert(noexcept(safeheron::sbuf::version()), "version() is noexcept");

TEST(Version, FunctionMatchesHeader) {
    EXPECT_STREQ(safeheron::sbuf::version(), SECURE_BUFFER_VERSION_STRING);
}

TEST(Version, HeaderMatchesCMake) {
    EXPECT_STREQ(SECURE_BUFFER_VERSION_STRING, SECURE_BUFFER_EXPECTED_VERSION);
}
