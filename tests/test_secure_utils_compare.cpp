#include <gtest/gtest.h>
#include <secure-buffer/compat/span.h>
#include <secure-buffer/secure_array.h>
#include <secure-buffer/secure_utils.h>
#include <array>
#include <cstdint>
#include <utility>

using namespace safeheron::secure_buffer;

// --- constant_time_equal(const void*, const void*, size_t) ---

TEST(ConstantTimeEqualRawTest, EqualBuffers) {
    uint8_t a[] = {1, 2, 3, 4};
    uint8_t b[] = {1, 2, 3, 4};
    EXPECT_TRUE(constant_time_equal(a, b, 4));
}

TEST(ConstantTimeEqualRawTest, NotEqualFirstByte) {
    uint8_t a[] = {9, 2, 3, 4};
    uint8_t b[] = {1, 2, 3, 4};
    EXPECT_FALSE(constant_time_equal(a, b, 4));
}

TEST(ConstantTimeEqualRawTest, NotEqualLastByte) {
    uint8_t a[] = {1, 2, 3, 4};
    uint8_t b[] = {1, 2, 3, 5};
    EXPECT_FALSE(constant_time_equal(a, b, 4));
}

TEST(ConstantTimeEqualRawTest, ZeroLengthAlwaysEqual) {
    uint8_t a[] = {1};
    uint8_t b[] = {2};
    EXPECT_TRUE(constant_time_equal(a, b, 0));
}

// --- constant_time_equal(const void*, size_t, const void*, size_t) ---

TEST(ConstantTimeEqualLenTest, EqualSameLength) {
    uint8_t a[] = {0xAA, 0xBB};
    uint8_t b[] = {0xAA, 0xBB};
    EXPECT_TRUE(constant_time_equal(a, static_cast<size_t>(2), b, static_cast<size_t>(2)));
}

TEST(ConstantTimeEqualLenTest, DifferentLengthsReturnFalse) {
    uint8_t a[] = {1, 2, 3};
    uint8_t b[] = {1, 2, 3, 4};
    EXPECT_FALSE(constant_time_equal(a, static_cast<size_t>(3), b, static_cast<size_t>(4)));
}

TEST(ConstantTimeEqualLenTest, BothEmpty) {
    uint8_t a[] = {0};
    uint8_t b[] = {0};
    EXPECT_TRUE(constant_time_equal(a, static_cast<size_t>(0), b, static_cast<size_t>(0)));
}

// --- constant_time_equal(const SecureBytes&, const SecureBytes&) ---

TEST(ConstantTimeEqualBytesTest, Equal) {
    SecureBytes a = {1, 2, 3};
    SecureBytes b = {1, 2, 3};
    EXPECT_TRUE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualBytesTest, NotEqual) {
    SecureBytes a = {1, 2, 3};
    SecureBytes b = {1, 2, 4};
    EXPECT_FALSE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualBytesTest, DifferentSizes) {
    SecureBytes a = {1, 2, 3};
    SecureBytes b = {1, 2};
    EXPECT_FALSE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualBytesTest, BothEmpty) {
    SecureBytes a;
    SecureBytes b;
    EXPECT_TRUE(constant_time_equal(a, b));
}

// --- constant_time_equal(const SecureString&, const SecureString&) ---

TEST(ConstantTimeEqualStringTest, Equal) {
    SecureString a("secret");
    SecureString b("secret");
    EXPECT_TRUE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualStringTest, NotEqualSameLength) {
    SecureString a("secret");
    SecureString b("differ");
    EXPECT_FALSE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualStringTest, DifferentSizes) {
    SecureString a("secret");
    SecureString b("short");
    EXPECT_FALSE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualStringTest, BothEmpty) {
    SecureString a;
    SecureString b;
    EXPECT_TRUE(constant_time_equal(a, b));
}


// --- Additional coverage ---

TEST(ConstantTimeEqualRawTest, MultipleDifferencesAccumulateOver32Bytes) {
    unsigned char a[32], b[32];
    for (int i = 0; i < 32; ++i) a[i] = b[i] = static_cast<unsigned char>(i);
    EXPECT_TRUE(constant_time_equal(a, b, 32));
    b[0] ^= 0x01; b[15] ^= 0x80; b[31] ^= 0xFF;   // first, middle, last differ
    EXPECT_FALSE(constant_time_equal(a, b, 32));
    b[0] ^= 0x01; b[31] ^= 0xFF;                   // only the middle diff remains
    EXPECT_FALSE(constant_time_equal(a, b, 32));
}

// --- constant_time_equal(SecureArray, SecureArray) ---

static_assert(noexcept(constant_time_equal(std::declval<const SecureArray<uint8_t, 32>&>(),
                                           std::declval<const SecureArray<uint8_t, 32>&>())),
              "the SecureArray overload is noexcept");

TEST(ConstantTimeEqualSecureArrayTest, Equal) {
    SecureArray<uint8_t, 32> a;
    SecureArray<uint8_t, 32> b;
    for (size_t i = 0; i < 32; ++i) a[i] = b[i] = 0x5A;
    EXPECT_TRUE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualSecureArrayTest, DifferentLastByte) {
    SecureArray<uint8_t, 32> a;
    SecureArray<uint8_t, 32> b;
    for (size_t i = 0; i < 32; ++i) a[i] = b[i] = 0x5A;
    b[31] ^= 0x01;
    EXPECT_FALSE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualSecureArrayTest, WiderElementsCompareAllBytes) {
    SecureArray<uint32_t, 4> a;
    SecureArray<uint32_t, 4> b;
    for (size_t i = 0; i < 4; ++i) a[i] = b[i] = 0x11223344u + static_cast<uint32_t>(i);
    EXPECT_TRUE(constant_time_equal(a, b));
    b[3] = a[3] ^ 0x01000000u;   // differs only in the most significant byte of the last element
    EXPECT_FALSE(constant_time_equal(a, b));
}

TEST(ConstantTimeEqualSecureArrayTest, ZeroLength) {
    SecureArray<uint8_t, 0> a;
    SecureArray<uint8_t, 0> b;
    EXPECT_TRUE(constant_time_equal(a, b));
}

// --- constant_time_equal(span<const uint8_t>, span<const uint8_t>) ---

using CSpan = compat::span<const uint8_t>;

static_assert(noexcept(constant_time_equal(CSpan(), CSpan())), "noexcept");

TEST(ConstantTimeEqualSpanTest, Equal) {
    uint8_t a[] = {1, 2, 3};
    uint8_t b[] = {1, 2, 3};
    EXPECT_TRUE(constant_time_equal(CSpan(a), CSpan(b)));
}

TEST(ConstantTimeEqualSpanTest, NotEqualLastByte) {
    uint8_t a[] = {1, 2, 3};
    uint8_t b[] = {1, 2, 4};
    EXPECT_FALSE(constant_time_equal(CSpan(a), CSpan(b)));
}

TEST(ConstantTimeEqualSpanTest, DifferentSizes) {
    uint8_t a[] = {1, 2, 3};
    uint8_t b[] = {1, 2, 3, 4};
    EXPECT_FALSE(constant_time_equal(CSpan(a), CSpan(b)));
}

TEST(ConstantTimeEqualSpanTest, BothEmpty) {
    EXPECT_TRUE(constant_time_equal(CSpan(), CSpan()));
}

TEST(ConstantTimeEqualSpanTest, OneEmpty) {
    uint8_t a[] = {1, 2, 3};
    EXPECT_FALSE(constant_time_equal(CSpan(a), CSpan()));
}

TEST(ConstantTimeEqualSpanTest, TypedNullWithZeroLength) {
    EXPECT_TRUE(constant_time_equal(CSpan(static_cast<const uint8_t*>(nullptr), 0), CSpan()));
}

TEST(ConstantTimeEqualSpanTest, ImplicitConversions) {
    uint8_t raw1[4] = {1, 2, 3, 4}, raw2[4] = {1, 2, 3, 4};
    std::array<uint8_t, 4> arr1{{1, 2, 3, 4}};
    std::array<uint8_t, 4> arr2 = arr1;
    compat::span<uint8_t> mut(raw1);
    compat::span<const uint8_t, 4> fixed(raw2);
    EXPECT_TRUE(constant_time_equal(raw1, raw2));
    EXPECT_TRUE(constant_time_equal(arr1, arr2));
    EXPECT_TRUE(constant_time_equal(mut, fixed));
    EXPECT_TRUE(constant_time_equal(fixed, arr1));
    arr2[3] = 0;
    EXPECT_FALSE(constant_time_equal(arr1, arr2));
}

TEST(ConstantTimeEqualSpanTest, ZeroLengthStaticViews) {
    compat::span<const uint8_t, 0> e1;
    compat::span<const uint8_t, 0> e2;
    EXPECT_TRUE(constant_time_equal(e1, e2));
}
