#include <gtest/gtest.h>
#include <secure-buffer/secure_utils.h>
#include <cstdint>

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
