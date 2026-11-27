#include <gtest/gtest.h>
#include <secure-buffer/secure_memzero.h>
#include <cstring>
#include <vector>

TEST(SecureMemzeroTest, ZerosStackBuffer) {
    unsigned char buf[64];
    std::memset(buf, 0xAB, sizeof(buf));
    safeheron::sbuf::secure_memzero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i) {
        EXPECT_EQ(buf[i], 0) << "byte " << i << " not zeroed";
    }
}

TEST(SecureMemzeroTest, ZerosHeapBuffer) {
    const size_t size = 256;
    auto* buf = new unsigned char[size];
    std::memset(buf, 0xCD, size);
    safeheron::sbuf::secure_memzero(buf, size);
    for (size_t i = 0; i < size; ++i) {
        EXPECT_EQ(buf[i], 0) << "byte " << i << " not zeroed";
    }
    delete[] buf;
}

TEST(SecureMemzeroTest, ZerosZeroLength) {
    unsigned char buf[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    safeheron::sbuf::secure_memzero(buf, 0);
    EXPECT_EQ(buf[0], 0xAA);
    EXPECT_EQ(buf[1], 0xBB);
}

TEST(SecureMemzeroTest, ZerosSingleByte) {
    unsigned char byte = 0xFF;
    safeheron::sbuf::secure_memzero(&byte, 1);
    EXPECT_EQ(byte, 0);
}

TEST(SecureMemzeroTest, ZerosPartialBuffer) {
    unsigned char buf[8];
    std::memset(buf, 0xFF, sizeof(buf));
    safeheron::sbuf::secure_memzero(buf, 4);
    for (size_t i = 0; i < 4; ++i) {
        EXPECT_EQ(buf[i], 0);
    }
    for (size_t i = 4; i < 8; ++i) {
        EXPECT_EQ(buf[i], 0xFF);
    }
}
