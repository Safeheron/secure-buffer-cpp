#include <gtest/gtest.h>
#include <secure-buffer/secure_bytes.h>

using namespace safeheron::secure_buffer;

// --- SecureBytes basic ---

TEST(SecureBytesTest, DefaultConstruction) {
    SecureBytes buf;
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
}

TEST(SecureBytesTest, SizedConstruction) {
    SecureBytes buf(32, 0);
    EXPECT_EQ(buf.size(), 32u);
    for (auto b : buf) EXPECT_EQ(b, 0);
}

TEST(SecureBytesTest, CopyAndMove) {
    SecureBytes a(16, 0xAB);
    SecureBytes b = a;
    EXPECT_EQ(a, b);

    SecureBytes c = std::move(b);
    EXPECT_EQ(c, a);
    EXPECT_TRUE(b.empty());
}

TEST(SecureBytesTest, PushBackAndResize) {
    SecureBytes buf;
    buf.push_back(0x01);
    buf.push_back(0x02);
    EXPECT_EQ(buf.size(), 2u);
    EXPECT_EQ(buf[0], 0x01);
    EXPECT_EQ(buf[1], 0x02);

    buf.resize(5, 0xFF);
    EXPECT_EQ(buf.size(), 5u);
    EXPECT_EQ(buf[2], 0xFF);
}

// --- make_secure_bytes ---

TEST(MakeSecureBytesTest, CorrectSize) {
    auto key = make_secure_bytes<32>();
    EXPECT_EQ(key.size(), 32u);
    for (auto b : key) EXPECT_EQ(b, 0);
}

TEST(MakeSecureBytesTest, ZeroSize) {
    auto empty = make_secure_bytes<0>();
    EXPECT_EQ(empty.size(), 0u);
}

// --- Additional coverage ---

TEST(SecureBytesTest, InsertEraseShrinkToFit) {
    SecureBytes buf = {0x01, 0x02, 0x04};
    buf.insert(buf.begin() + 2, 0x03);                   // full vector interface
    ASSERT_EQ(buf.size(), 4u);
    EXPECT_EQ(buf[2], 0x03);
    buf.erase(buf.begin());
    ASSERT_EQ(buf.size(), 3u);
    EXPECT_EQ(buf[0], 0x02);
    buf.reserve(64);
    buf.shrink_to_fit();                                 // realloc path (old buffer wiped by allocator)
    EXPECT_EQ(buf, (SecureBytes{0x02, 0x03, 0x04}));
}

TEST(SecureAllocatorTest, AllocateReturnsUsablePointer) {
    safeheron::secure_buffer::SecureAllocator<uint8_t> alloc;
    uint8_t* p = alloc.allocate(16);
    ASSERT_NE(p, nullptr);
    for (int i = 0; i < 16; ++i) p[i] = static_cast<uint8_t>(i);
    EXPECT_EQ(p[15], 15);
    alloc.deallocate(p, 16);
}
