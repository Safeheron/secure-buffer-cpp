#include <gtest/gtest.h>
#include <secure-buffer/secure_bytes.h>
#include <secure-buffer/secure_utils.h>
#include <algorithm>
#include <cstdint>
#include <type_traits>
#include <utility>
#include <vector>

using namespace safeheron::sbuf;

namespace {

// Detection traits: true only if `lhs OP rhs` is a well-formed expression
// (a deleted function selected by overload resolution counts as ill-formed).
template <class T, class U, class = void> struct has_equal_with : std::false_type {};
template <class T, class U>
struct has_equal_with<T, U, std::void_t<decltype(std::declval<const T&>() == std::declval<const U&>())>>
    : std::true_type {};

template <class T, class = void> struct has_equal : std::false_type {};
template <class T>
struct has_equal<T, std::void_t<decltype(std::declval<const T&>() == std::declval<const T&>())>>
    : std::true_type {};

template <class T, class = void> struct has_not_equal : std::false_type {};
template <class T>
struct has_not_equal<T, std::void_t<decltype(std::declval<const T&>() != std::declval<const T&>())>>
    : std::true_type {};

template <class T, class = void> struct has_less : std::false_type {};
template <class T>
struct has_less<T, std::void_t<decltype(std::declval<const T&>() < std::declval<const T&>())>>
    : std::true_type {};

template <class T, class = void> struct has_greater : std::false_type {};
template <class T>
struct has_greater<T, std::void_t<decltype(std::declval<const T&>() > std::declval<const T&>())>>
    : std::true_type {};

template <class T, class = void> struct has_less_equal : std::false_type {};
template <class T>
struct has_less_equal<T, std::void_t<decltype(std::declval<const T&>() <= std::declval<const T&>())>>
    : std::true_type {};

template <class T, class = void> struct has_greater_equal : std::false_type {};
template <class T>
struct has_greater_equal<T, std::void_t<decltype(std::declval<const T&>() >= std::declval<const T&>())>>
    : std::true_type {};

bool same_bytes(const SecureBytes& a, const SecureBytes& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

} // namespace

// --- No comparison operators ---

static_assert(!has_equal<SecureBytes>::value && !has_not_equal<SecureBytes>::value &&
              !has_less<SecureBytes>::value && !has_greater<SecureBytes>::value &&
              !has_less_equal<SecureBytes>::value && !has_greater_equal<SecureBytes>::value,
              "SecureBytes has no comparison operators");
static_assert(!has_equal_with<SecureBytes, std::vector<uint8_t>>::value,
              "SecureBytes cannot be compared with a plain vector either");
static_assert(has_equal<std::vector<uint8_t>>::value && has_less<std::vector<uint8_t>>::value,
              "plain std::vector<uint8_t> comparisons are unaffected");

TEST(SecureBytesTest, NonSecretComparisonPaths) {
    SecureBytes a(16, 0xAB);
    SecureBytes b(16, 0xAB);
    SecureBytes c(16, 0xAB);
    c[15] = 0xAC;
    EXPECT_TRUE(std::equal(a.begin(), a.end(), b.begin(), b.end()));
    EXPECT_FALSE(std::equal(a.begin(), a.end(), c.begin(), c.end()));
    EXPECT_TRUE(constant_time_equal(a, b));
    EXPECT_FALSE(constant_time_equal(a, c));
}

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
    EXPECT_TRUE(same_bytes(a, b));

    SecureBytes c = std::move(b);
    EXPECT_TRUE(same_bytes(c, a));
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
    buf.insert(buf.begin() + 2, 0x03);                   // vector interface
    ASSERT_EQ(buf.size(), 4u);
    EXPECT_EQ(buf[2], 0x03);
    buf.erase(buf.begin());
    ASSERT_EQ(buf.size(), 3u);
    EXPECT_EQ(buf[0], 0x02);
    buf.reserve(64);
    buf.shrink_to_fit();                                 // realloc path (old buffer wiped by allocator)
    EXPECT_TRUE(same_bytes(buf, SecureBytes{0x02, 0x03, 0x04}));
}

TEST(SecureAllocatorTest, AllocateReturnsUsablePointer) {
    safeheron::sbuf::SecureAllocator<uint8_t> alloc;
    uint8_t* p = alloc.allocate(16);
    ASSERT_NE(p, nullptr);
    for (int i = 0; i < 16; ++i) p[i] = static_cast<uint8_t>(i);
    EXPECT_EQ(p[15], 15);
    alloc.deallocate(p, 16);
}
