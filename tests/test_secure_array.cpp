#include <gtest/gtest.h>
#include <secure-buffer/secure_buffer.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

using namespace safeheron::secure_buffer;
using A = SecureArray<uint8_t, 32>;

static_assert(A::size() == 32 && !A::empty() && SecureArray<uint8_t, 0>::empty(),
              "size() and empty() are compile-time constants");
static_assert(std::is_same<A::iterator, uint8_t*>::value &&
              std::is_same<A::const_iterator, const uint8_t*>::value,
              "iterators are raw pointers");
static_assert(std::is_nothrow_default_constructible<A>::value &&
              std::is_nothrow_copy_constructible<A>::value &&
              std::is_nothrow_copy_assignable<A>::value &&
              std::is_nothrow_move_constructible<A>::value &&   // a copy
              std::is_nothrow_move_assignable<A>::value,
              "SecureArray special members are noexcept");
static_assert(!std::is_assignable<A&&, const A&>::value, "no assignment to temporaries");
static_assert(!std::is_constructible<A, std::array<uint8_t, 32>>::value &&
              !std::is_convertible<A, std::array<uint8_t, 32>>::value &&
              !std::is_assignable<A&, std::array<uint8_t, 32>>::value,
              "no conversion to or from std::array");
static_assert(noexcept(std::declval<A&>().data()) && noexcept(std::declval<A&>().begin()) &&
              !noexcept(std::declval<A&>()[0]) && !noexcept(std::declval<A&>().at(0)),
              "noexcept only on wide-contract members");
static_assert(noexcept(secure_cleanse(std::declval<A&>())), "secure_cleanse is noexcept");
static_assert(!detail::is_cleansable<A>::value, "ScopedCleanse rejects it: it wipes itself");

namespace {

template <typename Arr>
bool AllEqual(const Arr& a, int v) {
    return std::all_of(a.begin(), a.end(), [v](auto x) { return x == static_cast<decltype(x)>(v); });
}

A Make() {
    A r;
    r[0] = 42;
    return r;
}

} // namespace

TEST(SecureArrayTest, DefaultIsAllZero) {
    A a;
    SecureArray<int32_t, 256> c;
    EXPECT_TRUE(AllEqual(a, 0));
    EXPECT_TRUE(AllEqual(c, 0));
}

TEST(SecureArrayTest, ElementAccess) {
    A a;
    a[0] = 1;
    a.at(1) = 2;
    a.front() += 3;
    a.back() = 9;
    const A& c = a;
    EXPECT_EQ(c[0], 4);
    EXPECT_EQ(c.at(1), 2);
    EXPECT_EQ(c.front(), 4);
    EXPECT_EQ(c.back(), 9);
    EXPECT_EQ(&a.front(), a.data());
    EXPECT_EQ(&a.back(), a.data() + 31);
    EXPECT_EQ(&c.front(), c.data());
    EXPECT_EQ(&c.back(), c.data() + 31);
}

TEST(SecureArrayTest, AtThrowsOutOfRange) {
    A a;
    const A& c = a;
    EXPECT_THROW(a.at(32), std::out_of_range);
    EXPECT_THROW(c.at(32), std::out_of_range);
}

TEST(SecureArrayTest, IteratorsCoverAllElements) {
    A a;
    for (auto& x : a) x = 0x11;
    EXPECT_EQ(std::count(a.cbegin(), a.cend(), 0x11), 32);
    EXPECT_EQ(a.end() - a.begin(), 32);
}

TEST(SecureArrayTest, CopyConstructionKeepsSource) {
    A a;
    std::fill(a.begin(), a.end(), uint8_t{0xAA});
    A b(a);
    EXPECT_TRUE(AllEqual(a, 0xAA));
    EXPECT_TRUE(AllEqual(b, 0xAA));
    EXPECT_NE(b.data(), a.data());
}

TEST(SecureArrayTest, CopyAssignmentOverwritesInPlace) {
    A a;
    std::fill(a.begin(), a.end(), uint8_t{0xAA});
    A b;
    const uint8_t* before = b.data();
    b = a;
    EXPECT_TRUE(AllEqual(b, 0xAA));
    EXPECT_EQ(b.data(), before);
}

TEST(SecureArrayTest, SelfAssignmentKeepsContent) {
    A a;
    std::fill(a.begin(), a.end(), uint8_t{0xAA});
    A& alias = a;
    a = alias;
    EXPECT_TRUE(AllEqual(a, 0xAA));
}

TEST(SecureArrayTest, MoveIsACopy) {
    A a;
    std::fill(a.begin(), a.end(), uint8_t{0xAA});
    A b = std::move(a);
    EXPECT_TRUE(AllEqual(b, 0xAA));
    EXPECT_TRUE(AllEqual(a, 0xAA));  // NOLINT: the source of a move keeps its value
}

TEST(SecureArrayTest, ReturnByValue) {
    EXPECT_EQ(Make()[0], 42);
}

TEST(SecureArrayTest, StdSwapExchangesContents) {
    A a, b;
    std::fill(a.begin(), a.end(), uint8_t{1});
    std::fill(b.begin(), b.end(), uint8_t{2});
    std::swap(a, b);
    EXPECT_TRUE(AllEqual(a, 2));
    EXPECT_TRUE(AllEqual(b, 1));
}

TEST(SecureArrayTest, WorksInStdVector) {
    std::vector<A> v;
    v.reserve(1);
    for (int i = 1; i <= 4; ++i) {
        A x;
        std::fill(x.begin(), x.end(), static_cast<uint8_t>(i));
        v.push_back(x);  // reallocates: elements are relocated by copy
    }
    ASSERT_EQ(v.size(), 4u);
    for (int i = 0; i < 4; ++i) EXPECT_TRUE(AllEqual(v[static_cast<size_t>(i)], i + 1));
}

TEST(SecureArrayTest, SecureCleanseWipesInPlace) {
    A a;
    std::fill(a.begin(), a.end(), uint8_t{0xAA});
    secure_cleanse(a);
    EXPECT_TRUE(AllEqual(a, 0));
    EXPECT_EQ(a.size(), 32u);
    a[0] = 7;
    EXPECT_EQ(a[0], 7);
}

TEST(SecureArrayTest, WiderElementTypes) {
    SecureArray<int32_t, 256> i;
    std::fill(i.begin(), i.end(), int32_t{-5});
    EXPECT_TRUE(AllEqual(i, -5));
    secure_cleanse(i);
    EXPECT_TRUE(AllEqual(i, 0));

    SecureArray<uint64_t, 4> u;
    std::fill(u.begin(), u.end(), UINT64_C(0xFFFFFFFFFFFFFFFF));
    EXPECT_EQ(u[3], UINT64_C(0xFFFFFFFFFFFFFFFF));
    secure_cleanse(u);
    EXPECT_TRUE(AllEqual(u, 0));

    SecureArray<std::byte, 8> b;
    std::fill(b.begin(), b.end(), std::byte{0xFF});
    EXPECT_EQ(b[7], std::byte{0xFF});
    secure_cleanse(b);
    EXPECT_TRUE(std::all_of(b.begin(), b.end(), [](std::byte x) { return x == std::byte{0}; }));

    SecureArray<bool, 6> f;
    std::fill(f.begin(), f.end(), true);
    EXPECT_TRUE(f[5]);
    secure_cleanse(f);
    EXPECT_TRUE(std::none_of(f.begin(), f.end(), [](bool x) { return x; }));
}

TEST(SecureArrayTest, ZeroLengthArray) {
    {
        SecureArray<uint8_t, 0> z;
        secure_cleanse(z);
        EXPECT_TRUE(z.empty());
        EXPECT_EQ(z.begin(), z.end());
        EXPECT_THROW(z.at(0), std::out_of_range);
    }  // destructor runs
}
