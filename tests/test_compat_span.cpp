// compat::span tests. The same source is also built as C++20 against std::span
// (SB_TEST_STD_SPAN): every check outside the fallback-only blocks must hold for
// both, which keeps compat::span a strict subset of std::span.
#include <gtest/gtest.h>
#include <secure-buffer/secure_buffer.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <type_traits>
#include <utility>
#include <vector>

#if defined(SB_TEST_STD_SPAN)
#include <span>
#if !defined(__cpp_lib_span) || __cpp_lib_span < 202002L
#error "SB_TEST_STD_SPAN requires a standard library that provides std::span (__cpp_lib_span >= 202002L)"
#endif
#define SB_SPAN std::span
#define SB_DYNAMIC_EXTENT std::dynamic_extent
#else
#include <secure-buffer/compat/span.h>
#define SB_SPAN safeheron::secure_buffer::compat::span
#define SB_DYNAMIC_EXTENT safeheron::secure_buffer::compat::dynamic_extent
#endif

using safeheron::secure_buffer::SecureArray;
using safeheron::secure_buffer::SecureBytes;
using safeheron::secure_buffer::secure_cleanse;
using u8 = std::uint8_t;

namespace {

struct Base { int x; };
struct Derived : Base { int y; };
struct Point { int x; int y; };

// True if S can be copy-list-initialized from {pointer, count}: false when the
// (pointer, count) constructor is explicit.
template <class S, class = void> struct brace_init_ptr_count : std::false_type {};
template <class S>
struct brace_init_ptr_count<S, std::void_t<decltype(std::declval<void (&)(S)>()(
                                   {std::declval<typename S::pointer>(), std::size_t{}}))>>
    : std::true_type {};

constexpr int kInts[4] = {1, 2, 3, 4};

} // namespace

// --- Construction, conversion and deduced types (both backends) ---

static_assert(SB_SPAN<int>::extent == SB_DYNAMIC_EXTENT && SB_SPAN<int, 4>::extent == 4, "extent");
static_assert(std::is_default_constructible<SB_SPAN<int>>::value &&
              std::is_default_constructible<SB_SPAN<int, 0>>::value &&
              !std::is_default_constructible<SB_SPAN<int, 4>>::value,
              "only dynamic and zero-length spans are default constructible");
static_assert(std::is_convertible<int (&)[4], SB_SPAN<int>>::value &&
              std::is_convertible<int (&)[4], SB_SPAN<int, 4>>::value &&
              std::is_convertible<int (&)[4], SB_SPAN<const int, 4>>::value &&
              !std::is_constructible<SB_SPAN<int, 5>, int (&)[4]>::value &&
              !std::is_constructible<SB_SPAN<int>, const int (&)[4]>::value,
              "built-in arrays");
static_assert(std::is_convertible<std::array<int, 4>&, SB_SPAN<int, 4>>::value &&
              std::is_convertible<const std::array<int, 4>&, SB_SPAN<const int, 4>>::value &&
              std::is_convertible<std::array<int, 4>&, SB_SPAN<const int>>::value &&
              !std::is_constructible<SB_SPAN<int, 4>, const std::array<int, 4>&>::value &&
              !std::is_constructible<SB_SPAN<int, 5>, std::array<int, 4>&>::value,
              "std::array");
static_assert(std::is_convertible<SB_SPAN<u8>, SB_SPAN<const u8>>::value &&
              !std::is_constructible<SB_SPAN<u8>, SB_SPAN<const u8>>::value &&
              std::is_convertible<SB_SPAN<u8, 32>, SB_SPAN<const u8, 32>>::value &&
              !std::is_constructible<SB_SPAN<u8, 32>, SB_SPAN<const u8, 32>>::value,
              "adding const is implicit, removing it is rejected");
static_assert(!std::is_constructible<SB_SPAN<const u8>, const char*, std::size_t>::value &&
              !std::is_constructible<SB_SPAN<const char>, SB_SPAN<const u8>>::value &&
              !std::is_constructible<SB_SPAN<Base>, Derived*, std::size_t>::value &&
              !std::is_constructible<SB_SPAN<Base>, SB_SPAN<Derived>>::value,
              "no conversion between different element types");
static_assert(!std::is_constructible<SB_SPAN<const u8>, std::nullptr_t, std::size_t>::value &&
              !std::is_constructible<SB_SPAN<const u8, 4>, std::nullptr_t, std::size_t>::value,
              "a nullptr literal is rejected");
static_assert(brace_init_ptr_count<SB_SPAN<const u8>>::value &&
              !brace_init_ptr_count<SB_SPAN<const u8, 4>>::value &&
              std::is_constructible<SB_SPAN<const u8, 4>, const u8*, std::size_t>::value,
              "(pointer, count) is explicit for a static extent only");
static_assert(std::is_convertible<SB_SPAN<const u8, 4>, SB_SPAN<const u8>>::value &&
              std::is_constructible<SB_SPAN<const u8, 4>, SB_SPAN<const u8>>::value &&
              !std::is_convertible<SB_SPAN<const u8>, SB_SPAN<const u8, 4>>::value &&
              !std::is_constructible<SB_SPAN<const u8, 8>, SB_SPAN<const u8, 4>>::value,
              "static to dynamic is implicit, dynamic to static explicit, N to M rejected");
static_assert(std::is_same<decltype(std::declval<SB_SPAN<int, 8>>().first(2)), SB_SPAN<int>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int, 8>>().last(2)), SB_SPAN<int>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int, 8>>().subspan(2, 3)), SB_SPAN<int>>::value,
              "run-time slices are dynamic, even of a static span");
static_assert(SB_SPAN<const int, 4>(kInts).size() == 4 && SB_SPAN<const int, 4>(kInts)[2] == 3 &&
              SB_SPAN<const int>(kInts).subspan(1, 2)[0] == 2 &&
              SB_SPAN<const int>(kInts).last(1)[0] == 4,
              "usable in constant expressions");
static_assert(std::is_same<decltype(std::declval<SB_SPAN<int, 8>>().first<3>()), SB_SPAN<int, 3>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int, 8>>().last<3>()), SB_SPAN<int, 3>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int, 8>>().subspan<2>()), SB_SPAN<int, 6>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int, 8>>().subspan<2, 3>()), SB_SPAN<int, 3>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int, 8>>().subspan<8>()), SB_SPAN<int, 0>>::value,
              "compile-time slices of a static span");
static_assert(std::is_same<decltype(std::declval<SB_SPAN<int>>().first<3>()), SB_SPAN<int, 3>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int>>().last<3>()), SB_SPAN<int, 3>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int>>().subspan<2>()), SB_SPAN<int>>::value &&
              std::is_same<decltype(std::declval<SB_SPAN<int>>().subspan<2, 3>()), SB_SPAN<int, 3>>::value,
              "compile-time slices of a dynamic span");
static_assert(std::is_same<decltype(std::declval<SB_SPAN<int>>().subspan<2, SB_DYNAMIC_EXTENT>()),
                           SB_SPAN<int>>::value &&
              SB_SPAN<const int>(kInts).subspan<2>().size() == 2 &&
              SB_SPAN<const int>(kInts).subspan<2, SB_DYNAMIC_EXTENT>().size() == 2 &&
              SB_SPAN<const int>(kInts).subspan<2, SB_DYNAMIC_EXTENT>()[0] == 3,
              "subspan<Offset>() and subspan<Offset, dynamic_extent>() of a dynamic span are the rest");
static_assert(std::is_same<decltype(std::declval<SB_SPAN<const int, 8>>().first<3>()),
                           SB_SPAN<const int, 3>>::value,
              "slices keep the element type");
static_assert(SB_SPAN<const int, 4>(kInts).first<2>()[1] == 2 &&
              SB_SPAN<const int, 4>(kInts).subspan<1, 2>()[0] == 2 &&
              SB_SPAN<const int>(kInts).last<1>()[0] == 4,
              "compile-time slices in constant expressions");

namespace {

// True if SB_SPAN(a) deduces its template arguments from an A and builds the span.
template <class A, class = void> struct ctad_ok : std::false_type {};
template <class A>
struct ctad_ok<A, std::void_t<decltype(SB_SPAN(std::declval<A>()))>> : std::true_type {};

} // namespace

static_assert(ctad_ok<int (&)[4]>::value && ctad_ok<const int (&)[4]>::value &&
              ctad_ok<std::array<int, 4>&>::value && ctad_ok<const std::array<int, 4>&>::value,
              "deduction from lvalue arrays");
static_assert(!ctad_ok<int[4]>::value && !ctad_ok<std::array<int, 4>>::value,
              "no deduction from a non-const rvalue array: the view would dangle");
static_assert(std::is_same<decltype(SB_SPAN(std::declval<const std::array<int, 4>>())),
                           SB_SPAN<const int>>::value &&
              std::is_same<decltype(SB_SPAN(std::declval<const int[4]>())), SB_SPAN<const int>>::value,
              "a const rvalue array deduces a dynamic extent");

// --- Iterator (both backends) ---

namespace {

using It = SB_SPAN<int>::iterator;
using ConstIt = SB_SPAN<const int>::iterator;

} // namespace

static_assert(!std::is_convertible<It, int*>::value && !std::is_convertible<It, const void*>::value,
              "an iterator does not convert to a pointer");
static_assert(std::is_default_constructible<It>::value, "iterators are default constructible");
static_assert(std::is_same<std::iterator_traits<It>::value_type, int>::value &&
              std::is_same<std::iterator_traits<It>::reference, int&>::value &&
              std::is_same<std::iterator_traits<It>::difference_type, std::ptrdiff_t>::value &&
              std::is_base_of<std::random_access_iterator_tag,
                              std::iterator_traits<It>::iterator_category>::value,
              "random-access iterator traits");
static_assert(std::is_same<std::iterator_traits<ConstIt>::reference, const int&>::value &&
              std::is_same<std::iterator_traits<ConstIt>::value_type, int>::value,
              "a span of const elements iterates const elements");

namespace {

constexpr int hit(bool b) { return b ? 1 : 0; }

// Walks kInts with every iterator operation; each correct result adds one.
constexpr int iterator_walk() {
    const SB_SPAN<const int> s(kInts);
    const ConstIt first = s.begin();
    const ConstIt last = s.end();
    ConstIt it = first;
    int ok = 0;
    ok += hit(*it == 1);
    ok += hit(*++it == 2);
    ok += hit(*it++ == 2);
    ok += hit(*it == 3);
    ok += hit(*--it == 2);
    ok += hit(*it-- == 2);
    ok += hit(*it == 1);
    it += 3;
    ok += hit(*it == 4);
    it -= 2;
    ok += hit(*it == 2);
    ok += hit(*(it + 1) == 3);
    ok += hit(*(1 + it) == 3);
    ok += hit(*(it - 1) == 1);
    ok += hit(it[2] == 4);
    ok += hit(last - first == 4);
    ok += hit(it - first == 1);
    ok += hit(it == first + 1);
    ok += hit(it != last);
    ok += hit(first < it);
    ok += hit(last > it);
    ok += hit(first <= it);
    ok += hit(it >= first);
    return ok;
}

} // namespace

static_assert(iterator_walk() == 21, "iterator operations are usable in constant expressions");

#if !defined(SB_TEST_STD_SPAN)
// --- compat::span only: properties std::span does not promise, or lacks ---

namespace compat = safeheron::secure_buffer::compat;

namespace {

template <class S, class = void> struct has_cbegin : std::false_type {};
template <class S>
struct has_cbegin<S, std::void_t<decltype(std::declval<const S&>().cbegin())>> : std::true_type {};

template <class A, class B, class = void> struct can_subtract : std::false_type {};
template <class A, class B>
struct can_subtract<A, B, std::void_t<decltype(std::declval<A>() - std::declval<B>())>>
    : std::true_type {};

template <class A, class B, class = void> struct can_compare_equal : std::false_type {};
template <class A, class B>
struct can_compare_equal<A, B, std::void_t<decltype(std::declval<A>() == std::declval<B>())>>
    : std::true_type {};

using FixedIt = compat::span<int, 4>::iterator;

} // namespace

static_assert(!std::is_constructible<compat::span<int>::iterator, int*>::value &&
              !std::is_constructible<compat::span<int>::iterator, std::nullptr_t>::value &&
              !std::is_convertible<std::nullptr_t, compat::span<int>::iterator>::value,
              "no iterator from a pointer: take a pointer from data()");
static_assert(std::is_trivially_copyable<compat::span<int>::iterator>::value,
              "iterators are trivially copyable");
static_assert(!std::is_same<FixedIt, It>::value && !std::is_convertible<FixedIt, It>::value &&
              !std::is_convertible<It, FixedIt>::value &&
              !std::is_constructible<It, FixedIt>::value &&
              !std::is_constructible<FixedIt, It>::value,
              "spans of different extents have unrelated iterator types");
static_assert(can_subtract<It, It>::value && can_compare_equal<It, It>::value &&
              can_subtract<FixedIt, FixedIt>::value && can_compare_equal<FixedIt, FixedIt>::value,
              "iterators of one span type subtract and compare");
static_assert(!can_subtract<FixedIt, It>::value && !can_subtract<It, FixedIt>::value &&
              !can_compare_equal<FixedIt, It>::value && !can_compare_equal<It, FixedIt>::value,
              "iterators of different extents neither subtract nor compare");
static_assert(!std::is_convertible<It, ConstIt>::value && !std::is_convertible<ConstIt, It>::value &&
              !std::is_constructible<It, ConstIt>::value &&
              !std::is_constructible<ConstIt, It>::value &&
              !can_subtract<It, ConstIt>::value && !can_subtract<ConstIt, It>::value &&
              !can_compare_equal<It, ConstIt>::value && !can_compare_equal<ConstIt, It>::value,
              "iterators of span<int> and span<const int> neither convert, construct, subtract nor compare");
static_assert(noexcept(*std::declval<const It&>()) && noexcept(std::declval<const It&>()[1]) &&
              noexcept(std::declval<const It&>().operator->()) &&
              noexcept(++std::declval<It&>()) && noexcept(std::declval<It&>()++) &&
              noexcept(--std::declval<It&>()) && noexcept(std::declval<It&>()--) &&
              noexcept(std::declval<It&>() += 1) && noexcept(std::declval<It&>() -= 1) &&
              noexcept(std::declval<const It&>() + 1) && noexcept(1 + std::declval<const It&>()) &&
              noexcept(std::declval<const It&>() - 1) &&
              noexcept(std::declval<const It&>() - std::declval<const It&>()) &&
              noexcept(std::declval<const It&>() == std::declval<const It&>()) &&
              noexcept(std::declval<const It&>() != std::declval<const It&>()) &&
              noexcept(std::declval<const It&>() < std::declval<const It&>()) &&
              noexcept(std::declval<const It&>() > std::declval<const It&>()) &&
              noexcept(std::declval<const It&>() <= std::declval<const It&>()) &&
              noexcept(std::declval<const It&>() >= std::declval<const It&>()) &&
              noexcept(It()) && noexcept(std::declval<const compat::span<int>&>().begin()),
              "every iterator operation is noexcept");
static_assert(std::is_trivially_copyable<compat::span<int>>::value &&
              std::is_trivially_copyable<compat::span<int, 4>>::value,
              "spans are trivially copyable");
static_assert(!has_cbegin<compat::span<int>>::value, "no cbegin(), as in C++20 std::span");
static_assert(noexcept(compat::span<int>(std::declval<int*>(), std::size_t{})) &&
              noexcept(std::declval<const compat::span<int>&>()[0]) &&
              noexcept(std::declval<const compat::span<int>&>().first(0)) &&
              noexcept(std::declval<const compat::span<int>&>().last(0)) &&
              noexcept(std::declval<const compat::span<int>&>().subspan(0, 0)) &&
              noexcept(std::declval<const compat::span<int>&>().first<1>()) &&
              noexcept(std::declval<const compat::span<int>&>().last<1>()) &&
              noexcept(std::declval<const compat::span<int>&>().subspan<1, 1>()),
              "every operation is noexcept");
static_assert(!std::is_constructible<compat::span<const u8>, const std::vector<u8>&>::value &&
              !std::is_constructible<compat::span<const u8>, const SecureBytes&>::value &&
              !std::is_constructible<compat::span<const u8>, const SecureArray<u8, 4>&>::value &&
              !std::is_constructible<compat::span<const u8, 4>, const std::vector<u8>&>::value &&
              !std::is_constructible<compat::span<const u8, 4>, const SecureBytes&>::value &&
              !std::is_constructible<compat::span<const u8, 4>, const SecureArray<u8, 4>&>::value,
              "no container constructor: borrow through data() and size()");
#endif

// --- Run-time behaviour (both backends) ---

TEST(CompatSpanTest, DefaultIsEmpty) {
    SB_SPAN<const u8> s;
    EXPECT_EQ(s.data(), nullptr);
    EXPECT_EQ(s.size(), 0u);
    EXPECT_TRUE(s.empty());
    EXPECT_TRUE(s.begin() == s.end());

    SB_SPAN<const u8, 0> z;
    EXPECT_EQ(z.data(), nullptr);
    EXPECT_TRUE(z.empty());
}

TEST(CompatSpanTest, TypedNullWithZeroLength) {
    SB_SPAN<const u8> s(static_cast<const u8*>(nullptr), 0);
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.data(), nullptr);
}

TEST(CompatSpanTest, ZeroLengthStdArray) {
    std::array<u8, 0> a{};
    SB_SPAN<u8> d = a;
    SB_SPAN<u8, 0> f = a;
    EXPECT_TRUE(d.empty());
    EXPECT_EQ(f.size(), 0u);
}

TEST(CompatSpanTest, FromArraysKeepsAddressAndLength) {
    u8 raw[4] = {1, 2, 3, 4};
    SB_SPAN<u8> d = raw;
    SB_SPAN<u8, 4> f = raw;
    EXPECT_EQ(d.data(), raw);
    EXPECT_EQ(d.size(), 4u);
    EXPECT_EQ(f.data(), raw);
    EXPECT_EQ(f.size(), 4u);

    std::uint32_t w[3] = {};
    SB_SPAN<std::uint32_t, 3> ws = w;
    EXPECT_EQ(ws.size_bytes(), 12u);

    std::array<u8, 4> a{};
    SB_SPAN<const u8, 4> as = a;
    EXPECT_EQ(as.data(), a.data());
}

TEST(CompatSpanTest, StaticFromPointerAndDynamic) {
    u8 raw[4] = {1, 2, 3, 4};
    SB_SPAN<const u8, 4> p(raw, 4);
    SB_SPAN<const u8, 4> c(SB_SPAN<const u8>(raw, 4));
    EXPECT_EQ(p.data(), raw);
    EXPECT_EQ(p.size(), 4u);
    EXPECT_EQ(c.data(), raw);
    EXPECT_EQ(c.size(), 4u);
}

TEST(CompatSpanTest, RunTimeSlices) {
    int v[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    SB_SPAN<int> s = v;

    EXPECT_EQ(s.first(3).data(), v);
    EXPECT_EQ(s.first(3).size(), 3u);
    EXPECT_EQ(s.last(3).data(), v + 5);
    EXPECT_EQ(s.last(3).size(), 3u);
    EXPECT_EQ(s.subspan(2, 3).data(), v + 2);
    EXPECT_EQ(s.subspan(2, 3).size(), 3u);
    EXPECT_EQ(s.subspan(2).data(), v + 2);
    EXPECT_EQ(s.subspan(2).size(), 6u);
    EXPECT_EQ(s.subspan(1, SB_DYNAMIC_EXTENT).size(), 7u);  // taking to the end is legal
    EXPECT_TRUE(s.subspan(8).empty());
    EXPECT_TRUE(s.subspan(8, 0).empty());
    EXPECT_TRUE(s.first(0).empty());
    EXPECT_TRUE(s.last(0).empty());
    EXPECT_EQ(s.subspan(0).data(), v);

    SB_SPAN<int, 8> f = v;
    auto r = f.subspan(2, 3);
    EXPECT_EQ(r.data(), v + 2);
}

TEST(CompatSpanTest, CompileTimeSlicesOfStaticSpan) {
    u8 buf[128] = {};
    SB_SPAN<const u8, 128> all = buf;

    auto rho = all.first<32>();
    EXPECT_EQ(rho.data(), buf);
    EXPECT_EQ(rho.size(), 32u);
    auto key = all.subspan<32, 32>();
    EXPECT_EQ(key.data(), buf + 32);
    EXPECT_EQ(key.size(), 32u);
    auto tr = all.subspan<64, 64>();
    EXPECT_EQ(tr.data(), buf + 64);
    EXPECT_EQ(tr.size(), 64u);
    auto tail = all.last<16>();
    EXPECT_EQ(tail.data(), buf + 112);
    EXPECT_EQ(tail.size(), 16u);
}

TEST(CompatSpanTest, CompileTimeSlicesOfDynamicSpan) {
    u8 buf[128] = {};
    SB_SPAN<const u8> d = buf;

    auto f = d.first<4>();
    EXPECT_EQ(f.data(), buf);
    EXPECT_EQ(f.size(), 4u);
    auto m = d.subspan<4, 8>();
    EXPECT_EQ(m.data(), buf + 4);
    EXPECT_EQ(m.size(), 8u);
    auto rest = d.subspan<12>();
    EXPECT_EQ(rest.data(), buf + 12);
    EXPECT_EQ(rest.size(), 116u);
    auto rest_explicit = d.subspan<12, SB_DYNAMIC_EXTENT>();
    EXPECT_EQ(rest_explicit.data(), buf + 12);
    EXPECT_EQ(rest_explicit.size(), 116u);
}

TEST(CompatSpanTest, ZeroLengthCompileTimeSlices) {
    u8 buf[128] = {};
    SB_SPAN<const u8, 128> all = buf;
    auto none = all.first<0>();
    auto past_end = all.subspan<128>();
    EXPECT_TRUE(none.empty());
    EXPECT_TRUE(past_end.empty());

    SB_SPAN<int, 0> z;
    auto zf = z.first<0>();
    auto zs = z.subspan<0>();
    EXPECT_TRUE(zf.empty());
    EXPECT_TRUE(zs.empty());
    const bool zf_null = zf.data() == nullptr;
    const bool zs_null = zs.data() == nullptr;
    EXPECT_TRUE(zf_null);
    EXPECT_TRUE(zs_null);
}

TEST(CompatSpanTest, CursorWalksFixedSizeFields) {
    u8 buf[12];
    for (std::size_t i = 0; i < 12; ++i) buf[i] = static_cast<u8>(i);
    SB_SPAN<const u8, 12> whole = buf;
    SB_SPAN<const u8> in = whole.subspan<0>();
    for (std::size_t i = 0; i < 3; ++i) {
        SB_SPAN<const u8, 4> field = in.first<4>();
        EXPECT_EQ(field.data(), buf + 4 * i);
        EXPECT_EQ(field[0], static_cast<u8>(4 * i));
        in = in.subspan(4);
    }
    EXPECT_TRUE(in.empty());
}

TEST(CompatSpanTest, EmptyViewSlicesStayNull) {
    SB_SPAN<int> e;
    EXPECT_EQ(e.first(0).data(), nullptr);
    EXPECT_EQ(e.last(0).data(), nullptr);
    EXPECT_EQ(e.subspan(0).data(), nullptr);
}

TEST(CompatSpanTest, WritesGoThroughToTheOwner) {
    int v[3] = {};
    SB_SPAN<int> s = v;
    s[1] = 5;
    EXPECT_EQ(v[1], 5);

    const SB_SPAN<int, 3> cs = v;
    cs[2] = 7;  // a const span does not make the elements const
    EXPECT_EQ(v[2], 7);

    int sum = 0;
    for (int x : s) sum += x;
    EXPECT_EQ(sum, 12);
}

TEST(CompatSpanTest, IteratorIsRandomAccess) {
    int v[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    SB_SPAN<int> s = v;
    const It b = s.begin();
    const It e = s.end();

    const std::ptrdiff_t length = e - b;
    EXPECT_EQ(length, 8);
    EXPECT_EQ(*(b + 2), 2);
    EXPECT_EQ(*(2 + b), 2);
    EXPECT_EQ(*(e - 1), 7);
    EXPECT_EQ(b[1], 1);

    It it = b;
    it += 3;
    EXPECT_EQ(*it, 3);
    it -= 2;
    EXPECT_EQ(*it, 1);
    EXPECT_EQ(*++it, 2);
    EXPECT_EQ(*it++, 2);
    EXPECT_EQ(*it, 3);
    EXPECT_EQ(*--it, 2);
    EXPECT_EQ(*it--, 2);
    EXPECT_EQ(*it, 1);
    *it = 10;
    EXPECT_EQ(v[1], 10);

    EXPECT_TRUE(b == s.begin());
    EXPECT_FALSE(b != s.begin());
    EXPECT_TRUE(b != e);
    EXPECT_TRUE(b < e);
    EXPECT_FALSE(e < b);
    EXPECT_TRUE(e > b);
    EXPECT_TRUE(b <= s.begin());
    EXPECT_TRUE(b <= e);
    EXPECT_TRUE(e >= s.end());
    EXPECT_FALSE(b >= e);

    Point pts[2] = {{1, 2}, {3, 4}};
    SB_SPAN<Point> ps = pts;
    EXPECT_EQ(ps.begin()->y, 2);
    EXPECT_EQ((ps.begin() + 1)->x, 3);

    const std::reverse_iterator<It> r(s.end());
    EXPECT_EQ(*r, 7);

    int shuffled[8] = {5, 2, 7, 0, 3, 6, 1, 4};
    SB_SPAN<int> sh = shuffled;
    std::sort(sh.begin(), sh.end());
    for (int i = 0; i < 8; ++i) EXPECT_EQ(shuffled[i], i);

    std::array<int, 8> out{};
    std::copy(s.begin(), s.end(), out.begin());
    for (std::size_t i = 0; i < out.size(); ++i) EXPECT_EQ(out[i], v[i]);
}

TEST(CompatSpanTest, DeductionGuidesMatchStd) {
    int c[4] = {};
    std::array<int, 4> a{};
    const std::array<int, 4> ca{};
    int* p = c;
    const int* cp = c;
    SB_SPAN s1 = c;
    SB_SPAN s2 = a;
    SB_SPAN s3 = ca;
    SB_SPAN s4(p, 4);
    SB_SPAN s5(cp, std::size_t{4});
    static_assert(std::is_same<decltype(s1), SB_SPAN<int, 4>>::value, "C array");
    static_assert(std::is_same<decltype(s2), SB_SPAN<int, 4>>::value, "std::array");
    static_assert(std::is_same<decltype(s3), SB_SPAN<const int, 4>>::value, "const std::array");
    static_assert(std::is_same<decltype(s4), SB_SPAN<int>>::value, "pointer and int count");
    static_assert(std::is_same<decltype(s5), SB_SPAN<const int>>::value, "const pointer");
    EXPECT_EQ(s1.size() + s2.size() + s3.size() + s4.size() + s5.size(), 20u);
}

// --- Borrowing from owners (both backends) ---

TEST(CompatSpanBorrowTest, SecureBytesWithoutCopy) {
    SecureBytes b = {1, 2, 3};
    SB_SPAN<u8> s(b.data(), b.size());
    EXPECT_EQ(s.data(), b.data());
    s[0] = 9;
    EXPECT_EQ(b[0], 9);
}

TEST(CompatSpanBorrowTest, SecureArrayStdVectorStdArrayCArray) {
    SecureArray<u8, 4> sa;
    std::vector<u8> vec(4);
    std::array<u8, 4> arr{};
    u8 raw[4] = {};

    SB_SPAN<u8> vsa(sa.data(), sa.size());
    SB_SPAN<u8> vvec(vec.data(), vec.size());
    SB_SPAN<u8> varr(arr.data(), arr.size());
    SB_SPAN<u8> vraw = raw;
    EXPECT_EQ(vsa.data(), sa.data());
    EXPECT_EQ(vvec.data(), vec.data());
    EXPECT_EQ(varr.data(), arr.data());
    EXPECT_EQ(vraw.data(), raw);

    vsa[1] = 1;
    vvec[1] = 2;
    varr[1] = 3;
    vraw[1] = 4;
    EXPECT_EQ(sa[1], 1);
    EXPECT_EQ(vec[1], 2);
    EXPECT_EQ(arr[1], 3);
    EXPECT_EQ(raw[1], 4);
}

TEST(CompatSpanBorrowTest, ViewDestructionLeavesOwnerIntact) {
    SecureBytes b = {1, 2, 3};
    {
        SB_SPAN<u8> s(b.data(), b.size());
        EXPECT_EQ(s.size(), 3u);
    }
    ASSERT_EQ(b.size(), 3u);
    EXPECT_EQ(b[0], 1);
    EXPECT_EQ(b[1], 2);
    EXPECT_EQ(b[2], 3);
}

TEST(CompatSpanBorrowTest, CleanseByOwnerIsVisibleThroughView) {
    const auto all_zero = [](SB_SPAN<const u8> view) {
        return std::all_of(view.begin(), view.end(), [](u8 x) { return x == 0; });
    };

    SecureArray<u8, 4> sa;
    sa[0] = 1;
    SB_SPAN<const u8> vsa(sa.data(), sa.size());
    EXPECT_FALSE(all_zero(vsa));
    secure_cleanse(sa);
    EXPECT_TRUE(all_zero(vsa));

    u8 raw[4] = {};
    raw[0] = 1;
    SB_SPAN<const u8> vraw = raw;
    EXPECT_FALSE(all_zero(vraw));
    secure_cleanse(raw);
    EXPECT_TRUE(all_zero(vraw));

    std::array<u8, 4> arr{};
    arr[0] = 1;
    SB_SPAN<const u8> varr = arr;
    EXPECT_FALSE(all_zero(varr));
    secure_cleanse(arr);
    EXPECT_TRUE(all_zero(varr));
}

// --- Preconditions (compat::span only, debug builds) ---

#if !defined(SB_TEST_STD_SPAN) && !defined(NDEBUG) && GTEST_HAS_DEATH_TEST && !defined(_MSC_VER)
TEST(CompatSpanDeathTest, RunTimePreconditionsAreAsserted) {
    u8 raw[4] = {};
    compat::span<u8> s = raw;
    using S4 = compat::span<u8, 4>;
    EXPECT_DEATH((void)s[4], "[Aa]ssertion");
    EXPECT_DEATH((void)s.first(SIZE_MAX), "[Aa]ssertion");
    EXPECT_DEATH((void)s.last(SIZE_MAX), "[Aa]ssertion");
    EXPECT_DEATH((void)s.subspan(SIZE_MAX), "[Aa]ssertion");
    EXPECT_DEATH((void)s.subspan(5), "[Aa]ssertion");
    // 2 + count wraps around, so a single added comparison would pass
    EXPECT_DEATH((void)s.subspan(2, SIZE_MAX - 1), "[Aa]ssertion");
    EXPECT_DEATH((void)S4(raw, 3), "[Aa]ssertion");
    EXPECT_DEATH((void)S4(compat::span<u8>(raw, 3)), "[Aa]ssertion");
}

TEST(CompatSpanDeathTest, CompileTimeSlicesOfDynamicSpanAreAsserted) {
    u8 raw[4] = {};
    compat::span<u8> s = raw;
    EXPECT_DEATH((void)s.first<5>(), "[Aa]ssertion");
    EXPECT_DEATH((void)s.last<5>(), "[Aa]ssertion");
    EXPECT_DEATH((void)s.subspan<5>(), "[Aa]ssertion");
    // Offset and Count each fit, together they do not
    const auto offset_2_count_3 = [&s] { return s.subspan<2, 3>(); };
    EXPECT_DEATH((void)offset_2_count_3(), "[Aa]ssertion");
}
#endif
