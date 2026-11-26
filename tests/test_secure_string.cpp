#include <gtest/gtest.h>
#include <secure-buffer/secure_string.h>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <algorithm>
#include <cctype>
#include <iterator>
#include <type_traits>
#include <utility>
#include <vector>

using namespace safeheron::secure_buffer;

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

} // namespace

// --- Construction ---

TEST(SecureStringTest, DefaultConstruction) {
    SecureString s;
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
    EXPECT_EQ(s.length(), 0u);
    EXPECT_STREQ(s.c_str(), "");
}

TEST(SecureStringTest, ConstructFromCStr) {
    SecureString s("hello");
    EXPECT_EQ(s.size(), 5u);
    EXPECT_STREQ(s.c_str(), "hello");
}

TEST(SecureStringTest, ConstructFromCStrWithLen) {
    SecureString s("hello world", 5);
    EXPECT_EQ(s.size(), 5u);
    EXPECT_STREQ(s.c_str(), "hello");
}

TEST(SecureStringTest, FillConstruction) {
    SecureString s(4, '*');
    EXPECT_EQ(s.size(), 4u);
    EXPECT_STREQ(s.c_str(), "****");
}

TEST(SecureStringTest, ConstructFromRuntimeNullThrows) {
    const char* p = nullptr;
    EXPECT_THROW((void)SecureString(p), std::invalid_argument);
}

TEST(SecureStringTest, CopyConstruction) {
    SecureString a("secret");
    SecureString b(a);
    EXPECT_EQ(a.view(), b.view());
    EXPECT_STREQ(b.c_str(), "secret");
}

TEST(SecureStringTest, MoveConstruction) {
    SecureString a("secret");
    SecureString b(std::move(a));
    EXPECT_STREQ(b.c_str(), "secret");
    EXPECT_TRUE(a.empty());
}

// --- Assignment ---

TEST(SecureStringTest, CopyAssignment) {
    SecureString a("hello");
    SecureString b;
    b = a;
    EXPECT_EQ(a.view(), b.view());
}

TEST(SecureStringTest, MoveAssignment) {
    SecureString a("hello");
    SecureString b;
    b = std::move(a);
    EXPECT_STREQ(b.c_str(), "hello");
    EXPECT_TRUE(a.empty());
}

TEST(SecureStringTest, AssignFromCStr) {
    SecureString s("old");
    s = "new value";
    EXPECT_STREQ(s.c_str(), "new value");
}

TEST(SecureStringTest, AssignRuntimeNullThrowsAndPreserves) {
    SecureString s("old");
    const char* p = nullptr;
    EXPECT_THROW(s = p, std::invalid_argument);
    EXPECT_EQ(s.view(), "old");              // strong guarantee: untouched
    EXPECT_EQ(s.c_str()[3], '\0');
}

// --- Element access ---

TEST(SecureStringTest, OperatorBracket) {
    SecureString s("abc");
    EXPECT_EQ(s[0], 'a');
    EXPECT_EQ(s[2], 'c');
}

TEST(SecureStringTest, OperatorBracketNonConst) {
    SecureString s("abc");
    s[0] = 'X';
    EXPECT_STREQ(s.c_str(), "Xbc");
}

TEST(SecureStringTest, At) {
    SecureString s("abc");
    EXPECT_EQ(s.at(1), 'b');
    EXPECT_THROW(s.at(3), std::out_of_range);
}

TEST(SecureStringTest, AtNonConst) {
    SecureString s("abc");
    s.at(0) = 'Z';
    EXPECT_STREQ(s.c_str(), "Zbc");
}

TEST(SecureStringTest, FrontBack) {
    SecureString s("abc");
    EXPECT_EQ(s.front(), 'a');
    EXPECT_EQ(s.back(), 'c');
}

TEST(SecureStringTest, FrontBackNonConst) {
    SecureString s("abc");
    s.front() = 'Z';
    s.back() = 'Y';
    EXPECT_STREQ(s.c_str(), "ZbY");
}

TEST(SecureStringTest, DataAndCStr) {
    SecureString s("test");
    EXPECT_STREQ(s.c_str(), "test");
    EXPECT_STREQ(s.data(), "test");
    EXPECT_EQ(s.data(), s.c_str());
}

TEST(SecureStringTest, DataNonConst) {
    SecureString s("abc");
    char* p = s.data();
    p[0] = 'X';
    EXPECT_STREQ(s.c_str(), "Xbc");
}

// --- Capacity ---

TEST(SecureStringTest, ResizeGrow) {
    SecureString s("abc");
    s.resize(5, 'x');
    EXPECT_EQ(s.size(), 5u);
    EXPECT_STREQ(s.c_str(), "abcxx");
}

TEST(SecureStringTest, ResizeShrink) {
    SecureString s("abcdef");
    s.resize(2);
    EXPECT_EQ(s.size(), 2u);
    EXPECT_STREQ(s.c_str(), "ab");
}

TEST(SecureStringTest, Reserve) {
    SecureString s;
    s.reserve(100);
    EXPECT_EQ(s.size(), 0u);
}

// --- Iterators ---

TEST(SecureStringTest, ForwardIteration) {
    SecureString s("abc");
    std::string collected;
    for (auto it = s.begin(); it != s.end(); ++it) {
        collected += *it;
    }
    EXPECT_EQ(collected, "abc");
}

TEST(SecureStringTest, RangeBasedFor) {
    SecureString s("xyz");
    std::string collected;
    for (char c : s) {
        collected += c;
    }
    EXPECT_EQ(collected, "xyz");
}

TEST(SecureStringTest, ConstIterators) {
    const SecureString s("test");
    std::string collected(s.cbegin(), s.cend());
    EXPECT_EQ(collected, "test");
}

TEST(SecureStringTest, ReverseIterators) {
    SecureString s("abc");
    std::string reversed(s.rbegin(), s.rend());
    EXPECT_EQ(reversed, "cba");
}

TEST(SecureStringTest, ConstReverseIterators) {
    const SecureString s("abc");
    std::string reversed(s.crbegin(), s.crend());
    EXPECT_EQ(reversed, "cba");
}

TEST(SecureStringTest, NonConstIteratorModify) {
    SecureString s("abc");
    std::transform(s.begin(), s.end(), s.begin(), [](char c) {
        return static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    });
    EXPECT_STREQ(s.c_str(), "ABC");
}

// --- Comparison ---

TEST(SecureStringTest, ViewEquality) {
    SecureString a("hello");
    SecureString b("hello");
    SecureString c("world");
    EXPECT_TRUE(a.view() == b.view());
    EXPECT_FALSE(a.view() == c.view());
    EXPECT_FALSE(a.view() != b.view());
    EXPECT_TRUE(a.view() != c.view());
}

TEST(SecureStringTest, EqualityWithLiteralsGoesThroughView) {
    SecureString s("hello");
    EXPECT_TRUE(s.view() == "hello");
    EXPECT_FALSE(s.view() == "world");
    EXPECT_TRUE(s.view() != "world");
    EXPECT_TRUE(s.view() == std::string("hello"));
    EXPECT_TRUE("hello" == s.view());        // symmetric: works in either operand order
}

TEST(SecureStringTest, EqualityEmpty) {
    SecureString a;
    SecureString b;
    EXPECT_TRUE(a.view() == b.view());
    EXPECT_TRUE(a.view() == "");
    EXPECT_TRUE(a.view().empty());
}

// --- Swap ---

TEST(SecureStringTest, Swap) {
    SecureString a("aaa");
    SecureString b("bbb");
    a.swap(b);
    EXPECT_STREQ(a.c_str(), "bbb");
    EXPECT_STREQ(b.c_str(), "aaa");
}

// --- Conversion ---

TEST(SecureStringTest, ToUnsecureString) {
    SecureString s("secret");
    std::string result = s.to_unsecure_string();
    EXPECT_EQ(result, "secret");
}

TEST(SecureStringTest, ToUnsecureStringEmpty) {
    SecureString s;
    std::string result = s.to_unsecure_string();
    EXPECT_TRUE(result.empty());
}

// --- Modification ---

TEST(SecureStringTest, AppendCStr) {
    SecureString s("hello");
    s.append(" world");
    EXPECT_STREQ(s.c_str(), "hello world");
}

TEST(SecureStringTest, AppendCStrWithLen) {
    SecureString s("hello");
    s.append(" world!!!", 6);
    EXPECT_STREQ(s.c_str(), "hello world");
}

TEST(SecureStringTest, AppendSecureString) {
    SecureString s("hello");
    SecureString suffix(" world");
    s.append(suffix);
    EXPECT_STREQ(s.c_str(), "hello world");
}

TEST(SecureStringTest, AppendFill) {
    SecureString s("ab");
    s.append(3, 'c');
    EXPECT_STREQ(s.c_str(), "abccc");
}

TEST(SecureStringTest, AppendRuntimeNullThrowsAndPreserves) {
    SecureString s("hello");
    const char* p = nullptr;
    EXPECT_THROW(s.append(p), std::invalid_argument);
    EXPECT_THROW(s += p, std::invalid_argument);
    EXPECT_EQ(s.view(), "hello");
    EXPECT_STREQ(s.c_str(), "hello");
}

TEST(SecureStringTest, OperatorPlusEqual) {
    SecureString s("a");
    s += "bc";
    s += 'd';
    SecureString suffix("ef");
    s += suffix;
    EXPECT_STREQ(s.c_str(), "abcdef");
}

TEST(SecureStringTest, PushBack) {
    SecureString s("ab");
    s.push_back('c');
    EXPECT_STREQ(s.c_str(), "abc");
    EXPECT_EQ(s.size(), 3u);
}

TEST(SecureStringTest, PopBack) {
    SecureString s("abc");
    s.pop_back();
    EXPECT_STREQ(s.c_str(), "ab");
    EXPECT_EQ(s.size(), 2u);
}

TEST(SecureStringTest, PopBackToEmpty) {
    SecureString s("a");
    s.pop_back();
    EXPECT_TRUE(s.empty());
    EXPECT_STREQ(s.c_str(), "");
}

TEST(SecureStringTest, PopBackEmpty) {
    SecureString s;
    s.pop_back();  // no-op on an empty string
    EXPECT_TRUE(s.empty());
}

TEST(SecureStringTest, Clear) {
    SecureString s("sensitive data");
    EXPECT_FALSE(s.empty());
    s.clear();
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
    EXPECT_STREQ(s.c_str(), "");
}

// --- Empty-state invariant (empty <=> data_.empty(); non-null nul_) ---

TEST(SecureStringEmptyState, DefaultConstructedIsEmptyAndNonNull) {
    SecureString s;
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
    EXPECT_NE(s.data(), nullptr);
    EXPECT_NE(s.c_str(), nullptr);
    EXPECT_EQ(s.data(), s.c_str());   // matches std::string
    EXPECT_EQ(s.c_str()[0], '\0');
}

TEST(SecureStringEmptyState, ClearedStringStaysNonNullAndTerminated) {
    SecureString s("secret");
    s.clear();
    EXPECT_TRUE(s.empty());
    EXPECT_NE(s.data(), nullptr);
    EXPECT_EQ(s.c_str()[0], '\0');
}

TEST(SecureStringEmptyState, NonConstDataOnEmptyIsWritable) {
    SecureString s;
    char* p = s.data();
    ASSERT_NE(p, nullptr);
    *p = '\0';                        // writing '\0' is the only legal write
    EXPECT_EQ(s.c_str()[0], '\0');
}

TEST(SecureStringEmptyState, MovedFromIsValidEmpty) {
    SecureString a("abc");
    SecureString b(std::move(a));
    EXPECT_EQ(b.view(), "abc");
    EXPECT_NE(a.data(), nullptr);     // moved-from is a valid (empty) string
    EXPECT_TRUE(a.empty());
}

TEST(SecureStringEmptyState, GrowFromEmptyThenTrimBackToEmpty) {
    SecureString s;
    s.push_back('x');
    EXPECT_EQ(s.view(), "x");
    s.pop_back();
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.c_str()[0], '\0');
    s.append("hello");
    EXPECT_EQ(s.view(), "hello");
}

// --- (const char*, size_t) null contract ---

TEST(SecureStringNullContract, ValidPtrZeroLenIsEmpty) {
    const char data[] = "x";
    SecureString s(data, 0);          // valid ptr, len 0: empty
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.c_str()[0], '\0');
}

TEST(SecureStringNullContract, RuntimeNullWithZeroLenIsEmpty) {
    const char* p = nullptr;
    SecureString s(p, 0);             // allowed: len == 0, str is never dereferenced
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.c_str()[0], '\0');
}

TEST(SecureStringNullContract, ConstructPtrLenRuntimeNullThrows) {
    const char* p = nullptr;
    EXPECT_THROW((void)SecureString(p, 5), std::invalid_argument);
}

TEST(SecureStringNullContract, AppendPtrLenRuntimeNullThrowsAndPreserves) {
    SecureString s("abc");
    const char* p = nullptr;
    EXPECT_THROW(s.append(p, 5), std::invalid_argument);   // rejected before any pointer arithmetic
    EXPECT_EQ(s.view(), "abc");
    EXPECT_STREQ(s.c_str(), "abc");
    s.append(p, 0);                          // (nullptr, 0): valid empty range, no-op
    EXPECT_EQ(s.view(), "abc");
}

TEST(SecureStringNullContract, NullIsReportedBeforeSizeLimit) {
    // Check order: zero-length return, then null (invalid_argument), then size (length_error).
    SecureString s("abc");
    const char* p = nullptr;
    EXPECT_THROW(s.append(p, SIZE_MAX), std::invalid_argument);
    EXPECT_EQ(s.view(), "abc");
}

TEST(SecureStringNullContract, CtorReportsNullBeforeSizeLimit) {
    const char* p = nullptr;
    EXPECT_THROW((void)SecureString(p, SIZE_MAX), std::invalid_argument);   // null check precedes the size check
}

// Literal null / 0 / {} are compile errors on every C-string entry point.
static_assert(!std::is_constructible<SecureString, std::nullptr_t>::value, "SecureString(nullptr) must not compile");
static_assert(!std::is_constructible<SecureString, std::nullptr_t, size_t>::value, "SecureString(nullptr, n) must not compile");
static_assert(!std::is_assignable<SecureString&, std::nullptr_t>::value, "s = nullptr must not compile");

template <class T, class = void> struct can_append_nullptr : std::false_type {};
template <class T> struct can_append_nullptr<T, std::void_t<decltype(std::declval<T&>().append(nullptr))>> : std::true_type {};
template <class T, class = void> struct can_pluseq_nullptr : std::false_type {};
template <class T> struct can_pluseq_nullptr<T, std::void_t<decltype(std::declval<T&>() += nullptr)>> : std::true_type {};
template <class T, class = void> struct can_assign_zero : std::false_type {};
template <class T> struct can_assign_zero<T, std::void_t<decltype(std::declval<T&>() = 0)>> : std::true_type {};
static_assert(!can_append_nullptr<SecureString>::value, "s.append(nullptr) must not compile");

template <class T, class = void> struct can_append_nullptr_len : std::false_type {};
template <class T> struct can_append_nullptr_len<T, std::void_t<decltype(std::declval<T&>().append(nullptr, std::declval<size_t>()))>> : std::true_type {};
static_assert(!can_append_nullptr_len<SecureString>::value, "s.append(nullptr, n) must not compile");

static_assert(!can_pluseq_nullptr<SecureString>::value, "s += nullptr must not compile");
static_assert(!can_assign_zero<SecureString>::value, "s = 0 must not compile (ambiguous between const char* and nullptr_t)");

template <class T, class = void> struct can_assign_braces : std::false_type {};
template <class T> struct can_assign_braces<T, std::void_t<decltype(std::declval<T&>() = {})>> : std::true_type {};
template <class T, class = void> struct can_append_zero : std::false_type {};
template <class T> struct can_append_zero<T, std::void_t<decltype(std::declval<T&>().append(0))>> : std::true_type {};
template <class T, class = void> struct can_pluseq_zero : std::false_type {};
template <class T> struct can_pluseq_zero<T, std::void_t<decltype(std::declval<T&>() += 0)>> : std::true_type {};
static_assert(!can_assign_braces<SecureString>::value, "s = {} must not compile (ambiguous)");
static_assert(!can_append_zero<SecureString>::value, "s.append(0) must not compile (ambiguous)");
static_assert(!can_pluseq_zero<SecureString>::value, "s += 0 must not compile (ambiguous)");

// Equality is deliberately absent, also across types: compare through view() instead.
template <class T, class U, class = void> struct can_equal : std::false_type {};
template <class T, class U> struct can_equal<T, U, std::void_t<decltype(std::declval<const T&>() == std::declval<const U&>())>> : std::true_type {};
static_assert(!can_equal<SecureString, SecureString>::value, "SecureString == SecureString must not compile");
static_assert(!can_equal<SecureString, const char*>::value, "s == \"x\" must not compile");
static_assert(!can_equal<const char*, SecureString>::value, "\"x\" == s must not compile");
static_assert(!can_equal<SecureString, std::string>::value, "s == std::string must not compile");
static_assert(!can_equal<SecureString, std::string_view>::value, "s == string_view must not compile");
static_assert(!can_equal<std::string_view, SecureString>::value, "string_view == s must not compile");
// A bare literal 0 is a null pointer constant: ambiguous between the deleted
// nullptr_t ctor and const char*, hence ill-formed (pinned here).
template <class T, class = void> struct can_construct_from_zero : std::false_type {};
template <class T> struct can_construct_from_zero<T, std::void_t<decltype(T(0))>> : std::true_type {};
static_assert(!can_construct_from_zero<SecureString>::value, "SecureString(0) must not compile (ambiguous)");

// --- Size-arithmetic overflow throws length_error, state preserved ---

TEST(SecureStringOverflow, ResizeSizeMaxThrowsPreservesNonEmpty) {
    SecureString s("abc");
    EXPECT_THROW(s.resize(SIZE_MAX), std::length_error);
    EXPECT_EQ(s.view(), "abc");      // content unchanged
    EXPECT_EQ(s.size(), 3u);                // length unchanged
    EXPECT_EQ(s.c_str()[3], '\0');          // terminator intact
}

TEST(SecureStringOverflow, ResizeMaxSizePlusOneThrows) {
    SecureString s("abc");
    EXPECT_THROW(s.resize(s.max_size() + 1), std::length_error);
    EXPECT_EQ(s.view(), "abc");
}

TEST(SecureStringOverflow, ResizeFillSizeMaxThrowsPreserves) {
    SecureString s("abc");
    EXPECT_THROW(s.resize(SIZE_MAX, 'x'), std::length_error);
    EXPECT_EQ(s.view(), "abc");
    EXPECT_EQ(s.c_str()[3], '\0');
}

TEST(SecureStringOverflow, ReserveSizeMaxThrowsPreserves) {
    SecureString s("abc");
    EXPECT_THROW(s.reserve(SIZE_MAX), std::length_error);
    EXPECT_EQ(s.view(), "abc");
}

TEST(SecureStringOverflow, ResizeSizeMaxOnEmptyStaysEmpty) {
    SecureString s;
    EXPECT_THROW(s.resize(SIZE_MAX), std::length_error);
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.c_str()[0], '\0');
}

TEST(SecureStringOverflow, AppendFillSizeMaxThrowsPreserves) {
    SecureString s("secret");
    EXPECT_THROW(s.append(SIZE_MAX, 'x'), std::length_error);
    EXPECT_EQ(s.view(), "secret");
    EXPECT_EQ(s.size(), 6u);
    EXPECT_EQ(s.c_str()[6], '\0');
}

TEST(SecureStringOverflow, AppendPtrHugeLenThrowsBeforePointerArith) {
    SecureString s("secret");
    EXPECT_THROW(s.append("x", SIZE_MAX), std::length_error);   // check runs before "x" + SIZE_MAX
    EXPECT_EQ(s.view(), "secret");
    EXPECT_EQ(s.c_str()[6], '\0');
}

TEST(SecureStringOverflow, ConstructFillSizeMaxThrows) {
    EXPECT_THROW(SecureString(SIZE_MAX, 'x'), std::length_error);
}

TEST(SecureStringOverflow, ConstructPtrHugeLenThrowsBeforePointerArith) {
    EXPECT_THROW(SecureString("x", SIZE_MAX), std::length_error);  // before "x" + SIZE_MAX
}

// --- std::string_view::find is overflow-safe by the standard ---

TEST(SecureStringView, FindBeyondSizeIsNpos) {
    SecureString s("abc");
    std::string_view v = s.view();
    EXPECT_EQ(v.find("a", std::string_view::npos), std::string_view::npos);   // pos past the end: npos, no out-of-bounds read
    EXPECT_EQ(v.find("a", v.size() + 1), std::string_view::npos);
    EXPECT_EQ(v.find("", v.size()), v.size());
    EXPECT_EQ(v.find("", v.size() + 1), std::string_view::npos);
    EXPECT_EQ(v.find("abc", std::string_view::npos - 1), std::string_view::npos);
}

// --- Embedded NUL is an ordinary byte; length-aware compare/search ---

TEST(SecureStringEmbeddedNul, ConstructPreservesEmbeddedNul) {
    SecureString s("abc\0def", 7);
    EXPECT_EQ(s.size(), 7u);
    EXPECT_EQ(s[3], '\0');
    EXPECT_EQ(s[4], 'd');
    EXPECT_EQ(s.c_str()[7], '\0');              // trailing terminator
    EXPECT_EQ(std::strlen(s.c_str()), 3u);      // C view sees only "abc"
}

TEST(SecureStringEmbeddedNul, ViewEqualityIsLengthAware) {
    SecureString a("abc\0def", 7);
    SecureString b("abc\0def", 7);
    SecureString c("abc\0xyz", 7);
    EXPECT_TRUE(a.view() == b.view());
    EXPECT_FALSE(a.view() == c.view());                        // differ after the NUL
    SecureString d("abc");
    EXPECT_FALSE(a.view() == d.view());                        // 7 bytes != 3 bytes
}

TEST(SecureStringEmbeddedNul, EqualityWithLiteralIsLengthAware) {
    SecureString s("expected\0attacker", 17);
    EXPECT_FALSE(s.view() == "expected");        // no truncation at the embedded NUL
    EXPECT_TRUE(s.view() != "expected");
    EXPECT_EQ(s.view().size(), 17u);
    SecureString e("expected");
    EXPECT_TRUE(e.view() == "expected");
}

TEST(SecureStringEmbeddedNul, FindNeedleWithEmbeddedNul) {
    SecureString s("xxab\0cdyy", 9);
    SecureString needle("ab\0cd", 5);
    EXPECT_EQ(s.view().find(needle.view()), 2u);                 // full needle, not "ab"
    EXPECT_EQ(s.view().find(std::string_view("ab\0zz", 5)), std::string_view::npos);
}

TEST(SecureStringEmbeddedNul, FindCharNul) {
    SecureString s("ab\0cd", 5);
    EXPECT_EQ(s.view().find('\0'), 2u);          // NUL is findable as an ordinary byte
}

TEST(SecureStringEmbeddedNul, MultipleNuls) {
    SecureString s("\0a\0b\0", 5);
    EXPECT_EQ(s.size(), 5u);
    EXPECT_EQ(s[0], '\0');
    EXPECT_EQ(s[4], '\0');
    EXPECT_EQ(s.c_str()[5], '\0');
    SecureString expected("\0a\0b\0", 5);
    EXPECT_TRUE(s.view() == expected.view());
}

TEST(SecureStringEmbeddedNul, MutableWriteOfNulKeepsObjectValid) {
    SecureString s("abc");
    s[1] = '\0';                                 // embedded NUL is allowed content
    EXPECT_EQ(s.size(), 3u);                     // length unchanged
    EXPECT_EQ(s.c_str()[3], '\0');               // trailing terminator intact
    SecureString expected("a\0c", 3);
    EXPECT_TRUE(s.view() == expected.view());
    EXPECT_FALSE(s.view() == "a");                // length-aware: 3 bytes != 1
}

TEST(SecureStringEmbeddedNul, EmptyUnaffected) {
    SecureString s;
    EXPECT_EQ(s.view().find('\0'), std::string_view::npos);
    EXPECT_TRUE(s.view() == "");
    SecureString other;
    EXPECT_TRUE(s.view() == other.view());
}

// --- operator=(const char*) is safe when the source aliases the target ---

TEST(SecureStringSelfAssign, AssignFromOwnCStr) {
    SecureString s("secret");
    s = s.c_str();                       // self-assign via own buffer
    EXPECT_EQ(s.view(), "secret"); // content survives the aliasing source
    EXPECT_STREQ(s.c_str(), "secret");
}

TEST(SecureStringSelfAssign, AssignFromOwnDataSlice) {
    SecureString s("hello");
    s = s.c_str() + 2;                   // internal slice "llo"
    EXPECT_EQ(s.view(), "llo");
}

TEST(SecureStringSelfAssign, NormalAssign) {
    SecureString s("old");
    s = "new value";
    EXPECT_EQ(s.view(), "new value");
    s = "";
    EXPECT_TRUE(s.empty());
}

// --- Additional coverage ---

TEST(SecureStringCoverage, AtNonConstOutOfRangeThrows) {
    SecureString s("abc");
    EXPECT_THROW(s.at(3) = 'z', std::out_of_range);
}

TEST(SecureStringCoverage, ResizeGrowSingleArgZeroFills) {
    SecureString s("ab");
    s.resize(5);                              // grows with '\0' fill (std::string parity)
    EXPECT_EQ(s.size(), 5u);
    EXPECT_EQ(s[0], 'a');
    EXPECT_EQ(s[2], '\0');
    EXPECT_EQ(s[4], '\0');
    EXPECT_EQ(s.c_str()[5], '\0');            // terminator after the content
}

TEST(SecureStringCoverage, ReserveThenBuildWithinCapacity) {
    SecureString s;
    s.reserve(100);
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.c_str()[0], '\0');
    s.append("0123456789");                   // must be correct within reserved space
    s.push_back('x');
    EXPECT_EQ(s.size(), 11u);
    EXPECT_EQ(s.view(), "0123456789x");
}

// --- view(): the single read-only interface ---

TEST(SecureStringView, NonEmptyViewCoversWholeContent) {
    SecureString s("hello world");
    std::string_view v = s.view();
    EXPECT_EQ(v.size(), s.size());
    EXPECT_EQ(v.data(), s.c_str());          // the full view is the terminated buffer
    EXPECT_EQ(v, "hello world");
}

TEST(SecureStringView, EmptyViewIsNonNullAndEmpty) {
    SecureString s;
    std::string_view v = s.view();
    EXPECT_EQ(v.size(), 0u);
    EXPECT_NE(v.data(), nullptr);            // points at the per-object nul_
    EXPECT_EQ(v.data(), s.c_str());
    EXPECT_EQ(v, "");
    SecureString moved_from("x");
    SecureString sink(std::move(moved_from));
    EXPECT_NE(moved_from.view().data(), nullptr);   // moved-from: still the per-object nul_
    EXPECT_EQ(moved_from.view().size(), 0u);
    SecureString cleared("abc");
    cleared.clear();
    EXPECT_NE(cleared.view().data(), nullptr);      // after clear(): still non-null
    EXPECT_EQ(cleared.view(), "");
}

TEST(SecureStringView, ViewKeepsEmbeddedNul) {
    SecureString s("ab\0cd", 5);
    std::string_view v = s.view();
    EXPECT_EQ(v.size(), 5u);                 // never strlen
    EXPECT_EQ(v, std::string_view("ab\0cd", 5));
    EXPECT_NE(v, std::string_view("ab"));    // length-aware
    EXPECT_EQ(v.find('\0'), 2u);             // NUL is an ordinary byte
    EXPECT_EQ(v.find(std::string_view("\0c", 2)), 2u);
}

TEST(SecureStringView, StandardQueriesThroughView) {
    SecureString s("hello world");
    std::string_view v = s.view();
    EXPECT_EQ(v.find(' '), 5u);
    EXPECT_EQ(v.rfind('o'), 7u);
    EXPECT_EQ(v.find("zzz"), std::string_view::npos);
    EXPECT_EQ(v.substr(6), "world");
    EXPECT_EQ(v.substr(0, 5), "hello");
    EXPECT_EQ(v.compare("hello world"), 0);
    EXPECT_TRUE(v.substr(0, 5) == "hello");  // C++17 spelling of starts_with
    EXPECT_THROW((void)v.substr(100), std::out_of_range);
}

TEST(SecureStringView, SubViewIsNotACString) {
    SecureString s("hello world");
    std::string_view word = s.view().substr(0, 5);
    EXPECT_EQ(word, "hello");
    EXPECT_EQ(word.data()[word.size()], ' ');   // a slice's data() runs on into the secret
    EXPECT_EQ(s.c_str()[s.size()], '\0');       // only c_str() carries the terminator
}

TEST(SecureStringView, MnemonicSplitIdiom) {
    SecureString mnemonic("abandon ability able");
    std::string_view v = mnemonic.view();
    std::vector<std::string_view> words;
    for (size_t start = 0;;) {
        size_t sp = v.find(' ', start);
        words.push_back(v.substr(start, sp - start));   // npos - start clamps to the end
        if (sp == std::string_view::npos) break;
        start = sp + 1;
    }
    ASSERT_EQ(words.size(), 3u);
    EXPECT_EQ(words[0], "abandon");
    EXPECT_EQ(words[1], "ability");
    EXPECT_EQ(words[2], "able");
}

// view() is noexcept, callable on lvalues only (rvalue overload deleted).
static_assert(noexcept(std::declval<const SecureString&>().view()), "view() must be noexcept");

template <class T, class = void>
struct view_callable_on : std::false_type {};
template <class T>
struct view_callable_on<T, std::void_t<decltype(std::declval<T>().view())>> : std::true_type {};
static_assert(!view_callable_on<SecureString>::value, "view() must not be callable on a temporary");
static_assert(view_callable_on<SecureString&>::value, "view() must be callable on an lvalue");

// Mutators that return *this are lvalue-only, so a chain on a temporary can
// never reach view(): SecureString("x").append(y).view() must not compile.
template <class T, class A, class = void> struct can_append_on : std::false_type {};
template <class T, class A> struct can_append_on<T, A, std::void_t<decltype(std::declval<T>().append(std::declval<A>()))>> : std::true_type {};
template <class T, class A, class = void> struct can_pluseq_on : std::false_type {};
template <class T, class A> struct can_pluseq_on<T, A, std::void_t<decltype(std::declval<T>() += std::declval<A>())>> : std::true_type {};
template <class T, class = void> struct can_append_ptr_len_on : std::false_type {};
template <class T> struct can_append_ptr_len_on<T, std::void_t<decltype(std::declval<T>().append(std::declval<const char*>(), std::declval<size_t>()))>> : std::true_type {};
template <class T, class = void> struct can_append_fill_on : std::false_type {};
template <class T> struct can_append_fill_on<T, std::void_t<decltype(std::declval<T>().append(std::declval<size_t>(), 'x'))>> : std::true_type {};
template <class T, class = void> struct can_assign_cstr_on : std::false_type {};
template <class T> struct can_assign_cstr_on<T, std::void_t<decltype(std::declval<T>() = "x")>> : std::true_type {};
template <class T, class = void> struct can_move_assign_on : std::false_type {};
template <class T> struct can_move_assign_on<T, std::void_t<decltype(std::declval<T>() = std::declval<SecureString>())>> : std::true_type {};
template <class T, class = void> struct can_copy_assign_on : std::false_type {};
template <class T> struct can_copy_assign_on<T, std::void_t<decltype(std::declval<T>() = std::declval<const SecureString&>())>> : std::true_type {};
template <class T, class = void> struct can_chain_view_on : std::false_type {};
template <class T> struct can_chain_view_on<T, std::void_t<decltype(std::declval<T>().append("x").view())>> : std::true_type {};
#define SB_PIN_LVALUE_ONLY(TRAIT, ARG, MSG) \
    static_assert(TRAIT<SecureString&, ARG>::value && !TRAIT<SecureString, ARG>::value, MSG)
SB_PIN_LVALUE_ONLY(can_append_on, const char*, "append(const char*) is lvalue-only");
SB_PIN_LVALUE_ONLY(can_append_on, std::string_view, "append(string_view) is lvalue-only");
SB_PIN_LVALUE_ONLY(can_append_on, const SecureString&, "append(const SecureString&) is lvalue-only");
SB_PIN_LVALUE_ONLY(can_pluseq_on, const char*, "operator+=(const char*) is lvalue-only");
SB_PIN_LVALUE_ONLY(can_pluseq_on, std::string_view, "operator+=(string_view) is lvalue-only");
SB_PIN_LVALUE_ONLY(can_pluseq_on, const SecureString&, "operator+=(const SecureString&) is lvalue-only");
SB_PIN_LVALUE_ONLY(can_pluseq_on, char, "operator+=(char) is lvalue-only");
#undef SB_PIN_LVALUE_ONLY
static_assert(can_append_ptr_len_on<SecureString&>::value && !can_append_ptr_len_on<SecureString>::value, "append(ptr, len) is lvalue-only");
static_assert(can_append_fill_on<SecureString&>::value && !can_append_fill_on<SecureString>::value, "append(n, c) is lvalue-only");
static_assert(can_assign_cstr_on<SecureString&>::value && !can_assign_cstr_on<SecureString>::value, "operator=(const char*) is lvalue-only");
static_assert(can_move_assign_on<SecureString&>::value && !can_move_assign_on<SecureString>::value, "move assignment is lvalue-only");
static_assert(can_copy_assign_on<SecureString&>::value && !can_copy_assign_on<SecureString>::value, "copy assignment is lvalue-only");
static_assert(can_chain_view_on<SecureString&>::value && !can_chain_view_on<SecureString>::value, "a chain on a temporary must not reach view()");

// --- Construction from std::string_view ---

TEST(SecureStringFromView, ConstructFromStringViewExactLength) {
    std::string_view sv("ab\0cd", 5);
    SecureString s(sv);
    EXPECT_EQ(s.size(), 5u);
    EXPECT_EQ(s.view(), sv);
    EXPECT_EQ(s.c_str()[5], '\0');
}

TEST(SecureStringFromView, ConstructFromStdStringDirectInit) {
    std::string legacy("a\0b", 3);
    SecureString s(legacy);                  // std::string converts to string_view
    EXPECT_EQ(s.size(), 3u);
    EXPECT_EQ(s.view(), std::string_view("a\0b", 3));
}

TEST(SecureStringFromView, ConstructFromDefaultStringViewIsEmpty) {
    std::string_view sv;                     // data() == nullptr, size() == 0
    SecureString s(sv);
    EXPECT_TRUE(s.empty());
    EXPECT_NE(s.c_str(), nullptr);
    EXPECT_EQ(s.c_str()[0], '\0');
}

TEST(SecureStringFromView, OwningCopyOfASlice) {
    SecureString mnemonic("abandon ability able");
    std::string_view v = mnemonic.view();
    SecureString word(v.substr(8, 7));       // the secret copy is explicit at the call site
    EXPECT_EQ(word.view(), "ability");
    EXPECT_STREQ(word.c_str(), "ability");   // and this one is a C string
}

// --- append / += from std::string_view ---

TEST(SecureStringAppendView, AppendStringView) {
    SecureString s("ab");
    s.append(std::string_view("c\0d", 3));
    EXPECT_EQ(s.view(), std::string_view("abc\0d", 5));
    EXPECT_EQ(s.c_str()[5], '\0');
}

TEST(SecureStringAppendView, AppendAndPlusEqualStdString) {
    SecureString s("x");
    std::string a("a\0b", 3);
    s.append(a);
    s += a;
    EXPECT_EQ(s.size(), 7u);
    EXPECT_EQ(s.view(), std::string_view("xa\0ba\0b", 7));
}

TEST(SecureStringAppendView, AppendEmptyViewIsNoOp) {
    SecureString s("abc");
    s.append(std::string_view{});
    s += std::string_view{};
    EXPECT_EQ(s.view(), "abc");
}

TEST(SecureStringAppendView, AppendOwnViewDoublesContent) {
    SecureString s("ab\0c", 4);
    s.append(s.view());                      // aliasing: *this is untouched until the grown copy is complete
    EXPECT_EQ(s.view(), std::string_view("ab\0cab\0c", 8));
    EXPECT_EQ(s.c_str()[8], '\0');
}

TEST(SecureStringAppendView, AppendOwnViewSliceAndPlusEqual) {
    SecureString s("hello");
    s += s.view().substr(1);                 // "hello" + "ello"
    EXPECT_EQ(s.view(), "helloello");
    s.append(s.view().substr(s.size() - 1)); // append the last char
    EXPECT_EQ(s.view(), "helloelloo");
}

TEST(SecureStringAppendView, AppendOwnViewSliceWithinReservedCapacity) {
    SecureString s("hello");
    s.reserve(64);                           // no reallocation will be needed
    const char* before = s.data();
    s.append(s.view().substr(1));            // aliasing on the in-place path
    EXPECT_EQ(s.view(), "helloello");
    EXPECT_EQ(s.c_str()[9], '\0');
    EXPECT_EQ(s.data(), before);   // the in-place path did not reallocate
}

TEST(SecureStringAppendView, AppendIncludingOwnTerminator) {
    for (int reserved = 0; reserved < 2; ++reserved) {   // growth path, then in place
        SecureString s("abc");
        if (reserved) s.reserve(16);
        s.append(s.c_str(), s.size() + 1);   // the content and its '\0'
        EXPECT_EQ(s.view(), std::string_view("abcabc\0", 7));
        EXPECT_EQ(s.c_str()[7], '\0');
    }
}

TEST(SecureStringAppendView, EmptyAppendFromOwnNul) {
    for (int reserved = 0; reserved < 2; ++reserved) {   // growth path, then in place
        SecureString e;
        if (reserved) e.reserve(8);
        e.append(e.c_str(), 1);              // an empty string's c_str() is its own '\0'
        EXPECT_FALSE(e.empty());
        EXPECT_EQ(e.size(), 1u);
        EXPECT_EQ(e[0], '\0');
        EXPECT_EQ(e.c_str()[1], '\0');
    }
}

TEST(SecureStringAppendView, SelfSliceAppendMatchesStdString) {
    // Every (offset, length) slice of the string itself, up to and including
    // its terminator, with embedded NULs, on both the growth and in-place paths
    // (without reserve, short slices grow only because construction fits the
    // content exactly, as libstdc++, libc++ and MSVC do).
    for (int reserved = 0; reserved < 2; ++reserved)
    for (size_t n = 1; n <= 12; ++n)
    for (size_t off = 0; off <= n; ++off)
    for (size_t len = 0; off + len <= n + 1; ++len) {
        std::string ref;
        for (size_t i = 0; i < n; ++i) ref.push_back(i % 5 == 2 ? '\0' : static_cast<char>('a' + i));
        const std::string with_nul = ref + '\0';
        const std::string expected = ref + with_nul.substr(off, len);
        SecureString s(ref.data(), ref.size());
        if (reserved) s.reserve(4 * n);
        s.append(s.c_str() + off, len);
        ASSERT_EQ(s.view(), std::string_view(expected)) << "n=" << n << " off=" << off << " len=" << len;
        ASSERT_EQ(s.c_str()[s.size()], '\0');
    }
}

TEST(SecureStringAppendView, AppendReturnsSelfForChaining) {
    SecureString s;
    SecureString other("D");
    s.append("a").append("bc", 2).append(std::string_view("d")).append(other).append(2, 'x');
    EXPECT_EQ(s.view(), "abcdDxx");
    EXPECT_EQ(&s.append("y"), &s);
}

TEST(SecureStringAppendView, LiteralStillMeansCString) {
    // A literal is an exact match for const char*; string_view needs a
    // user-defined conversion, so C-string (strlen) semantics still win.
    SecureString s("a\0b");        // const char* ctor: "a"
    EXPECT_EQ(s.size(), 1u);
    s.append("c\0d");              // const char* append: "c"
    s += "e\0f";                   // const char* +=: "e"
    EXPECT_EQ(s.view(), "ace");
}

// --- Contract pins: reference returns, noexcept set, no implicit boundary crossing ---

TEST(SecureStringContractPins, ConstAccessorsReturnReferencesIntoStorage) {
    const SecureString cs("abc");
    static_assert(std::is_same<decltype(cs[0]), const char&>::value, "operator[] const returns const char&");
    static_assert(std::is_same<decltype(cs.at(0)), const char&>::value, "at() const returns const char&");
    static_assert(std::is_same<decltype(cs.front()), const char&>::value, "front() const returns const char&");
    static_assert(std::is_same<decltype(cs.back()), const char&>::value, "back() const returns const char&");
    EXPECT_EQ(&cs[0], cs.c_str());
    EXPECT_EQ(&cs.front(), cs.data());
    EXPECT_EQ(&cs.back(), cs.data() + 2);
    EXPECT_EQ(&cs[cs.size()], cs.c_str() + 3);   // [size()] is the terminator
    const SecureString empty;
    EXPECT_EQ(&empty[0], empty.c_str());           // empty: the per-object nul_
    EXPECT_EQ(empty[0], '\0');
}

// noexcept: wide-contract, structurally non-throwing members only.
static_assert(noexcept(std::declval<SecureString&>().data()), "");
static_assert(noexcept(std::declval<const SecureString&>().data()), "");
static_assert(noexcept(std::declval<const SecureString&>().c_str()), "");
static_assert(noexcept(std::declval<const SecureString&>().size()), "");
static_assert(noexcept(std::declval<const SecureString&>().length()), "");
static_assert(noexcept(std::declval<const SecureString&>().empty()), "");
static_assert(noexcept(std::declval<const SecureString&>().max_size()), "");
static_assert(noexcept(std::declval<SecureString&>().begin()) && noexcept(std::declval<SecureString&>().end()), "");
static_assert(noexcept(std::declval<const SecureString&>().begin()) && noexcept(std::declval<const SecureString&>().cend()), "");
static_assert(noexcept(std::declval<SecureString&>().rbegin()) && noexcept(std::declval<const SecureString&>().crend()), "");
static_assert(noexcept(std::declval<SecureString&>().clear()), "");
static_assert(noexcept(std::declval<SecureString&>().pop_back()), "");
static_assert(noexcept(std::declval<SecureString&>().swap(std::declval<SecureString&>())), "");
static_assert(!has_equal<SecureString>::value && !has_not_equal<SecureString>::value, "");
static_assert(!has_equal_with<SecureString, const char*>::value, "");
// Narrow-contract, throwing or allocating members are not noexcept.
static_assert(!noexcept(std::declval<const SecureString&>()[0]), "operator[] has a narrow contract");
static_assert(!noexcept(std::declval<const SecureString&>().at(0)), "at() throws");
static_assert(!noexcept(std::declval<const SecureString&>().front()), "front() has a narrow contract");
static_assert(!noexcept(std::declval<const SecureString&>().back()), "back() has a narrow contract");
static_assert(!noexcept(std::declval<SecureString&>().append("x")), "append allocates");
static_assert(!noexcept(std::declval<SecureString&>().push_back('x')), "push_back allocates");
static_assert(!noexcept(std::declval<SecureString&>().reserve(1)), "reserve allocates");
static_assert(!noexcept(std::declval<SecureString&>().resize(1)), "resize allocates");
static_assert(!noexcept(std::declval<const SecureString&>().to_unsecure_string()), "copy-out allocates");
static_assert(!noexcept(SecureString("x")), "converting ctor allocates");
static_assert(std::is_same<decltype(std::declval<SecureString&>().append(std::declval<size_t>(), 'x')), SecureString&>::value, "append(n, c) returns *this");
static_assert(std::is_same<decltype(std::declval<SecureString&>() += std::declval<std::string_view>()), SecureString&>::value, "operator+=(string_view) returns *this");
static_assert(std::is_same<decltype(std::declval<SecureString&>().append(std::declval<std::string_view>())), SecureString&>::value, "append(string_view) returns *this");
