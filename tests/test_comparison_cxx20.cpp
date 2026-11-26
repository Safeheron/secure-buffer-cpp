// C++20 only: the rewritten operators (>, <=, >=, <=>) must stay unavailable too.
#include <secure-buffer/secure_buffer.h>

#include <algorithm>
#include <compare>
#include <cstdint>
#include <type_traits>
#include <utility>
#include <vector>

using safeheron::secure_buffer::SecureArray;
using safeheron::secure_buffer::SecureBytes;
using safeheron::secure_buffer::SecureString;
using safeheron::secure_buffer::constant_time_equal;

namespace {

template <class T, class = void> struct has_equal : std::false_type {};
template <class T>
struct has_equal<T, std::void_t<decltype(std::declval<const T&>() == std::declval<const T&>())>>
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

template <class T, class = void> struct has_three_way : std::false_type {};
template <class T>
struct has_three_way<T, std::void_t<decltype(std::declval<const T&>() <=> std::declval<const T&>())>>
    : std::true_type {};

static_assert(!has_equal<SecureBytes>::value && !has_greater<SecureBytes>::value &&
              !has_less_equal<SecureBytes>::value && !has_greater_equal<SecureBytes>::value &&
              !has_three_way<SecureBytes>::value);
static_assert(!has_equal<SecureString>::value && !has_three_way<SecureString>::value);
static_assert(!has_equal<SecureArray<uint8_t, 4>>::value &&
              !has_three_way<SecureArray<uint8_t, 4>>::value);
// Positive control: proves the trait can detect <=> (independent of the standard library's vector).
static_assert(has_three_way<int>::value);

}  // namespace

int main() {
    SecureBytes a(16, 0xAB);
    SecureBytes b(16, 0xAB);
    const bool same = std::equal(a.begin(), a.end(), b.begin(), b.end());
    return same && constant_time_equal(a, b) ? 0 : 1;
}
