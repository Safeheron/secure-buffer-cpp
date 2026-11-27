// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_BYTES_H
#define SAFEHERON_SECURE_BYTES_H

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>
#if defined(__cpp_impl_three_way_comparison)
#include <compare>
#endif
#include <secure-buffer/secure_allocator.h>

namespace safeheron {
namespace sbuf {

// SecureString casts between uint8_t* and char*, which is valid only if
// uint8_t is a character type.
static_assert(std::is_same<std::uint8_t, unsigned char>::value,
              "secure-buffer requires uint8_t to be unsigned char");

/// std::vector with SecureAllocator: the vector interface without comparison operators,
/// wiped on release.
using SecureBytes = std::vector<uint8_t, SecureAllocator<uint8_t>>;

/// Comparison operators are deleted: comparing secrets must not stop at the first differing byte.
/// Use constant_time_equal; compare non-secret data with std::equal.
bool operator==(const SecureBytes&, const SecureBytes&) = delete;
bool operator!=(const SecureBytes&, const SecureBytes&) = delete;
bool operator<(const SecureBytes&, const SecureBytes&) = delete;
bool operator>(const SecureBytes&, const SecureBytes&) = delete;
bool operator<=(const SecureBytes&, const SecureBytes&) = delete;
bool operator>=(const SecureBytes&, const SecureBytes&) = delete;
#if defined(__cpp_impl_three_way_comparison)
std::strong_ordering operator<=>(const SecureBytes&, const SecureBytes&) = delete;
#endif

/// N zero-initialized bytes.
template <std::size_t N>
SecureBytes make_secure_bytes() {
    return SecureBytes(N, 0);
}

} // namespace sbuf
} // namespace safeheron

#endif // SAFEHERON_SECURE_BYTES_H
