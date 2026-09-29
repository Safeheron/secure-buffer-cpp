// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_BYTES_H
#define SAFEHERON_SECURE_BYTES_H

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>
#include <secure-buffer/secure_allocator.h>

namespace safeheron {
namespace secure_buffer {

// SecureString casts between uint8_t* and char*, which is valid only if
// uint8_t is a character type.
static_assert(std::is_same<std::uint8_t, unsigned char>::value,
              "secure-buffer requires uint8_t to be unsigned char");

/// std::vector with SecureAllocator: the full vector interface, wiped on release.
using SecureBytes = std::vector<uint8_t, SecureAllocator<uint8_t>>;

/// N zero-initialized bytes.
template <std::size_t N>
SecureBytes make_secure_bytes() {
    return SecureBytes(N, 0);
}

} // namespace secure_buffer
} // namespace safeheron

#endif // SAFEHERON_SECURE_BYTES_H
