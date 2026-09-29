// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_MEMZERO_H
#define SAFEHERON_SECURE_MEMZERO_H

#include <cstddef>

namespace safeheron {
namespace secure_buffer {

/// Zeroes len bytes at ptr; the compiler cannot elide it.
// Defined in src/secure_memzero.cpp, the only platform-specific source.
void secure_memzero(void* ptr, std::size_t len) noexcept;

} // namespace secure_buffer
} // namespace safeheron

#endif // SAFEHERON_SECURE_MEMZERO_H
