// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_UTILS_H
#define SAFEHERON_SECURE_UTILS_H

#include <cstddef>
#include <string>
#include <secure-buffer/secure_array.h>
#include <secure-buffer/secure_bytes.h>
#include <secure-buffer/secure_string.h>

namespace safeheron {
namespace secure_buffer {

// --- Conversion from and to std::string ---

/// The source is not wiped.
inline SecureBytes to_secure_bytes(const std::string& str) {
    return SecureBytes(str.begin(), str.end());
}

/// The result is ordinary, unwiped memory.
[[nodiscard]] inline std::string to_unsecure_string(const SecureBytes& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

/// The source is not wiped.
inline SecureString to_secure_string(const std::string& str) {
    return SecureString(str.c_str(), str.size());
}

// --- Constant-time comparison ---
// Only equality is offered: an ordering would reveal where inputs differ.

/// Compares len bytes in time that depends on len only.
// No branch on the data and no early exit.
[[nodiscard]] inline bool constant_time_equal(const void* lhs,
                                              const void* rhs,
                                              std::size_t len) noexcept {
    const auto* a = static_cast<const unsigned char*>(lhs);
    const auto* b = static_cast<const unsigned char*>(rhs);
    unsigned char diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

/// Returns false immediately if the lengths differ; length is not secret.
[[nodiscard]] inline bool constant_time_equal(const void* lhs, std::size_t lhs_len,
                                              const void* rhs, std::size_t rhs_len) noexcept {
    if (lhs_len != rhs_len) return false;
    return constant_time_equal(lhs, rhs, lhs_len);
}

[[nodiscard]] inline bool constant_time_equal(const SecureBytes& lhs,
                                              const SecureBytes& rhs) noexcept {
    if (lhs.size() != rhs.size()) return false;
    if (lhs.empty()) return true;
    return constant_time_equal(lhs.data(), rhs.data(), lhs.size());
}

[[nodiscard]] inline bool constant_time_equal(const SecureString& lhs,
                                              const SecureString& rhs) noexcept {
    if (lhs.size() != rhs.size()) return false;
    if (lhs.empty()) return true;
    return constant_time_equal(lhs.data(), rhs.data(), lhs.size());
}

/// Compares all N * sizeof(T) bytes in time that depends on N only.
// The length is part of the type, so there is no length check; for N == 0 the
// raw overload never dereferences, so a null data() is fine.
template <typename T, std::size_t N>
[[nodiscard]] bool constant_time_equal(const SecureArray<T, N>& lhs,
                                       const SecureArray<T, N>& rhs) noexcept {
    return constant_time_equal(lhs.data(), rhs.data(), N * sizeof(T));
}

} // namespace secure_buffer
} // namespace safeheron

#endif // SAFEHERON_SECURE_UTILS_H
