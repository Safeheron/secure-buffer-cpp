// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_ALLOCATOR_H
#define SAFEHERON_SECURE_ALLOCATOR_H

#include <cstddef>
#include <memory>
#include <secure-buffer/secure_memzero.h>

namespace safeheron {
namespace secure_buffer {

/// Stateless allocator that wipes memory before releasing it.
template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() noexcept = default;

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        return std::allocator<T>().allocate(n);
    }

    /// Wipes the block, then releases it through std::allocator<T>.
    void deallocate(T* ptr, std::size_t n) noexcept {
        secure_memzero(ptr, n * sizeof(T));
        std::allocator<T>().deallocate(ptr, n);
    }

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

} // namespace secure_buffer
} // namespace safeheron

#endif // SAFEHERON_SECURE_ALLOCATOR_H
