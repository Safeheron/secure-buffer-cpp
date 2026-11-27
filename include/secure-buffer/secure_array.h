// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_ARRAY_H
#define SAFEHERON_SECURE_ARRAY_H

#include <array>
#include <cassert>
#include <cstddef>
#include <stdexcept>
#include <type_traits>

#include <secure-buffer/compat/span.h>
#include <secure-buffer/secure_cleanse.h>
#include <secure-buffer/secure_memzero.h>

namespace safeheron {
namespace sbuf {

/// Fixed-size array of N integers (or std::byte), zero-initialized and wiped
/// on destruction. Use it for secrets whose size is known at compile time.
/// Every copy wipes itself on destruction.
/// Moves are copies, as for std::array: the source keeps its value until it is
/// destroyed; call secure_cleanse() to wipe it sooner.
/// There is no conversion to or from std::array; pass data() and size(),
/// or borrow a view with as_span() / as_writable_span().
/// N == 0 is allowed.
template <typename T, std::size_t N>
class SecureArray final {
    static_assert(detail::is_cleansable_scalar<T>::value,
                  "SecureArray elements must be integers or std::byte, without const or volatile");

public:
    using value_type = T;
    using size_type = std::size_t;
    using reference = T&;
    using const_reference = const T&;
    using iterator = T*;
    using const_iterator = const T*;

    /// All elements are zero.
    SecureArray() = default;

    // Wipes N * sizeof(T) bytes from data(): for N == 0 data() may be null
    // while sizeof(data_) is not 0.
    ~SecureArray() { secure_memzero(data(), N * sizeof(T)); }

    SecureArray(const SecureArray&) = default;
    SecureArray& operator=(const SecureArray&) & = default;

    // --- Access ---

    T* data() noexcept { return data_.data(); }
    const T* data() const noexcept { return data_.data(); }

    /// Precondition: i < N.
    T& operator[](size_type i) {
        assert(i < N);
        return data_[i];
    }
    const T& operator[](size_type i) const {
        assert(i < N);
        return data_[i];
    }

    /// Throws std::out_of_range if i >= N.
    // For N == 0 every index is out of range; the branch keeps the return out of
    // that instantiation, where MSVC would report it as unreachable (C4702).
    T& at(size_type i) {
        if constexpr (N == 0) {
            (void)i;
            throw_out_of_range();
        } else {
            if (i >= N) throw_out_of_range();
            return data_[i];
        }
    }
    const T& at(size_type i) const {
        if constexpr (N == 0) {
            (void)i;
            throw_out_of_range();
        } else {
            if (i >= N) throw_out_of_range();
            return data_[i];
        }
    }

    /// Precondition: N > 0.
    T& front() {
        assert(N > 0);
        return data_[0];
    }
    const T& front() const {
        assert(N > 0);
        return data_[0];
    }
    T& back() {
        assert(N > 0);
        return data_[N - 1];
    }
    const T& back() const {
        assert(N > 0);
        return data_[N - 1];
    }

    // --- Capacity ---

    [[nodiscard]] static constexpr size_type size() noexcept { return N; }
    [[nodiscard]] static constexpr bool empty() noexcept { return N == 0; }

    // --- Iterators ---

    iterator begin() noexcept { return data(); }
    iterator end() noexcept { return data() + N; }
    const_iterator begin() const noexcept { return data(); }
    const_iterator end() const noexcept { return data() + N; }
    const_iterator cbegin() const noexcept { return data(); }
    const_iterator cend() const noexcept { return data() + N; }

private:
    [[noreturn]] static void throw_out_of_range() {
        throw std::out_of_range("SecureArray::at: index out of range");
    }

    std::array<T, N> data_{};
};

/// Zeroes the elements in place; the compiler cannot elide it. The size is
/// unchanged and the array stays usable.
template <typename T, std::size_t N>
void secure_cleanse(SecureArray<T, N>& array) noexcept {
    secure_memzero(array.data(), N * sizeof(T));
}

/// Borrows the elements as a view of compile-time length N. The view does not
/// extend the array's lifetime and does not wipe anything.
template <typename T, std::size_t N>
span<const T, N> as_span(const SecureArray<T, N>& a) noexcept {
    return span<const T, N>(a.data(), N);
}

/// Borrows the elements as a modifiable view of compile-time length N. Same
/// lifetime rules as as_span; it takes a modifiable lvalue, so temporaries are
/// rejected.
template <typename T, std::size_t N>
span<T, N> as_writable_span(SecureArray<T, N>& a) noexcept {
    return span<T, N>(a.data(), N);
}

// A view of a temporary would dangle once the array is wiped at the end of
// the full-expression.
template <typename T, std::size_t N>
void as_span(const SecureArray<T, N>&&) = delete;

static_assert(std::is_nothrow_default_constructible<SecureArray<unsigned char, 32>>::value,
              "SecureArray() must be noexcept");
static_assert(std::is_nothrow_copy_constructible<SecureArray<unsigned char, 32>>::value,
              "SecureArray copy construction must be noexcept");
static_assert(std::is_nothrow_copy_assignable<SecureArray<unsigned char, 32>>::value,
              "SecureArray copy assignment must be noexcept");
static_assert(std::is_nothrow_move_constructible<SecureArray<unsigned char, 32>>::value,
              "SecureArray move construction (a copy) must be noexcept");
static_assert(std::is_nothrow_move_assignable<SecureArray<unsigned char, 32>>::value,
              "SecureArray move assignment (a copy) must be noexcept");
static_assert(!std::is_convertible<SecureArray<unsigned char, 32>,
                                   std::array<unsigned char, 32>>::value,
              "leaving the secure world is explicit: pass data() and size()");
static_assert(!std::is_convertible<std::array<unsigned char, 32>,
                                   SecureArray<unsigned char, 32>>::value,
              "SecureArray is not built from a std::array");

} // namespace sbuf
} // namespace safeheron

#endif // SAFEHERON_SECURE_ARRAY_H
