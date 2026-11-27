// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_BUFFER_COMPAT_SPAN_H
#define SAFEHERON_SECURE_BUFFER_COMPAT_SPAN_H

#include <array>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <type_traits>

namespace safeheron {
namespace sbuf {
namespace compat {

/// The extent of a span whose length is known only at run time.
inline constexpr std::size_t dynamic_extent = static_cast<std::size_t>(-1);

template <typename T, std::size_t Extent>
class span;

namespace detail {

// The iterator of span<T, Extent>: a thin wrapper around T*. Each element type
// and extent has its own type, with no conversions between them. Only the span
// constructs one from a pointer, and there is no conversion back to a pointer.
template <typename T, std::size_t Extent>
class span_iterator {
public:
    using iterator_category = std::random_access_iterator_tag;
    using value_type = std::remove_cv_t<T>;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using reference = T&;

    constexpr span_iterator() noexcept = default;

    constexpr reference operator*() const noexcept { return *ptr_; }
    constexpr pointer operator->() const noexcept { return ptr_; }
    constexpr reference operator[](difference_type n) const noexcept { return ptr_[n]; }

    constexpr span_iterator& operator++() noexcept {
        ++ptr_;
        return *this;
    }
    constexpr span_iterator operator++(int) noexcept {
        span_iterator old = *this;
        ++ptr_;
        return old;
    }
    constexpr span_iterator& operator--() noexcept {
        --ptr_;
        return *this;
    }
    constexpr span_iterator operator--(int) noexcept {
        span_iterator old = *this;
        --ptr_;
        return old;
    }
    constexpr span_iterator& operator+=(difference_type n) noexcept {
        ptr_ += n;
        return *this;
    }
    constexpr span_iterator& operator-=(difference_type n) noexcept {
        ptr_ -= n;
        return *this;
    }

    friend constexpr span_iterator operator+(span_iterator it, difference_type n) noexcept {
        return it += n;
    }
    friend constexpr span_iterator operator+(difference_type n, span_iterator it) noexcept {
        return it += n;
    }
    friend constexpr span_iterator operator-(span_iterator it, difference_type n) noexcept {
        return it -= n;
    }
    friend constexpr difference_type operator-(span_iterator a, span_iterator b) noexcept {
        return a.ptr_ - b.ptr_;
    }

    friend constexpr bool operator==(span_iterator a, span_iterator b) noexcept {
        return a.ptr_ == b.ptr_;
    }
    friend constexpr bool operator!=(span_iterator a, span_iterator b) noexcept {
        return a.ptr_ != b.ptr_;
    }
    friend constexpr bool operator<(span_iterator a, span_iterator b) noexcept {
        return a.ptr_ < b.ptr_;
    }
    friend constexpr bool operator>(span_iterator a, span_iterator b) noexcept {
        return a.ptr_ > b.ptr_;
    }
    friend constexpr bool operator<=(span_iterator a, span_iterator b) noexcept {
        return a.ptr_ <= b.ptr_;
    }
    friend constexpr bool operator>=(span_iterator a, span_iterator b) noexcept {
        return a.ptr_ >= b.ptr_;
    }

private:
    friend class compat::span<T, Extent>;

    constexpr explicit span_iterator(T* p) noexcept : ptr_(p) {}

    T* ptr_ = nullptr;
};

// A U* may be viewed as a T* when T is U with at most added const/volatile: no
// conversion between different element types (char and uint8_t, Derived and Base).
template <typename U, typename T>
using is_array_convertible = std::is_convertible<U (*)[], T (*)[]>;

// The extent of subspan<Offset, Count>() of a span<T, Extent>, as for std::span:
// Count unless it is dynamic_extent, else what is left of a static extent, else
// dynamic.
template <std::size_t Extent, std::size_t Offset, std::size_t Count>
inline constexpr std::size_t subspan_extent =
    Count != dynamic_extent ? Count
                            : (Extent != dynamic_extent ? Extent - Offset : dynamic_extent);

// A static extent stores only the pointer: the length is the template argument.
template <typename T, std::size_t Extent>
class span_storage {
public:
    constexpr span_storage(T* p, std::size_t) noexcept : ptr_(p) {}
    constexpr T* data() const noexcept { return ptr_; }
    static constexpr std::size_t size() noexcept { return Extent; }

private:
    T* ptr_;
};

template <typename T>
class span_storage<T, dynamic_extent> {
public:
    constexpr span_storage(T* p, std::size_t n) noexcept : ptr_(p), size_(n) {}
    constexpr T* data() const noexcept { return ptr_; }
    constexpr std::size_t size() const noexcept { return size_; }

private:
    T* ptr_;
    std::size_t size_;
};

} // namespace detail

/// A view of a contiguous sequence of T: a C++17 subset of C++20 std::span, with
/// a length known at run time (span<T>) or at compile time (span<T, N>). Code
/// written against it compiles unchanged once the library switches to std::span.
/// A span does not own, allocate or wipe memory, and does not extend the owner's
/// lifetime: the owner keeps the data alive and is responsible for wiping it.
/// SecureArray and SecureBytes wipe themselves; a plain array needs secure_cleanse
/// or ScopedCleanse; a std::vector is not wiped.
/// Preconditions are checked by assert() only, so they are controlled by NDEBUG
/// alone: with NDEBUG a violation is undefined behaviour. Standard-library
/// hardening modes (_GLIBCXX_ASSERTIONS, libc++ hardening, MSVC checked
/// iterators) do not apply to this class.
/// A const span<T> does not make the elements const; use span<const T>.
template <typename T, std::size_t Extent = dynamic_extent>
class span {
    static_assert(std::is_object<T>::value && !std::is_abstract<T>::value,
                  "span element type must be an object type that is not abstract");

public:
    using element_type = T;
    using value_type = std::remove_cv_t<T>;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    // A class, not T*, so that code written against compat::span cannot treat
    // an iterator as a pointer (std::span's iterator need not be one); use
    // data() for a pointer.
    using iterator = detail::span_iterator<T, Extent>;

    static constexpr size_type extent = Extent;

    // --- Construction ---
    // Each constructor taking U accepts it when U(*)[] converts to T(*)[]. The
    // (pointer, count) and dynamic-to-static constructors come in pairs with
    // exclusive constraints, one explicit, emulating C++20 explicit(bool).

    /// An empty view: data() == nullptr. Only for a dynamic or zero extent.
    template <std::size_t E = Extent,
              std::enable_if_t<E == dynamic_extent || E == 0, int> = 0>
    constexpr span() noexcept : storage_(nullptr, 0) {}

    /// Precondition: n == 0, or [p, p + n) is a valid range within one array object.
    template <typename U, std::enable_if_t<Extent == dynamic_extent &&
                                               detail::is_array_convertible<U, T>::value,
                                           int> = 0>
    constexpr span(U* p, size_type n) noexcept : storage_(p, n) {}

    /// Precondition: n == Extent, and [p, p + n) is a valid range within one array object.
    template <typename U, std::enable_if_t<Extent != dynamic_extent &&
                                               detail::is_array_convertible<U, T>::value,
                                           int> = 0>
    constexpr explicit span(U* p, size_type n) noexcept : storage_(p, n) {
        assert(n == Extent);
    }

    // The parameter is element_type, not a deduced U, as in std::span: a
    // non-const array still binds to span<const T>, and the deduction guides
    // below decide the deduced type.
    template <std::size_t N, std::enable_if_t<Extent == dynamic_extent || N == Extent, int> = 0>
    constexpr span(element_type (&arr)[N]) noexcept : storage_(arr, N) {}

    template <typename U, std::size_t N,
              std::enable_if_t<(Extent == dynamic_extent || N == Extent) &&
                                   detail::is_array_convertible<U, T>::value,
                               int> = 0>
    constexpr span(std::array<U, N>& arr) noexcept : storage_(arr.data(), N) {}

    template <typename U, std::size_t N,
              std::enable_if_t<(Extent == dynamic_extent || N == Extent) &&
                                   detail::is_array_convertible<const U, T>::value,
                               int> = 0>
    constexpr span(const std::array<U, N>& arr) noexcept : storage_(arr.data(), N) {}

    // Same extent, or static to dynamic: implicit.
    template <typename U, std::size_t E,
              std::enable_if_t<(Extent == dynamic_extent || E == Extent) &&
                                   detail::is_array_convertible<U, T>::value,
                               int> = 0>
    constexpr span(const span<U, E>& other) noexcept : storage_(other.data(), other.size()) {}

    /// Precondition: other.size() == Extent.
    template <typename U, std::size_t E,
              std::enable_if_t<Extent != dynamic_extent && E == dynamic_extent &&
                                   detail::is_array_convertible<U, T>::value,
                               int> = 0>
    constexpr explicit span(const span<U, E>& other) noexcept
        : storage_(other.data(), other.size()) {
        assert(other.size() == Extent);
    }

    constexpr span(const span&) noexcept = default;
    constexpr span& operator=(const span&) noexcept = default;

    // --- Observers ---

    constexpr pointer data() const noexcept { return storage_.data(); }
    constexpr size_type size() const noexcept { return storage_.size(); }
    constexpr size_type size_bytes() const noexcept { return size() * sizeof(T); }
    [[nodiscard]] constexpr bool empty() const noexcept { return size() == 0; }

    // --- Element access ---

    /// Precondition: i < size().
    constexpr reference operator[](size_type i) const noexcept {
        assert(i < size());
        return data()[i];
    }

    // --- Iterators ---

    constexpr iterator begin() const noexcept { return iterator(data()); }
    constexpr iterator end() const noexcept { return iterator(data() + size()); }

    // --- Compile-time slices: the length is part of the result type ---
    // As for std::span, a slice beyond a static extent does not compile; on a
    // dynamic span the bounds are run-time preconditions, except that
    // subspan<Offset, Count>() still rejects a Count other than dynamic_extent
    // above SIZE_MAX - Offset at compile time (the Count <= Extent check of
    // first<Count>() and last<Count>() always holds there). A static result
    // type does not prove that a dynamic source is long enough.

    /// Precondition: Count <= size().
    template <std::size_t Count>
    constexpr span<T, Count> first() const noexcept {
        static_assert(Count <= Extent, "span::first<Count>: Count exceeds the extent");
        assert(Count <= size());
        return span<T, Count>(data(), Count);
    }

    /// Precondition: Count <= size().
    template <std::size_t Count>
    constexpr span<T, Count> last() const noexcept {
        static_assert(Count <= Extent, "span::last<Count>: Count exceeds the extent");
        assert(Count <= size());
        return span<T, Count>(data() + (size() - Count), Count);
    }

    /// The result's extent is Count unless Count is dynamic_extent; then it is
    /// Extent - Offset for a static span, and dynamic for a dynamic one.
    /// Precondition: Offset <= size(), and Count == dynamic_extent or
    /// Count <= size() - Offset.
    template <std::size_t Offset, std::size_t Count = dynamic_extent>
    constexpr span<T, detail::subspan_extent<Extent, Offset, Count>> subspan() const noexcept {
        static_assert(Offset <= Extent,
                      "span::subspan<Offset, Count>: Offset exceeds the extent");
        // A separate check, skipped when Offset already failed: one error per mistake.
        static_assert(Count == dynamic_extent || Offset > Extent || Count <= Extent - Offset,
                      "span::subspan<Offset, Count>: Count exceeds the extent minus Offset");
        // Two comparisons: Offset + Count <= size() could wrap around.
        assert(Offset <= size());
        assert(Count == dynamic_extent || Count <= size() - Offset);
        // Offset == 0 keeps data() as is: no arithmetic on a null pointer.
        return span<T, detail::subspan_extent<Extent, Offset, Count>>(
            Offset == 0 ? data() : data() + Offset,
            Count == dynamic_extent ? size() - Offset : Count);
    }

    // --- Run-time slices: always dynamic, even of a static span ---

    /// Precondition: count <= size().
    constexpr span<T> first(size_type count) const noexcept {
        assert(count <= size());
        return span<T>(data(), count);
    }

    /// Precondition: count <= size().
    constexpr span<T> last(size_type count) const noexcept {
        assert(count <= size());
        return span<T>(data() + (size() - count), count);
    }

    /// Precondition: offset <= size(), and count == dynamic_extent or
    /// count <= size() - offset.
    constexpr span<T> subspan(size_type offset,
                              size_type count = dynamic_extent) const noexcept {
        // Two comparisons: offset + count <= size() could wrap around.
        assert(offset <= size());
        assert(count == dynamic_extent || count <= size() - offset);
        // offset == 0 keeps data() as is: no arithmetic on a null pointer.
        return span<T>(offset == 0 ? data() : data() + offset,
                       count == dynamic_extent ? size() - offset : count);
    }

private:
    detail::span_storage<T, Extent> storage_;
};

// Explicit guides: the guides generated from the constructors would deduce a
// dynamic extent from a built-in array, and no element type from a std::array
// or a pointer. With these, as with std::span, an lvalue array keeps its
// length and a pointer and a count give a dynamic span.
template <typename T, std::size_t N>
span(T (&)[N]) -> span<T, N>;
template <typename T, std::size_t N>
span(std::array<T, N>&) -> span<T, N>;
template <typename T, std::size_t N>
span(const std::array<T, N>&) -> span<const T, N>;
template <typename T>
span(T*, std::size_t) -> span<T>;

// The rvalue guides keep std::span's results for rvalue arrays, which it
// deduces through its range guide: span<const T> for a const array. For a
// non-const array they deduce span<T>, which no constructor builds from an
// rvalue, so a view of a temporary is rejected instead of deduced as
// span<const T, N>.
template <typename T, std::size_t N>
span(std::array<T, N>&&) -> span<T>;
template <typename T, std::size_t N>
span(const std::array<T, N>&&) -> span<const T>;
template <typename T, std::size_t N>
span(T (&&)[N]) -> span<T>;

} // namespace compat
} // namespace sbuf
} // namespace safeheron

namespace safeheron {
namespace sbuf {

// The documented spelling. The class lives in compat, so a span does not by
// itself make this namespace an associated namespace for argument-dependent
// lookup (as with std::span); its element type still contributes its own.
using compat::span;
using compat::dynamic_extent;

} // namespace sbuf
} // namespace safeheron

#endif // SAFEHERON_SECURE_BUFFER_COMPAT_SPAN_H
