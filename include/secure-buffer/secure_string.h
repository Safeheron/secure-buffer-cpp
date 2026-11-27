// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_STRING_H
#define SAFEHERON_SECURE_STRING_H

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <secure-buffer/secure_bytes.h>

namespace safeheron {
namespace sbuf {

/// Owning, length-aware string whose storage is wiped on release.
///
/// Content is [data(), data() + size()), may contain '\0', and is always
/// followed by a terminator. Read-only queries go through view().
///
/// Bytes leave the object only explicitly: view(), data(), c_str() and the
/// iterators expose them without copying; to_unsecure_string() copies them
/// into unwiped memory. There is no implicit conversion.
///
/// All value constructors are explicit, and members that return *this are
/// lvalue-only.
class SecureString {
private:
    SecureBytes data_;        // empty, or content + '\0'
    char        nul_ = '\0';  // what data()/c_str() point to when empty

    // Size checks; run before any "+ 1" arithmetic or state change.
    void check_size(size_t n) const {
        if (n > max_size()) throw std::length_error("SecureString: size exceeds max_size");
    }
    void check_grow(size_t extra) const {
        if (extra > max_size() - size()) throw std::length_error("SecureString: size exceeds max_size");
    }

    // Null checks; run before the pointer is used. (nullptr, 0) is valid.
    static void check_cstr(const char* str) {
        if (!str) throw std::invalid_argument("SecureString: null C string");
    }
    static void check_buf(const char* str, size_t len) {
        if (len != 0 && !str) throw std::invalid_argument("SecureString: null buffer with non-zero length");
    }

    void init_from(const char* str, size_t len) {
        check_buf(str, len);
        check_size(len);
        if (len == 0) { data_.clear(); return; }
        data_.reserve(len + 1);   // single allocation
        data_.assign(str, str + len);
        data_.push_back(0);
    }

    // Excludes the terminator slot.
    size_t content_capacity() const noexcept {
        return data_.capacity() == 0 ? 0 : data_.capacity() - 1;
    }

    // Geometric growth: at least double, capped at max_size().
    size_t next_capacity(size_t needed) const noexcept {
        const size_t cap = content_capacity();
        const size_t doubled = cap > max_size() / 2 ? max_size() : 2 * cap;
        return max_of(needed, doubled);
    }

    // Not std::max: the Windows SDK defines a max() macro that would break it.
    static constexpr size_t max_of(size_t a, size_t b) noexcept {
        return a > b ? a : b;
    }

    // Precondition: len <= content_capacity() - size(). Nothing is
    // reallocated, so s may point into *this.
    void append_in_place(const char* s, size_t len) {
        assert(len <= content_capacity() - size());
        if (len == 0) return;                    // keep an empty string empty
        const size_t pos = size();
        data_.resize(pos + len + 1);
        std::memmove(data() + pos, s, len);      // after resize: data() may have been nul_
        data_[pos + len] = 0;
    }

public:
    using iterator = char*;
    using const_iterator = const char*;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    // --- Construction ---

    SecureString() = default;

    /// A literal null is a compile error.
    SecureString(std::nullptr_t) = delete;
    SecureString(std::nullptr_t, size_t) = delete;

    /// C string.
    /// Throws std::invalid_argument if str is null.
    explicit SecureString(const char* str) {
        check_cstr(str);
        init_from(str, std::strlen(str));
    }

    /// Copies [str, str + len); embedded '\0' is kept.
    /// Throws std::invalid_argument if str is null and len > 0.
    explicit SecureString(const char* str, size_t len) {
        init_from(str, len);
    }

    /// Copies sv exactly; also accepts std::string.
    explicit SecureString(std::string_view sv) {
        init_from(sv.data(), sv.size());
    }

    /// n copies of c. SecureString{'a', 'b'} selects this overload (97 x 'b').
    explicit SecureString(size_t n, char c) {
        check_size(n);
        if (n == 0) return;
        data_.reserve(n + 1);     // single allocation
        data_.assign(n, static_cast<uint8_t>(c));
        data_.push_back(0);
    }

    SecureString(const SecureString&) = default;
    SecureString& operator=(const SecureString&) & = default;
    /// Move steals the buffer; move assignment wipes the one it replaces.
    SecureString(SecureString&&) noexcept = default;
    SecureString& operator=(SecureString&&) & noexcept = default;
    ~SecureString() = default;

    // --- Assignment from C string ---

    /// A literal null is a compile error.
    SecureString& operator=(std::nullptr_t) & = delete;

    /// C string. A non-empty value replaces the buffer, so reserved capacity
    /// is not kept.
    /// Throws std::invalid_argument if str is null.
    SecureString& operator=(const char* str) & {
        check_cstr(str);
        size_t len = std::strlen(str);
        check_size(len);
        if (len == 0) {
            clear();
            return *this;
        }
        // Copy first: str may point into *this (s = s.c_str()).
        SecureBytes tmp;
        tmp.reserve(len + 1);
        tmp.assign(str, str + len);
        tmp.push_back(0);
        data_.swap(tmp);                     // old buffer is wiped with tmp
        return *this;
    }

    // --- Read-only view ---

    /// Non-owning view of the content, including embedded '\0'.
    /// Only the full view is NUL-terminated; a sub-view's data() is not a C
    /// string. Comparisons through the view are not constant-time.
    /// Invalidated by any mutation, by moving from *this and by destruction.
    /// Lvalue-only: a view of a temporary does not compile.
    [[nodiscard]] std::string_view view() const & noexcept {
        return std::string_view(data(), size());
    }
    std::string_view view() const && = delete;

    // --- Element access ---

    /// Precondition: pos <= size(); [size()] is the terminator.
    const char& operator[](size_t pos) const {
        assert(pos <= size());
        return data()[pos];
    }
    char& operator[](size_t pos) {
        assert(pos <= size());
        return data()[pos];
    }

    const char& at(size_t pos) const {
        if (pos >= size()) throw std::out_of_range("SecureString::at");
        return data()[pos];
    }
    char& at(size_t pos) {
        if (pos >= size()) throw std::out_of_range("SecureString::at");
        return data()[pos];
    }

    /// Precondition: !empty().
    const char& front() const { assert(!empty()); return data()[0]; }
    char& front() { assert(!empty()); return data()[0]; }
    /// Precondition: !empty().
    const char& back() const { assert(!empty()); return data()[size() - 1]; }
    char& back() { assert(!empty()); return data()[size() - 1]; }

    /// Never null, including when empty or moved-from.
    const char* c_str() const noexcept {
        return data_.empty() ? &nul_ : reinterpret_cast<const char*>(data_.data());
    }
    /// Same pointer as c_str().
    const char* data() const noexcept { return c_str(); }
    char* data() noexcept {
        return data_.empty() ? &nul_ : reinterpret_cast<char*>(data_.data());
    }

    // --- Capacity ---

    [[nodiscard]] size_t size() const noexcept { return data_.empty() ? 0 : data_.size() - 1; }
    [[nodiscard]] size_t length() const noexcept { return size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    /// One element is reserved for the terminator.
    [[nodiscard]] size_t max_size() const noexcept { return data_.max_size() - 1; }

    /// Shrinking does not wipe the removed bytes.
    void resize(size_t n) {
        check_size(n);
        if (n == 0) { data_.clear(); return; }
        data_.resize(n + 1);
        data_[n] = 0;
    }

    /// Shrinking does not wipe the removed bytes.
    void resize(size_t n, char c) {
        check_size(n);
        if (n == 0) { data_.clear(); return; }
        size_t old_size = size();
        data_.resize(n + 1);
        if (n > old_size) {
            std::fill(data_.data() + old_size, data_.data() + n,
                      static_cast<uint8_t>(c));
        }
        data_[n] = 0;
    }

    /// reserve(0) does not allocate.
    void reserve(size_t n) {
        check_size(n);
        if (n == 0) return;
        data_.reserve(n + 1);
    }

    // --- Iterators ---
    // Raw pointers; same validity as data().

    iterator begin() noexcept { return data(); }
    iterator end() noexcept { return data() + size(); }
    const_iterator begin() const noexcept { return data(); }
    const_iterator end() const noexcept { return data() + size(); }
    const_iterator cbegin() const noexcept { return begin(); }
    const_iterator cend() const noexcept { return end(); }

    reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }
    reverse_iterator rend() noexcept { return reverse_iterator(begin()); }
    const_reverse_iterator rbegin() const noexcept { return const_reverse_iterator(end()); }
    const_reverse_iterator rend() const noexcept { return const_reverse_iterator(begin()); }
    const_reverse_iterator crbegin() const noexcept { return const_reverse_iterator(end()); }
    const_reverse_iterator crend() const noexcept { return const_reverse_iterator(begin()); }

    // --- Modification ---
    // Strong exception guarantee: on failure the string is unchanged.

    /// A literal null is a compile error.
    SecureString& append(std::nullptr_t) & = delete;
    SecureString& append(std::nullptr_t, size_t) & = delete;

    /// C string.
    /// Throws std::invalid_argument if s is null.
    SecureString& append(const char* s) & {
        check_cstr(s);
        return append(s, std::strlen(s));
    }

    /// Appends [s, s + len); s may point into *this. Allocates only when the
    /// result exceeds the capacity.
    /// Throws std::invalid_argument if s is null and len > 0.
    SecureString& append(const char* s, size_t len) & {
        // Every pointer, view and SecureString append funnels into here.
        if (len == 0) return *this;
        check_buf(s, len);
        check_grow(len);
        const size_t old_size = size();
        const size_t new_size = old_size + len;
        if (new_size <= content_capacity()) {
            append_in_place(s, len);
        } else {
            // Build the result in a new buffer, then swap: *this, and any
            // source inside it, stays intact until the swap.
            SecureString grown;
            grown.reserve(next_capacity(new_size));
            grown.append_in_place(data(), old_size);
            grown.append_in_place(s, len);
            swap(grown);                   // old buffer is wiped with grown
        }
        return *this;
    }

    SecureString& append(std::string_view sv) & {
        return append(sv.data(), sv.size());
    }

    SecureString& append(const SecureString& other) & {
        return append(other.data(), other.size());
    }

    SecureString& append(size_t n, char c) & {
        if (n == 0) return *this;
        check_grow(n);
        if (data_.empty()) {
            data_.resize(n + 1);     // reuses reserved capacity
            std::fill(data_.data(), data_.data() + n, static_cast<uint8_t>(c));
        } else {
            data_.insert(data_.end() - 1, n, static_cast<uint8_t>(c));  // before the '\0'
        }
        return *this;
    }

    /// A literal null is a compile error.
    SecureString& operator+=(std::nullptr_t) & = delete;
    SecureString& operator+=(const char* s) & { return append(s); }
    SecureString& operator+=(std::string_view sv) & { return append(sv); }
    SecureString& operator+=(const SecureString& other) & { return append(other); }
    SecureString& operator+=(char c) & { push_back(c); return *this; }

    void push_back(char c) {
        check_grow(1);
        if (data_.empty()) {
            data_.resize(2);                         // reuses reserved capacity
            data_[0] = static_cast<uint8_t>(c);
        } else {
            data_.insert(data_.end() - 1, static_cast<uint8_t>(c));  // before the '\0'
        }
    }

    /// No-op when empty. Does not wipe the removed byte.
    void pop_back() noexcept {
        size_t s = size();
        if (s == 0) return;
        if (s == 1) {
            data_.clear();
        } else {
            data_[s - 1] = 0;   // becomes the new terminator
            data_.pop_back();
        }
    }

    /// Keeps capacity and does not wipe; memory is wiped when released.
    void clear() noexcept { data_.clear(); }

    // --- Comparison ---

    /// Deleted: comparing secrets must not stop at the first differing byte.
    /// Use constant_time_equal; compare non-secret data through view().
    bool operator==(const SecureString& other) const = delete;
    bool operator!=(const SecureString& other) const = delete;

    // --- Swap ---

    /// Pointers into an empty string refer to its own nul_ and do not follow
    /// the swap.
    void swap(SecureString& other) noexcept {
        data_.swap(other.data_);
    }

    // --- Conversion ---

    /// Copies the content into an ordinary, unwiped std::string.
    [[nodiscard]] std::string to_unsecure_string() const {
        return std::string(data(), size());
    }
};

static_assert(std::is_nothrow_default_constructible<SecureString>::value,
              "SecureString() must be noexcept");
static_assert(std::is_nothrow_move_constructible<SecureString>::value,
              "SecureString move construction must be noexcept");
static_assert(std::is_nothrow_move_assignable<SecureString>::value,
              "SecureString move assignment must be noexcept");
static_assert(std::is_nothrow_swappable<SecureString>::value,
              "SecureString swap must be noexcept");
static_assert(!std::is_convertible<SecureString, std::string_view>::value,
              "leaving the secure world is explicit: use view()");
static_assert(!std::is_convertible<SecureString, const char*>::value,
              "leaving the secure world is explicit: use c_str()");
static_assert(!std::is_convertible<std::string_view, SecureString>::value,
              "entering the secure world is explicit: SecureString(sv)");
static_assert(!std::is_convertible<const char*, SecureString>::value,
              "entering the secure world is explicit: SecureString(str)");
static_assert(!std::is_convertible<std::string, SecureString>::value,
              "entering the secure world is explicit: SecureString(str) or to_secure_string(str)");

} // namespace sbuf
} // namespace safeheron

#endif // SAFEHERON_SECURE_STRING_H
