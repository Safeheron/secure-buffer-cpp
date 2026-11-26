// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_CLEANSE_H
#define SAFEHERON_SECURE_CLEANSE_H

#include <array>
#include <cstddef>
#include <memory>
#include <type_traits>

#include <secure-buffer/secure_memzero.h>

namespace safeheron {
namespace secure_buffer {

/// Specialize as std::true_type to declare that every byte of T is data
/// stored inline (no pointer, view or handle members) and that all-zero bytes
/// are a valid value of T. secure_cleanse and ScopedCleanse then accept T and
/// arrays of T.
/// A specialization may be written at global scope with the qualified name
/// (template <> struct safeheron::secure_buffer::enable_secure_cleanse<X> ...)
/// or inside namespace safeheron::secure_buffer, but not inside the namespace of
/// X. It must be visible in every translation unit that wipes T.
template <typename T>
struct enable_secure_cleanse : std::false_type {};

namespace detail {

// An element type that can be wiped by zeroing its bytes: an unqualified
// integer type (including bool and the character types) or std::byte.
template <typename T>
struct is_cleansable_scalar
    : std::bool_constant<!std::is_const<T>::value && !std::is_volatile<T>::value &&
                         (std::is_integral<T>::value || std::is_same<T, std::byte>::value)> {};

// The checks a registered type must pass: a non-cv class or union that is
// trivially copyable and trivially copy-assignable.
template <typename T>
struct is_valid_registration
    : std::bool_constant<(std::is_class<T>::value || std::is_union<T>::value) &&
                         !std::is_const<T>::value && !std::is_volatile<T>::value &&
                         std::is_trivially_copyable<T>::value &&
                         std::is_trivially_copy_assignable<T>::value> {};

// A scalar, a valid registered type, or a (possibly nested) std::array /
// built-in array of them. A cv-qualified built-in array is rejected through its
// cv-qualified element type; a cv-qualified std::array does not match the
// std::array specialization and is rejected by the primary template. The
// conjunction/disjunction short-circuit, so the trivially-copyable traits are
// instantiated only for registered types.
template <typename T>
struct is_cleansable
    : std::disjunction<is_cleansable_scalar<T>,
                       std::conjunction<enable_secure_cleanse<T>, is_valid_registration<T>>> {};

template <typename U, std::size_t N>
struct is_cleansable<std::array<U, N>> : is_cleansable<U> {};

template <typename U, std::size_t N>
struct is_cleansable<U[N]> : is_cleansable<U> {};

// T is registered with enable_secure_cleanse but fails the checks; looks
// through std::array / built-in arrays to the element type.
template <typename T>
struct has_invalid_registration
    : std::conjunction<enable_secure_cleanse<T>, std::negation<is_valid_registration<T>>> {};

template <typename U, std::size_t N>
struct has_invalid_registration<std::array<U, N>> : has_invalid_registration<U> {};

template <typename U, std::size_t N>
struct has_invalid_registration<U[N]> : has_invalid_registration<U> {};

} // namespace detail

/// Zeroes obj in place; the compiler cannot elide it. The object stays alive
/// and holds zeros afterwards.
/// Accepts integers, std::byte, types registered with enable_secure_cleanse and
/// fixed-size (std::array or built-in, possibly nested) arrays of them.
/// Precondition: obj is not a base-class subobject or a [[no_unique_address]]
/// member; those can share bytes with neighbouring members.
template <typename T>
void secure_cleanse(T& obj) noexcept {
    static_assert(!detail::has_invalid_registration<T>::value,
                  "a type registered with enable_secure_cleanse must be a non-cv class or union "
                  "that is trivially copyable and trivially copy-assignable");
    static_assert(detail::is_cleansable<T>::value,
                  "secure_cleanse accepts integers, std::byte, types registered with "
                  "enable_secure_cleanse and fixed-size arrays of them; dynamic containers "
                  "cannot be wiped in place, use SecureBytes/SecureString");
    secure_memzero(std::addressof(obj), sizeof(obj));
}

/// Wipes the referenced object when the guard is destroyed: on normal return,
/// early return and exception unwinding. Not run if the process ends through
/// std::exit, std::abort or std::terminate (for example, an uncaught exception).
/// Accepts integers, std::byte, types registered with enable_secure_cleanse and
/// fixed-size (std::array or built-in, possibly nested) arrays of them.
/// Precondition: the object outlives the guard. Temporaries are rejected.
/// Precondition: the object is not a base-class subobject or a
/// [[no_unique_address]] member; those can share bytes with neighbouring members.
/// Do not return a guarded named object by value: when the copy is elided the
/// guard wipes the caller's object.
/// The guard is neither copyable nor movable.
// [[nodiscard]] on the class lets compilers that support it (Clang) diagnose an
// unnamed guard such as `ScopedCleanse{key};`, which is destroyed - and wipes -
// at the end of the statement. It is deliberately not on the constructor, where
// GCC <= 9 would emit -Wattributes in every consumer translation unit.
template <typename T>
class [[nodiscard]] ScopedCleanse final {
    static_assert(!detail::has_invalid_registration<T>::value,
                  "a type registered with enable_secure_cleanse must be a non-cv class or union "
                  "that is trivially copyable and trivially copy-assignable");
    static_assert(detail::is_cleansable<T>::value,
                  "ScopedCleanse accepts integers, std::byte, types registered with "
                  "enable_secure_cleanse and fixed-size arrays of them; SecureArray wipes "
                  "itself, and dynamic containers need SecureBytes/SecureString");

public:
    explicit ScopedCleanse(T& obj) noexcept : obj_(obj) {}
    ScopedCleanse(T&&) = delete;
    ~ScopedCleanse() { secure_cleanse(obj_); }

    ScopedCleanse(const ScopedCleanse&) = delete;
    ScopedCleanse& operator=(const ScopedCleanse&) = delete;
    ScopedCleanse(ScopedCleanse&&) = delete;
    ScopedCleanse& operator=(ScopedCleanse&&) = delete;

private:
    T& obj_;
};

// Same deduction as the constructor's implicit guide. Declared so that
// -Wctad-maybe-unsupported (GCC, Clang; part of -Weverything) does not fire on
// `ScopedCleanse guard(x);` in consumer builds. Temporaries are rejected by the
// deleted T&& constructor, not by this guide.
template <typename T>
ScopedCleanse(T&) -> ScopedCleanse<T>;

} // namespace secure_buffer
} // namespace safeheron

#endif // SAFEHERON_SECURE_CLEANSE_H
