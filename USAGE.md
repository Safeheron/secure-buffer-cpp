# Usage Guide

Installation and a quick start are in the [README](README.md). This guide specifies the behavior of each type.

## Choosing a Type

| Data | Type |
|------|------|
| Variable-length binary secrets (keys, seeds, nonces) | `SecureBytes` |
| Text secrets (passwords, mnemonics) | `SecureString` |
| Fixed-size secrets you own or return by value (keys, seeds, nonces of known length) | `SecureArray<T, N>` |
| Existing fixed-size buffers and integers | `ScopedCleanse` / `secure_cleanse()` |
| Plain-data structs of fixed-size fields, including third-party types | register with `enable_secure_cleanse`, then `ScopedCleanse` / `secure_cleanse()` |

## SecureString

A length-aware string with `std::string`-like semantics whose storage is wiped on release. `SecureString` owns and mutates the data; read-only operations (search, slicing, comparison) go through `view()`.

```cpp
{
    SecureString s("correct horse battery staple");
    use_c_api(s.c_str());      // always NUL-terminated
}                              // destruction wipes the whole allocation
```

### Content and Embedded NULs

The content is `[data(), data() + size())` and may contain `'\0'`. All explicit-length entry points (`(ptr, len)`, `std::string_view`, `SecureString`) are length-aware; a bare `const char*` is read as a C string (`strlen`). `c_str()` is always terminated after the content, but a C API reading it stops at the first embedded NUL.

### Wiping

The allocator wipes the entire allocation on deallocation, reallocation and destruction. `clear()`, `pop_back()` and a shrinking `resize()` have standard-library semantics and do not wipe. `SecureString` and `SecureBytes` have no wipe-in-place operation: scope the object so that its lifetime matches the secret's (RAII). Fixed-size objects can be wiped in place with `secure_cleanse()`; see [Fixed-Size Buffers](#fixed-size-buffers).

### Exception Safety

All mutators provide the strong exception guarantee. Requests exceeding `max_size()` throw `std::length_error`, null pointers throw `std::invalid_argument`, and allocation failure throws `std::bad_alloc`; in each case content, size and terminator are unchanged.

### Null Pointers

A literal null (`nullptr`, `0` or `{}`) is rejected at compile time by `SecureString(p)`, `SecureString(p, n)`, `operator=`, `append(p)`, `append(p, n)` and `operator+=`. A null pointer known only at run time throws `std::invalid_argument` when passed as a C string or with `len > 0`. `(ptr, 0)` denotes an empty range for any `ptr`, including null.

### Constructors

All value constructors are `explicit`, including the two-argument ones: `SecureString s("x")`, `SecureString s(p, n)`, `SecureString s(sv)`. Copy-initialization such as `SecureString s = "x"` or `s = {p, n}` does not compile. Direct-list-initialization `SecureString{'a', 'b'}` selects the fill constructor and yields 97 × `'b'`.

### Aliasing

Operations whose source aliases the string itself are safe: `s += s`, `s = s.c_str()`, `s.append(s.view().substr(1))`.

### Allocation

An append allocates only when the result exceeds the current capacity. Within capacity reserved by `reserve()`, appends from pointers, views and the string itself are allocation-free, so reserve the final size when assembling a secret incrementally (e.g. a mnemonic word by word). On growth, the new buffer is fully constructed before the old one is released and wiped; this makes appending a view of the string to itself well-defined, although the append invalidates that view like any other mutation. Assigning a non-empty C string (`s = "literal"`) adopts a new buffer and discards reserved capacity; `s = ""` preserves it.

### Differences from std::string

- No `find`, `substr`, `compare` or related queries; use `view()`.
- There is no `operator==` or `!=`; compare secrets with `constant_time_equal` and non-secret data through `view()` (see [Comparing Secrets](#comparing-secrets)).
- No implicit conversion to `std::string_view` or `const char*`.
- No assignment from `std::string` / `std::string_view`; write `s = SecureString(sv)`.
- No `operator<<`, `insert`, `erase`, `replace` or `capacity()`.

### Views

`view()` returns a `std::string_view` over the entire content, for parsing, searching and comparison:

```cpp
SecureString mnemonic("abandon ability able ...");
std::string_view v = mnemonic.view();          // non-owning; refers to the wiped storage

for (size_t start = 0;;) {                     // tokenize without copying
    size_t sp = v.find(' ', start);
    std::string_view word = v.substr(start, sp - start);
    lookup(word);
    if (sp == std::string_view::npos) break;
    start = sp + 1;
}

if (v == expected) { ... }                     // short-circuit comparison
SecureString owned(v.substr(0, 7));            // explicit owning copy
```

**Lifetime.** A view is invalidated by any mutation (`append`, `resize`, `reserve`, `clear`, `pop_back`, assignment, `swap`), by moving from the string, and by its destruction. This also applies within a single expression: `s.view() == f(s)` is undefined behavior if `f` mutates `s`, since the evaluation order of the operands is unspecified.

**Temporaries.** `view()` is lvalue-only: `make().view()` does not compile. The mutators that return `*this` (`append`, `operator+=`, assignment) are lvalue-only as well, so `make().append("x").view()` is rejected too. Ref-qualifiers cannot cover a function that returns a reference to its argument: with `const SecureString& pick(const SecureString& s) { return s; }`, `pick(make()).view()` compiles and dangles. Bind the string to a named object before taking a view.

**Termination.** `std::string_view::data()` is not a C string. Only `c_str()`, equal to `data()` of the full view, is NUL-terminated; passing a sub-view's `data()` to a C API reads past the slice into the rest of the secret. Make an owning copy first:

```cpp
SecureString tmp(word);
legacy_api(tmp.c_str());
```

**Timing.** Comparisons and searches through a view (`v == x`, `v.compare(...)`, `v.find(...)`) are short-circuit, not constant-time. Use `constant_time_equal` where timing is observable by an attacker.

**Exposure.** `view()`, `data()`, `c_str()`, the element accessors and the iterators expose the bytes without copying. `s.to_unsecure_string()` copies them into ordinary, unwiped memory and is the designated export path (`std::string(s.view())` is equivalent but hides the intent). Because `begin()`/`end()` make `SecureString` a range, generic formatters and serializers can iterate it; never pass it to a logger, formatter or JSON writer.

## SecureBytes

`std::vector<uint8_t>` with a wiping allocator, exposing the vector interface except comparison operators (see [Comparing Secrets](#comparing-secrets)).

```cpp
auto key = make_secure_bytes<32>();          // 32 zero-initialized bytes (still resizable)
SecureBytes buf(seed.begin(), seed.end());
```

Memory is wiped on deallocation, reallocation and destruction, as for `SecureString`. `clear()` retains capacity and does not wipe. When building incrementally, `reserve()` in advance: each reallocation incurs an additional wipe.

## SecureArray

A fixed-size array of `N` elements, zero-initialized and wiped on destruction. Use it for secrets whose size is known at compile time. Element types are integers (including `bool` and the character types) and `std::byte`, without `const` or `volatile`. `N == 0` is allowed.

```cpp
SecureArray<uint8_t, 32> seed;                 // 32 zero bytes
fill_random(seed.data(), seed.size());         // pass data() and size() to C-style APIs
seed[0] = 1;
uint8_t first = seed.at(0);                    // throws std::out_of_range if the index >= N
for (uint8_t b : seed) { ... }                 // raw-pointer iterators
```

- **Copies.** Every copy is a separate array that wipes itself on destruction.
- **Moves are copies**, as for `std::array`: the source keeps its value until it is destroyed. Call `secure_cleanse(source)` to wipe it sooner.
- **No conversion to or from `std::array`.** Pass `data()` and `size()` instead.
- **Returning.** Write `return result;`, not `return std::move(result);`. The plain form lets the compiler construct the result in place; `std::move` forces a copy, after which the local is wiped when it is destroyed.
- **Access.** `operator[]`, `front()` and `back()` assert their preconditions in debug builds; `at()` throws `std::out_of_range`.
- **Copies out of the array.** Bytes copied out through `data()` are not protected; keep the secret in a `SecureArray`, or guard each copy.
- **Lifetime.** Pointers, references and iterators from `data()`, `begin()` and the like must not outlive the `SecureArray`.
- **Pass by `const&`.** By-value parameters, by-value lambda captures and range-for by value each make a copy. The copies are wiped, but more copies of the secret exist meanwhile.
- **Comparison.** There is no `operator==` or `!=`; use `constant_time_equal(a, b)` for two arrays of the same type.

## Conversion from and to std::string

```cpp
SecureBytes  b = to_secure_bytes(legacy);    // import
SecureString s = to_secure_string(legacy);
std::string  u = to_unsecure_string(b);      // export; the result is not protected
```

The source `std::string` is not wiped; that remains the caller's responsibility.

`SecureString(std::string_view)` also accepts a `std::string` directly (`SecureString s(legacy);`). `to_secure_string` is the named equivalent.

## Comparing Secrets

Use `constant_time_equal` wherever timing is attacker-observable (MACs, tokens, keys). For inputs of equal length its running time is independent of the contents; inputs of different length return `false` immediately, so compare fixed-length values such as digests rather than variable-length passwords. View-based comparisons and `std::equal` are short-circuit and suitable only for tests and non-secret data.

```cpp
if (constant_time_equal(mac1, mac2)) { ... }             // SecureBytes / SecureString / SecureArray of the same type
if (constant_time_equal(a.data(), b.data(), 32)) { ... } // raw pointers
```

`SecureBytes`, `SecureString` and `SecureArray` have no comparison operators: `a == b` (and `!=`, `<`, `>`, `<=`, `>=`, `<=>`) does not compile, so a secret cannot be compared by accident with a short-circuit operator. For non-secret data, use `std::equal` (`SecureBytes`, `SecureArray`) or `view()` (`SecureString`):

```cpp
bool same = std::equal(a.begin(), a.end(), b.begin(), b.end());  // SecureBytes, non-secret data
bool eq   = s.view() == "expected";                              // SecureString, non-secret data
```

This is compile-time misuse prevention, not isolation: an explicit `std::operator==(a, b)`, `std::equal` or `memcmp` still compares the bytes, so review those. The protection applies to the `SecureBytes` name (or the umbrella header `secure_buffer.h`); a type spelled out as `std::vector<uint8_t, SecureAllocator<uint8_t>>` without including `secure_bytes.h` is not covered.

The containers remain usable as values: `std::vector<SecureBytes>`, `std::optional<SecureBytes>` and the mapped type of `std::map` / `std::unordered_map` all work. They cannot be a `std::map` / `std::set` key, be sorted with `std::sort`, be searched by value with `std::find` / `std::count`, or have two `std::vector<SecureBytes>` compared with `==`, all with the default comparator. Key by a public identifier (key ID, fingerprint) and keep the secret as the value. If you really need a secret as a key, write your own comparator, and note that it is not constant-time, so lookups leak timing.

In tests, Google Test's `EXPECT_EQ` on these types does not compile; compare views (`EXPECT_EQ(s.view(), "abc")`) or use `EXPECT_TRUE(constant_time_equal(a, b))`.

## Fixed-Size Buffers

For fixed-size objects that you do not want to replace with `SecureArray`, `ScopedCleanse` wipes the object when the guard goes out of scope, on normal return, early return and exception unwinding. It does not run if the process ends through `std::exit`, `std::abort` or `std::terminate` (for example, an uncaught exception). `secure_cleanse(obj)` wipes it immediately and leaves it alive, holding zeros.

```cpp
std::array<uint8_t, 32> key{};
ScopedCleanse guard(key);              // create the guard before writing the secret
derive(key.data(), key.size());

uint8_t nonce[12];
ScopedCleanse nonce_guard(nonce);      // built-in arrays work too

uint32_t counter = 0;
// ...
secure_cleanse(counter);               // wipe now; counter stays usable and holds 0
```

Accepted types are integers (including `bool` and the character types), `std::byte`, plain-data types registered with `enable_secure_cleanse` (see [Registering Plain-Data Types](#registering-plain-data-types)), and `std::array` or built-in arrays of them, nested to any depth, without `const` or `volatile`. `secure_cleanse` also accepts a `SecureArray`. A dynamic container (`std::vector`, `std::string`, ...) is a compile error, because its secret lives outside the object. For example, `secure_cleanse` reports:

```
secure_cleanse accepts integers, std::byte, types registered with enable_secure_cleanse and fixed-size arrays of them; dynamic containers cannot be wiped in place, use SecureBytes/SecureString
```

`ScopedCleanse` is neither copyable nor movable. Rules for using it:

- Create the guard before writing the secret, so that no exit path can skip it.
- The object must outlive the guard, so declare the object first. Binding a guard to a temporary does not compile.
- Always name the guard. `ScopedCleanse{key};` creates a temporary that is destroyed, and wipes `key`, at the end of the statement.
- Never return a guarded named object by value. When the compiler elides the copy, the guard wipes the caller's object. Use an output parameter, return a `SecureArray`, or return an explicit copy such as `return std::array<uint8_t, 32>(result);` and guard that copy at the caller.
- `std::move` of a plain array copies it and does not wipe the source.
- A copy of a guarded array, and bytes copied out through `data()`, are not protected. Each copy needs its own guard, or keep the secret in a `SecureArray`, whose copies wipe themselves.
- Pointers, references and iterators obtained from the guarded array must not outlive it.
- `x = f()` and `g(f())` create unguarded temporaries that are not wiped. Initialize a guarded named variable instead and pass that.

`secure_memzero(ptr, len)` remains available as the low-level primitive for memory you manage yourself.

## Registering Plain-Data Types

`secure_cleanse()` and `ScopedCleanse` accept a class or union type only if you register it. Registering is a declaration that every byte of the type is data stored inline, with no pointer, view or handle members, and that all-zero bytes are a valid value of the type. Specialize `enable_secure_cleanse` as `std::true_type`:

```cpp
namespace app {
struct SessionKeys {
    std::array<uint8_t, 32> enc;
    std::array<uint8_t, 32> mac;
};
}  // namespace app

template <>
struct safeheron::secure_buffer::enable_secure_cleanse<app::SessionKeys> : std::true_type {};

app::SessionKeys keys = derive_session_keys(master);
ScopedCleanse guard(keys);
```

The specialization may be written at global scope with the qualified name, as above, or inside namespace `safeheron::secure_buffer`. It cannot be written inside the namespace of the type itself.

Every use of a registered type is checked, including as an array element, and the checks cannot be turned off, for your own types and third-party types alike. The type must be:

- a class or union, which rejects registering pointers, enums and floating-point types. Registering an array type itself has no effect: arrays are accepted or rejected according to their element type, so register the element type;
- free of `const` and `volatile`, which rejects wiping a `const` object;
- trivially copyable, which rejects dynamic members such as `std::vector` or `std::string`, user-provided destructors and virtual functions;
- trivially copy-assignable, which rejects `const` and reference members: writing zeros into a `const` member is undefined behaviour, and into a reference it breaks the reference.

A type that fails a check is a compile error at the point where it is wiped:

```
a type registered with enable_secure_cleanse must be a non-cv class or union that is trivially copyable and trivially copy-assignable
```

The checks cannot see everything. You are responsible for these:

- Pointer, view and handle members, private ones included. `struct { uint8_t* p; size_t n; }` passes every check, but wiping it zeroes only the pointer and leaves the secret where it was.
- All-zero must be a valid value of the type, for example no enum member that may not be 0.
- No `volatile` members. The checks cannot see them, and zeroing a `volatile` object with `memset` is undefined behaviour; such structs are usually hardware register maps.
- Wipe the complete object, never a base-class part of a derived object or a `[[no_unique_address]]` member: those can share bytes (tail padding) with neighbouring members, and the wipe would zero them.

Visibility:

- Every translation unit that wipes the type must see the registration. For your own type, register it right after the type definition. For a third-party type, put the registration in one registration header and include that where you wipe the type, instead of including the third-party header directly.
- A translation unit that misses the registration does not compile; it never skips the wipe silently.
- Register each type in exactly one place. A duplicate specialization in one translation unit is an error, and specializations in different translation units must be identical.

Registering needs no change to the type's source, so it works for third-party types. Put a `sizeof` tripwire and the version you checked next to the registration, because the checks cannot see a pointer member added by an upgrade:

```cpp
// kdf_cleanse.h: include this instead of <vendor/kdf.h> wherever KdfState is wiped.
#ifndef KDF_CLEANSE_H
#define KDF_CLEANSE_H

#include <vendor/kdf.h>
#include <secure-buffer/secure_cleanse.h>

// Checked against vendor 2.3: fixed-size arrays only, no pointer or view members.
static_assert(sizeof(vendor::KdfState) == 200,
              "vendor::KdfState layout changed; re-check it before wiping");

template <>
struct safeheron::secure_buffer::enable_secure_cleanse<vendor::KdfState> : std::true_type {};

#endif // KDF_CLEANSE_H
```

You are vouching for the layout of a type you do not own, so check its private members too. If an upgrade adds a dynamic member, a destructor, or a `const` or reference member, the checks fail to compile. If it adds a pointer member, only the `sizeof` tripwire notices. A third-party type that is not plain data is rejected; wrap it in your own class whose destructor calls the library's own cleanup function.

Notes:

- Arrays of a registered type are accepted, such as `std::array<app::SessionKeys, 4>` and `app::SessionKeys[2]`.
- Registration does not propagate. A struct whose members are all cleansable or registered must be registered itself.
- A registered type cannot be a `SecureArray` element; `SecureArray` holds only integers and `std::byte`.
- Only objects you guard or wipe are wiped. Copies and temporaries are not.

## Custom Secret Types

For record-like plain types, such as a group of key bytes, see [Registering Plain-Data Types](#registering-plain-data-types) instead. When a secret is a member of your own class, give the class a destructor that wipes its plain fixed-size storage. `Coeff` below stands for your own plain coefficient type.

```cpp
class Poly {
 public:
    Poly() noexcept = default;
    // Declared because a user-declared destructor deprecates the implicit
    // copy; moves fall back to these copies, which cost the same for an array.
    Poly(const Poly&) noexcept = default;
    Poly& operator=(const Poly&) noexcept = default;
    // Every Poly, named or temporary, is wiped when its lifetime ends.
    ~Poly() { safeheron::secure_buffer::secure_memzero(&coeffs_, sizeof(coeffs_)); }

 private:
    std::array<Coeff, 256> coeffs_{};
    // Rejects storage such as std::vector or std::string, whose secret lives
    // outside the object and would survive this wipe.
    static_assert(std::is_trivially_copyable_v<decltype(coeffs_)>,
                  "only plain fixed-size storage can be wiped in the destructor");
};
```

The `static_assert` cannot catch raw pointer members: a struct holding a pointer is still trivially copyable, and the wipe would not reach what the pointer refers to. Confirm that the type holds no pointer to secret data.

This covers named objects, temporaries, copies, and objects destroyed by `std::optional::reset()`, since every one of them runs the destructor. Costs:

- Under C++17 the type loses `constexpr` construction, because the destructor is not trivial.
- The type is no longer trivially copyable, so it cannot be registered with `enable_secure_cleanse`; the two approaches are alternatives.
- Every value of the type is wiped, including ones you hand out publicly.

## Per-Platform Builds

See [PLATFORMS.md](PLATFORMS.md).

## Out of Scope

Compiler-generated stack copies, swapped-out pages, core dumps, and residual data in CPU registers or caches are not covered. See [Security Notes](README.md#security-notes) for application-level mitigations.
