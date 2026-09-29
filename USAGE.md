# Usage Guide

Installation and a quick start are in the [README](README.md). This guide specifies the behavior of each type.

## Choosing a Type

| Data | Type |
|------|------|
| Binary secrets (keys, seeds, nonces) | `SecureBytes` |
| Text secrets (passwords, mnemonics) | `SecureString` |
| Caller-managed stack buffers | `secure_memzero(ptr, len)` |

## SecureString

A length-aware string with `std::string`-like semantics whose storage is wiped on release. `SecureString` owns and mutates the data; read-only operations (search, slicing, comparison) go through `view()`.

```cpp
{
    SecureString s("correct horse battery staple");
    use_c_api(s.c_str());      // always NUL-terminated
}                              // destruction wipes the whole allocation
```

### Content and Embedded NULs

The content is `[data(), data() + size())` and may contain `'\0'`. All explicit-length entry points (`(ptr, len)`, `std::string_view`, `SecureString`) and `operator==` are length-aware; a bare `const char*` is read as a C string (`strlen`). `c_str()` is always terminated after the content, but a C API reading it stops at the first embedded NUL.

### Wiping

The allocator wipes the entire allocation on deallocation, reallocation and destruction. `clear()`, `pop_back()` and a shrinking `resize()` have standard-library semantics and do not wipe. The library intentionally provides no wipe-in-place operation: scope the object so that its lifetime matches the secret's (RAII).

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
- `operator==` is defined only between `SecureString`s; compare other types through `view()`.
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

`std::vector<uint8_t>` with a wiping allocator, exposing the full vector interface.

```cpp
auto key = make_secure_bytes<32>();          // 32 zero-initialized bytes (still resizable)
SecureBytes buf(seed.begin(), seed.end());
```

Memory is wiped on deallocation, reallocation and destruction, as for `SecureString`. `clear()` retains capacity and does not wipe. When building incrementally, `reserve()` in advance: each reallocation incurs an additional wipe.

## Conversion from and to std::string

```cpp
SecureBytes  b = to_secure_bytes(legacy);    // import
SecureString s = to_secure_string(legacy);
std::string  u = to_unsecure_string(b);      // export; the result is not protected
```

The source `std::string` is not wiped; that remains the caller's responsibility.

`SecureString(std::string_view)` also accepts a `std::string` directly (`SecureString s(legacy);`). `to_secure_string` is the named equivalent.

## Comparing Secrets

Use `constant_time_equal` wherever timing is attacker-observable (MACs, tokens, keys). For inputs of equal length its running time is independent of the contents; inputs of different length return `false` immediately, so compare fixed-length values such as digests rather than variable-length passwords. `operator==` and all view-based comparisons are short-circuit and suitable only for tests and non-secret data.

```cpp
if (constant_time_equal(mac1, mac2)) { ... }             // SecureBytes / SecureString
if (constant_time_equal(a.data(), b.data(), 32)) { ... } // raw pointers
```

## Stack Buffers

```cpp
uint8_t tmp[64];
derive(tmp, sizeof(tmp));
// ... use tmp ...
secure_memzero(tmp, sizeof(tmp));   // not elided by the optimizer
```

## Per-Platform Builds

See [PLATFORMS.md](PLATFORMS.md).

## Out of Scope

Compiler-generated stack copies, swapped-out pages, core dumps, and residual data in CPU registers or caches are not covered. See [Security Notes](README.md#security-notes) for application-level mitigations.
