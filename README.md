# secure-buffer-cpp

A C++17 library of self-wiping containers for sensitive data such as keys, seeds and mnemonics. Heap memory owned by `SecureBytes` and `SecureString` is securely zeroed whenever it is released, on destruction and on reallocation. The limits of that guarantee are listed under [Security Notes](#security-notes).

The library is a foundational component of Safeheron's TEE and cryptography stack.

## Features

- No dependencies beyond the C++ standard library and the platform.
- Supports Linux (including AWS Nitro Enclaves), macOS, Windows, Android, iOS, SGX and WebAssembly.
- Header-first API with a minimal compiled core: all platform-specific code is confined to `src/secure_memzero.cpp`, built as a small static library.
- `SecureAllocator` zeroes every block before deallocating it.
- Fixed-size secrets: `SecureArray` is wiped on destruction, and `ScopedCleanse` / `secure_cleanse()` wipe existing arrays and integers, and plain-data types you register with `enable_secure_cleanse`.
- `sbuf::span`: a C++17 subset of `std::span` with run-time or compile-time length, for borrowing buffers without copying; `as_span()` borrows a `SecureArray` with its length.

## Quick Start

```cpp
#include <secure-buffer/secure_buffer.h>

using namespace safeheron::sbuf;

// 32 zero-initialized bytes
auto key = make_secure_bytes<32>();

// Fixed-size secret, zero-initialized and wiped on destruction
SecureArray<uint8_t, 32> seed;

// Borrow without copying; the length stays in the type
auto seed_view = as_span(seed);              // span<const uint8_t, 32>
auto half = seed_view.first<16>();           // span<const uint8_t, 16>

// Existing stack buffer, wiped when the guard goes out of scope
uint8_t nonce[32];
ScopedCleanse guard(nonce);

// Heap-backed string without SSO, so short secrets are wiped as well
SecureString mnemonic("abandon abandon abandon ... about");

// Read-only access through a non-owning view (no copy)
std::string_view v = mnemonic.view();
std::string_view first_word = v.substr(0, v.find(' '));

// Import from std::string
std::string legacy = get_secret();
SecureBytes bytes = to_secure_bytes(legacy);
SecureString str = to_secure_string(legacy);

// Constant-time comparison
if (constant_time_equal(key, expected_key)) { /* match */ }

// Export to std::string; the result is not protected
std::string unsafe = to_unsecure_string(bytes);
```

## Types

| Type | Description |
|------|-------------|
| `SecureBytes` | `std::vector<uint8_t, SecureAllocator<uint8_t>>`: the vector interface without comparison operators, wiped on every deallocation. |
| `SecureString` | Length-aware string backed by `SecureBytes`. It has no small-string optimization, whose inline buffer would bypass the allocator. Read-only queries go through `view()`. |
| `SecureArray<T, N>` | Fixed-size array of integers or `std::byte`, zero-initialized and wiped on destruction. Every copy wipes itself; moves are copies. |
| `sbuf::span<T>` / `sbuf::span<T, N>` | Non-owning view of contiguous memory: a C++17 subset of `std::span`, with run-time or compile-time length. Does not wipe. `as_span()` / `as_writable_span()` borrow a `SecureArray`. |
| `secure_cleanse` / `ScopedCleanse` | Wipe an existing fixed-size object (integer, `std::byte`, a plain-data type registered with `enable_secure_cleanse`, or a `std::array` or built-in array of them) in place, or when a guard leaves scope. `secure_cleanse` also accepts a `SecureArray`; `ScopedCleanse` does not, since `SecureArray` wipes itself. |
| `SecureAllocator<T>` | Allocator that calls `secure_memzero` before each deallocation. |
| `secure_memzero` | Portable memory zeroing that the compiler cannot elide. |
| `version()` / `SECURE_BUFFER_VERSION_*` | The library version: `version()` reports the linked library at run time, the macros in `version.h` the headers at compile time. |

## Integration

`safeheron::secure-buffer` is a static library built from source with your own toolchain; no prebuilt binaries are shipped. On desktop platforms, WebAssembly, Android and iOS it is consumed as an ordinary CMake target. SGX enclaves are the exception: the source files must be compiled with the enclave toolchain, for example as a trusted library via [Safeheron ssgx](https://github.com/Safeheron/ssgx), since a host-built archive cannot be linked into an enclave.

[USAGE.md](USAGE.md) documents the contracts of each type; [PLATFORMS.md](PLATFORMS.md) covers Android, iOS, WebAssembly, Nitro and SGX builds.

### CMake find_package (installed library)

Build and install the library without its tests, configured with the same compiler, toolchain file and options as the project that uses it:

```bash
cmake -B build -DSECURE_BUFFER_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cmake --install build --config Release --prefix <prefix>
```

Then point `CMAKE_PREFIX_PATH` at `<prefix>`:

```cmake
find_package(secure-buffer 0.12 REQUIRED)
target_link_libraries(my_project PRIVATE safeheron::secure-buffer)
```

### CMake FetchContent

```cmake
include(FetchContent)

FetchContent_Declare(
    secure-buffer
    GIT_REPOSITORY https://github.com/Safeheron/secure-buffer-cpp.git
    GIT_TAG v0.12.0
)
FetchContent_MakeAvailable(secure-buffer)

target_link_libraries(my_project PRIVATE safeheron::secure-buffer)
```

### Git Submodule

```bash
git submodule add https://github.com/Safeheron/secure-buffer-cpp.git third_party/secure-buffer
```

```cmake
add_subdirectory(third_party/secure-buffer)
target_link_libraries(my_project PRIVATE safeheron::secure-buffer)
```

## Building Tests

```bash
cmake -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Requires CMake 3.28+ and a C++17 compiler. `--config` / `-C` select the configuration for multi-config generators (Visual Studio, Xcode) and have no effect otherwise. Google Test (BSD-3-Clause) is fetched at configure time when the tests are built, and is never installed.

CI covers Linux (GCC and Clang, libstdc++ and libc++, plus an ASan/UBSan build), macOS (Apple Clang) and Windows (MSVC); see `.github/workflows/ci.yml`. An integration job (`tests/integration/run.sh`) checks installation, use through `find_package` and `add_subdirectory` with and without the tests, and that settings passed in from outside take effect.

## Build Options

- `SECURE_BUFFER_BUILD_TESTS`: ON by default when this is the top-level project, OFF when it is added as a subproject. When OFF, Google Test is not downloaded, built or installed. When a parent project turns it ON, the parent's top-level `CMakeLists.txt` must call `enable_testing()` for the parent's `ctest` to find these tests; otherwise run `ctest` in the library's build directory.
- Settings defined by the user, a toolchain file or a parent project take precedence. Otherwise the library target uses these defaults:
  - C++17 without compiler extensions (`CMAKE_CXX_STANDARD`, `CMAKE_CXX_EXTENSIONS`);
  - position-independent code, so the library can be linked into a shared library (`CMAKE_POSITION_INDEPENDENT_CODE`);
  - no C++20 module scanning of its source, which has no modules (`CMAKE_CXX_SCAN_FOR_MODULES`), so a C++20 build with Ninja does not need `clang-scan-deps` for it;
  - warnings as errors only when the tests are built (`CMAKE_COMPILE_WARNING_AS_ERROR`; `cmake --compile-no-warning-as-error` turns it off).

  None of these defaults reaches the parent project. The tests use the same C++ standard defaults, which also apply to Google Test; warnings as errors never do.
- The library is always static; `BUILD_SHARED_LIBS` does not apply to it.

## Security Notes

Memory is wiped when it is deallocated, on destruction or reallocation; the allocator always wipes the entire block. `clear()`, `pop_back()` and a shrinking `resize()` keep standard-library semantics and do not wipe the removed bytes, which remain in the allocation until it is released. Tie a secret's lifetime to the owning object (RAII).

The absence of `operator<<` is not a confidentiality guarantee. Any code holding `data()`, `view()` or an iterator can read the contents, and generic range formatters and serializers can iterate a `SecureString`. Do not log, format or serialize secrets.

The secure containers have no comparison operators (`a == b` does not compile), so a secret is not compared with a short-circuit operator by accident. This is compile-time misuse prevention, not isolation: an explicit `std::equal` or `memcmp` still compares the bytes. Use `constant_time_equal` for secrets.

`constant_time_equal` is constant-time in the contents for inputs of equal length. Inputs of different length return immediately; length is treated as public.

Only heap memory managed by `SecureAllocator`, `SecureArray` storage, and objects guarded by `ScopedCleanse` or wiped with `secure_cleanse()` are protected. Out of scope:

- Unguarded stack variables and compiler-generated temporaries.
- Swap: use `mlock()` / `VirtualLock()` at the application level.
- Core dumps: use `madvise(MADV_DONTDUMP)` or `prctl(PR_SET_DUMPABLE, 0)` at the application level.
- CPU registers and caches: requires hardware support.

Wiping a registered plain-data type zeroes its own bytes only; pointer or view members are not followed, so the data they refer to is not wiped.

## License

Copyright 2026 Safeheron Inc. Licensed under the [Apache License 2.0](LICENSE).
