# Platform Integration

The library is one set of portable headers plus two compiled source files,
built from source with your own toolchain: `src/secure_memzero.cpp`, which holds
all platform-specific code, and `src/version.cpp`, which only provides
`version()`. The only question per platform is: **which toolchain compiles
those two files.**

On most platforms the answer is your own toolchain via this repo's CMake:
configure with the platform's toolchain file, if any, and link one target:

```cmake
target_link_libraries(my_target PRIVATE safeheron::secure-buffer)
```

## Linux / macOS / Windows

Standard CMake build. Consume it via `find_package` (installed) or
`FetchContent` / `add_subdirectory` (in-tree); see the [README](README.md).

## Android

Configure with the NDK toolchain file, then link as usual:

```bash
cmake -B build \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21
```

The typical setup is a JNI `.so` that links this library statically. Multiple
`.so` files embedding their own copy are harmless, as the library has no
global state.

## iOS

CMake has built-in iOS support; building a static library needs no code
signing:

```bash
cmake -B build -G Xcode -DCMAKE_SYSTEM_NAME=iOS \
  -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64
```

Link the resulting static library or framework into the app as usual.

## WebAssembly

```bash
emcmake cmake -B build && cmake --build build
```

The compiled core is built by emcc like any other source file; the memory
barrier lowers to a compiler barrier, which is sufficient there.

## AWS Nitro Enclaves

A Nitro enclave runs an ordinary Linux binary: build as for Linux (static
linking is recommended for a minimal rootfs) and package with
`nitro-cli build-enclave`. No library-specific steps are required.

## SGX enclave

SGX is the exception, since an enclave cannot link a host-built archive. Recompile
`src/secure_memzero.cpp` and `src/version.cpp` with the enclave toolchain and
expose the public headers to the enclave target. An enclave that never calls
`safeheron::sbuf::version()` may compile `src/secure_memzero.cpp` alone. With
[Safeheron ssgx](https://github.com/Safeheron/ssgx):

```cmake
ssgx_add_trusted_library(secure_buffer_t SRCS
    ${secure_buffer_dir}/src/secure_memzero.cpp
    ${secure_buffer_dir}/src/version.cpp)
target_include_directories(secure_buffer_t PUBLIC ${secure_buffer_dir}/include)

ssgx_add_enclave_library(my_enclave SRCS enclave.cpp
    TRUSTED_LIBS secure_buffer_t ...)
```

The library performs pure in-enclave computation and requires no ECALL,
OCALL or EDL definitions.

## One process, one version

Keep every component in a process on the same library version and the same C++
standard library / toolchain. Same-version duplicate copies (e.g. several `.so`
files each embedding the static library) are harmless; mixing different
versions or standard libraries across a shared-library boundary is not
supported. Do not merge this library's object files into other archives
(e.g. via `--whole-archive`); a plain `target_link_libraries` is sufficient.
