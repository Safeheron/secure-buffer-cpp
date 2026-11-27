// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#include <secure-buffer/secure_memzero.h>
#include <cstring>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>        // SecureZeroMemory
#endif

namespace safeheron {
namespace sbuf {

void secure_memzero(void* ptr, std::size_t len) noexcept {
    if (len == 0) return;

#if defined(_WIN32)
    // Documented never to be optimized away:
    // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366877(v=vs.85)
    ::SecureZeroMemory(ptr, len);

#elif defined(__GNUC__) || defined(__clang__)
    // memset, then a compiler barrier against dead-store elimination, as in
    // musl explicit_bzero and BoringSSL OPENSSL_cleanse. The asm emits no
    // instructions; "memory" is a compiler clobber, not a hardware fence.
    // https://git.musl-libc.org/cgit/musl/tree/src/string/explicit_bzero.c
    // https://boringssl.googlesource.com/boringssl/+/HEAD/crypto/mem.cc
    // https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
    std::memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");

#else
    // Portable fallback: volatile stores cannot be elided.
    // https://en.cppreference.com/w/cpp/language/cv
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (std::size_t i = 0; i < len; ++i) p[i] = 0;
#endif
}

} // namespace sbuf
} // namespace safeheron
