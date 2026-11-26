// Checks that SecureArray wipes its storage before the memory is freed.
//
// Replaces the global operator new/delete for this executable only; the full
// set is replaced so allocation and deallocation stay paired through
// malloc/free. Every delete overload runs the check, since which one the
// standard library calls varies by toolchain. Each test asserts that the check
// actually ran. SecureArray objects are heap-allocated so that the free of the
// object itself is observable after its destructor has run.
#include <gtest/gtest.h>
#include <secure-buffer/secure_array.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <utility>

namespace {
    void*  g_target      = nullptr;  // block expected to be zeroed
    size_t g_target_size = 0;        // its size in bytes
    bool   g_armed       = false;
    bool   g_checked     = false;    // target's free was intercepted
    bool   g_zeroed      = false;    // target was all zero at that point

    void reset() {
        g_target = nullptr; g_target_size = 0;
        g_armed = false; g_checked = false; g_zeroed = false;
    }

    // Runs on every deallocation form; must not allocate (re-entrancy).
    void intercept_free(void* p) {
        if (g_armed && p && p == g_target) {
            g_checked = true;
            g_zeroed  = true;
            const auto* b = static_cast<const unsigned char*>(p);
            for (size_t i = 0; i < g_target_size; ++i) {
                if (b[i] != 0) { g_zeroed = false; break; }
            }
            g_target = nullptr;   // one-shot
        }
        std::free(p);
    }
}

void* operator new(std::size_t n) {
    void* p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return std::malloc(n ? n : 1); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return std::malloc(n ? n : 1); }
void operator delete(void* p) noexcept { intercept_free(p); }
void operator delete(void* p, std::size_t) noexcept { intercept_free(p); }
void operator delete[](void* p) noexcept { intercept_free(p); }
void operator delete[](void* p, std::size_t) noexcept { intercept_free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { intercept_free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { intercept_free(p); }

namespace {
    void arm(void* p, size_t n) { reset(); g_target = p; g_target_size = n; g_armed = true; }
}

using safeheron::secure_buffer::SecureArray;

TEST(SecureArrayZeroingTest, DestructorWipesBeforeFree) {
    using SA = SecureArray<uint8_t, 64>;
    auto* p = new SA;
    for (size_t i = 0; i < SA::size(); ++i) (*p)[i] = 0xAA;
    arm(p, sizeof(*p));
    delete p;
    EXPECT_TRUE(g_checked) << "target object was never intercepted -- check did not run";
    EXPECT_TRUE(g_zeroed)  << "array was not wiped before deallocation";
    reset();
}

TEST(SecureArrayZeroingTest, CopyIsWipedOnDestruction) {
    using SA = SecureArray<uint8_t, 64>;
    auto* src = new SA;
    for (size_t i = 0; i < SA::size(); ++i) (*src)[i] = 0xAA;
    auto* cp = new SA(*src);
    arm(cp, sizeof(*cp));
    delete cp;
    EXPECT_TRUE(g_checked) << "copy was never intercepted -- check did not run";
    EXPECT_TRUE(g_zeroed)  << "copy was not wiped before deallocation";
    reset();
    EXPECT_EQ((*src)[0], 0xAA);
    delete src;
}

TEST(SecureArrayZeroingTest, MovedFromSourceIsWipedOnDestruction) {
    using SA = SecureArray<uint8_t, 64>;
    auto* src = new SA;
    for (size_t i = 0; i < SA::size(); ++i) (*src)[i] = 0xAA;
    SA dst = std::move(*src);   // a copy: the source keeps its value
    arm(src, sizeof(*src));
    delete src;
    EXPECT_TRUE(g_checked) << "moved-from source was never intercepted -- check did not run";
    EXPECT_TRUE(g_zeroed)  << "moved-from source was not wiped before deallocation";
    reset();
    EXPECT_EQ(dst[0], 0xAA);
}

TEST(SecureArrayZeroingTest, WiderElements) {
    using SA = SecureArray<uint64_t, 8>;
    auto* p = new SA;
    for (size_t i = 0; i < SA::size(); ++i) (*p)[i] = ~0ULL;
    arm(p, sizeof(*p));
    delete p;
    EXPECT_TRUE(g_checked) << "target object was never intercepted -- check did not run";
    EXPECT_TRUE(g_zeroed)  << "array was not wiped before deallocation";
    reset();
}
