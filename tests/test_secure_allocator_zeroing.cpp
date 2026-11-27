// Checks that SecureAllocator zeroes a block before the block is freed.
//
// Replaces the global operator new/delete for this executable only; the full
// set is replaced so allocation and deallocation stay paired through
// malloc/free. Every delete overload runs the check, since which one the
// standard library calls varies by toolchain. Each test asserts that the check
// actually ran.
#include <gtest/gtest.h>
#include <secure-buffer/secure_allocator.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <vector>

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

using SecureBytes = std::vector<uint8_t, safeheron::sbuf::SecureAllocator<uint8_t>>;

TEST(SecureAllocatorZeroingTest, DeallocateZerosMemory) {
    reset();
    {
        SecureBytes buf(64, 0xAB);
        g_target      = buf.data();
        g_target_size = buf.capacity();
        g_armed       = true;
    }  // destruction: zeroed, then freed
    g_armed = false;

    EXPECT_TRUE(g_checked) << "target buffer was never intercepted -- check did not run";
    EXPECT_TRUE(g_zeroed)  << "memory was not zeroed before deallocation";
}

TEST(SecureAllocatorZeroingTest, ReallocZerosOldBuffer) {
    reset();
    SecureBytes buf(32, 0xCD);
    g_target      = buf.data();          // the old buffer
    g_target_size = buf.capacity();
    g_armed       = true;

    buf.reserve(1024);                   // reallocation: old buffer zeroed, then freed
    g_armed = false;

    EXPECT_TRUE(g_checked) << "old buffer was never intercepted -- check did not run";
    EXPECT_TRUE(g_zeroed)  << "old buffer was not zeroed on reallocation";
}

TEST(SecureAllocatorZeroingTest, AllocatorEquality) {
    safeheron::sbuf::SecureAllocator<uint8_t> a1;
    safeheron::sbuf::SecureAllocator<uint8_t> a2;
    safeheron::sbuf::SecureAllocator<int> a3;

    EXPECT_TRUE(a1 == a2);
    EXPECT_FALSE(a1 != a2);
    EXPECT_TRUE(a1 == a3);
}
