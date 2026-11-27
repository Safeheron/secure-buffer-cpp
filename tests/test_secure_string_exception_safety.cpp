// Exception safety of SecureString mutators under allocation failure.
//
// Replaces the global operator new/delete for this executable only, so the
// fault injection cannot affect other tests.
#include <gtest/gtest.h>
#include <secure-buffer/secure_string.h>

#include <cstddef>
#include <cstdlib>
#include <new>
#include <string_view>

using namespace safeheron::sbuf;

namespace {
    std::size_t g_new_count = 0;
    std::size_t g_fail_at   = 0;   // 0: count only, never fail
    bool        g_armed     = false;

    // Armed for its lifetime only, so GoogleTest assertions, which allocate,
    // run with injection off.
    struct AllocFault {
        explicit AllocFault(std::size_t fail_at) {
            g_new_count = 0;
            g_fail_at   = fail_at;
            g_armed     = true;
        }
        ~AllocFault() {
            g_armed   = false;
            g_fail_at = 0;
        }
    };

    // Allocations an empty container makes on construction: 0, except 1 with
    // MSVC's debug STL, which allocates a proxy in every std::vector
    // constructor, noexcept ones included. Failing that allocation would
    // terminate, so fault indices skip past it.
    std::size_t container_overhead_allocs() {
        AllocFault f(0);                 // count only
        SecureBytes probe;
        (void)probe;
        return g_new_count;
    }
}

// Only the throwing scalar new is subject to fault injection. Every form is
// replaced so that new and delete stay paired through malloc/free; a form left
// to the default would be freed here, which ASan reports as a mismatch.
void* operator new(std::size_t n) {
    if (g_armed) {
        ++g_new_count;
        if (g_fail_at && g_new_count == g_fail_at) throw std::bad_alloc();
    }
    void* p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc();
    return p;
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return std::malloc(n ? n : 1); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return std::malloc(n ? n : 1); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }

// --- A failed allocation leaves the object valid and unchanged ---

TEST(SecureStringExcSafety, PushBackReallocFailPreservesNonEmpty) {
    SecureString s("abc");   // size==capacity==4, so the next grow reallocates
    bool threw = false;
    {
        AllocFault f(1);     // fail the insert's reallocation
        try { s.push_back('x'); } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(s.size(), 3u);
    EXPECT_EQ(s.view(), "abc");
    EXPECT_EQ(s.c_str()[3], '\0');
    EXPECT_STREQ(s.c_str(), "abc");
}

TEST(SecureStringExcSafety, AppendOwnSliceWithTerminatorGrowthAllocFailPreserves) {
    SecureString s("abc");               // exact fit: the append must grow
    bool threw = false;
    {
        AllocFault f(container_overhead_allocs() + 1);   // the growth buffer
        try { s.append(s.c_str() + 1, 3); } catch (const std::bad_alloc&) { threw = true; }   // "bc" + its '\0'
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(s.view(), "abc");   // untouched: the new buffer is built before *this changes
    EXPECT_STREQ(s.c_str(), "abc");
}

TEST(SecureStringExcSafety, AppendPtrGrowthAllocFailPreserves) {
    SecureString s("abc");
    bool threw = false;
    {
        AllocFault f(container_overhead_allocs() + 1);   // the growth buffer
        try { s.append("XY", 2); } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(s.view(), "abc");   // the new buffer is built first; *this is unchanged and terminated
    EXPECT_STREQ(s.c_str(), "abc");
}

TEST(SecureStringExcSafety, AppendFillReallocFailPreserves) {
    SecureString s("abc");
    bool threw = false;
    {
        AllocFault f(1);
        try { s.append(5, 'z'); } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(s.view(), "abc");
    EXPECT_EQ(s.c_str()[3], '\0');
}

// --- Aliasing: self-append and internal-slice append are correct ---

TEST(SecureStringExcSafety, SelfAppendCorrect) {
    SecureString s("abc");
    s += s;
    EXPECT_EQ(s.view(), "abcabc");
    EXPECT_STREQ(s.c_str(), "abcabc");
}

TEST(SecureStringExcSafety, InternalSliceAppendCorrect) {
    SecureString s("hello");
    s.append(s.c_str() + 1, 3);          // "ell", aliasing an internal slice
    EXPECT_EQ(s.view(), "helloell");
}

TEST(SecureStringExcSafety, EmbeddedNulAppendCorrect) {
    SecureString s("ab");
    const char with_nul[] = { 'x', '\0', 'y' };
    s.append(with_nul, 3);
    EXPECT_EQ(s.size(), 5u);
    EXPECT_EQ(s[2], 'x');
    EXPECT_EQ(s[3], '\0');
    EXPECT_EQ(s[4], 'y');
    EXPECT_EQ(s.c_str()[5], '\0');
}

// --- Capacity is preserved (the reason the empty branch resizes, not swaps) ---

TEST(SecureStringExcSafety, ValueAppendUnderReservedCapacityDoesNotAllocate) {
    SecureString s("ab");
    s.reserve(100);
    std::size_t allocs = 0;
    {
        AllocFault f(0);                 // count only
        s.append(10, 'x');               // value append: fits capacity
        s.push_back('y');                // fits capacity
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, 0u);
    EXPECT_EQ(s.size(), 13u);
}

TEST(SecureStringExcSafety, EmptyBranchPreservesReservedCapacity) {
    SecureString s;
    s.reserve(100);
    std::size_t allocs = 0;
    {
        AllocFault f(0);
        s.push_back('x');                // empty branch resize(2) fits reserved capacity
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, 0u);               // would allocate if it swapped in a temp
    EXPECT_EQ(s.view(), "x");
}

TEST(SecureStringExcSafety, ClearThenAppendReusesCapacity) {
    SecureString s(100, 'x');
    s.clear();                           // data_.clear() keeps capacity
    std::size_t allocs = 0;
    {
        AllocFault f(0);
        s.push_back('y');
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, 0u);
    EXPECT_EQ(s.view(), "y");
}

// --- Pointer / view / self appends: allocate only to grow ---

TEST(SecureStringExcSafety, AppendWithinCapacityDoesNotAllocate) {
    SecureString s("ab");
    s.reserve(100);
    const SecureString other("cd");
    const char* before = s.data();
    std::size_t allocs = 0;
    {
        AllocFault f(0);                 // count only
        s.append("xyz");                 // C string
        s.append("pq", 2);               // pointer + length
        s += std::string_view("uv");     // view
        s.append(other);                 // another SecureString
        s.append(s.view());              // itself: nothing reallocates, so no copy is needed
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, 0u);
    EXPECT_EQ(s.data(), before);         // appended in place
    EXPECT_EQ(s.view(), "abxyzpquvcdabxyzpquvcd");
    EXPECT_EQ(s.c_str()[s.size()], '\0');
}

TEST(SecureStringExcSafety, AppendIntoReservedEmptyDoesNotAllocate) {
    SecureString s;
    s.reserve(16);                       // the documented way to build a secret piece by piece
    std::size_t allocs = 0;
    const char* after_first = nullptr;
    {
        AllocFault f(0);                 // count only
        s.append("abandon", 7);
        after_first = s.data();
        s.append(" ability", 8);
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, 0u);
    EXPECT_EQ(s.data(), after_first);    // the reserved block is kept
    EXPECT_EQ(s.view(), "abandon ability");
}

TEST(SecureStringExcSafety, AppendAfterClearReusesCapacity) {
    SecureString s(100, 'x');
    s.clear();                           // keeps the 100-byte block
    std::size_t allocs = 0;
    {
        AllocFault f(0);
        s.append("abc", 3);
        s.append(s.view());
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, 0u);
    EXPECT_EQ(s.view(), "abcabc");
}

TEST(SecureStringExcSafety, AppendExactFitDoesNotAllocate) {
    SecureString s("ab");
    s.reserve(5);                        // room for exactly "ab" + "xyz"
    const char* before = s.data();
    std::size_t allocs = 0;
    {
        AllocFault f(0);
        s.append("xyz", 3);
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, 0u);
    EXPECT_EQ(s.data(), before);
    EXPECT_EQ(s.view(), "abxyz");
    EXPECT_EQ(s.c_str()[5], '\0');
}

TEST(SecureStringExcSafety, AppendGrowthAllocatesOnce) {
    SecureString s("abc");               // exact fit
    std::size_t allocs = 0;
    {
        AllocFault f(0);
        s.append(s.view());              // grows; the source is *this
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, container_overhead_allocs() + 1);   // the new buffer only; no copy of the source
    EXPECT_EQ(s.view(), "abcabc");
}

TEST(SecureStringExcSafety, RepeatedAppendGrowsGeometrically) {
    SecureString s;
    std::size_t allocs = 0;
    {
        AllocFault f(0);
        for (int i = 0; i < 100000; ++i) s.append("x", 1);
        allocs = g_new_count;
    }
    EXPECT_EQ(s.size(), 100000u);
    EXPECT_LE(allocs, 64u);              // amortized O(1): about log2(100000) growths
}

// --- Allocation failure on the empty-string branch ---

TEST(SecureStringExcSafety, EmptyPushBackAllocFailStaysEmpty) {
    SecureString s;                      // no capacity: resize(2) must allocate
    bool threw = false;
    {
        AllocFault f(1);
        try { s.push_back('x'); } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_TRUE(s.empty());              // resize is strong: still a valid empty string
    EXPECT_EQ(s.c_str()[0], '\0');
    s.push_back('x');                    // usable afterwards
    EXPECT_EQ(s.view(), "x");
}

TEST(SecureStringExcSafety, EmptyAppendGrowthAllocFailStaysEmpty) {
    SecureString s;
    bool threw = false;
    {
        AllocFault f(container_overhead_allocs() + 1);   // the growth buffer
        try { s.append("XY", 2); } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.c_str()[0], '\0');
}

// --- string_view mutators share the pointer append's guarantees ---

TEST(SecureStringExcSafety, AppendViewGrowthAllocFailPreserves) {
    SecureString s("abc");
    bool threw = false;
    {
        AllocFault f(container_overhead_allocs() + 1);   // the growth buffer
        try { s += std::string_view("XY"); } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(s.view(), "abc");   // the new buffer is built first; *this is unchanged and terminated
    EXPECT_STREQ(s.c_str(), "abc");
}

TEST(SecureStringExcSafety, AppendOwnViewGrowthAllocFailPreserves) {
    SecureString s("abc");
    bool threw = false;
    {
        AllocFault f(container_overhead_allocs() + 1);   // growth fails while the source aliases *this
        try { s.append(s.view()); } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(s.view(), "abc");
    EXPECT_STREQ(s.c_str(), "abc");
}

TEST(SecureStringExcSafety, ConstructFromViewAllocFailThrows) {
    bool threw = false;
    {
        AllocFault f(container_overhead_allocs() + 1);   // the content buffer
        try { SecureString t(std::string_view("abc")); (void)t; } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
}

// --- operator=(const char*): the snapshot gives the strong guarantee ---

TEST(SecureStringExcSafety, AssignCStrSnapshotAllocFailPreserves) {
    SecureString s("abc");
    bool threw = false;
    {
        AllocFault f(container_overhead_allocs() + 1);   // the snapshot's buffer
        try { s = "XYZW"; } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(s.view(), "abc");
    EXPECT_STREQ(s.c_str(), "abc");
}

TEST(SecureStringExcSafety, SelfAssignSnapshotAllocFailPreserves) {
    SecureString s("secret");
    bool threw = false;
    {
        AllocFault f(container_overhead_allocs() + 1);   // the snapshot's buffer
        try { s = s.c_str() + 2; } catch (const std::bad_alloc&) { threw = true; }
    }
    EXPECT_TRUE(threw);
    EXPECT_EQ(s.view(), "secret");
}

// --- reserve(0) must not allocate a block for the terminator alone ---

TEST(SecureStringExcSafety, ReserveZeroDoesNotAllocate) {
    SecureString s;
    std::size_t allocs = 0;
    {
        AllocFault f(0);                 // count only
        s.reserve(0);
        allocs = g_new_count;
    }
    EXPECT_EQ(allocs, 0u);
    EXPECT_TRUE(s.empty());
}
