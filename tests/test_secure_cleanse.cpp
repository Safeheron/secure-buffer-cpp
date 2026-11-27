#include <gtest/gtest.h>
#include <secure-buffer/secure_buffer.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace safeheron::sbuf;
using detail::is_cleansable;
using detail::is_cleansable_scalar;

namespace {
struct Plain { uint8_t a[4]; };
enum class Kind : uint8_t { A, B };
using Key = std::array<uint8_t, 32>;

bool Fill(Key& k, bool bail) {
    ScopedCleanse g(k);
    k.fill(0xAA);
    if (bail) return false;
    return true;
}

void FillAndThrow(Key& k) {
    ScopedCleanse g(k);
    k.fill(0xAA);
    throw std::runtime_error("x");
}
}

// Registration test types; specialized before any trait is evaluated on them.
namespace {
struct SessionKeys { std::array<uint8_t, 32> enc; std::array<uint8_t, 32> mac; };
struct Padded { uint8_t tag; uint32_t value; };
union Word { uint32_t w; uint8_t b[4]; };
struct Unregistered { std::array<uint8_t, 8> a; };
struct HasVector { std::vector<uint8_t> v; };
struct HasDtor { std::array<uint8_t, 4> a; ~HasDtor() noexcept {} };
struct HasConst { const uint8_t a[4]; };
struct HasRef { const std::array<uint8_t, 4>& r; };
enum class Mode : uint8_t { A = 1 };
struct AddrOverload {
    uint8_t header[8];
    uint8_t key[32];
    uint8_t* operator&() { return key; }
};
struct AddrDeleted {
    uint8_t a[4];
    void operator&() const = delete;
};
}
namespace vendor {
struct KdfState { std::array<uint8_t, 48> chain; uint64_t counter; };
}

// Own types: specialized inside the library namespace.
namespace safeheron {
namespace sbuf {
template <> struct enable_secure_cleanse<SessionKeys> : std::true_type {};
template <> struct enable_secure_cleanse<Padded> : std::true_type {};
template <> struct enable_secure_cleanse<Word> : std::true_type {};
template <> struct enable_secure_cleanse<HasVector> : std::true_type {};
template <> struct enable_secure_cleanse<HasDtor> : std::true_type {};
template <> struct enable_secure_cleanse<HasConst> : std::true_type {};
template <> struct enable_secure_cleanse<HasRef> : std::true_type {};
template <> struct enable_secure_cleanse<Mode> : std::true_type {};
template <> struct enable_secure_cleanse<AddrOverload> : std::true_type {};
template <> struct enable_secure_cleanse<AddrDeleted> : std::true_type {};
template <> struct enable_secure_cleanse<uint8_t*> : std::true_type {};
} // namespace sbuf
} // namespace safeheron

// Third-party type: specialized at global scope with the qualified name.
template <> struct safeheron::sbuf::enable_secure_cleanse<vendor::KdfState> : std::true_type {};

// --- Whitelist ---
static_assert(is_cleansable_scalar<uint8_t>::value && is_cleansable_scalar<bool>::value &&
              is_cleansable_scalar<char32_t>::value && is_cleansable_scalar<std::byte>::value);
static_assert(!is_cleansable_scalar<uint8_t[4]>::value && !is_cleansable_scalar<Key>::value &&
              !is_cleansable_scalar<float>::value && !is_cleansable_scalar<const int>::value);
static_assert(is_cleansable<int64_t>::value && is_cleansable<Key>::value &&
              is_cleansable<uint8_t[32]>::value && is_cleansable<int32_t[4][256]>::value &&
              is_cleansable<std::array<std::array<bool, 256>, 6>>::value &&
              is_cleansable<std::array<uint8_t, 0>>::value);
static_assert(!is_cleansable<const Key>::value && !is_cleansable<const uint8_t[4]>::value &&
              !is_cleansable<volatile int>::value && !is_cleansable<float>::value &&
              !is_cleansable<Kind>::value && !is_cleansable<uint8_t*>::value &&
              !is_cleansable<Plain>::value && !is_cleansable<std::vector<uint8_t>>::value &&
              !is_cleansable<std::string>::value && !is_cleansable<SecureBytes>::value &&
              !is_cleansable<SecureString>::value &&
              !is_cleansable<std::array<std::vector<uint8_t>, 4>>::value &&
              !is_cleansable<std::array<float, 4>>::value);

// --- Contract pins ---
static_assert(noexcept(secure_cleanse(std::declval<Key&>())));
static_assert(std::is_nothrow_constructible<ScopedCleanse<Key>, Key&>::value);
static_assert(!std::is_constructible<ScopedCleanse<Key>, Key&&>::value);
static_assert(!std::is_copy_constructible<ScopedCleanse<Key>>::value &&
              !std::is_move_constructible<ScopedCleanse<Key>>::value &&
              !std::is_copy_assignable<ScopedCleanse<Key>>::value &&
              !std::is_move_assignable<ScopedCleanse<Key>>::value);

TEST(SecureCleanseTest, ZeroesScalars) {
    int64_t i = -1;
    std::byte b{0xAA};
    bool f = true;
    secure_cleanse(i);
    secure_cleanse(b);
    secure_cleanse(f);
    EXPECT_EQ(i, 0);
    EXPECT_EQ(b, std::byte{0});
    EXPECT_FALSE(f);
}

TEST(SecureCleanseTest, ZeroesStdArray) {
    Key k;
    k.fill(0xAA);
    secure_cleanse(k);
    for (uint8_t v : k) EXPECT_EQ(v, 0);
    EXPECT_EQ(k.size(), 32u);
}

TEST(SecureCleanseTest, ZeroesBuiltInArray) {
    int32_t c[256];
    for (auto& v : c) v = -5;
    secure_cleanse(c);
    for (int32_t v : c) EXPECT_EQ(v, 0);
}

TEST(SecureCleanseTest, ZeroesNestedBoolArrays) {
    std::array<std::array<bool, 256>, 6> h;
    for (auto& row : h) row.fill(true);
    secure_cleanse(h);
    for (const auto& row : h)
        for (bool v : row) EXPECT_FALSE(v);
}

TEST(SecureCleanseTest, LeavesNeighboursUntouched) {
    uint8_t m[3][8];
    for (auto& row : m)
        for (auto& v : row) v = 0xAA;
    secure_cleanse(m[1]);
    for (uint8_t v : m[0]) EXPECT_EQ(v, 0xAA);
    for (uint8_t v : m[1]) EXPECT_EQ(v, 0);
    for (uint8_t v : m[2]) EXPECT_EQ(v, 0xAA);
}

TEST(SecureCleanseTest, RepeatedCleanseIsHarmless) {
    Key k;
    k.fill(0xAA);
    secure_cleanse(k);
    for (uint8_t v : k) EXPECT_EQ(v, 0);
    secure_cleanse(k);
    for (uint8_t v : k) EXPECT_EQ(v, 0);
    k[0] = 7;
    EXPECT_EQ(k[0], 7);
}

TEST(ScopedCleanseTest, WipesAtScopeExitNotBefore) {
    Key k;
    k.fill(0xAA);
    {
        ScopedCleanse g(k);
        EXPECT_EQ(k[0], 0xAA);
    }
    for (uint8_t v : k) EXPECT_EQ(v, 0);
}

TEST(ScopedCleanseTest, WipesOnEarlyReturn) {
    Key k;
    k.fill(0x11);
    EXPECT_FALSE(Fill(k, true));
    for (uint8_t v : k) EXPECT_EQ(v, 0);
}

TEST(ScopedCleanseTest, WipesDuringUnwinding) {
    Key k;
    k.fill(0x11);
    EXPECT_THROW(FillAndThrow(k), std::runtime_error);
    for (uint8_t v : k) EXPECT_EQ(v, 0);
}

TEST(ScopedCleanseTest, DeducesBuiltInArray) {
    uint8_t nonce[32];
    for (auto& v : nonce) v = 0xAA;
    {
        ScopedCleanse g(nonce);
        static_assert(std::is_same<decltype(g), ScopedCleanse<uint8_t[32]>>::value);
    }
    for (uint8_t v : nonce) EXPECT_EQ(v, 0);
}

// --- Registration ---
static_assert(!enable_secure_cleanse<Unregistered>::value && !enable_secure_cleanse<int>::value);
static_assert(is_cleansable<SessionKeys>::value && is_cleansable<Padded>::value &&
              is_cleansable<Word>::value && is_cleansable<vendor::KdfState>::value &&
              is_cleansable<std::array<SessionKeys, 4>>::value && is_cleansable<SessionKeys[2]>::value &&
              is_cleansable<std::array<std::array<SessionKeys, 2>, 3>>::value);
static_assert(!is_cleansable<Unregistered>::value && !is_cleansable<const SessionKeys>::value &&
              !is_cleansable<HasVector>::value && !is_cleansable<HasDtor>::value &&
              !is_cleansable<HasConst>::value && !is_cleansable<HasRef>::value &&
              !is_cleansable<Mode>::value && !is_cleansable<uint8_t*>::value &&
              !is_cleansable<std::array<HasVector, 2>>::value);
static_assert(detail::has_invalid_registration<HasVector>::value &&
              detail::has_invalid_registration<HasDtor>::value &&
              detail::has_invalid_registration<HasConst>::value &&
              detail::has_invalid_registration<HasRef>::value &&
              detail::has_invalid_registration<Mode>::value &&
              detail::has_invalid_registration<uint8_t*>::value &&
              detail::has_invalid_registration<std::array<HasConst, 2>>::value &&
              detail::has_invalid_registration<HasDtor[2]>::value);
static_assert(!detail::has_invalid_registration<SessionKeys>::value &&
              !detail::has_invalid_registration<Unregistered>::value &&
              !detail::has_invalid_registration<const SessionKeys>::value &&
              !detail::has_invalid_registration<int>::value);
static_assert(!is_cleansable_scalar<SessionKeys>::value);  // SecureArray elements stay scalars
static_assert(noexcept(secure_cleanse(std::declval<SessionKeys&>())));
static_assert(std::is_nothrow_constructible<ScopedCleanse<SessionKeys>, SessionKeys&>::value &&
              !std::is_constructible<ScopedCleanse<SessionKeys>, SessionKeys&&>::value);

namespace {
void FillKeysBytes(SessionKeys& k) {
    k.enc.fill(0xAA);
    k.mac.fill(0xAA);
}

bool KeysZero(const SessionKeys& k) {
    for (uint8_t v : k.enc) if (v != 0) return false;
    for (uint8_t v : k.mac) if (v != 0) return false;
    return true;
}

bool KeysFilled(const SessionKeys& k) {
    for (uint8_t v : k.enc) if (v != 0xAA) return false;
    for (uint8_t v : k.mac) if (v != 0xAA) return false;
    return true;
}

bool FillKeysEarly(SessionKeys& k, bool bail) {
    ScopedCleanse g(k);
    FillKeysBytes(k);
    if (bail) return false;
    return true;
}

void FillKeys(SessionKeys& k, bool fail) {
    ScopedCleanse g(k);
    FillKeysBytes(k);
    if (fail) throw std::runtime_error("x");
}
}

TEST(RegistrationTest, RegisteredStructIsZeroed) {
    SessionKeys keys;
    FillKeysBytes(keys);
    secure_cleanse(keys);
    EXPECT_TRUE(KeysZero(keys));
}

TEST(RegistrationTest, PaddingBytesAreZeroed) {
    static_assert(sizeof(Padded) > sizeof(uint8_t) + sizeof(uint32_t));
    Padded p;
    std::memset(&p, 0xAA, sizeof p);
    secure_cleanse(p);
    unsigned char bytes[sizeof(Padded)];
    std::memcpy(bytes, &p, sizeof p);
    for (unsigned char b : bytes) EXPECT_EQ(b, 0);
}

TEST(RegistrationTest, UnionIsZeroed) {
    Word w;
    w.w = 0xFFFFFFFFu;
    secure_cleanse(w);
    EXPECT_EQ(w.w, 0u);
}

TEST(RegistrationTest, NestedArraysOfRegisteredType) {
    std::array<std::array<SessionKeys, 2>, 3> grid;
    for (auto& row : grid) for (auto& k : row) FillKeysBytes(k);
    secure_cleanse(grid);
    for (auto& row : grid) for (auto& k : row) EXPECT_TRUE(KeysZero(k));

    SessionKeys pair[2];
    FillKeysBytes(pair[0]);
    FillKeysBytes(pair[1]);
    {
        ScopedCleanse g(pair);
        static_assert(std::is_same<decltype(g), ScopedCleanse<SessionKeys[2]>>::value);
    }
    EXPECT_TRUE(KeysZero(pair[0]));
    EXPECT_TRUE(KeysZero(pair[1]));
}

TEST(RegistrationTest, LeavesNeighboursUntouched) {
    SessionKeys arr[3];
    for (auto& k : arr) FillKeysBytes(k);
    secure_cleanse(arr[1]);
    EXPECT_TRUE(KeysFilled(arr[0]));
    EXPECT_TRUE(KeysZero(arr[1]));
    EXPECT_TRUE(KeysFilled(arr[2]));
}

TEST(RegistrationTest, OverloadedAddressOfIsIgnored) {
    AddrOverload arr[3];
    for (auto& b : arr) {
        std::memset(b.header, 0xAA, sizeof(b.header));
        std::memset(b.key, 0xAA, sizeof(b.key));
    }
    secure_cleanse(arr[1]);
    for (uint8_t v : arr[1].header) EXPECT_EQ(v, 0);
    for (uint8_t v : arr[1].key) EXPECT_EQ(v, 0);
    for (int i : {0, 2}) {
        for (uint8_t v : arr[i].header) EXPECT_EQ(v, 0xAA);
        for (uint8_t v : arr[i].key) EXPECT_EQ(v, 0xAA);
    }
}

TEST(RegistrationTest, DeletedAddressOfStillWipes) {
    AddrDeleted d;
    std::memset(d.a, 0xAA, sizeof(d.a));
    secure_cleanse(d);
    for (uint8_t v : d.a) EXPECT_EQ(v, 0);
}

TEST(RegistrationTest, GuardWipesAtScopeExitAndEarlyReturn) {
    SessionKeys k;
    FillKeysBytes(k);
    {
        ScopedCleanse g(k);
        EXPECT_TRUE(KeysFilled(k));
    }
    EXPECT_TRUE(KeysZero(k));

    FillKeysBytes(k);
    EXPECT_FALSE(FillKeysEarly(k, true));
    EXPECT_TRUE(KeysZero(k));
}

TEST(RegistrationTest, GuardWipesDuringUnwinding) {
    SessionKeys k;
    FillKeysBytes(k);
    volatile bool fail = true;
    EXPECT_THROW(FillKeys(k, fail), std::runtime_error);
    EXPECT_TRUE(KeysZero(k));
}

TEST(RegistrationTest, ThirdPartyTypeFromAnotherNamespace) {
    vendor::KdfState s;
    s.chain.fill(0xAA);
    s.counter = 0xFFFFFFFFFFFFFFFFull;
    {
        ScopedCleanse g(s);
        static_assert(std::is_same<decltype(g), ScopedCleanse<vendor::KdfState>>::value);
    }
    for (uint8_t v : s.chain) EXPECT_EQ(v, 0);
    EXPECT_EQ(s.counter, 0u);
}
