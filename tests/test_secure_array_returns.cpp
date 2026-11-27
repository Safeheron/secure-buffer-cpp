// Return-path checks for SecureArray and ScopedCleanse.
//
// Built twice: normally, and with optional copy elision disabled
// (-fno-elide-constructors) so that every return takes the copy path. The
// results must be the same either way.
#include <gtest/gtest.h>
#include <secure-buffer/secure_array.h>
#include <secure-buffer/secure_cleanse.h>

#include <array>
#include <cstdint>

using safeheron::sbuf::ScopedCleanse;
using safeheron::sbuf::SecureArray;

namespace {

using SA = SecureArray<uint8_t, 32>;
using RawArray = std::array<uint8_t, 32>;

SA MakeArray() {
    SA result;
    result[0] = 42;
    return result;
}

// Two named locals: NRVO is impossible, so the return copies.
SA MakeEither(bool first) {
    SA a;
    a[0] = 1;
    SA b;
    b[0] = 2;
    if (first) return a;
    return b;
}

// The guarded object is never the returned object.
RawArray SafeReturn() {
    RawArray result{};
    ScopedCleanse guard(result);
    result[0] = 42;
    return RawArray(result);
}

void FillOut(RawArray& out) { out[0] = 42; }

} // namespace

TEST(SecureArrayReturnTest, NamedLocal) {
    EXPECT_EQ(MakeArray()[0], 42);
}

TEST(SecureArrayReturnTest, CopyPathWhenNrvoImpossible) {
    EXPECT_EQ(MakeEither(true)[0], 1);
    EXPECT_EQ(MakeEither(false)[0], 2);
}

TEST(SecureArrayReturnTest, ExplicitIndependentReturnObject) {
    EXPECT_EQ(SafeReturn()[0], 42);
}

TEST(SecureArrayReturnTest, OutputParameterWithCallerGuard) {
    RawArray r{};
    {
        ScopedCleanse g(r);
        FillOut(r);
        EXPECT_EQ(r[0], 42);
    }
    EXPECT_EQ(r[0], 0);
}
