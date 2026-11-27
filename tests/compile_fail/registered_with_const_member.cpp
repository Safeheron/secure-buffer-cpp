// Must fail: a registered type with a const member is not copy-assignable.
#include <cstdint>
#include <type_traits>

#include <secure-buffer/secure_cleanse.h>

struct HoldsConst {
    const uint8_t a[4];
};
template <>
struct safeheron::sbuf::enable_secure_cleanse<HoldsConst> : std::true_type {};

int main() {
    HoldsConst x{{1, 2, 3, 4}};
    safeheron::sbuf::ScopedCleanse g(x);
    return 0;
}
