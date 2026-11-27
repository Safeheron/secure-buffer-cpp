// Must fail: a registered type that owns heap memory is not trivially copyable.
#include <cstdint>
#include <type_traits>
#include <vector>

#include <secure-buffer/secure_cleanse.h>

struct HoldsVector {
    std::vector<uint8_t> v;
};
template <>
struct safeheron::sbuf::enable_secure_cleanse<HoldsVector> : std::true_type {};

int main() {
    HoldsVector x;
    safeheron::sbuf::secure_cleanse(x);
    return 0;
}
