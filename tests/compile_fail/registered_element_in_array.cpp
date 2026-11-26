// Must fail: the registration check also applies to array elements.
#include <array>
#include <cstdint>
#include <type_traits>

#include <secure-buffer/secure_cleanse.h>

struct HasDestructor {
    uint8_t a[4];
    ~HasDestructor() {}
};
template <>
struct safeheron::secure_buffer::enable_secure_cleanse<HasDestructor> : std::true_type {};

int main() {
    std::array<HasDestructor, 2> x;
    safeheron::secure_buffer::secure_cleanse(x);
    return 0;
}
