// Must fail: SecureArray elements stay scalars even for registered types.
#include <cstdint>
#include <type_traits>

#include <secure-buffer/secure_array.h>
#include <secure-buffer/secure_cleanse.h>

struct Plain {
    uint8_t a[8];
};
template <>
struct safeheron::secure_buffer::enable_secure_cleanse<Plain> : std::true_type {};

int main() {
    safeheron::secure_buffer::SecureArray<Plain, 2> x;
    (void)x;
    return 0;
}
