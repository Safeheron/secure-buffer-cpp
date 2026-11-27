// Must fail: subspan<Offset, Count>() on a dynamic span with Count above SIZE_MAX - Offset,
// a length no object can have.
#include <cstdint>

#include <secure-buffer/compat/span.h>

int main() {
    std::uint8_t raw[32] = {};
    safeheron::secure_buffer::compat::span<const std::uint8_t> d = raw;
    auto bad = d.subspan<2, SIZE_MAX - 1>();
    (void)bad;
    return 0;
}
