// Must fail: subspan<Offset, Count>() on a static span with Count beyond the extent minus Offset.
#include <cstdint>

#include <secure-buffer/compat/span.h>

int main() {
    std::uint8_t raw[32] = {};
    safeheron::sbuf::span<const std::uint8_t, 32> s = raw;
    auto bad = s.subspan<16, 32>();
    (void)bad;
    return 0;
}
