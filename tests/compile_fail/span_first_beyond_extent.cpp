// Must fail: first<Count>() on a static span with Count beyond the extent.
#include <cstdint>

#include <secure-buffer/compat/span.h>

int main() {
    std::uint8_t raw[32] = {};
    safeheron::sbuf::span<const std::uint8_t, 32> s = raw;
    auto bad = s.first<33>();
    (void)bad;
    return 0;
}
