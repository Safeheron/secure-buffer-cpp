// Must fail: subspan<Offset>() on a static span with Offset beyond the extent.
#include <cstdint>

#include <secure-buffer/compat/span.h>

int main() {
    std::uint8_t raw[32] = {};
    safeheron::sbuf::span<const std::uint8_t, 32> s = raw;
    auto bad = s.subspan<33>();
    (void)bad;
    return 0;
}
