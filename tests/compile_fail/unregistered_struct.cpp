// Must fail: a plain struct that is not registered is not cleansable.
#include <array>
#include <cstdint>

#include <secure-buffer/secure_cleanse.h>

struct Plain {
    std::array<uint8_t, 8> a;
};

int main() {
    Plain x;
    safeheron::sbuf::secure_cleanse(x);
    return 0;
}
