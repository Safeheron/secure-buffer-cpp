#include <secure-buffer/secure_memzero.h>

int main() {
    unsigned char buf[32];
    for (unsigned char& b : buf) {
        b = 0xA5;
    }
    safeheron::sbuf::secure_memzero(buf, sizeof buf);
    for (unsigned char b : buf) {
        if (b != 0) {
            return 1;
        }
    }
    return 0;
}
