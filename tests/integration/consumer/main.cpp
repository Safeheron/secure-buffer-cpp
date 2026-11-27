#include <secure-buffer/secure_memzero.h>
#include <secure-buffer/version.h>

#include <cstring>

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
    // The linked library and the headers this file was compiled with agree.
    if (std::strcmp(safeheron::sbuf::version(), SECURE_BUFFER_VERSION_STRING) != 0) {
        return 2;
    }
    return 0;
}
