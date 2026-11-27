// Must fail: operator== on SecureString is deleted.
#include <secure-buffer/secure_buffer.h>

int main() {
    safeheron::sbuf::SecureString a;
    safeheron::sbuf::SecureString b;
    (void)(a == b);
    return 0;
}
