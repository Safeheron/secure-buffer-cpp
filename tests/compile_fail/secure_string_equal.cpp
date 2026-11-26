// Must fail: operator== on SecureString is deleted.
#include <secure-buffer/secure_buffer.h>

int main() {
    safeheron::secure_buffer::SecureString a;
    safeheron::secure_buffer::SecureString b;
    (void)(a == b);
    return 0;
}
