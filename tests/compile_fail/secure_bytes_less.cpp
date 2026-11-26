// Must fail: operator< on SecureBytes is deleted.
#include <secure-buffer/secure_buffer.h>

int main() {
    safeheron::secure_buffer::SecureBytes a;
    safeheron::secure_buffer::SecureBytes b;
    (void)(a < b);
    return 0;
}
