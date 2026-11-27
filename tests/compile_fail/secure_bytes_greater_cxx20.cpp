// Must fail: operator> on SecureBytes is deleted under C++20 too.
#include <secure-buffer/secure_buffer.h>

int main() {
    safeheron::sbuf::SecureBytes a;
    safeheron::sbuf::SecureBytes b;
    (void)(a > b);
    return 0;
}
