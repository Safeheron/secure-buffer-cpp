// Must fail: operator<=> on SecureBytes is deleted (C++20).
#include <secure-buffer/secure_buffer.h>

int main() {
    safeheron::sbuf::SecureBytes a;
    safeheron::sbuf::SecureBytes b;
    (void)(a <=> b);
    return 0;
}
