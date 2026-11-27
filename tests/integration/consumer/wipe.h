#ifndef SECURE_BUFFER_CONSUMER_WIPE_H
#define SECURE_BUFFER_CONSUMER_WIPE_H

// Wipes a buffer with secure_memzero inside the shared library; returns 0 if
// every byte is zero afterwards.
int consumer_shared_wipe();

#endif
