// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#include <secure-buffer/version.h>

namespace safeheron {
namespace sbuf {

// Defined here rather than inline so it reports the version the library was
// built with, not the version of the caller's headers.
const char* version() noexcept { return SECURE_BUFFER_VERSION_STRING; }

} // namespace sbuf
} // namespace safeheron
