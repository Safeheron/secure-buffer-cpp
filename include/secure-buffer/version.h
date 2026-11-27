// Copyright 2026 Safeheron Inc.
// SPDX-License-Identifier: Apache-2.0

#ifndef SAFEHERON_SECURE_BUFFER_VERSION_H
#define SAFEHERON_SECURE_BUFFER_VERSION_H

// The library version: the only place it is written. cmake/version.cmake
// reads these three lines, so each stays on a line of its own, starting with
// #define, with a plain decimal number (no leading zero, suffix, parentheses
// or trailing comment).
#define SECURE_BUFFER_VERSION_MAJOR 0
#define SECURE_BUFFER_VERSION_MINOR 12
#define SECURE_BUFFER_VERSION_PATCH 0

// Expanded where SECURE_BUFFER_VERSION_STRING is used, so they stay defined.
#define SECURE_BUFFER_DETAIL_STRINGIFY_IMPL(x) #x
#define SECURE_BUFFER_DETAIL_STRINGIFY(x) SECURE_BUFFER_DETAIL_STRINGIFY_IMPL(x)

/// The version of these headers, e.g. "0.12.0", built from the three numbers above.
#define SECURE_BUFFER_VERSION_STRING                             \
    SECURE_BUFFER_DETAIL_STRINGIFY(SECURE_BUFFER_VERSION_MAJOR) "." \
    SECURE_BUFFER_DETAIL_STRINGIFY(SECURE_BUFFER_VERSION_MINOR) "." \
    SECURE_BUFFER_DETAIL_STRINGIFY(SECURE_BUFFER_VERSION_PATCH)

namespace safeheron {
namespace sbuf {

/// The version of the linked library, e.g. "0.12.0". The macros above give the
/// version of the headers the caller was compiled with; if the two differ, the
/// headers and the library do not belong together. For diagnostics only: this
/// is not an ABI or integrity check.
const char* version() noexcept;

} // namespace sbuf
} // namespace safeheron

#endif // SAFEHERON_SECURE_BUFFER_VERSION_H
