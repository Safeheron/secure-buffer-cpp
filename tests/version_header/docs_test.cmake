# Copyright 2026 Safeheron Inc.
# SPDX-License-Identifier: Apache-2.0

# The documents cannot take the version from version.h, so they are checked against it: every
# "find_package(secure-buffer X.Y" (or X.Y.Z) in README.md, USAGE.md and PLATFORMS.md must name the
# current minor version (or the current version). Before 1.0 a package satisfies requests for its
# own minor version only, so a stale number there is an instruction that fails. Likewise every
# "GIT_TAG vX.Y.Z" must name the current version. Run as
#   cmake -DROOT=<repository root> -P docs_test.cmake
cmake_minimum_required(VERSION 3.28)

if(NOT ROOT)
    message(FATAL_ERROR "usage: cmake -DROOT=<repository root> -P docs_test.cmake")
endif()
include(${ROOT}/cmake/version.cmake)
string(REGEX MATCH "^[0-9]+\\.[0-9]+" minor_version "${SECURE_BUFFER_VERSION}")

set(found 0)
set(problems "")
foreach(document README.md USAGE.md PLATFORMS.md)
    file(READ ${ROOT}/${document} text)
    string(REGEX MATCHALL "find_package\\(secure-buffer[ \t]+[0-9][0-9.]*" requests "${text}")
    foreach(request IN LISTS requests)
        math(EXPR found "${found} + 1")
        string(REGEX REPLACE ".*[ \t]" "" version "${request}")
        if(NOT version STREQUAL minor_version AND NOT version STREQUAL SECURE_BUFFER_VERSION)
            list(APPEND problems "${document}: ${request}")
        endif()
    endforeach()
endforeach()

# FetchContent examples name a release tag, which must be the current version: "GIT_TAG vX.Y.Z".
set(tags_found 0)
foreach(document README.md USAGE.md PLATFORMS.md)
    file(READ ${ROOT}/${document} text)
    string(REGEX MATCHALL "GIT_TAG[ \t]+v[0-9]+(\\.[0-9]+)*" tags "${text}")
    foreach(tag IN LISTS tags)
        math(EXPR tags_found "${tags_found} + 1")
        string(REGEX REPLACE ".*[ \t]v" "" version "${tag}")
        if(NOT version STREQUAL SECURE_BUFFER_VERSION)
            list(APPEND problems "${document}: ${tag} (must be v${SECURE_BUFFER_VERSION})")
        endif()
    endforeach()
endforeach()
if(tags_found EQUAL 0)
    message(FATAL_ERROR "No GIT_TAG v<version> found in the documents: the pattern no longer "
                        "matches how they are written")
endif()

if(found EQUAL 0)
    message(FATAL_ERROR "No find_package(secure-buffer <version> found in the documents: the "
                        "pattern no longer matches how they are written")
endif()
if(problems)
    list(JOIN problems "\n  " problems)
    message(FATAL_ERROR "The version is ${SECURE_BUFFER_VERSION}, so the documents must request "
                        "${minor_version} (or ${SECURE_BUFFER_VERSION}):\n  ${problems}")
endif()
