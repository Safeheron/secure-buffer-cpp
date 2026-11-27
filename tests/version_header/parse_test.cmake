# Copyright 2026 Safeheron Inc.
# SPDX-License-Identifier: Apache-2.0

# Drives cmake/version.cmake, the one place the version is read from include/secure-buffer/version.h,
# over headers written here: the forms it must accept give the version on standard output, and
# nothing else; the ones it must reject fail, naming the macro and the expected form. Run as
#   cmake -DROOT=<repository root> -DWORK=<scratch directory> -P parse_test.cmake
cmake_minimum_required(VERSION 3.28)

if(NOT ROOT OR NOT WORK)
    message(FATAL_ERROR "usage: cmake -DROOT=<repository root> -DWORK=<dir> -P parse_test.cmake")
endif()
file(REMOVE_RECURSE ${WORK})
file(MAKE_DIRECTORY ${WORK})

# parse(<case> <header text>): runs the script on a header holding <header text>; leaves its exit
# code, standard output and standard error in rc, out and err. Without <header text>, the script
# runs on its default header.
function(parse case)
    set(args "")
    if(ARGC GREATER 1)
        file(WRITE ${WORK}/${case}.h "${ARGV1}")
        set(args -DSECURE_BUFFER_VERSION_HEADER=${WORK}/${case}.h)
    endif()
    execute_process(COMMAND ${CMAKE_COMMAND} ${args} -P ${ROOT}/cmake/version.cmake
        RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
    set(rc "${rc}" PARENT_SCOPE)
    set(out "${out}" PARENT_SCOPE)
    set(err "${err}" PARENT_SCOPE)
endfunction()

# accept(<case> <version> <header text>...): exit code 0, and exactly "<version>\n" on standard
# output. The text may come in several pieces, joined.
function(accept case version)
    list(JOIN ARGN "" text)
    parse(${case} "${text}")
    if(NOT rc EQUAL 0 OR NOT out STREQUAL "${version}\n")
        message(FATAL_ERROR "${case}: expected '${version}', got exit code ${rc}, output "
                            "'${out}', errors:\n${err}")
    endif()
endfunction()

# reject(<case> <macro> <header text>...): a failure whose message names <macro> and the number
# form. The text may come in several pieces, joined.
function(reject case macro)
    list(JOIN ARGN "" text)
    parse(${case} "${text}")
    string(REGEX REPLACE "[ \n]+" " " message "${err}")   # CMake wraps long messages
    if(rc EQUAL 0)
        message(FATAL_ERROR "${case}: accepted, printing '${out}'")
    elseif(NOT message MATCHES "${macro}" OR NOT message MATCHES "0 or digits not starting with 0")
        message(FATAL_ERROR "${case}: the message does not name ${macro} and the form:\n${err}")
    endif()
endfunction()

set(major "#define SECURE_BUFFER_VERSION_MAJOR 0\n")
set(minor "#define SECURE_BUFFER_VERSION_MINOR 1\n")
set(patch "#define SECURE_BUFFER_VERSION_PATCH 0\n")

accept(Plain 0.1.0 "#pragma once\n${major}${minor}${patch}")
accept(Crlf 0.1.0 "#pragma once\r\n#define SECURE_BUFFER_VERSION_MAJOR 0\r\n"
       "#define SECURE_BUFFER_VERSION_MINOR 1\r\n#define SECURE_BUFFER_VERSION_PATCH 0\r\n")
accept(Aligned 0.1.0 "#define SECURE_BUFFER_VERSION_MAJOR   0\n#define SECURE_BUFFER_VERSION_MINOR\t1 \n"
       "#define SECURE_BUFFER_VERSION_PATCH \t 0\t\n")
accept(CommentedOldDefine 0.1.0 "// #define SECURE_BUFFER_VERSION_MAJOR 9\n${major}${minor}${patch}")
accept(MultiDigit 10.20.30 "#define SECURE_BUFFER_VERSION_MAJOR 10\n"
       "#define SECURE_BUFFER_VERSION_MINOR 20\n#define SECURE_BUFFER_VERSION_PATCH 30\n")

reject(MissingPatch SECURE_BUFFER_VERSION_PATCH "${major}${minor}")
reject(MinorTwice SECURE_BUFFER_VERSION_MINOR "${major}${minor}${minor}${patch}")
reject(LeadingZero SECURE_BUFFER_VERSION_MINOR "${major}#define SECURE_BUFFER_VERSION_MINOR 01\n${patch}")
reject(Suffix SECURE_BUFFER_VERSION_PATCH "${major}${minor}#define SECURE_BUFFER_VERSION_PATCH 0u\n")
reject(Parenthesized SECURE_BUFFER_VERSION_MAJOR
       "#define SECURE_BUFFER_VERSION_MAJOR (0)\n${minor}${patch}")
reject(TrailingComment SECURE_BUFFER_VERSION_MINOR
       "${major}#define SECURE_BUFFER_VERSION_MINOR 1  // minor\n${patch}")
reject(Indented SECURE_BUFFER_VERSION_PATCH "${major}${minor}  #define SECURE_BUFFER_VERSION_PATCH 0\n")

# Without a header given, the script reads the library's own: the same version as reading
# include/secure-buffer/version.h directly by the rule above.
file(STRINGS ${ROOT}/include/secure-buffer/version.h lines
     REGEX "^#define SECURE_BUFFER_VERSION_(MAJOR|MINOR|PATCH)[ \t]+[0-9]+[ \t]*$")
set(numbers "")
foreach(line IN LISTS lines)
    string(REGEX REPLACE ".*[ \t]([0-9]+)[ \t]*$" "\\1" number "${line}")
    list(APPEND numbers ${number})
endforeach()
list(JOIN numbers . expected)
parse(Default)
if(NOT rc EQUAL 0 OR NOT out STREQUAL "${expected}\n")
    message(FATAL_ERROR "Default: expected '${expected}', got exit code ${rc}, output '${out}', "
                        "errors:\n${err}")
endif()
