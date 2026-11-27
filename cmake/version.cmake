# Copyright 2026 Safeheron Inc.
# SPDX-License-Identifier: Apache-2.0

# Reads the library's version from the three number macros in include/secure-buffer/version.h, the
# one place it is written. Every other reader goes through this file, so the rule exists once.
#
# include()d (CMakeLists.txt, before project(); or another script): sets SECURE_BUFFER_VERSION to
# "MAJOR.MINOR.PATCH" from the library's own header, whatever SECURE_BUFFER_VERSION_HEADER may be
# set to around it. When configuring a project, the header becomes a configure dependency, so a
# changed version reconfigures the build.
#
# Run as a script, it prints the version and nothing else on standard output:
#   cmake [-DSECURE_BUFFER_VERSION_HEADER=<header>] -P cmake/version.cmake
#
# A header without exactly one line "#define SECURE_BUFFER_VERSION_<PART> <number>" for each part
# (MAJOR, MINOR, PATCH), the number being 0 or digits not starting with 0, stops with an error.
block(SCOPE_FOR VARIABLES PROPAGATE SECURE_BUFFER_VERSION)
    set(header ${CMAKE_CURRENT_LIST_DIR}/../include/secure-buffer/version.h)
    if(CMAKE_SCRIPT_MODE_FILE STREQUAL CMAKE_CURRENT_LIST_FILE AND SECURE_BUFFER_VERSION_HEADER)
        set(header ${SECURE_BUFFER_VERSION_HEADER})
    endif()
    get_filename_component(header "${header}" ABSOLUTE)

    # file(STRINGS) drops the line ends, \r included. A line not starting with "#define" (a
    # comment, an indented define) is not a definition of the version.
    file(STRINGS "${header}" lines REGEX "^#define[ \t]+SECURE_BUFFER_VERSION_(MAJOR|MINOR|PATCH)")
    set(numbers "")
    foreach(part MAJOR MINOR PATCH)
        set(name SECURE_BUFFER_VERSION_${part})
        set(found "")
        foreach(line IN LISTS lines)
            if(line MATCHES "^#define[ \t]+${name}([ \t]|$)")
                list(APPEND found "${line}")
            endif()
        endforeach()
        list(LENGTH found count)
        set(form "^#define[ \t]+${name}[ \t]+(0|[1-9][0-9]*)[ \t]*$")
        if(NOT count EQUAL 1 OR NOT found MATCHES "${form}")
            if(count EQUAL 0)
                set(problem "no line defines ${name}")
            elseif(count GREATER 1)
                set(problem "${name} is defined ${count} times")
            else()
                set(problem "${name} is defined as '${found}'")
            endif()
            message(FATAL_ERROR "${header}: ${problem}. The version is written as one line "
                    "\"#define ${name} <number>\" for each of MAJOR, MINOR and PATCH, starting at "
                    "the beginning of the line, where a number is 0 or digits not starting with 0 "
                    "(no suffix, no parentheses, no comment after it).")
        endif()
        list(APPEND numbers ${CMAKE_MATCH_1})
    endforeach()
    list(JOIN numbers . SECURE_BUFFER_VERSION)

    if(CMAKE_SCRIPT_MODE_FILE STREQUAL CMAKE_CURRENT_LIST_FILE)
        # message() writes to standard error; the version goes to standard output alone.
        execute_process(COMMAND ${CMAKE_COMMAND} -E echo ${SECURE_BUFFER_VERSION})
    elseif(NOT CMAKE_SCRIPT_MODE_FILE)
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${header}")
    endif()
endblock()
