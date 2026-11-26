# Compile-fail tests: each source must be rejected by a specific static_assert.
# The test runs a nested build of an EXCLUDE_FROM_ALL target and passes only if
# the build output matches MESSAGE_REGEX (the exit code is ignored, so an
# unrelated compile error does not pass). Nested builds of one tree share a
# lock because they must not run in parallel.
function(add_compile_fail_test NAME SOURCE MESSAGE_REGEX)
    add_executable(${NAME} EXCLUDE_FROM_ALL ${SOURCE})
    target_link_libraries(${NAME} PRIVATE safeheron::secure-buffer)
    target_compile_options(${NAME} PRIVATE ${TEST_COMPILE_OPTIONS})
    add_test(
        NAME compile_fail_${NAME}
        COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}
                --target ${NAME} --config $<CONFIG>
    )
    set_tests_properties(compile_fail_${NAME} PROPERTIES
        PASS_REGULAR_EXPRESSION "${MESSAGE_REGEX}"
        RESOURCE_LOCK compile_fail_build
        # Compiler diagnostics are matched by wording; force the untranslated
        # (English) messages on localized toolchains.
        ENVIRONMENT "LC_ALL=C;LANG=C;VSLANG=1033"
    )
endfunction()

set(INVALID_REGISTRATION
    "a type registered with enable_secure_cleanse must be a non-cv class or union that is trivially copyable and trivially copy-assignable")

add_compile_fail_test(registered_with_vector registered_with_vector.cpp
    "${INVALID_REGISTRATION}")
add_compile_fail_test(registered_with_const_member registered_with_const_member.cpp
    "${INVALID_REGISTRATION}")
add_compile_fail_test(registered_element_in_array registered_element_in_array.cpp
    "${INVALID_REGISTRATION}")
add_compile_fail_test(unregistered_struct unregistered_struct.cpp
    "secure_cleanse accepts integers, std::byte, types registered with enable_secure_cleanse and fixed-size arrays of them; dynamic containers cannot be wiped in place, use SecureBytes/SecureString")
add_compile_fail_test(secure_array_registered_element secure_array_registered_element.cpp
    "SecureArray elements must be integers or std::byte")

set(DELETED_COMPARISON "deleted (function|operator)")

add_compile_fail_test(secure_bytes_equal secure_bytes_equal.cpp
    "${DELETED_COMPARISON}")
add_compile_fail_test(secure_bytes_less secure_bytes_less.cpp
    "${DELETED_COMPARISON}")
add_compile_fail_test(secure_bytes_greater secure_bytes_greater.cpp
    "${DELETED_COMPARISON}")
add_compile_fail_test(secure_string_equal secure_string_equal.cpp
    "${DELETED_COMPARISON}")

# C++20 rewrites >, <=, >= and <=> in terms of other operators; pin them.
if("cxx_std_20" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
    add_compile_fail_test(secure_bytes_greater_cxx20 secure_bytes_greater_cxx20.cpp
        "${DELETED_COMPARISON}")
    add_compile_fail_test(secure_bytes_spaceship_cxx20 secure_bytes_spaceship_cxx20.cpp
        "${DELETED_COMPARISON}")
    set_target_properties(secure_bytes_greater_cxx20 secure_bytes_spaceship_cxx20
        PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
endif()
