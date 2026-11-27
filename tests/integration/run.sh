#!/usr/bin/env bash
# Integration checks: installation without the tests, use through find_package
# and add_subdirectory (with and without the tests), settings passed in from
# outside, and warnings-as-errors staying on this project's own targets.
# Needs Linux, CMake, Ninja, Python 3 and nm; the compiler comes from CC/CXX.
#
#   tests/integration/run.sh [WORK_DIR]
#
# WORK_DIR defaults to <repo>/build-integration and is recreated on every run.
# An existing directory is removed only if it is empty or an earlier run of
# this script created it; anything else is refused.
# Each check prints "ok - ..." or "FAIL - ..." (followed by the reason: the
# check's own output, or the last lines of the step's log); a step whose
# configure, build or install command fails is reported as aborted and the
# next step runs. The exit status is 0 only if every check passed.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONSUMER="$ROOT/tests/integration/consumer"
WORK=${1:-$ROOT/build-integration}

for tool in cmake ctest ninja python3 nm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "run.sh: $tool is required" >&2
        exit 2
    fi
done

MARKER=.secure-buffer-integration-work
if [[ -e $WORK || -L $WORK ]]; then
    if [[ ! -d $WORK || -L $WORK ]] || { [[ -n $(ls -A "$WORK") ]] && [[ ! -e $WORK/$MARKER ]]; }; then
        echo "run.sh: refusing to delete $WORK: it is not an empty directory or one this script created" >&2
        exit 2
    fi
fi
rm -rf "$WORK"
mkdir -p "$WORK"
touch "$WORK/$MARKER"
WORK=$(cd "$WORK" && pwd)

checks=0
failed=0
LOG=/dev/null

report() {  # report <0|1> <text>
    checks=$((checks + 1))
    if [[ $1 -eq 0 ]]; then
        echo "ok - $2"
    else
        failed=$((failed + 1))
        echo "FAIL - $2"
    fi
}

check() {  # check <text> <command...>: passes if the command succeeds
    local text=$1
    shift
    local out rc
    out=$("$@" 2>&1)
    rc=$?
    if [[ -n $out ]]; then
        printf '%s\n' "$out" >>"$LOG"
    fi
    report $rc "$text"
    if [[ $rc -ne 0 && -n $out ]]; then
        tail -n 20 <<<"$out" | sed 's/^/    /'
    fi
}

run() {  # run <command...>: a configure/build/install step that must succeed
    echo "+ $*" >>"$LOG"
    if ! "$@" >>"$LOG" 2>&1; then
        LAST_CMD="$*"
        return 1
    fi
}

step() {  # step <name> <function>
    LOG="$WORK/$1.log"
    : >"$LOG"
    echo "# $1"
    if ! "$2"; then
        report 1 "$1: aborted at: $LAST_CMD"
        echo "--- last lines of $LOG:"
        tail -n 20 "$LOG"
        echo "---"
    fi
}

# flags <build-dir> <source-name> want|reject <token>
# Reads compile_commands.json and compares exact tokens of every compile command
# for the source (one per configuration with a multi-config generator). A want
# check needs the token in all of them, a reject check in none; either fails if
# there is no compile command for the source at all.
flags() {
    python3 -I - "$1/compile_commands.json" "$2" "$3" "$4" <<'PY'
import json
import shlex
import sys

path, source, mode, token = sys.argv[1:5]
try:
    with open(path) as f:
        entries = json.load(f)
except OSError:
    sys.exit(1)
found = [e for e in entries if e["file"].endswith("/" + source)]
if not found:
    print(f"no compile command for {source} in {path}")
    sys.exit(1)
for e in found:
    tokens = e["arguments"] if "arguments" in e else shlex.split(e["command"])
    if (token in tokens) != (mode == "want"):
        print(f"{token} {'missing from' if mode == 'want' else 'present in'}: {' '.join(tokens)}")
        sys.exit(1)
PY
}

# Command output is captured before it is searched: grep -q exits at the first
# match, and the writer's SIGPIPE would fail the pipeline under pipefail.

defines_memzero() {  # defines_memzero <binary>: secure_memzero is linked into it
    local symbols
    symbols=$(nm -C "$1") || return 1
    grep -q 'T safeheron::secure_buffer::secure_memzero(' <<<"$symbols" ||
        { echo "no defined secure_memzero in $1"; return 1; }
}

no_path_matches() {  # no_path_matches <dir> <find -iname pattern>...
    local dir=$1
    shift
    local pattern
    local hit
    for pattern in "$@"; do
        hit=$(find "$dir" -iname "$pattern" -print -quit)
        if [[ -n $hit ]]; then
            echo "found $hit"
            return 1
        fi
    done
}

file_under() {  # file_under <dir> <name>
    [[ -n $(find "$1" -name "$2" -print -quit) ]] || { echo "no $2 under $1"; return 1; }
}

no_googletest() {  # no_googletest <build-dir>: GoogleTest was never fetched
    [[ ! -e $1/_deps ]] || { echo "$1/_deps exists"; return 1; }
    # Cache entries only: comment lines hold option descriptions.
    local entries
    entries=$(grep -v '^//' "$1/CMakeCache.txt") || return 1
    if grep -iE 'googletest|gtest|gmock' <<<"$entries"; then
        return 1
    fi
}

total_tests() {  # total_tests <build-dir> <count> [ctest args...]
    local dir=$1 count=$2
    shift 2
    local listing
    listing=$(ctest --test-dir "$dir" -N "$@") || return 1
    grep -qx "Total Tests: $count" <<<"$listing" || { echo "$listing"; return 1; }
}

lists_test() {  # lists_test <build-dir> <name> [ctest args...]
    local dir=$1 name=$2
    shift 2
    local listing
    listing=$(ctest --test-dir "$dir" -N "$@") || return 1
    grep -qE "Test +#[0-9]+: $name\$" <<<"$listing" || { echo "$listing"; return 1; }
}

configured_with() {  # configured_with <line>: the step's configure output has this exact line
    grep -qxF -- "$1" "$LOG" || { echo "not in the configure output: $1"; return 1; }
}

# Reuse the GoogleTest sources fetched by s3b, if any, instead of downloading again.
googletest_src() {
    GOOGLETEST_ARGS=()
    if [[ -d $WORK/dev-build/_deps/googletest-src ]]; then
        GOOGLETEST_ARGS=("-DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=$WORK/dev-build/_deps/googletest-src")
    fi
}

s1_install() {
    local b="$WORK/install-build"
    run cmake -S "$ROOT" -B "$b" -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE=Release -DSECURE_BUFFER_BUILD_TESTS=OFF || return 1
    run cmake --build "$b" || return 1
    run cmake --install "$b" --prefix "$WORK/prefix" || return 1
    check "s1: GoogleTest is not fetched" no_googletest "$b"
    check "s1: secure_memzero.cpp has -fPIC" flags "$b" secure_memzero.cpp want -fPIC
    check "s1: secure_memzero.cpp has no -Werror" flags "$b" secure_memzero.cpp reject -Werror
    check "s1: secure_memzero.cpp has -std=c++17" flags "$b" secure_memzero.cpp want -std=c++17
    check "s1: libsecure-buffer.a is installed" file_under "$WORK/prefix" libsecure-buffer.a
    check "s1: nothing of GoogleTest is installed" no_path_matches "$WORK/prefix" '*gtest*' '*gmock*'
}

s2_package_consumer() {
    local b="$WORK/package-consumer"
    run cmake -S "$CONSUMER" -B "$b" -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE=Release -DSB_CONSUMER_MODE=package \
        -DCMAKE_PREFIX_PATH="$WORK/prefix" || return 1
    run cmake --build "$b" || return 1
    check "s2: consumer tests pass" ctest --test-dir "$b" --output-on-failure
    check "s2: exactly 2 consumer tests" total_tests "$b" 2
    check "s2: consumer_static defines secure_memzero" defines_memzero "$b/consumer_static"
    check "s2: libconsumer_shared.so defines secure_memzero" defines_memzero "$b/libconsumer_shared.so"
    check "s2: own_warning.cpp has -Wall" flags "$b" own_warning.cpp want -Wall
    check "s2: own_warning.cpp has no -Werror" flags "$b" own_warning.cpp reject -Werror
}

s3_overrides() {
    local b="$WORK/override-build"
    run cmake -S "$ROOT" -B "$b" -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE=Release -DSECURE_BUFFER_BUILD_TESTS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=OFF -DCMAKE_CXX_STANDARD=20 \
        -DCMAKE_CXX_EXTENSIONS=ON -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
        "-DCMAKE_CXX_FLAGS=-DSB_INTEGRATION_MARKER=1" || return 1
    run cmake --build "$b" --target secure-buffer || return 1
    check "s3: secure_memzero.cpp has no -fPIC" flags "$b" secure_memzero.cpp reject -fPIC
    check "s3: secure_memzero.cpp has -std=gnu++20" flags "$b" secure_memzero.cpp want -std=gnu++20
    check "s3: secure_memzero.cpp has -Werror" flags "$b" secure_memzero.cpp want -Werror
    check "s3: secure_memzero.cpp has the CMAKE_CXX_FLAGS marker" \
        flags "$b" secure_memzero.cpp want -DSB_INTEGRATION_MARKER=1
}

s3b_dev_build() {
    local b="$WORK/dev-build"
    run cmake -S "$ROOT" -B "$b" -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE=Debug || return 1
    check "s3b: secure_memzero.cpp has -Werror" flags "$b" secure_memzero.cpp want -Werror
    check "s3b: test_secure_memzero.cpp has -Werror" flags "$b" test_secure_memzero.cpp want -Werror
    check "s3b: test_secure_memzero.cpp has -std=c++17" flags "$b" test_secure_memzero.cpp want -std=c++17
    check "s3b: gtest-all.cc has no -Werror" flags "$b" gtest-all.cc reject -Werror
}

s3c_no_warning_as_error() {
    local b="$WORK/dev-nowae"
    googletest_src
    run cmake --compile-no-warning-as-error -S "$ROOT" -B "$b" -G Ninja \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug "${GOOGLETEST_ARGS[@]}" || return 1
    check "s3c: secure_memzero.cpp has no -Werror" flags "$b" secure_memzero.cpp reject -Werror
    check "s3c: test_secure_memzero.cpp has no -Werror" flags "$b" test_secure_memzero.cpp reject -Werror
    check "s3c: header_conversion_clean.cpp keeps -Werror" \
        flags "$b" header_conversion_clean.cpp want -Werror
}

s4_subdirectory_tests() {
    local b="$WORK/subdir-tests"
    googletest_src
    run cmake -S "$CONSUMER" -B "$b" -G "Ninja Multi-Config" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DSB_CONSUMER_MODE=subdirectory -DSB_SOURCE_DIR="$ROOT" -DSB_CONSUMER_ENABLE_TESTS=ON \
        "${GOOGLETEST_ARGS[@]}" || return 1
    run cmake --build "$b" --config Debug || return 1
    check "s4: ctest lists test_secure_memzero" lists_test "$b" test_secure_memzero -C Debug
    check "s4: ctest lists compile_fail_secure_bytes_equal" \
        lists_test "$b" compile_fail_secure_bytes_equal -C Debug
    check "s4: ctest lists consumer_static" lists_test "$b" consumer_static -C Debug
    check "s4: all tests pass (Debug)" ctest --test-dir "$b" -C Debug --output-on-failure
    check "s4: compile-fail tests pass (Release)" \
        ctest --test-dir "$b" -C Release -R '^compile_fail_' --no-tests=error --output-on-failure
    check "s4: secure_memzero.cpp has -Werror" flags "$b" secure_memzero.cpp want -Werror
    check "s4: gtest-all.cc has no -Werror" flags "$b" gtest-all.cc reject -Werror
    check "s4: own_warning.cpp has no -Werror" flags "$b" own_warning.cpp reject -Werror
}

s5_subdirectory_defaults() {
    local b="$WORK/subdir-default"
    run cmake -S "$CONSUMER" -B "$b" -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_BUILD_TYPE=Release -DSB_CONSUMER_MODE=subdirectory -DSB_SOURCE_DIR="$ROOT" \
        -DSB_CONSUMER_CXX_STANDARD=20 -DBUILD_SHARED_LIBS=ON || return 1
    run cmake --build "$b" || return 1
    check "s5: no C++20 module scanning of the library" \
        configured_with "-- secure-buffer CXX_SCAN_FOR_MODULES: OFF"
    check "s5: GoogleTest is not fetched" no_googletest "$b"
    check "s5: only the 2 consumer tests are registered" total_tests "$b" 2
    check "s5: consumer tests pass" ctest --test-dir "$b" --output-on-failure
    check "s5: secure_memzero.cpp has -fPIC" flags "$b" secure_memzero.cpp want -fPIC
    check "s5: secure_memzero.cpp has no -Werror" flags "$b" secure_memzero.cpp reject -Werror
    check "s5: secure_memzero.cpp follows the parent's C++20" \
        flags "$b" secure_memzero.cpp want -std=c++20
    check "s5: secure-buffer is a static archive" file_under "$b" libsecure-buffer.a
    check "s5: no shared secure-buffer library" no_path_matches "$b" 'libsecure-buffer.so*'
    check "s5: consumer_static defines secure_memzero" defines_memzero "$b/consumer_static"
}

step s1-install s1_install
step s2-package-consumer s2_package_consumer
step s3-overrides s3_overrides
step s3b-dev-build s3b_dev_build
step s3c-no-warning-as-error s3c_no_warning_as_error
step s4-subdirectory-tests s4_subdirectory_tests
step s5-subdirectory-defaults s5_subdirectory_defaults

echo "$checks checks, $failed failed"
[[ $failed -eq 0 ]]
