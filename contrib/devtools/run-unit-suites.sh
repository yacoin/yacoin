#!/usr/bin/env bash
# Runs Boost unit test suites of test_bitcoin as separate parallel processes.
# Used by dev.sh (unit, asan) and "make cov-unit".
#
# Usage: run-unit-suites.sh BIN LOGDIR JOBS [SELECTOR...]
#
# Without selectors, all suites are listed from BIN and run. Each process gets
# its own TMPDIR below $TMPDIR (default /tmp), because the test fixtures create
# their datadirs in the temp dir. Writes LOGDIR/<n>-<name>.log per selector and
# LOGDIR/summary.txt; exits non-zero if any selector fails or none are found.
set -euo pipefail

bin="${1:?test binary required}" logdir="${2:?log dir required}" jobs="${3:?job count required}"
shift 3
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "$0: job count must be a positive integer" >&2; exit 2; }
if [[ $# -gt 0 ]]; then
    suites=("$@")
else
    # A failed or empty listing must never be reported as a pass, since suites
    # would be silently skipped.
    if ! content=$("$bin" --list_content 2>&1); then
        echo "'$bin --list_content' failed:" >&2
        echo "$content" >&2
        exit 1
    fi
    mapfile -t listed < <(sed -n 's/^\([A-Za-z0-9_][A-Za-z0-9_]*\)\*$/\1/p' <<< "$content")
    if [[ ${#listed[@]} -eq 0 ]]; then
        echo "No unit test suites found; '$bin --list_content' failed?" >&2
        exit 1
    fi
    # Start the slowest suites first, so they don't finish last on their own.
    slow=(transaction_tests coins_tests)
    suites=()
    for s in "${slow[@]}"; do
        for t in "${listed[@]}"; do if [[ $t == "$s" ]]; then suites+=("$t"); fi; done
    done
    for t in "${listed[@]}"; do
        if [[ " ${slow[*]} " != *" $t "* ]]; then suites+=("$t"); fi
    done
fi

tmproot="${TMPDIR:-/tmp}/unit-suites.$$"
rm -rf "$logdir"; mkdir -p "$logdir" "$tmproot"
trap 'rm -rf "$tmproot"' EXIT
export bin logdir tmproot
# Each selector is passed to bash as "$2", never pasted into the script, so
# Boost filters such as suite/case, suite/* or !suite reach --run_test as is.
# Log and temp dir names are the selector's index plus its characters that
# are safe in file names, so different selectors never share them.
for i in "${!suites[@]}"; do printf '%s\0%s\0' "$i" "${suites[$i]}"; done |
    xargs -0 -P "$jobs" -n 2 bash -c '
        name="$1-$(printf "%s" "$2" | tr -c "A-Za-z0-9_.-" "_")"
        dir="$tmproot/$name"; mkdir -p "$dir"
        if TMPDIR="$dir" "$bin" --run_test="$2" --log_level=test_suite >"$logdir/$name.log" 2>&1; then
            echo "PASS $2"
        else
            echo "FAIL $2"
        fi
        rm -rf "$dir"' _ | sort -k2 | tee "$logdir/summary.txt"
failed=$(grep -c '^FAIL' "$logdir/summary.txt" || true)
echo "$(grep -c '^PASS' "$logdir/summary.txt") passed, $failed failed (logs: $logdir)"
[[ "$failed" -eq 0 ]]
