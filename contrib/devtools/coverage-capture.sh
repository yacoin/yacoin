#!/usr/bin/env bash
# Parallel lcov 1.x capture: runs geninfo on chunks of the coverage data files
# in parallel and merges the parts. Used by "make cov-unit" / "cov-functional".
#
# Usage: coverage-capture.sh --geninfo CMD --lcov CMD --dir SRCDIR --out FILE
#                            (--initial | --test-name NAME) [--jobs N]
#
# --initial captures a baseline from the .gcno files (every instrumented line
# at 0); --test-name captures the counters in the .gcda files. CMD strings are
# split on spaces (geninfo/lcov path plus options such as --gcov-tool and --rc).
# Without .gcda files (e.g. the tests crashed) an empty output file is written
# and the exit status is 0; the Makefile then falls back to the baseline. Any
# other failure exits non-zero.
set -euo pipefail

geninfo="" lcov="" dir="" out="" mode="" name="" jobs=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --geninfo) geninfo="$2"; shift 2 ;;
        --lcov) lcov="$2"; shift 2 ;;
        --dir) dir="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --initial) mode=initial; shift ;;
        --test-name) mode=test; name="$2"; shift 2 ;;
        --jobs) jobs="$2"; shift 2 ;;
        *) echo "$0: unknown argument $1" >&2; exit 2 ;;
    esac
done
[[ -n "$geninfo" && -n "$lcov" && -n "$dir" && -n "$out" && -n "$mode" ]] ||
    { echo "$0: missing arguments" >&2; exit 2; }
[[ -n "$jobs" ]] || jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "$0: --jobs must be a positive integer" >&2; exit 2; }

read -ra geninfo_cmd <<< "$geninfo"
read -ra lcov_cmd <<< "$lcov"
geninfo_cmd+=(-b "$dir")
if [[ $mode == initial ]]; then
    ext=gcno; geninfo_cmd+=(-i)
else
    ext=gcda; geninfo_cmd+=(-t "$name")
fi

mapfile -d '' files < <(find "$dir" -name "*.$ext" -print0)
if [[ ${#files[@]} -eq 0 ]]; then
    if [[ $mode == initial ]]; then
        echo "$0: no .gcno files under $dir; is this an --enable-lcov build?" >&2
        exit 1
    fi
    : > "$out"
    exit 0
fi

parts="$out.parts"
rm -rf "$parts"; mkdir -p "$parts"
trap 'rm -rf "$parts"' EXIT
export parts

# Runs geninfo on the given files into a new part. On failure it prints
# geninfo's output, which names the file and the error.
run_part() {
    local part
    part=$(mktemp "$parts/part.XXXXXX")
    if ! "$@" -o "$part.info" > "$part.log" 2>&1; then
        cat "$part.log" >&2
        return 1
    fi
}
export -f run_part

# The first file is processed alone to check the mode. Running geninfo in
# parallel is only safe when gcov runs in intermediate mode, where each run
# works in its own temp dir. Otherwise all runs would share the .gcov files in
# the object directories, so fall back to a single process. geninfo picks the
# mode itself. (lcov 1.15's --initial capture parses the .gcno files and
# ignores .gcda files: a baseline taken next to existing counters is all 0.)
run_part "${geninfo_cmd[@]}" "${files[0]}"
if [[ $mode == test ]] && ! grep -qh "Using intermediate gcov format" "$parts"/part.*.log; then
    echo "$0: gcov intermediate format not available; capturing with one process" >&2
    jobs=1
fi

# About three chunks per job, so the last round doesn't leave cores idle.
if [[ ${#files[@]} -gt 1 ]]; then
    rest=("${files[@]:1}")
    per_chunk=$(( (${#rest[@]} + jobs * 3 - 1) / (jobs * 3) ))
    if ! printf '%s\0' "${rest[@]}" |
            xargs -0 -n "$per_chunk" -P "$jobs" bash -c 'run_part "$@"' _ "${geninfo_cmd[@]}"; then
        echo "$0: geninfo failed (see the output above)" >&2
        exit 1
    fi
fi

# lcov 1.x aborts a merge on a part without records (e.g. an object with no
# executable lines), so merge only the parts that have some.
merge=()
for f in "$parts"/part.*.info; do
    if grep -q '^SF:' "$f"; then merge+=(-a "$f"); fi
done
if [[ ${#merge[@]} -eq 0 ]]; then
    [[ $mode == test ]] || { echo "$0: the baseline has no records" >&2; exit 1; }
    : > "$out"
    exit 0
fi
"${lcov_cmd[@]}" -q "${merge[@]}" -o "$out"
