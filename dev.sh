#!/usr/bin/env bash
# Local developer build and test helper for yacoind.
#
# Always builds against the pinned libraries from depends/ (never system
# libraries), so local builds use the same dependency versions as CI.
# All build output, caches and test data stay inside .devbuild/ and build/.
# See doc/developer-build.md for the workflow.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${HOST:-x86_64-pc-linux-gnu}"
JOBS="${JOBS:-$(nproc)}"
DEPENDS_PREFIX="$ROOT/depends/$HOST"
DEVBUILD="$ROOT/.devbuild"

# Keep ccache and temporary test data inside the repository.
export CCACHE_DIR="${CCACHE_DIR:-$DEVBUILD/ccache}"
export CCACHE_BASEDIR="$ROOT"
export CCACHE_MAXSIZE="${CCACHE_MAXSIZE:-10G}"
# With -g, ccache hashes the working directory by default, so identical
# objects in build/dev, build/func, ... would never share cache entries.
export CCACHE_NOHASHDIR=1
export TMPDIR="$DEVBUILD/tmp"
mkdir -p "$CCACHE_DIR" "$TMPDIR" "$DEVBUILD/logs"

usage() {
    cat <<EOF
Usage: ./dev.sh <command> [args]

  depends [qt]            Build the pinned dependencies (NO_QT unless "qt")
  configure <variant>     (Re)configure build/<variant>
  build <variant> [tgt]   Build build/<variant> (optionally one make target)
  unit [suite...]         Build test_bitcoin (dev) and run unit test suites;
                          no suites = all suites, in parallel (UNIT_JOBS)
  check                   Full "make check" on build/dev (serial, as upstream)
  ftest [test...]         Functional tests on build/func, serially (-j 1)
  asan                    Build and run all unit tests with ASan + UBSan
  all                     dev build + unit, func build + ftest, release build
  ccache-stats            Show ccache statistics

Variants: dev (mainnet consensus, no GUI, -O1 -g), func (dev + low difficulty),
          release (default optimisation),
          asan (dev + AddressSanitizer/UndefinedBehaviorSanitizer)
EOF
}

log() { printf '\033[1;34m==> %s\033[0m\n' "$*"; }

timed() {
    local start=$SECONDS
    "$@"
    log "$1 ${2:-} finished in $((SECONDS - start))s"
}

cmd_depends() {
    # Some upstream download hosts accept connections but never send data, so
    # abort stalled transfers and let depends fall back to its mirror.
    local dl="curl --location --fail --connect-timeout 10 --speed-limit 1024 --speed-time 20 --retry 3 -o"
    local args=(-C "$ROOT/depends" -j"$JOBS" HOST="$HOST" "build_linux_DOWNLOAD=$dl")
    [[ "${1:-}" == qt ]] || args+=(NO_QT=1)
    make "${args[@]}"
}

ensure_autogen() {
    [[ -x "$ROOT/configure" ]] || (cd "$ROOT" && ./autogen.sh)
}

# Sets the configure arguments for a build variant in the array "flags".
variant_flags() {
    local ld="-fuse-ld=gold"
    local san="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"
    flags=(--without-gui --disable-man --enable-ccache)
    # Unit tests assume mainnet consensus parameters (e.g. pow_tests), while the
    # functional tests need the low-difficulty build, as in CI.
    case "$1" in
        dev)
            flags+=("CXXFLAGS=-O1 -g" "CFLAGS=-O1 -g" "LDFLAGS=$ld") ;;
        func)
            flags+=(--enable-low-difficulty-for-development
                    "CXXFLAGS=-O1 -g" "CFLAGS=-O1 -g" "LDFLAGS=$ld") ;;
        release)
            flags+=("LDFLAGS=$ld") ;;
        asan)
            # secp256k1's x86_64 field assembly needs more registers than are
            # left under ASan, so build it in plain C (passed to its configure).
            flags+=(--with-asm=no
                    "CXXFLAGS=-O1 -g $san" "CFLAGS=-O1 -g $san" "LDFLAGS=$ld $san") ;;
        *) echo "unknown variant: $1" >&2; exit 2 ;;
    esac
}

cmd_configure() {
    local variant="${1:?variant required}"
    [[ -f "$DEPENDS_PREFIX/share/config.site" ]] || { echo "Run ./dev.sh depends first" >&2; exit 1; }
    ensure_autogen
    mkdir -p "$ROOT/build/$variant"
    local flags
    variant_flags "$variant"
    (cd "$ROOT/build/$variant" &&
        CONFIG_SITE="$DEPENDS_PREFIX/share/config.site" "$ROOT/configure" "${flags[@]}")
    # The functional test runner reads ../config.ini relative to its own path,
    # so give each out-of-tree build its own runner that points at its config.
    mkdir -p "$ROOT/build/$variant/test/functional"
    ln -sf "$ROOT/test/functional/test_runner.py" "$ROOT/build/$variant/test/functional/test_runner.py"
}

cmd_build() {
    local variant="${1:?variant required}"
    [[ -f "$ROOT/build/$variant/Makefile" ]] || cmd_configure "$variant"
    if [[ -n "${2:-}" ]]; then
        make -C "$ROOT/build/$variant/src" -j"$JOBS" "$2"
    else
        make -C "$ROOT/build/$variant" -j"$JOBS"
    fi
}

# Runs Boost test suites as separate processes. Each process gets its own
# TMPDIR, because the test fixtures create their datadirs in the temp dir.
run_unit_suites() {
    local bin="$1"; shift
    local suites=("$@")
    if [[ ${#suites[@]} -eq 0 ]]; then
        mapfile -t suites < <("$bin" --list_content 2>&1 | sed -n 's/^\([A-Za-z0-9_]*\)\*$/\1/p')
    fi
    local outdir="$DEVBUILD/logs/unit"
    rm -rf "$outdir"; mkdir -p "$outdir"
    export bin outdir
    printf '%s\n' "${suites[@]}" | xargs -P "${UNIT_JOBS:-$JOBS}" -I{} bash -c '
        dir="$TMPDIR/unit-{}"; rm -rf "$dir"; mkdir -p "$dir"
        if TMPDIR="$dir" "$bin" --run_test={} --log_level=test_suite >"$outdir/{}.log" 2>&1; then
            echo "PASS {}"
        else
            echo "FAIL {}"
        fi
        rm -rf "$dir"' | sort | tee "$outdir/summary.txt"
    local failed
    failed=$(grep -c '^FAIL' "$outdir/summary.txt" || true)
    log "$(grep -c '^PASS' "$outdir/summary.txt") passed, $failed failed (logs: .devbuild/logs/unit/)"
    [[ "$failed" -eq 0 ]]
}

cmd_unit() {
    cmd_build dev test/test_bitcoin
    run_unit_suites "$ROOT/build/dev/src/test/test_bitcoin" "$@"
}

cmd_check() {
    cmd_build dev
    make -C "$ROOT/build/dev" check
}

cmd_ftest() {
    cmd_build func
    "$ROOT/build/func/test/functional/test_runner.py" -j 1 --tmpdirprefix="$TMPDIR" "$@"
}

cmd_asan() {
    cmd_build asan test/test_bitcoin
    ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1}" \
        run_unit_suites "$ROOT/build/asan/src/test/test_bitcoin" "$@"
}

cmd_all() {
    timed cmd_build dev
    timed cmd_unit
    timed cmd_ftest
    timed cmd_build release
}

case "${1:-}" in
    depends|configure|build|unit|check|ftest|asan|all)
        c="$1"; shift; timed "cmd_$c" "$@" ;;
    # configure picks up the pinned ccache built by depends, so query that one.
    ccache-stats) "$DEPENDS_PREFIX/native/bin/ccache" -s ;;
    *) usage; exit 1 ;;
esac
