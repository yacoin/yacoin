# Local developer build

`dev.sh` in the repository root wraps a fast build and test loop for regular
development on Linux (tested on Ubuntu 22.04, 8 cores). It always builds
against the pinned libraries from `depends/`, never system libraries, so local
builds use the same dependency versions as the CI and release builds.

Everything it creates stays inside the repository and is ignored by git:

| Path | Contents |
|---|---|
| `depends/x86_64-pc-linux-gnu/` | Built dependencies (shared by all variants) |
| `build/<variant>/` | Out-of-tree build directories |
| `.devbuild/ccache/` | Compiler cache, shared by all variants |
| `.devbuild/tmp/` | Temporary data directories of unit and functional tests |
| `.devbuild/logs/` | Logs, including one log per unit test suite |

## One-time setup

Install the host tools (needs sudo):

```sh
sudo apt install build-essential autoconf automake libtool bison bsdmainutils ccache pkg-config python3 curl
```

Build the dependencies once. Later runs reuse `depends/built/` unless a
package version changes.

```sh
./dev.sh depends        # without Qt, enough for yacoind and all tests
./dev.sh depends qt     # only needed for yacoin-qt
```

`dev.sh` aborts downloads that stall for 20 seconds, so depends falls back to
its mirror (`bitcoincore.org/depends-sources`) when an upstream host hangs.
The package hashes are still checked.

## Build variants

| Variant | Purpose | Configuration |
|---|---|---|
| `dev` | Unit tests, TDD loop | Mainnet consensus, no GUI, `-O1 -g` |
| `func` | Functional tests | `dev` plus `--enable-low-difficulty-for-development` (as in CI) |
| `release` | Check before a PR | Mainnet, default optimisation |
| `asan` | Memory and UB checks | `dev` plus AddressSanitizer, LeakSanitizer and UBSan |

The unit tests assume mainnet consensus parameters (for example `pow_tests`),
so they fail on the low-difficulty build. The functional tests need it.

All variants use the gold linker and ccache. The `asan` variant builds
secp256k1 without its x86_64 assembly, which doesn't compile under ASan.

## Commands

```sh
./dev.sh build dev                  # build everything in build/dev
./dev.sh build dev test/test_bitcoin  # build one make target
./dev.sh unit                       # all unit test suites, in parallel
./dev.sh unit pow_tests coins_tests # selected suites
./dev.sh check                      # upstream "make check" (serial)
./dev.sh ftest                      # all functional tests, serially
./dev.sh ftest feature_tokens.py    # selected functional tests
./dev.sh asan                       # unit tests under ASan/LSan/UBSan
./dev.sh all                        # dev + unit, func + ftest, release
./dev.sh ccache-stats
```

A variant is configured automatically on first use; `./dev.sh configure
<variant>` reconfigures it.

### TDD loop

1. Write or change a test in `src/test/`.
2. `./dev.sh unit <suite>` rebuilds only `test_bitcoin` and runs that suite.
3. Change the code until it passes, then run `./dev.sh unit` for all suites.
4. Before a PR: `./dev.sh all` and `./dev.sh asan`.

### Unit tests in parallel

`./dev.sh unit` lists the Boost test suites and runs each in its own process
(`UNIT_JOBS`, default: number of cores). The test fixtures create their data
directories under the temp directory, so every process gets its own `TMPDIR`.
The suites don't use network ports or other shared state. Results are the
same as a serial run. Per-suite logs and `summary.txt` are written to
`.devbuild/logs/unit/`.

### Functional tests

Functional tests run serially (`-j 1`) for now; running them in parallel
hasn't been verified. Their data directories go to `.devbuild/tmp/`.

## Reference timings

Ubuntu 22.04, 8 cores, 15 GB RAM.

| Step | Time |
|---|---|
| `depends` without Qt (first run, including downloads) | 4 min 14 s |
| Configure one variant | 48 s |
| Clean build of a variant, cold ccache | 6 min 52 s – 7 min 55 s |
| Rebuild after switching configuration, warm ccache | 67 s |
| Rebuild `test_bitcoin` after changing one source file | 7 s |
| All unit tests, serial | 29 s |
| All unit tests, parallel (`./dev.sh unit`) | 15 s |
| All functional tests, serial | 13 min 40 s |

The parallel unit test time is bounded by `transaction_tests/test_big_transaction`
(about 17 s at `-O1`).

## Baseline test results (v1.11.0, 9706af8b)

- Unit tests (`dev`): 53 of 53 suites, 239 test cases pass.
- Functional tests (`func`): 45 of 45 pass.
- Sanitizers (`asan`): 49 of 53 suites pass. Findings:
  - `checkqueue_tests`: stack-use-after-scope in `test_CheckQueueControl_Locks`
    (test code, `checkqueue_tests.cpp:422`).
  - `DoS_tests`: `CNode` objects created by the test are never freed (leak).
  - `accounting_tests`, `wallet_tests`: small leaks inside Berkeley DB
    (`__os_malloc`).
  - No UBSan findings.
- Unit test files present but not compiled: `blockencodings`, `main`,
  `merkle`, `miner`, `policyestimator`, `versionbits`.

## Notes

- `autogen.sh` regenerates some tracked files under `build-aux/` with the
  local autotools versions. Don't commit those changes.
- The ccache shipped by depends is used; `./dev.sh ccache-stats` queries it.
