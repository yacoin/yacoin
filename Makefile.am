# Copyright (c) 2013-2016 The Bitcoin Core developers
# Copyright (c) 2017-2025 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

ACLOCAL_AMFLAGS = -I build-aux/m4
SUBDIRS = src
#if ENABLE_MAN
#SUBDIRS += doc/man
#endif
.PHONY: deploy FORCE

GZIP_ENV="-9n"
export PYTHONPATH

#if BUILD_BITCOIN_LIBS
#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = libbitcoinconsensus.pc
#endif

BITCOIND_BIN=$(top_builddir)/src/$(BITCOIN_DAEMON_NAME)$(EXEEXT)
BITCOIN_QT_BIN=$(top_builddir)/src/qt/$(BITCOIN_GUI_NAME)$(EXEEXT)
BITCOIN_CLI_BIN=$(top_builddir)/src/$(BITCOIN_CLI_NAME)$(EXEEXT)
BITCOIN_WIN_INSTALLER=$(PACKAGE)-$(PACKAGE_VERSION)-win$(WINDOWS_BITS)-setup$(EXEEXT)

empty :=
space := $(empty) $(empty)

OSX_APP=Yacoin-Qt.app
OSX_VOLNAME = $(subst $(space),-,$(PACKAGE_NAME))
OSX_DMG = $(OSX_VOLNAME).dmg
OSX_BACKGROUND_SVG=background.svg
OSX_BACKGROUND_IMAGE=background.tiff
OSX_BACKGROUND_IMAGE_DPIS=36 72
OSX_DSSTORE_GEN=$(top_srcdir)/contrib/macdeploy/custom_dsstore.py
OSX_DEPLOY_SCRIPT=$(top_srcdir)/contrib/macdeploy/macdeployqtplus
OSX_FANCY_PLIST=$(top_srcdir)/contrib/macdeploy/fancy.plist
OSX_INSTALLER_ICONS=$(top_srcdir)/src/qt/res/icons/bitcoin.icns
OSX_PLIST=$(top_builddir)/share/qt/Info.plist #not installed
OSX_QT_TRANSLATIONS = da,de,es,hu,ru,uk,zh_CN,zh_TW

DIST_DOCS = $(wildcard doc/*.md) $(wildcard doc/release-notes/*.md)
#DIST_CONTRIB = $(top_srcdir)/contrib/bitcoin-cli.bash-completion \
#	       $(top_srcdir)/contrib/bitcoin-tx.bash-completion \
#	       $(top_srcdir)/contrib/bitcoind.bash-completion \
#	       $(top_srcdir)/contrib/init \
#	       $(top_srcdir)/contrib/rpm
#DIST_SHARE = \
#  $(top_srcdir)/share/genbuild.sh \
#  $(top_srcdir)/share/rpcuser
#
#BIN_CHECKS=$(top_srcdir)/contrib/devtools/symbol-check.py \
#           $(top_srcdir)/contrib/devtools/security-check.py
#
#WINDOWS_PACKAGING = $(top_srcdir)/share/pixmaps/bitcoin.ico \
#  $(top_srcdir)/share/pixmaps/nsis-header.bmp \
#  $(top_srcdir)/share/pixmaps/nsis-wizard.bmp \
#  $(top_srcdir)/doc/README_windows.txt
#
#OSX_PACKAGING = $(OSX_DEPLOY_SCRIPT) $(OSX_FANCY_PLIST) $(OSX_INSTALLER_ICONS) \
#  $(top_srcdir)/contrib/macdeploy/$(OSX_BACKGROUND_SVG) \
#  $(OSX_DSSTORE_GEN) \
#  $(top_srcdir)/contrib/macdeploy/detached-sig-apply.sh \
#  $(top_srcdir)/contrib/macdeploy/detached-sig-create.sh

dist-hook:
	-$(GIT) archive --format=tar HEAD -- src/clientversion.cpp | $(AMTAR) -C $(top_distdir) -xf -

$(BITCOIN_WIN_INSTALLER): all-recursive
	$(MKDIR_P) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIND_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_QT_BIN) $(top_builddir)/release
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM) $(BITCOIN_CLI_BIN) $(top_builddir)/release
	@test -f $(MAKENSIS) && $(MAKENSIS) -V2 $(top_builddir)/share/setup.nsi || \
	  echo error: could not build $@
	@echo built $@

$(OSX_APP)/Contents/PkgInfo:
	$(MKDIR_P) $(@D)
	@echo "APPL????" > $@

$(OSX_APP)/Contents/Resources/empty.lproj:
	$(MKDIR_P) $(@D)
	@touch $@ 

$(OSX_APP)/Contents/Info.plist: $(OSX_PLIST)
	$(MKDIR_P) $(@D)
	$(INSTALL_DATA) $< $@

$(OSX_APP)/Contents/Resources/bitcoin.icns: $(OSX_INSTALLER_ICONS)
	$(MKDIR_P) $(@D)
	$(INSTALL_DATA) $< $@

$(OSX_APP)/Contents/MacOS/Yacoin-Qt: $(BITCOIN_QT_BIN)
	$(MKDIR_P) $(@D)
	STRIPPROG="$(STRIP)" $(INSTALL_STRIP_PROGRAM)  $< $@

$(OSX_APP)/Contents/Resources/Base.lproj/InfoPlist.strings:
	$(MKDIR_P) $(@D)
	echo '{	CFBundleDisplayName = "$(PACKAGE_NAME)"; CFBundleName = "$(PACKAGE_NAME)"; }' > $@

OSX_APP_BUILT=$(OSX_APP)/Contents/PkgInfo $(OSX_APP)/Contents/Resources/empty.lproj \
  $(OSX_APP)/Contents/Resources/bitcoin.icns $(OSX_APP)/Contents/Info.plist \
  $(OSX_APP)/Contents/MacOS/Yacoin-Qt $(OSX_APP)/Contents/Resources/Base.lproj/InfoPlist.strings

osx_volname:
	echo $(OSX_VOLNAME) >$@

if BUILD_DARWIN
$(OSX_DMG): $(OSX_APP_BUILT) $(OSX_PACKAGING) $(OSX_BACKGROUND_IMAGE)
	$(PYTHON) $(OSX_DEPLOY_SCRIPT) $(OSX_APP) -add-qt-tr $(OSX_QT_TRANSLATIONS) -translations-dir=$(QT_TRANSLATION_DIR) -dmg -fancy $(OSX_FANCY_PLIST) -verbose 2 -volname $(OSX_VOLNAME)

$(OSX_BACKGROUND_IMAGE).png: contrib/macdeploy/$(OSX_BACKGROUND_SVG)
	sed 's/PACKAGE_NAME/$(PACKAGE_NAME)/' < "$<" | $(RSVG_CONVERT) -f png -d 36 -p 36 -o $@
$(OSX_BACKGROUND_IMAGE)@2x.png: contrib/macdeploy/$(OSX_BACKGROUND_SVG)
	sed 's/PACKAGE_NAME/$(PACKAGE_NAME)/' < "$<" | $(RSVG_CONVERT) -f png -d 72 -p 72 -o $@
$(OSX_BACKGROUND_IMAGE): $(OSX_BACKGROUND_IMAGE).png $(OSX_BACKGROUND_IMAGE)@2x.png
	tiffutil -cathidpicheck $^ -out $@

deploydir: $(OSX_DMG)
else
APP_DIST_DIR=$(top_builddir)/dist
APP_DIST_EXTRAS=$(APP_DIST_DIR)/.background/$(OSX_BACKGROUND_IMAGE) $(APP_DIST_DIR)/.DS_Store $(APP_DIST_DIR)/Applications

$(APP_DIST_DIR)/Applications:
	@rm -f $@
	@cd $(@D); $(LN_S) /Applications $(@F)

$(APP_DIST_EXTRAS): $(APP_DIST_DIR)/$(OSX_APP)/Contents/MacOS/Bitcoin-Qt

$(OSX_DMG): $(APP_DIST_EXTRAS)
	$(GENISOIMAGE) -no-cache-inodes -D -l -probe -V "$(OSX_VOLNAME)" -no-pad -r -dir-mode 0755 -apple -o $@ dist

dpi%.$(OSX_BACKGROUND_IMAGE): contrib/macdeploy/$(OSX_BACKGROUND_SVG)
	sed 's/PACKAGE_NAME/$(PACKAGE_NAME)/' < "$<" | $(RSVG_CONVERT) -f png -d $* -p $* | $(IMAGEMAGICK_CONVERT) - $@
OSX_BACKGROUND_IMAGE_DPIFILES := $(foreach dpi,$(OSX_BACKGROUND_IMAGE_DPIS),dpi$(dpi).$(OSX_BACKGROUND_IMAGE))
$(APP_DIST_DIR)/.background/$(OSX_BACKGROUND_IMAGE): $(OSX_BACKGROUND_IMAGE_DPIFILES)
	$(MKDIR_P) $(@D)
	$(TIFFCP) -c none $(OSX_BACKGROUND_IMAGE_DPIFILES) $@

$(APP_DIST_DIR)/.DS_Store: $(OSX_DSSTORE_GEN)
	$(PYTHON) $< "$@" "$(OSX_VOLNAME)"

$(APP_DIST_DIR)/$(OSX_APP)/Contents/MacOS/Bitcoin-Qt: $(OSX_APP_BUILT) $(OSX_PACKAGING)
	INSTALLNAMETOOL=$(INSTALLNAMETOOL)  OTOOL=$(OTOOL) STRIP=$(STRIP) $(PYTHON) $(OSX_DEPLOY_SCRIPT) $(OSX_APP) -translations-dir=$(QT_TRANSLATION_DIR) -add-qt-tr $(OSX_QT_TRANSLATIONS) -verbose 2

deploydir: $(APP_DIST_EXTRAS)
endif

if TARGET_DARWIN
appbundle: $(OSX_APP_BUILT)
deploy: $(OSX_DMG)
endif
if TARGET_WINDOWS
deploy: $(BITCOIN_WIN_INSTALLER)
endif

$(BITCOIN_QT_BIN): FORCE
	$(MAKE) -C src qt/$(@F)

$(BITCOIND_BIN): FORCE
	$(MAKE) -C src $(@F)

$(BITCOIN_CLI_BIN): FORCE
	$(MAKE) -C src $(@F)

$(BITCOIN_TEST_BIN): FORCE
	$(MAKE) -C src $(@F)

release: all-recursive
	$(MKDIR_P) $(top_builddir)/release
	$(MKDIR_P) $(top_builddir)/debug
	cp $(BITCOIND_BIN) $(top_builddir)/debug/yacoind
	cp $(BITCOIN_CLI_BIN) $(top_builddir)/debug/yacoin-cli
	cp $(BITCOIN_QT_BIN) $(top_builddir)/debug/yacoin-qt
	$(STRIP) $(BITCOIND_BIN) -o $(top_builddir)/release/yacoind
	$(STRIP) $(BITCOIN_CLI_BIN) -o $(top_builddir)/release/yacoin-cli
	$(STRIP) $(BITCOIN_QT_BIN) -o $(top_builddir)/release/yacoin-qt

COVERAGE_UNIT_FILES = unit_baseline.info test_bitcoin.info test_bitcoin_all.info \
  test_bitcoin_coverage.info test_bitcoin.log test_bitcoin.status unit_baseline.log \
  test_bitcoin.capture-failed
COVERAGE_FUNCTIONAL_FILES = functional_baseline.info functional_test.info \
  functional_test_all.info functional_test_coverage.info functional_test.log \
  functional_test.status functional_baseline.log functional_test.capture-failed

if USE_LCOV
# Coverage of the unit tests (cov-unit) and of the functional tests
# (cov-functional). They need differently configured builds: the unit tests
# assume mainnet consensus, the functional tests need
# --enable-low-difficulty-for-development. dev.sh builds both and merges them.
#
# Each target zeroes the counters, records a baseline (so files that never run
# still count), runs the tests, captures, removes vendored and test code, and
# writes an HTML report plus a summary. Coverage is captured even if tests
# fail; the target fails afterwards in that case.
#
# Captures run geninfo in parallel (COV_JOBS processes, default: all cores),
# and the unit test suites run in parallel too. -b points geninfo at the
# compile directory: with ccache's base_dir the objects record source paths
# relative to src/.

COV_JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
# Functional test scripts run in parallel by cov-functional (gcov merges the
# counters of concurrent processes under a file lock).
FTEST_JOBS ?= 4
COV_TOOLS = $(abs_top_srcdir)/contrib/devtools
COV_CAPTURE = $(COV_TOOLS)/coverage-capture.sh --geninfo "$(GENINFO) $(LCOV_OPTS)" \
  --lcov "$(LCOV) $(LCOV_OPTS)" --dir $(abs_builddir)/src --jobs "$(COV_JOBS)"
# lcov 1.x only: lcov 2.x rejects -r patterns that match nothing.
LCOV_FILTER = "/usr/*" "*/depends/*" "*/src/leveldb/*" "*/src/secp256k1/*" \
  "*/src/univalue/*" "*/src/crypto/ctaes/*" "*/src/test/*" "*/src/wallet/test/*"
GENHTML_OPTS = --branch-coverage --demangle-cpp -s

cov-unit:
	rm -rf test_bitcoin.coverage/ test_bitcoin.logs/ $(COVERAGE_UNIT_FILES)
	@# Build everything, so the baseline has no stale .gcno files.
	$(MAKE) all
	$(LCOV) $(LCOV_OPTS) -q -z -d $(abs_builddir)/src
	@# The baseline only reads .gcno files, so it runs while the tests run. The
	@# tests run one process per suite; libgcov locks the .gcda files while
	@# merging. Most of the test time is transaction_tests/test_big_transaction.
	nice -n 10 $(COV_CAPTURE) --initial --out unit_baseline.info > unit_baseline.log 2>&1 & pid=$$!; \
	  trap 'kill $$pid 2>/dev/null' INT TERM HUP; \
	  TMPDIR=$(abs_builddir)/test/tmp; $(MKDIR_P) $$TMPDIR; export TMPDIR; \
	  $(COV_TOOLS)/run-unit-suites.sh $(abs_builddir)/src/test/test_bitcoin$(EXEEXT) \
	    test_bitcoin.logs $(COV_JOBS) > test_bitcoin.log 2>&1; echo $$? > test_bitcoin.status; \
	  wait $$pid || { cat unit_baseline.log >&2; exit 1; }
	@# A crashed test run writes no counters, so the capture is empty; that and a
	@# failed capture fall back to the baseline (0%) so a report is still made.
	$(COV_CAPTURE) --test-name test_bitcoin --out test_bitcoin.info || \
	  { rm -f test_bitcoin.info; echo capture > test_bitcoin.capture-failed; }
	grep -q '^SF:' test_bitcoin.info 2>/dev/null || cp unit_baseline.info test_bitcoin.info
	$(LCOV) $(LCOV_OPTS) -q -a unit_baseline.info -a test_bitcoin.info -o test_bitcoin_all.info
	$(LCOV) $(LCOV_OPTS) -q -r test_bitcoin_all.info $(LCOV_FILTER) -o test_bitcoin_coverage.info
	$(GENHTML) $(GENHTML_OPTS) -q test_bitcoin_coverage.info -o test_bitcoin.coverage
	$(LCOV) $(LCOV_OPTS) --summary test_bitcoin_coverage.info
	@test ! -f test_bitcoin.capture-failed || { echo "capturing the unit test counters failed (see above); the report shows the baseline only" >&2; exit 1; }
	@test "$$(cat test_bitcoin.status)" = 0 || { echo "unit tests failed (see test_bitcoin.log and test_bitcoin.logs/); coverage was captured anyway" >&2; exit 1; }

cov-functional:
	rm -rf functional_test.coverage/ $(COVERAGE_FUNCTIONAL_FILES)
	@# Build everything, so the baseline has no stale .gcno files.
	$(MAKE) all
	@# test_runner.py finds config.ini relative to its own path, so out-of-tree
	@# builds need a link to the runner inside the build directory.
	$(MKDIR_P) test/functional
	if test "$(abs_top_srcdir)" != "$(abs_top_builddir)"; then \
	  ln -sf $(abs_top_srcdir)/test/functional/test_runner.py test/functional/test_runner.py; fi
	$(LCOV) $(LCOV_OPTS) -q -z -d $(abs_builddir)/src
	@# The baseline only reads .gcno files, so it runs while the tests run.
	nice -n 10 $(COV_CAPTURE) --initial --out functional_baseline.info > functional_baseline.log 2>&1 & pid=$$!; \
	  trap 'kill $$pid 2>/dev/null' INT TERM HUP; \
	  test/functional/test_runner.py -j $(FTEST_JOBS) --tmpdirprefix=$(abs_builddir)/test/tmp > functional_test.log 2>&1; \
	  echo $$? > functional_test.status; \
	  wait $$pid || { cat functional_baseline.log >&2; exit 1; }
	@# A crashed test run writes no counters, so the capture is empty; that and a
	@# failed capture fall back to the baseline (0%) so a report is still made.
	$(COV_CAPTURE) --test-name functional_tests --out functional_test.info || \
	  { rm -f functional_test.info; echo capture > functional_test.capture-failed; }
	grep -q '^SF:' functional_test.info 2>/dev/null || cp functional_baseline.info functional_test.info
	$(LCOV) $(LCOV_OPTS) -q -a functional_baseline.info -a functional_test.info -o functional_test_all.info
	$(LCOV) $(LCOV_OPTS) -q -r functional_test_all.info $(LCOV_FILTER) -o functional_test_coverage.info
	$(GENHTML) $(GENHTML_OPTS) -q functional_test_coverage.info -o functional_test.coverage
	$(LCOV) $(LCOV_OPTS) --summary functional_test_coverage.info
	@test ! -f functional_test.capture-failed || { echo "capturing the functional test counters failed (see above); the report shows the baseline only" >&2; exit 1; }
	@test "$$(cat functional_test.status)" = 0 || { echo "functional tests failed (see functional_test.log); coverage was captured anyway" >&2; exit 1; }

.PHONY: cov-unit cov-functional
endif


# if USE_COMPARISON_TOOL
# check-local:
# 	$(MKDIR_P) qa/tmp
# 	@qa/pull-tester/run-bitcoind-for-test.sh $(JAVA) -jar $(JAVA_COMPARISON_TOOL) qa/tmp/compTool $(COMPARISON_TOOL_REORG_TESTS) 2>&1
# endif

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST = $(top_srcdir)/share/genbuild.sh contrib/devtools/coverage-capture.sh contrib/devtools/run-unit-suites.sh qa/pull-tester/rpc-tests.sh qa/pull-tester/run-bitcoin-cli qa/rpc-tests $(DIST_DOCS) $(WINDOWS_PACKAGING) $(OSX_PACKAGING)

CLEANFILES = $(OSX_DMG) $(BITCOIN_WIN_INSTALLER)

DISTCHECK_CONFIGURE_FLAGS = --enable-man

clean-local:
	rm -rf test_bitcoin.coverage/ test_bitcoin.logs/ functional_test.coverage/ *.info.parts/ test/tmp/ cache/ $(OSX_APP)
	rm -f $(COVERAGE_UNIT_FILES) $(COVERAGE_FUNCTIONAL_FILES)
	rm -rf test/functional/__pycache__
