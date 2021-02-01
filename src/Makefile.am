DIST_SUBDIRS =
AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS)

if EMBEDDED_LEVELDB
DEFS+=-DUSE_LEVELDB
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/include
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/helpers
LEVELDB_CPPFLAGS += -I$(srcdir)/leveldb/helpers/memenv
LIBLEVELDB += $(builddir)/leveldb/libleveldb.a
LIBMEMENV  += $(builddir)/leveldb/libmemenv.a

# NOTE: This dependency is not strictly necessary, but without it make may try to build both in parallel, which breaks the LevelDB build system in a race
$(LIBLEVELDB): $(LIBMEMENV)

$(LIBLEVELDB) $(LIBMEMENV):
	@echo "Building LevelDB ..." && $(MAKE) -C $(@D) $(@F) CXX="$(CXX)" \
	  CC="$(CC)" PLATFORM=$(TARGET_OS) AR="$(AR)" $(LEVELDB_TARGET_FLAGS) \
          OPT="$(CXXFLAGS) $(CPPFLAGS)"
endif

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

LIBYACOIN_COMMON=libyacoin_common.a

EXTRA_LIBRARIES = \
  libyacoin_common.a

LIBBITCOIN_CONSENSUS=
bin_PROGRAMS =
TESTS =
 
if BUILD_BITCOIND
  bin_PROGRAMS += yacoind
endif

BUILT_SOURCES = obj/build.h

obj/build.h:
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)

SCRYPTDEFS=-DBOOST_SPIRIT_THREADSAFE -DUSE_ASM 
SCRYPTHARDENING=-fno-stack-protector -fstack-protector-all -Wstack-protector -D_FORTIFY_SOURCE=2 -fPIC
xCXXFLAGS=-O2 -msse2 -pthread -Wall -Wextra -Wformat -Wformat-security -Wno-unused-parameter $(SCRYPTDEFS) $(SCRYPTHARDENING) -std=c++0x

# yacoind-scrypt-x86.o: scrypt-x86.S
# 	$(CXX) -c $(xCXXFLAGS) -MMD -o $@ $<

# yacoind-scrypt-x86_64.o: scrypt-x86_64.S
# 	$(CXX) -c $(xCXXFLAGS) -MMD -o $@ $<

SCRYPTDEFS+=-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA -DSCRYPT_CHOOSE_COMPILETIME
DEFS+=-DSCRYPT_KECCAK512 -DSCRYPT_CHACHA -DSCRYPT_CHOOSE_COMPILETIME

xCXXFLAGS_SCRYPT_JANE=-O3 -msse2 -pthread -Wall -Wextra -Wformat -Wformat-security -Wno-unused-parameter -DUSE_ASM $(DEBUGFLAGS) $(SCRYPTDEFS) $(SCRYPTHARDENING) 
yacoind-scrypt-jane.o: scrypt-jane/scrypt-jane.c
	gcc -c $(xCXXFLAGS_SCRYPT_JANE) -MMD -o $@ $<

libyacoin_common_a_SOURCES= \
    txdb-leveldb.cpp \
    alert.cpp \
    version.cpp \
    checkpoints.cpp \
    netbase.cpp \
    addrman.cpp \
    crypter.cpp \
    key.cpp \
    db.cpp \
    irc.cpp \
    keystore.cpp \
    kernelrecord.cpp \
    stun.cpp \
    miner.cpp \
    main.cpp \
    net.cpp \
    protocol.cpp \
    bitcoinrpc.cpp \
    price.cpp \
    random_nonce.cpp \
    rpcdump.cpp \
    rpcnet.cpp \
    rpcmining.cpp \
    rpcwallet.cpp \
    rpcblockchain.cpp \
    rpcrawtransaction.cpp \
    script.cpp \
    sync.cpp \
    util.cpp \
    wallet.cpp \
    walletdb.cpp \
    noui.cpp \
    kernel.cpp \
    pbkdf2.cpp \
    scrypt.cpp \
    scrypt-x86.S \
    scrypt-x86_64.S \
    scrypt-generic.cpp \
    scrypt-jane/scrypt-jane.c

libyacoin_common_a_CPPFLAGS = $(BITCOIN_INCLUDES)
libyacoin_common_a_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -ldl -lpthread -lrt

yacoind_SOURCES = init.cpp

yacoind_LDADD = $(LIBYACOIN_COMMON)
yacoind_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(LIBLEVELDB) $(LIBMEMENV)
yacoind_CPPFLAGS = $(BITCOIN_INCLUDES)
yacoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -ldl -lpthread -lrt

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb

clean-local:
	-$(MAKE) -C leveldb clean
	rm -f leveldb/*/*.gcno leveldb/helpers/memenv/*.gcno
	rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

# .mm.o:
# 	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
# 	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(CXXFLAGS)  -c -o $@ $<

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_TESTS
bin_PROGRAMS+=yacoin_test
yacoin_test_SOURCES= \
  test/accounting_tests.cpp \
  test/allocator_tests.cpp \
  test/base32_tests.cpp \
  test/base64_tests.cpp \
  test/bignum_tests.cpp \
  test/getarg_tests.cpp \
  test/mruset_tests.cpp \
  test/multisig_tests.cpp \
  test/rpc_tests.cpp \
  test/script_P2SH_tests.cpp \
  test/sigopcount_tests.cpp \
  test/script_tests.cpp \
  test/test_bitcoin.cpp \
  test/transaction_tests.cpp \
  test/util_tests.cpp \
  test/wallet_tests.cpp \
  test/uint160_tests.cpp \
  test/uint256_tests.cpp \
  init.cpp

# FAILING tests
#  test/miner_tests.cpp \
#  test/key_tests.cpp \
#  test/base58_tests.cpp \
#  test/netbase_tests.cpp \
#  test/Checkpoints_tests.cpp 

yacoin_test_LDADD = $(LIBYACOIN_COMMON)
yacoin_test_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(LIBLEVELDB) $(LIBMEMENV)  $(BOOST_UNIT_TEST_FRAMEWORK_LIB)
yacoin_test_CPPFLAGS = $(BITCOIN_INCLUDES) -DTESTS_ENABLED
yacoin_test_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -ldl -lpthread -lrt
endif
