# DIST_SUBDIRS = secp256k1
DIST_SUBDIRS =
AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS)


if EMBEDDED_LEVELDB
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

EXTRA_LIBRARIES =
LIBBITCOIN_CONSENSUS=
bin_PROGRAMS =
TESTS =
 
if BUILD_BITCOIND
  bin_PROGRAMS += yacoind
endif

.PHONY: FORCE

obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)

SCRYPTDEFS=-DBOOST_SPIRIT_THREADSAFE -DUSE_LEVELDB -DUSE_ASM 
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

# libbitcoin_util_a-clientversion.$(OBJEXT): obj/build.h
# yacoind: obj/build.h

yacoind_SOURCES = \
    txdb-leveldb.cpp \
    alert.cpp \
    version.cpp \
    checkpoints.cpp \
    netbase.cpp \
    addrman.cpp \
    crypter.cpp \
    key.cpp \
    db.cpp \
    init.cpp \
    irc.cpp \
    keystore.cpp \
    stun.cpp \
    miner.cpp \
    main.cpp \
    net.cpp \
    protocol.cpp \
    bitcoinrpc.cpp \
    price.cpp \
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
    scrypt-jane/scrypt-jane.c


yacoind_LDADD = $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(LIBLEVELDB) $(LIBMEMENV)
yacoind_CPPFLAGS = $(BITCOIN_INCLUDES)
yacoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -ldl -lpthread -lrt

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a *.gcda *.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb

all-local: obj/build.h
	echo hallo

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
