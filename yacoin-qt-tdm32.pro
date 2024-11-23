TEMPLATE = app
TARGET = yacoin-qt
VERSION = 0.4.5
INCLUDEPATH += src src/json src/qt
QT += core gui network
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
DEFINES += QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE __STDC_FORMAT_MACROS WIN32 Yac1dot0
CONFIG += no_include_pwd
CONFIG += thread
CONFIG += static
CONFIG += release
CONFIG += warn_off

BOOST_INCLUDE_PATH =../../sw/boost_1_58_0/include
BOOST_LIB_PATH     =../../sw/boost_1_58_0/lib

BDB_INCLUDE_PATH =../../sw/db-4.8.30.NC/include
BDB_LIB_PATH     =../../sw/db-4.8.30.NC/lib

OPENSSL_INCLUDE_PATH =../../sw/openssl-1.0.1u/include
OPENSSL_LIB_PATH     =../../sw/openssl-1.0.1u/lib

MINIUPNPC_INCLUDE_PATH =../../sw/miniupnpc-1.9.20150206/include
MINIUPNPC_LIB_PATH     =../../sw/miniupnpc-1.9.20150206/lib

QRENCODE_INCLUDE_PATH =../../sw/qrencode-3.4.4/include
QRENCODE_LIB_PATH     =../../sw/qrencode-3.4.4/lib

YQT=../../sw/qt-everywhere-opensource-src-4.8.6

DEL_FILE = rm
OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build
LIBS += -Wl,-Bstatic

QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat -Wl,--large-address-aware

# regenerate build.h
contains(USE_BUILD_INFO, 1) {
    genbuild.depends = FORCE
    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh build/build.h
    genbuild.target = build/build.h
    PRE_TARGETDEPS += build/build.h
    QMAKE_EXTRA_TARGETS += genbuild
    DEFINES += HAVE_BUILD_INFO
}

# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
contains(USE_UPNP, -) {
    message(Building without UPNP support)
} else {
    message(Building with UPNP support)
    count(USE_UPNP, 0) {
        USE_UPNP=1
    }
    DEFINES += USE_UPNP=$$USE_UPNP STATICLIB MINIUPNP_STATICLIB
    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
    win32:LIBS += -liphlpapi
}

# use: qmake "USE_IPV6=1" ( enabled by default; default)
#  or: qmake "USE_IPV6=0" (disabled by default)
#  or: qmake "USE_IPV6=-" (not supported)
contains(USE_IPV6, -) {
    message(Building without IPv6 support)
} else {
    count(USE_IPV6, 0) {
        USE_IPV6=1
    }
    DEFINES += USE_IPV6=$$USE_IPV6
}

contains(USE_ASM, 1) {
    message(Using optimized scrypt core implementation)
    SOURCES += src/scrypt-arm.S src/scrypt-x86.S src/scrypt-x86_64.S
    DEFINES += USE_ASM
} else {
    message(Using generic scrypt core implementation)
    SOURCES += src/scrypt-generic.cpp
}

# use: qmake "USE_QRCODE=1" ( enabled by default; default)
#  or: qmake "USE_QRCODE=0" (not supported)
contains(USE_QRCODE, 1) {
    message(Building with QrEncode support)
    DEFINES += USE_QRCODE=$$USE_QRCODE STATICLIB QRMINIUPNP_STATICLIB
    INCLUDEPATH += $$QRENCODE_INCLUDE_PATH
    LIBS += $$join(QRENCODE_LIB_PATH,,-L,) -lqrencode
    win32:LIBS += -liphlpapi
} else {
    message(Building without QrEncode support)    
}

#if you start with an empty build directory, you must delete../yacoin/.genjane or
#scrypt_jane won't be built, spoiling the make
#
#I don't know how to invoke QMAKE_CLEAN below, or if it works???  Not how to test it?????
#
genjane.target = .genjane
genjane.commands = touch .genjane; gcc -c -O3 -DSCRYPT_CHACHA -DSCRYPT_KECCAK512 -DSCRYPT_CHOOSE_COMPILETIME -o $$OBJECTS_DIR/scrypt-jane.o src/scrypt-jane/scrypt-jane.c
LIBS += $$OBJECTS_DIR/scrypt-jane.o
PRE_TARGETDEPS += .genjane
QMAKE_EXTRA_TARGETS += genjane
QMAKE_CLEAN += .genjane


message(Building with LevelDB transaction index)
DEFINES += USE_LEVELDB
INCLUDEPATH += src/leveldb/include src/leveldb/helpers
LIBS += $$PWD/src/leveldb/libleveldb.a $$PWD/src/leveldb/libmemenv.a
SOURCES += src/txdb-leveldb.cpp
genleveldb.target = .genleveldb
genleveldb.commands = touch .genleveldb; cd src/leveldb && { make clean; TARGET_OS=NATIVE_WINDOWS OPT=\"-msse2\" make libleveldb.a libmemenv.a; }
PRE_TARGETDEPS += .genleveldb
QMAKE_EXTRA_TARGETS += genleveldb
QMAKE_CLEAN += .genleveldb

genleveldb.commands = touch .genleveldb; cd src/leveldb && { make clean; TARGET_OS=NATIVE_WINDOWS OPT=\"-std=gnu++0x -msse2\" make libleveldb.a libmemenv.a; }

genminiupnpc.target = src/miniupnpc/miniupnpc.h
genminiupnpc.commands = mkdir -p src/miniupnpc; cp $$MINIUPNPC_INCLUDE_PATH/*.h src/miniupnpc
PRE_TARGETDEPS += src/miniupnpc/miniupnpc.h
QMAKE_EXTRA_TARGETS += genminiupnpc


QMAKE_CXXFLAGS += -O2 -msse2
QMAKE_CFLAGS += -O2 -msse2

# Input
DEPENDPATH += src src/json src/qt
HEADERS += \
    src/qt/bitcoingui.h \
    src/qt/transactiontablemodel.h \
    src/qt/addresstablemodel.h \
    src/qt/optionsdialog.h \
    src/qt/coincontroldialog.h \
    src/qt/coincontroltreewidget.h \
    src/qt/sendcoinsdialog.h \
    src/qt/addressbookpage.h \
    src/qt/signverifymessagedialog.h \
    src/qt/aboutdialog.h \
    src/qt/editaddressdialog.h \
    src/qt/bitcoinaddressvalidator.h \
    src/qt/mintingfilterproxy.h \
    src/qt/mintingtablemodel.h \
    src/qt/mintingview.h \
    src/kernelrecord.h \
    src/alert.h \
    src/addrdb.h \
    src/addrman.h \
    src/addressindex.h \
    src/base58.h \
    src/bignum.h \
    src/checkpoints.h \
    src/compat.h \
    src/coincontrol.h \
    src/coins.h \
    src/indirectmap.h \
    src/LibBoolEE.h \
    src/sync.h \
    src/util.h \
    src/utilstrencodings.h \
    src/utiltime.h \
    src/netaddress.h \
    src/timedata.h \
    src/warnings.h \
    src/timestamps.h \
    src/hash.h \
    src/uint256.h \
    src/kernel.h \
    src/scrypt.h \
    src/pbkdf2.h \
    src/prevector.h \
    src/serialize.h \
    src/strlcpy.h \
    src/main.h \
    src/memusage.h \
    src/miner.h \
    src/random_nonce.h \
    src/net.h \
    src/ministun.h \
    src/key.h \
    src/db.h \
    src/dbwrapper.h \
    src/txdb.h \
    src/tinyformat.h \
    src/walletdb.h \
    src/script/script.h \
    src/init.h \
    src/irc.h \
    src/mruset.h \
    src/compat/endian.h \
    src/compat/byteswap.h \
    src/json/json_spirit_writer_template.h \
    src/json/json_spirit_writer.h \
    src/json/json_spirit_value.h \
    src/json/json_spirit_utils.h \
    src/json/json_spirit_stream_reader.h \
    src/json/json_spirit_reader_template.h \
    src/json/json_spirit_reader.h \
    src/json/json_spirit_error_position.h \
    src/json/json_spirit.h \
    src/qt/clientmodel.h \
    src/qt/guiutil.h \
    src/qt/transactionrecord.h \
    src/qt/guiconstants.h \
    src/qt/optionsmodel.h \
    src/qt/monitoreddatamapper.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/bitcoinamountfield.h \
    src/wallet.h \
    src/keystore.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionview.h \
    src/qt/walletmodel.h \
    src/bitcoinrpc.h \
    src/qt/overviewpage.h \
    src/qt/explorer.h \	
    src/qt/csvmodelwriter.h \
    src/crypter.h \
    src/qt/sendcoinsentry.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/bitcoinunits.h \
    src/qt/qvaluecombobox.h \
    src/qt/askpassphrasedialog.h \
    src/qt/trafficgraphwidget.h \
    src/protocol.h \
    src/qt/notificator.h \
    src/qt/qtipcserver.h \
    src/allocators.h \
    src/ui_interface.h \
    src/qt/rpcconsole.h \
    src/version.h \
    src/netbase.h \
    src/clientversion.h \
    src/scrypt-jane/scrypt-jane.h \
    src/qt/multisigaddressentry.h \
    src/qt/multisiginputentry.h \
    src/qt/multisigdialog.h

#    src/txdb-leveldb.cpp \
#    src/txdb-bdb.cpp \

SOURCES += src/qt/bitcoin.cpp src/qt/bitcoingui.cpp \
    src/qt/transactiontablemodel.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/coincontroldialog.cpp \
    src/qt/coincontroltreewidget.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/aboutdialog.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/bitcoinaddressvalidator.cpp \
    src/qt/trafficgraphwidget.cpp \
    src/qt/mintingfilterproxy.cpp \
    src/qt/mintingtablemodel.cpp \
    src/qt/mintingview.cpp \
    src/kernelrecord.cpp \
    src/alert.cpp \
    src/addrdb.cpp \
    src/hash.cpp \
    src/base58.cpp \
    src/version.cpp \
    src/sync.cpp \
    src/util.cpp \
    src/utilstrencodings.cpp \
    src/utiltime.cpp \
    src/netaddress.cpp \
    src/timedata.cpp \
    src/warnings.cpp \
    src/netbase.cpp \
    src/key.cpp \
    src/LibBoolEE.cpp \
    src/script/script.cpp \
    src/main.cpp \
    src/miner.cpp \
    src/init.cpp \
    src/net.cpp \
    src/price.cpp \
    src/random_nonce.cpp \
    src/stun.cpp \
    src/irc.cpp \
    src/checkpoints.cpp \
    src/addrman.cpp \
    src/db.cpp \
    src/fs.cpp \
    src/validationinterface.cpp \
    src/scheduler.cpp \
    src/random.cpp \
    src/dbwrapper.cpp \
    src/walletdb.cpp \
    src/txmempool.cpp \
    src/tokens/tokentypes.cpp \
    src/tokens/tokendb.cpp \
    src/tokens/tokens.cpp \
    src/primitives/transaction.cpp \
    src/primitives/block.cpp \
    src/policy/feerate.cpp \
    src/policy/fees.cpp \
    src/crypto/siphash.cpp \
    src/crypto/chacha20.cpp \
    src/crypto/sha256.cpp \
    src/crypto/sha512.cpp \
    src/crypto/ripemd160.cpp \
    src/crypto/hmac_sha512.cpp \
    src/compat/strnlen.cpp \
    src/support/cleanse.cpp \
    src/qt/clientmodel.cpp \
    src/qt/guiutil.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/monitoreddatamapper.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/bitcoinstrings.cpp \
    src/qt/bitcoinamountfield.cpp \
    src/wallet.cpp \
    src/keystore.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionview.cpp \
    src/qt/walletmodel.cpp \
    src/bitcoinrpc.cpp \
    src/rpctokens.cpp \
    src/rpcdump.cpp \
    src/rpcnet.cpp \
    src/rpcmining.cpp \
    src/rpcmisc.cpp \
    src/rpcwallet.cpp \
    src/rpcblockchain.cpp \
    src/rpcrawtransaction.cpp \
    src/qt/overviewpage.cpp \
   	src/qt/explorer.cpp \	
    src/qt/csvmodelwriter.cpp \
    src/crypter.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/bitcoinunits.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/protocol.cpp \
    src/qt/notificator.cpp \
    src/qt/qtipcserver.cpp \
    src/qt/rpcconsole.cpp \
    src/noui.cpp \
    src/kernel.cpp \
    src/scrypt.cpp \
    src/pbkdf2.cpp \
    src/qt/multisigaddressentry.cpp \
    src/qt/multisiginputentry.cpp \
    src/qt/multisigdialog.cpp
#	 src/scrypt-jane/scrypt-jane.c

RESOURCES += \
    src/qt/bitcoin.qrc

FORMS += \
    src/qt/forms/coincontroldialog.ui \
    src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/aboutdialog.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/transactiondescdialog.ui \
    src/qt/forms/overviewpage.ui \
   	src/qt/forms/explorer.ui \
	src/qt/forms/explorerBlockPage.ui \
	src/qt/forms/explorerTransactionPage.ui \	
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/askpassphrasedialog.ui \
    src/qt/forms/rpcconsole.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/multisigaddressentry.ui \
    src/qt/forms/multisiginputentry.ui \
    src/qt/forms/multisigdialog.ui

contains(USE_QRCODE, 1) {
DEFINES += USE_QRCODE
HEADERS += src/qt/qrcodedialog.h
SOURCES += src/qt/qrcodedialog.cpp
FORMS += src/qt/forms/qrcodedialog.ui
}

CODECFORTR = UTF-8

# for lrelease/lupdate
# also add new translations to src/qt/bitcoin.qrc under translations/
TRANSLATIONS = $$files(src/qt/locale/bitcoin_*.ts)

isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale
# automatically build translations, so they can be included in resource file
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# "Other files" to show in Qt Creator
OTHER_FILES += \
    doc/*.rst doc/*.txt doc/README README.md res/yacoin-qt.rc src/test/*.cpp src/test/*.h src/qt/test/*.cpp src/qt/test/*.h

windows:RC_FILE = src/qt/res/bitcoin-qt.rc

# Set libraries and includes at end, to use platform-defined defaults if not overridden
INCLUDEPATH += \
	$$BOOST_INCLUDE_PATH \
	$$BDB_INCLUDE_PATH \
	$$OPENSSL_INCLUDE_PATH \
	$$QRENCODE_INCLUDE_PATH
LIBS += \
	$$join(BOOST_LIB_PATH,,-L,) \
	$$join(BDB_LIB_PATH,,-L,) \
	$$join(OPENSSL_LIB_PATH,,-L,) \
	$$join(QRENCODE_LIB_PATH,,-L,)
LIBS += -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX -lqrencode
# -lgdi32 has to happen after -lcrypto (see  #681)
windows:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
LIBS += -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread
windows:LIBS += -lboost_chrono -Wl,-Bstatic -lpthread


#system($$QMAKE_LRELEASE -silent $$PWD/src/qt/locale/translations.pro)
