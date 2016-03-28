// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <string>

#include "version.h"

// Name of client reported in the 'version' message. Report the same name
// for both yacoind and yacoin-qt, to make it harder for attackers to
// target servers or GUI users specifically.
const std::string 
#ifdef _MSC_VER
    CLIENT_NAME("Yacoin-WM MSVC++");
#else
    CLIENT_NAME("Yacoin-WM");
#endif

// Client version number
#ifdef USE_LEVELDB
#define CLIENT_VERSION_SUFFIX   "-leveldb"
#else
#define CLIENT_VERSION_SUFFIX   "-bdb"
#endif

// First, include build.h if requested
#ifdef HAVE_BUILD_INFO
#    include "build.h"
#endif

#define BUILD_DESC_INFO(maj,min,rev) \
    "YAC-v" DO_STRINGIZE(maj) "." DO_STRINGIZE(min) "." DO_STRINGIZE(rev)

#ifndef BUILD_DESC
#define BUILD_DESC BUILD_DESC_INFO(DISPLAY_VERSION_MAJOR, DISPLAY_VERSION_MINOR, DISPLAY_VERSION_REVISION)
#endif

#ifndef BUILD_DATE
#define BUILD_DATE __DATE__ ", " __TIME__
#endif

const std::string CLIENT_BUILD(BUILD_DESC CLIENT_VERSION_SUFFIX);
const std::string CLIENT_DATE(BUILD_DATE);
