// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// 0.4.9.02     8/27/2018 reordered CProvider aBTCtoYACProviders[] in price.cpp
// 0.4.9.03     9/14/2018 allowed testnet solo mining
// 0.4.9.04     9/28/2018 changed fUseOld044Rules to true for testnet testing of old code

#include <string>

#ifndef BITCOIN_VERSION_H
 #include "version.h"
#endif

#define DISPLAY_VERSION_MAJOR       0
#define DISPLAY_VERSION_MINOR       5
#define DISPLAY_VERSION_REVISION    7
                                    // 4 for new versioning to be more aligned with btc standards
                                    // 5 for #define DEBUG_LOCKORDER
                                    // 5 for #define DEBUG_LOCKORDER
                                    // 6     20160 block length
#define DISPLAY_VERSION_BUILD       2
#define DISPLAY_VERSION_TESTING     01

const int
    DISPLAY_VERSION_MAJOR_for_Qt    = DISPLAY_VERSION_MAJOR   ,
    DISPLAY_VERSION_MINOR_for_Qt    = DISPLAY_VERSION_MINOR   ,
    DISPLAY_VERSION_REVISION_for_Qt = DISPLAY_VERSION_REVISION,
    DISPLAY_VERSION_BUILD_for_Qt    = DISPLAY_VERSION_BUILD   ,
    DISPLAY_VERSION_TESTING_for_Qt  = DISPLAY_VERSION_TESTING ;

//Set to 1 for Testing Version  But it is set to 1?
//#define DISPLAY_VERSION_TESTING     1

// Name of client reported in the 'version' message. Report the same name
// for both yacoind and yacoin-qt, to make it harder for attackers to
// target servers or GUI users specifically.

// this is a TestNet only version
const std::string 
    #ifdef QT_GUI
        #ifdef _MSC_VER
            CLIENT_NAME("Yacoin-WM MSVC++ Qt");
        #else
            CLIENT_NAME("Yacoin-WM Qt");
        #endif
    #else
        #ifdef _MSC_VER
            CLIENT_NAME("Yacoin-WM MSVC++ daemon");
        #else
            CLIENT_NAME("Yacoin-WM daemon");
        #endif
    #endif
//    #ifdef _MSC_VER
//        CLIENT_NAME("Yacoin-WM MSVC++");
//    #else
//        CLIENT_NAME("Yacoin-WM");
//    #endif
//}
// Client version number
#ifdef USE_LEVELDB
#ifdef LOW_DIFFICULTY_FOR_DEVELOPMENT
#define CLIENT_VERSION_SUFFIX   "-leveldb-low-difficulty"
#else
#define CLIENT_VERSION_SUFFIX   "-leveldb"
#endif
#else
#define CLIENT_VERSION_SUFFIX   "-bdb"
#endif

// First, include build.h if requested
#ifdef HAVE_BUILD_INFO
#    include "build.h"
#endif

//#define BUILD_DESC_INFO(maj,min,rev) 
//  "YAC-v" DO_STRINGIZE(maj) "." DO_STRINGIZE(min) "." DO_STRINGIZE(rev)
//    DO_STRINGIZE(maj) 

#define BUILD_DESC_INFO(maj,min,rev,build) \
    "YAC-v" \
    DO_STRINGIZE(maj) \
    "." \
    DO_STRINGIZE(min) \
    "." \
    DO_STRINGIZE(rev) \
    "." \
    DO_STRINGIZE(build)

#ifndef BUILD_DESC
#define BUILD_DESC BUILD_DESC_INFO(DISPLAY_VERSION_MAJOR, DISPLAY_VERSION_MINOR, DISPLAY_VERSION_REVISION,DISPLAY_VERSION_BUILD)
#endif

#ifndef BUILD_DATE
#define BUILD_DATE __DATE__ ", " __TIME__
#endif

const std::string CLIENT_BUILD(BUILD_DESC CLIENT_VERSION_SUFFIX);
const std::string CLIENT_DATE(BUILD_DATE);
