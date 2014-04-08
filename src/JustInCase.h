// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_JUSTINCASE_H
#define BITCOIN_JUSTINCASE_H

#ifdef _MSC_VER
    #define __PRETTY_FUNCTION__ __FUNCTION__
    #ifndef _DEBUG
        #include <string>
        extern void releaseModeAssertionfailure( const char* pFileName, const int nL, const std::string strFunctionName );
    #endif
#endif
#endif
