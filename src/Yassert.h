// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef YACOIN_YASSERT_H
#define YACOIN_YASSERT_H

#include <string>

extern void releaseModeAssertionfailure( 
                                        const char* pFileName, 
                                        const int nL, 
                                        const std::string strFunctionName, 
                                        const char * booleanExpression 
                                       );
#ifndef _DEBUG
    #define Yassert(bExpression) \
    if( !(bExpression) )\
        releaseModeAssertionfailure( __FILE__, __LINE__, __FUNCTION__, #bExpression )
#else
    #define Yassert(bExpression) \
    assert(bExpression)
#endif

#endif
