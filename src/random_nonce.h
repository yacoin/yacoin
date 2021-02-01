// Copyright (c) 2019 The YaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef YACOIN_RANDOM_NONCE_H
#define YACOIN_RANDOM_NONCE_H

#ifdef _MSC_VER
    #include "msvc_warnings.push.h"
#endif

#include <stdint.h>
#include <stdlib.h> // for rand()

//#include <boost/filesystem.hpp>
//_____________________________________________________________________________
class CRandomNonce
{
public:
    CRandomNonce() : initialized( false ) {}
    ~CRandomNonce() {}
    ::uint32_t get_a_nonce( unsigned int & nNonceReference );
    void randomize_the_nonce( unsigned int & nNonceReference );
private:
    bool initialized;
};

extern CRandomNonce Big;
//_____________________________________________________________________________
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
#endif
