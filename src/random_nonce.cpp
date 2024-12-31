// Copyright (c) 2019 The YaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include "msvc_warnings.push.h"
#endif

#include <stdint.h>
#include <stdlib.h> // for rand()
#include <stdio.h>  // for fclose()
#include "util.h"   // for gArgs.GetArg()(

//#include <boost/filesystem.hpp>

#ifndef YACOIN_RANDOM_NONCE_H
#include "random_nonce.h"
#endif

CRandomNonce Big;
//_____________________________________________________________________________
static ::uint32_t
    get_a_random_16bit_nonce( void )
{
    ::uint32_t
        value;

    value = ( rand() & 0x00007fff )
            |
            (
             ( ( rand() & 0x0001 ) ? 0x8000 : 0x0000 )
            );
    return value;
}
//_____________________________________________________________________________
static ::uint32_t
    get_a_random_32bit_value( void )
{
    ::uint32_t
        value;

    // for RAND_MAX = (0, 0x7fff), then 2nd 0x8000 | (0,0x7fff) gives (0, 0xffff)
    // for RAND_MAX = (0, 0x7fff), then 3rd 0x8000 | (0,0x7fff) gives (0, 0xffff)

    value =
        get_a_random_16bit_nonce( )
        |
        ( get_a_random_16bit_nonce( ) << 16 );

    return value;
}

//_____________________________________________________________________________
::uint32_t
    CRandomNonce::get_a_nonce( unsigned int & nNonceReference )
{
    return (0 == ++nNonceReference)? ++nNonceReference: nNonceReference;
}
//_____________________________________________________________________________
void
    CRandomNonce::randomize_the_nonce( unsigned int & nNonceReference )
{
    ::uint32_t
        n32value;

    // perform lazy initialization here
    if( !initialized )
    {
        initialized = true;
        // do any initialization here
    }
    srand( ( unsigned int )time( NULL ) );
    // can comment this out to get repeating random sequence

    // and can put our own test valuess below also to test
    n32value = get_a_random_32bit_value();
    nNonceReference = n32value;
}
//_____________________________________________________________________________
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
