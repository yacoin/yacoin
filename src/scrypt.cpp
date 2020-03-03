/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011 pooler, 2013 Balthazar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include <stdlib.h>

extern "C" {
#include "scrypt-jane/scrypt-jane.h"
}

#ifndef SCRYPT_H
 #include "scrypt.h"
#endif

#ifndef PBKDF2_H
 #include "pbkdf2.h"
#endif

#ifndef YACOIN_RANDOM_NONCE_H
 #include "random_nonce.h"
#endif

#ifndef BITCOIN_MAIN_H
 #include "main.h"
#endif

#define SCRYPT_BUFFER_SIZE (131072 + 63)
//                          (1<<17) + ((1<<6) -1) representing what, exactly??????

extern "C" void scrypt_core(unsigned int *X, unsigned int *V);

/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
   scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
   r = 1, p = 1, N = 1024
 */

uint256 scrypt_nosalt(const void* input, size_t inputlen, void *scratchpad)
{
    unsigned int *V;
    unsigned int X[32];
    uint256 result = 0;
    V = (unsigned int *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

    PBKDF2_SHA256((const uint8_t*)input, inputlen, (const uint8_t*)input, inputlen, 1, (uint8_t *)X, 128);
    scrypt_core(X, V);
    PBKDF2_SHA256((const uint8_t*)input, inputlen, (uint8_t *)X, 128, 1, (uint8_t*)&result, 32);

    return result;
}


static uint256 scrypt_SHA256(
                             const void* data, 
                             size_t datalen, 
                             const void* salt,
                             size_t saltlen, 
                             void *scratchpad
                            )
{
    unsigned int 
        *V;
    unsigned int 
        X[ 32 ];
    uint256 
        result = 0;

    V = (unsigned int *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

    PBKDF2_SHA256((const uint8_t*)data, datalen, (const uint8_t*)salt, saltlen, 1, (uint8_t *)X, 128);
    scrypt_core(X, V);
    PBKDF2_SHA256((const uint8_t*)data, datalen, (uint8_t *)X, 128, 1, (uint8_t*)&result, 32);

    return result;
}

uint256 scrypt_hash(const void* input, size_t inputlen)
{
    unsigned char scratchpad[SCRYPT_BUFFER_SIZE];
    return scrypt_nosalt(input, inputlen, scratchpad);
}

//YACOIN
void scrypt_hash(const void* input, size_t inputlen, ::uint32_t *res, unsigned char Nfactor)
{
    return scrypt((const unsigned char*)input, inputlen,
                  (const unsigned char*)input, inputlen,
                  Nfactor, 0, 0, (unsigned char*)res, 32);
}

uint256 scrypt_salted_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen)
{
    unsigned char scratchpad[SCRYPT_BUFFER_SIZE];
    return scrypt_SHA256(input, inputlen, salt, saltlen, scratchpad);
}

uint256 scrypt_salted_multiround_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen, const unsigned int nRounds)
{
    uint256 resultHash = scrypt_salted_hash(input, inputlen, salt, saltlen);
    uint256 transitionalHash = resultHash;

    for(unsigned int i = 1; i < nRounds; i++)
    {
        resultHash = scrypt_salted_hash(input, inputlen, (const void*)&transitionalHash, 32);
        transitionalHash = resultHash;
    }

    return resultHash;
}

uint256 scrypt_blockhash(const uint8_t* input)
{
    uint8_t scratchpad[SCRYPT_BUFFER_SIZE];
    ::uint32_t X[32];
    uint256 result = 0;

    ::uint32_t *V = (::uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

    PBKDF2_SHA256(input, 80, input, 80, 1, (uint8_t *)X, 128);
    scrypt_core(X, V);
    PBKDF2_SHA256(input, 80, (uint8_t *)X, 128, 1, (uint8_t*)&result, 32);

    return result;
}

void *scrypt_buffer_alloc() {
    return malloc(SCRYPT_BUFFER_SIZE);
}

void scrypt_buffer_free(void *scratchpad)
{
    free(scratchpad);
}

//_____________________________________________________________________________
unsigned int scanhash_scrypt(

                            block_header *pdata,
                            //::uint32_t max_nonce, 
                            ::uint32_t &hash_count,
                            void *result, 
                            block_header *res_header, 
                            unsigned char Nfactor
                            , CBlockIndex *pindexPrev
                            , uint256 *phashTarget
                            )
{
    const ::uint32_t
#ifdef _DEBUG
        nTunedTo5seconds = 15;
#else
        nTunedTo5seconds = 100;
#endif
const ::uint32_t
    NArbitraryHashCount = nTunedTo5seconds;   
                                // this is a function of the actual hps, 
                                // which will vary from cpu to cpu, etc.
                                // trying for ~5 seconds, noting that
                                // one minute is the average block period

    //hash_count = 0;
    block_header 
        data = *pdata;
    ::uint32_t 
        hash[8],
        &n = data.nonce;        // really any random uint32_t
    uint256
        nT = *phashTarget;
    unsigned char
      //hashTarget = (CBigNum().SetCompact(pdata->nBits)).getuint256(); // PoW hashTarget
        //*pTestHash = (unsigned char *)&nPoWeasiestTargetLimitTestNet,
        *hasht = (unsigned char *) &nT,
        *hashc = (unsigned char *) &hash,
      //highestZeroBitsSet = 0xe0;
        nMask = 0x00,
        highestZeroBitsSet = ~(hasht[ 31 ]),
        nMaskPattern = 0x80;

    while( 0x80 == ( 0x80 & highestZeroBitsSet) )
    {
        nMask |= nMaskPattern;
        highestZeroBitsSet <<= 1;
        nMaskPattern >>= 1;
    }

    highestZeroBitsSet <<= 1;
#ifdef Yac1dot0
    (void)printf(
                 "test mask %02x\n"
                 ""
                 , nMask
                );
#endif
    // here we should have already seeked to a random position in the file
    while (true) 
    {
        //++n;
        n = Big.get_a_nonce( n );
        //data.nonce = n;

        scrypt(
               (const unsigned char*)&data, 
               80,
               (const unsigned char*)&data, 
               80,
               Nfactor, 
               0, 
               0, 
               (unsigned char*)&hash, 
               32
              );
        ++hash_count;
        if (            
            ( 0 == ( nMask & hashc[31]))
           ) 
        {
            //memcpy(result, hash, 32);
            //return data.nonce;
            break;
        }
        if( 0 == (hash_count % NArbitraryHashCount) )
        {               // really we should hash for a while, then check
#ifdef Yac1dot0
    #ifdef _DEBUG
            (void)printf(
                         "hash count is %d\n"
                         ""
                         , hash_count
                        );
    #endif
#endif
            break;
        }
    }
    memcpy(result, hash, 32);
    return data.nonce;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
