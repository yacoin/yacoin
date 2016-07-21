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

#include "scrypt.h"
#include "pbkdf2.h"

#include "util.h"
//#include "net.h"
#include "main.h"

#define SCRYPT_BUFFER_SIZE (131072 + 63)

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


uint256 scrypt(
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
    return scrypt(input, inputlen, salt, saltlen, scratchpad);
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

unsigned int scanhash_scrypt(
                            block_header *pdata,
                            ::uint32_t max_nonce, 
                            ::uint32_t &hash_count,
                            void *result, 
                            block_header *res_header, 
                            unsigned char Nfactor
                            , CBlockIndex *pindexPrev
                            , uint256 *phashTarget
                            )
{
    hash_count = 0;
    const ::uint32_t
        nArbitraryHashCount = 70;
    block_header 
        data = *pdata;
    ::uint32_t 
        hash[8];
    unsigned char 
        *hashc = (unsigned char *) &hash;
    ::uint32_t  // really any random uint32_t
        n = (::uint32_t)GetRand( (::uint64_t)UINT_MAX );
    while (true) 
    {
        if( UINT_MAX == n ) // not allowed as a nonce
        {
            ++n;
        }
        data.nonce = n;

        scrypt(
               (const unsigned char*)&data, 
               80,
               (const unsigned char*)&data, 
               80,
               Nfactor, 
               0, 
               0, 
               (unsigned char*)hash, 
               32
              );
        ++hash_count;
        if (
            (0 == hashc[31])
            && (0 == ( 0xfc & hashc[30]))
           ) 
        {
            memcpy(result, hash, 32);
            return data.nonce;
        }
        if( 0 == (hash_count % nArbitraryHashCount) )
        {   // really we should hash for a while, then check
            if (
                (pindexPrev != pindexBest) ||
                fShutdown
               )
                break;
        }
        ++n;
    }
    return UINT_MAX;
}
