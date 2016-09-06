/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2012-2013 pooler
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

#include <emmintrin.h>
#include "scrypt.h"

static inline uint32_t le32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;
    return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}

static inline void le32enc(void *pp, uint32_t x)
{
    uint8_t *p = (uint8_t *)pp;
    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}

static inline void xor_salsa8_sse2(__m128i B[4], const __m128i Bx[4])
{
    __m128i X0 = B[0] = _mm_xor_si128(B[0], Bx[0]);
    __m128i X1 = B[1] = _mm_xor_si128(B[1], Bx[1]);
    __m128i X2 = B[2] = _mm_xor_si128(B[2], Bx[2]);
    __m128i X3 = B[3] = _mm_xor_si128(B[3], Bx[3]);

    for (uint32_t i = 0; i < 8; i += 2) {
        /* Operate on "columns". */
        __m128i T = _mm_add_epi32(X0, X3);
        X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 7));
        X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 25));
        T = _mm_add_epi32(X1, X0);
        X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
        X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
        T = _mm_add_epi32(X2, X1);
        X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 13));
        X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 19));
        T = _mm_add_epi32(X3, X2);
        X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
        X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));

        /* Rearrange data. */
        X1 = _mm_shuffle_epi32(X1, 0x93);
        X2 = _mm_shuffle_epi32(X2, 0x4E);
        X3 = _mm_shuffle_epi32(X3, 0x39);

        /* Operate on "rows". */
        T = _mm_add_epi32(X0, X1);
        X3 = _mm_xor_si128(X3, _mm_slli_epi32(T, 7));
        X3 = _mm_xor_si128(X3, _mm_srli_epi32(T, 25));
        T = _mm_add_epi32(X3, X0);
        X2 = _mm_xor_si128(X2, _mm_slli_epi32(T, 9));
        X2 = _mm_xor_si128(X2, _mm_srli_epi32(T, 23));
        T = _mm_add_epi32(X2, X3);
        X1 = _mm_xor_si128(X1, _mm_slli_epi32(T, 13));
        X1 = _mm_xor_si128(X1, _mm_srli_epi32(T, 19));
        T = _mm_add_epi32(X1, X2);
        X0 = _mm_xor_si128(X0, _mm_slli_epi32(T, 18));
        X0 = _mm_xor_si128(X0, _mm_srli_epi32(T, 14));

        /* Rearrange data. */
        X1 = _mm_shuffle_epi32(X1, 0x39);
        X2 = _mm_shuffle_epi32(X2, 0x4E);
        X3 = _mm_shuffle_epi32(X3, 0x93);
    }

    B[0] = _mm_add_epi32(B[0], X0);
    B[1] = _mm_add_epi32(B[1], X1);
    B[2] = _mm_add_epi32(B[2], X2);
    B[3] = _mm_add_epi32(B[3], X3);
}

//YACOIN
void scrypt_hash(const void* input, size_t inputlen, ::uint32_t *res, unsigned char Nfactor)
{
    return scrypt((const unsigned char*)input, inputlen,
                  (const unsigned char*)input, inputlen,
                  Nfactor, 0, 0, (unsigned char*)res, 32);
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