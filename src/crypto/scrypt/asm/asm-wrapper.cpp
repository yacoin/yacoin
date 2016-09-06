#include "scrypt.h"

extern "C" void scrypt_core(uint32_t *X, uint32_t *V);

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