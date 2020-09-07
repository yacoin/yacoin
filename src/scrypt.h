#ifndef SCRYPT_H
#define SCRYPT_H

#include <stdint.h>
#include <stdlib.h>

#ifndef BITCOIN_UTIL_H
 #include "util.h"
#endif

#ifndef BITCOIN_NET_H
 #include "net.h"
#endif

#pragma pack(push, 1)
struct block_header
{
    unsigned int version;
    uint256 prev_block;
    uint256 merkle_root;
    ::int64_t timestamp;
    unsigned int bits;
    unsigned int nonce;

};
#pragma pack(pop)

typedef struct
{
    unsigned int version;
    uint256 prev_block;
    uint256 merkle_root;
    unsigned int timestamp;
    unsigned int bits;
    unsigned int nonce;

} old_block_header;

uint256 scrypt_salted_multiround_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen, const unsigned int nRounds);
uint256 scrypt_salted_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen);
uint256 scrypt_hash(const void* input, size_t inputlen);
uint256 scrypt_blockhash(const ::uint8_t* input);
void *scrypt_buffer_alloc();
void scrypt_buffer_free(void *scratchpad);
unsigned int scanhash_scrypt(
                            char *pdata,
                            ::uint32_t &hash_count,
                            void *result, 
                            unsigned char Nfactor
                            , CBlockIndex *pindexPrev
                            , uint256 *phashTarget
                            );
void scrypt_hash(const void* input, size_t inputlen, ::uint32_t *res, unsigned char Nfactor);

#endif // SCRYPT_H


