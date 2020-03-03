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

typedef struct
{
    unsigned int version;
    uint256 prev_block;
    uint256 merkle_root;
    unsigned int timestamp;
    unsigned int bits;
    unsigned int nonce;

} block_header;


uint256 scrypt_salted_multiround_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen, const unsigned int nRounds);
uint256 scrypt_salted_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen);
uint256 scrypt_hash(const void* input, size_t inputlen);
uint256 scrypt_blockhash(const ::uint8_t* input);
void *scrypt_buffer_alloc();
void scrypt_buffer_free(void *scratchpad);
unsigned int scanhash_scrypt(
                            block_header *pdata,
                            ::uint32_t &hash_count,
                            void *result, 
                            block_header *res_header, 
                            unsigned char Nfactor
                            , CBlockIndex *pindexPrev
                            , uint256 *phashTarget
                            );
void scrypt_hash(const void* input, size_t inputlen, ::uint32_t *res, unsigned char Nfactor);

#endif // SCRYPT_H


