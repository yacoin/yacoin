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

class CBlockIndex;

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
bool scrypt_hash(const void* input, size_t inputlen, ::uint32_t *res, unsigned char Nfactor);

#endif // SCRYPT_H


