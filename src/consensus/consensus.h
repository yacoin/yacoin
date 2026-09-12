// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdlib.h>
#include <stdint.h>
#include <map>

enum GetMaxSize_mode
{
    MAX_BLOCK_SIZE,
    MAX_BLOCK_SIZE_GEN,
    MAX_BLOCK_SIGOPS,
};

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 1000000;
static const unsigned int MAX_GENESIS_BLOCK_SIZE = 1000000;
static const size_t MIN_TRANSACTION_WEIGHT = 68; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = 18; // 10 is the lower bound for the size of a serialized CTransaction
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY_AFTER_HARDFORK = 6;
static const int COINBASE_MATURITY_BEFORE_HARDFORK = 500;  // 500 blocks, 1 blk/minute => ~8.33 hrs

extern ::uint64_t GetMaxSize(enum GetMaxSize_mode mode, unsigned int nHeight = 0);
extern ::int64_t GetProofOfWorkReward(unsigned int nBits=0, ::int64_t nFees=0, unsigned int nHeight=0);
/**
 * Get minimum confirmations to use coinbase
 */
int GetCoinbaseMaturity();

/**
 * Get an extra confirmations to add coinbase to balance
 */
int GetCoinbaseMaturityOffset();

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
