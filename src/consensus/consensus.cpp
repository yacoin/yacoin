// Copyright (c) 2024 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <algorithm>

#include "consensus/consensus.h"
#include "policy/fees.h"
#include "../validation.h"
#include "chain.h"



/* yac: The maximum block size increases based on the block reward, which is
 * influenced by the money supply. After each epoch interval, both the block
 * reward and the maximum block size are adjusted.
 * TODO: It is necessary to review all instances where this function is called
 * to ensure the correct block height is passed, allowing for an accurate
 * calculation of the maximum block size.
 */
::uint64_t GetMaxSize(enum GetMaxSize_mode mode, unsigned int nHeight)
{
    ::uint64_t nMaxSize = 0;
    unsigned int blockHeight = nHeight ? nHeight : chainActive.Genesis() ? chainActive.Tip()->nHeight + 1 : 0;

    // New logic since hardfork
    if (blockHeight >= nMainnetNewLogicBlockNumber) {
        nMaxSize = (GetProofOfWorkReward(0, 0, blockHeight) * 1000 / MIN_TX_FEE);
    } else {
        nMaxSize = MAX_GENESIS_BLOCK_SIZE;
    }

    switch (mode)
    {
        case MAX_BLOCK_SIZE_GEN:
            nMaxSize /= 2;
            break;

        case MAX_BLOCK_SIGOPS:
            nMaxSize = std::max(nMaxSize, (::uint64_t)MAX_GENESIS_BLOCK_SIZE) / 50;
            break;

        case MAX_BLOCK_SIZE:
        default:
            break;
    }
    return nMaxSize;
}

int GetCoinbaseMaturity()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
    {
        return COINBASE_MATURITY_AFTER_HARDFORK;
    }
    else
    {
        return COINBASE_MATURITY_BEFORE_HARDFORK;
    }
}

int GetCoinbaseMaturityOffset()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
    {
        return 0;
    }
    else
    {
        return 20;
    }
}
