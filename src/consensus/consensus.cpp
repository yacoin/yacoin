// Copyright (c) 2024 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/consensus.h"
#include "policy/fees.h"

#include <algorithm>

//////////////////////////////////////////////////////////////////////////////
//
// CChain implementation
//
/** Efficiently check whether a block is present in this chain. */
bool CChain::Contains(const CBlockIndex *pindex) const {
    return (*this)[pindex->nHeight] == pindex;
}

/** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
CBlockIndex *CChain::Next(const CBlockIndex *pindex) const {
    if (Contains(pindex))
        return (*this)[pindex->nHeight + 1];
    else
        return NULL;
}

CBlockIndex *CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == NULL) {
        vChain.clear();
        return NULL;
    }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
    return pindex;
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);
    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->nHeight == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }
    return CBlockLocator(vHave);
}

CBlockIndex *CChain::FindFork(const CBlockLocator &locator) const {
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256& hash, locator.vHave) {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (Contains(pindex))
                return pindex;
        }
    }
    return Genesis();
}

CBlockIndex *CChain::FindFork(CBlockIndex *pindex) const {
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

::uint64_t GetMaxSize(enum GetMaxSize_mode mode)
{
    ::uint64_t nMaxSize = 0;
    if (chainActive.Genesis() == NULL || (chainActive.Tip()->nHeight + 1) < nMainnetNewLogicBlockNumber)
    {
        nMaxSize = MAX_GENESIS_BLOCK_SIZE;
    }
    else
    {
        nMaxSize = (GetProofOfWorkReward() * 1000 / MIN_TX_FEE);
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
