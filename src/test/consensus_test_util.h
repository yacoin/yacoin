// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_CONSENSUS_TEST_UTIL_H
#define YACOIN_TEST_CONSENSUS_TEST_UTIL_H

#include "chain.h"
#include "sync.h"
#include "uint256.h"
#include "util.h"
#include "validation.h"

#include <deque>
#include <vector>

/**
 * Saves the consensus globals that init.cpp normally sets (the unit tests
 * never run init, so they start as fork height 0, epoch 21000, Nfactor 0)
 * and restores them when the test ends.
 */
struct ConsensusGlobalsGuard
{
    ::int32_t nFork = nMainnetNewLogicBlockNumber;
    ::uint32_t nEpoch = nEpochInterval;
    ::uint32_t nDifficulty = nDifficultyInterval;
    unsigned char nFactor = nFactorAtHardfork;

    // nDifficultyInterval is only copied from nEpochInterval at static init,
    // so both are set together.
    void Set(::int32_t nForkHeight, ::uint32_t nInterval)
    {
        nMainnetNewLogicBlockNumber = nForkHeight;
        nEpochInterval = nInterval;
        nDifficultyInterval = nInterval;
    }

    ~ConsensusGlobalsGuard()
    {
        nMainnetNewLogicBlockNumber = nFork;
        nEpochInterval = nEpoch;
        nDifficultyInterval = nDifficulty;
        nFactorAtHardfork = nFactor;
    }
};

/**
 * Synthetic block index entries hanging off the real genesis block of
 * TestingSetup. Must be a local of the test body: its destructor resets the
 * active chain to genesis and removes the entries it registered in
 * mapBlockIndex, before ~TestingSetup deletes everything in that map.
 * Only Register()ed blocks have a hash (phashBlock); don't call GetBlockHash()
 * on the others.
 */
class SyntheticChain
{
public:
    SyntheticChain()
    {
        LOCK(cs_main);
        m_genesis = chainActive.Genesis();
        assert(m_genesis);
    }

    ~SyntheticChain()
    {
        LOCK(cs_main);
        chainActive.SetTip(m_genesis);
        for (const uint256& hash : m_registered) {
            mapBlockIndex.erase(hash);
        }
    }

    CBlockIndex* Genesis() const { return m_genesis; }

    /** Append a block on top of pprev (nullptr = on top of genesis). */
    CBlockIndex* Add(CBlockIndex* pprev, ::int64_t nTime, unsigned int nBits, ::int64_t nMoneySupply = 0)
    {
        if (!pprev) pprev = m_genesis;
        m_blocks.emplace_back();
        CBlockIndex* pindex = &m_blocks.back();
        pindex->pprev = pprev;
        pindex->nHeight = pprev->nHeight + 1;
        pindex->nTime = nTime;
        pindex->nBits = nBits;
        pindex->nMoneySupply = nMoneySupply;
        return pindex;
    }

    /** Append n blocks spaced nSpacing seconds apart, all with nBits; returns the last. */
    CBlockIndex* Extend(CBlockIndex* pprev, int n, ::int64_t nSpacing, unsigned int nBits)
    {
        if (!pprev) pprev = m_genesis;
        for (int i = 0; i < n; i++) {
            pprev = Add(pprev, pprev->GetBlockTime() + nSpacing, nBits);
        }
        return pprev;
    }

    /** Register pindex in mapBlockIndex under a fake hash, as header sync would. */
    void Register(CBlockIndex* pindex)
    {
        LOCK(cs_main);
        uint256 hash;
        do {
            hash = uint256(0x5e5e0000 + (++m_hashCounter));
        } while (mapBlockIndex.count(hash));
        pindex->phashBlock = &mapBlockIndex.emplace(hash, pindex).first->first;
        m_registered.push_back(hash);
    }

    void SetActiveTip(CBlockIndex* pindex)
    {
        LOCK(cs_main);
        chainActive.SetTip(pindex);
    }

private:
    CBlockIndex* m_genesis;
    std::deque<CBlockIndex> m_blocks; // deque: addresses stay valid on append
    std::vector<uint256> m_registered;
    ::uint64_t m_hashCounter = 0;
};

#endif // YACOIN_TEST_CONSENSUS_TEST_UTIL_H
