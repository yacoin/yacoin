// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "pow.h"
#include "random.h"
#include "util.h"
#include "validation.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, TestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    // Yacoin expected spacing: 1260000
    // Actual spacing: 1022578
    // => higher difficulty, lower target
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1e0fffff;

    // Retarget
    CBigNum bnNewTarget = CBigNum().SetCompact(pindexLast.nBits);
    ::int64_t nActualTimespan = pindexLast.nTime - nLastRetargetTime;
    ::int64_t nExpectedTimespan = nDifficultyInterval * chainParams->GetConsensus().nPowTargetSpacing;
    bnNewTarget *= nActualTimespan;
    bnNewTarget /= nExpectedTimespan;
    unsigned int retargetWork = bnNewTarget.GetCompact();

    unsigned int nextWork = CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus());
    BOOST_CHECK_EQUAL(nextWork, 0x1E0CFC2F);
    BOOST_CHECK(nextWork == retargetWork);
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    // Yacoin expected spacing: 1260000
    // Actual spacing: 2055491
    // => lower difficulty, higher target, but the upper bound limit is 0x1e0fffff (00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    // => keep target
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1e0fffff;

    // Retarget
    CBigNum bnNewTarget = CBigNum().SetCompact(pindexLast.nBits);
    ::int64_t nActualTimespan = pindexLast.nTime - nLastRetargetTime;
    ::int64_t nExpectedTimespan = nDifficultyInterval * chainParams->GetConsensus().nPowTargetSpacing;
    bnNewTarget *= nActualTimespan;
    bnNewTarget /= nExpectedTimespan;
    unsigned int retargetWork = bnNewTarget.GetCompact();

    unsigned int nextWork = CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus());
    BOOST_CHECK_EQUAL(nextWork, 0x1e0fffff);
    BOOST_CHECK(nextWork < retargetWork);
}

/* Test the constraint on the 1/3 highest difficulty */
BOOST_AUTO_TEST_CASE(get_next_work_one_third_highest_difficulty)
{
    // Create the chain with target 0000000000000000000000000000000000000fffff0000000000000000000000
    unsigned int highestDiff = 0xe0fffff;
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 9; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = highestDiff;
        blocks[i].bnChainTrust = i ? blocks[i - 1].bnChainTrust + blocks[i].GetBlockTrust() : 0;
    }
    chainActive.SetTip(&blocks[8]);

    // Yacoin expected spacing: 1260000
    // Actual spacing: 5040000
    // => lower difficulty, higher target, but the upper bound limit is 1/3 highest difficulty (0xe2ffffd)
    // => keep target
    int64_t nLastRetargetTime = 1269211443; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1274251443;  // Block #2015
    pindexLast.nBits = highestDiff;

    // Retarget
    CBigNum bnNewTarget = CBigNum().SetCompact(pindexLast.nBits);
    ::int64_t nActualTimespan = pindexLast.nTime - nLastRetargetTime;
    ::int64_t nExpectedTimespan = nDifficultyInterval * chainParams->GetConsensus().nPowTargetSpacing;
    bnNewTarget *= nActualTimespan;
    bnNewTarget /= nExpectedTimespan;
    unsigned int retargetWork = bnNewTarget.GetCompact();

    // Maximum target corresponding to 1/3 highest difficulty
    CBigNum bnMaximumTarget = CBigNum().SetCompact(highestDiff);
    bnMaximumTarget *= 3;
    unsigned int maximumWork = bnMaximumTarget.GetCompact();

    unsigned int nextWork = CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus());
    BOOST_CHECK_EQUAL(nextWork, 0xe2ffffd);
    BOOST_CHECK_EQUAL(nextWork, maximumWork);
    BOOST_CHECK(nextWork < retargetWork);
}

BOOST_AUTO_TEST_SUITE_END()
