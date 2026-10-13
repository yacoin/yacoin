// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "pow.h"
#include "random.h"
#include "util.h"
#include "validation.h"
#include "test/consensus_test_util.h"
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
    // => lower difficulty, higher target, but the upper bound limit is powLimit
    //    (0x1e0fffff on mainnet, 00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    // => keep target
    const unsigned int nPowLimitBits = chainParams->GetConsensus().powLimit.GetCompact();
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = nPowLimitBits;

    // Retarget
    CBigNum bnNewTarget = CBigNum().SetCompact(pindexLast.nBits);
    ::int64_t nActualTimespan = pindexLast.nTime - nLastRetargetTime;
    ::int64_t nExpectedTimespan = nDifficultyInterval * chainParams->GetConsensus().nPowTargetSpacing;
    bnNewTarget *= nActualTimespan;
    bnNewTarget /= nExpectedTimespan;
    unsigned int retargetWork = bnNewTarget.GetCompact();

    unsigned int nextWork = CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus());
    BOOST_CHECK_EQUAL(nextWork, nPowLimitBits);
    BOOST_CHECK(nextWork < retargetWork);
}

/* Test the constraint on the 1/3 highest difficulty */
BOOST_AUTO_TEST_CASE(get_next_work_one_third_highest_difficulty)
{
    // Create the chain with target 0000000000000000000000000000000000000fffff0000000000000000000000
    unsigned int highestDiff = 0xe0fffff;
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    // On top of the real genesis; the destructor resets chainActive to it
    SyntheticChain chain;
    chain.SetActiveTip(chain.Extend(nullptr, 8, chainParams->GetConsensus().nPowTargetSpacing, highestDiff));

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


// nBits used by the synthetic chains below: an ordinary difficulty and a much higher one
static const unsigned int NBITS_EASY = 0x1d0fffff;
static const unsigned int NBITS_HARD = 0x1c0fffff;
static const ::int64_t SPACING = 60;

/** Compact form of target(nBits) * num / den, with the same bignum steps as pow.cpp. */
static unsigned int ScaledBits(unsigned int nBits, ::int64_t num, ::int64_t den)
{
    CBigNum bn;
    bn.SetCompact(nBits);
    bn *= num;
    bn /= den;
    return bn.GetCompact();
}

/* Blocks 1 and 2 get initialHashTarget, also after the fork; no previous block gets powLimit */
BOOST_AUTO_TEST_CASE(next_target_first_blocks)
{
    ConsensusGlobalsGuard globals;
    globals.Set(0, 10);
    SyntheticChain chain;
    const Consensus::Params& params = Params().GetConsensus();
    CBlockIndex* pindex1 = chain.Add(nullptr, chain.Genesis()->GetBlockTime() + SPACING, NBITS_EASY);

    BOOST_CHECK_EQUAL(GetNextTargetRequired(nullptr, false), params.powLimit.GetCompact());
    BOOST_CHECK_EQUAL(GetNextTargetRequired(chain.Genesis(), false), params.initialHashTarget.GetCompact());
    BOOST_CHECK_EQUAL(GetNextTargetRequired(pindex1, false), params.initialHashTarget.GetCompact());
}

/* After the fork the target only changes at epoch boundaries; the fork block itself gets powLimit */
BOOST_AUTO_TEST_CASE(next_target_constant_within_epoch)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;
    const Consensus::Params& params = Params().GetConsensus();
    CBlockIndex* pindex19 = chain.Extend(nullptr, 19, SPACING, NBITS_HARD);
    CBlockIndex* pindex = chain.Extend(pindex19, 1, SPACING, NBITS_EASY);

    // Block 20 (the fork) gets powLimit regardless of the previous difficulty
    BOOST_CHECK_EQUAL(GetNextTargetRequired(pindex19, false), params.powLimit.GetCompact());

    // Blocks 21-29 keep the previous block's nBits
    for (int nHeight = 20; nHeight <= 28; nHeight++) {
        BOOST_CHECK_EQUAL(GetNextTargetRequired(pindex, false), (unsigned int)NBITS_EASY);
        pindex = chain.Extend(pindex, 1, SPACING, NBITS_EASY);
    }
}

/* The powLimit reset only happens when the fork height is a multiple of the epoch
 * interval (mainnet: 1890000 = 90 * 21000). Otherwise the fork block keeps the
 * previous nBits. Pins current behaviour. */
BOOST_AUTO_TEST_CASE(next_target_fork_height_not_on_interval)
{
    ConsensusGlobalsGuard globals;
    globals.Set(25, 10);
    SyntheticChain chain;
    CBlockIndex* pindex24 = chain.Extend(nullptr, 24, SPACING, NBITS_EASY);
    BOOST_CHECK_EQUAL(GetNextTargetRequired(pindex24, false), (unsigned int)NBITS_EASY);
}

/* At an epoch boundary the target is retargeted over the last nDifficultyInterval blocks */
BOOST_AUTO_TEST_CASE(next_target_retargets_at_epoch_boundary)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;
    // Blocks came twice as fast as the 60 s target => target halves
    CBlockIndex* pindex19 = chain.Extend(nullptr, 19, SPACING / 2, NBITS_EASY);
    CBlockIndex* pindex29 = chain.Extend(pindex19, 10, SPACING / 2, NBITS_EASY);
    chain.SetActiveTip(pindex29);

    unsigned int nBits = GetNextTargetRequired(pindex29, false);
    BOOST_CHECK_EQUAL(nBits, ScaledBits(NBITS_EASY, 1, 2));
    BOOST_CHECK_EQUAL(nBits, CalculateNextWorkRequired(pindex29, pindex19->GetBlockTime(), Params().GetConsensus()));
}

/* Within nDifficultyInterval+1 blocks of genesis the retarget window starts at the
 * genesis block of the active chain, read from disk */
BOOST_AUTO_TEST_CASE(next_target_early_retarget_uses_genesis)
{
    ConsensusGlobalsGuard globals;
    globals.Set(5, 10);
    SyntheticChain chain;
    CBlockIndex* pindex9 = chain.Extend(nullptr, 9, SPACING, NBITS_EASY);
    chain.SetActiveTip(pindex9);

    unsigned int nBits = GetNextTargetRequired(pindex9, false);
    // 9 blocks in 540 s against a nominal 600 s
    BOOST_CHECK_EQUAL(nBits, ScaledBits(NBITS_EASY, 9 * SPACING, 10 * SPACING));
    BOOST_CHECK_EQUAL(nBits, CalculateNextWorkRequired(pindex9, chain.Genesis()->GetBlockTime(), Params().GetConsensus()));
}

/* Before the fork: ppcoin-style exponential retarget every block, capped at powLimit */
BOOST_AUTO_TEST_CASE(next_target_pre_fork_exponential)
{
    ConsensusGlobalsGuard globals;
    globals.Set(1000, 10);
    SyntheticChain chain;
    const Consensus::Params& params = Params().GetConsensus();
    CBlockIndex* pindex4 = chain.Extend(nullptr, 4, SPACING, NBITS_EASY);
    // nInterval = one week / 60 s target spacing
    const ::int64_t nInterval = 7 * 24 * 60 * 60 / SPACING;

    // Slow block (120 s): target rises
    CBlockIndex* pindexSlow = chain.Add(pindex4, pindex4->GetBlockTime() + 2 * SPACING, NBITS_EASY);
    unsigned int nSlow = GetNextTargetRequired(pindexSlow, false);
    BOOST_CHECK_EQUAL(nSlow, ScaledBits(NBITS_EASY, (nInterval - 1) * SPACING + 4 * SPACING, (nInterval + 1) * SPACING));

    // Fast block (30 s): target falls
    CBlockIndex* pindexFast = chain.Add(pindex4, pindex4->GetBlockTime() + SPACING / 2, NBITS_EASY);
    unsigned int nFast = GetNextTargetRequired(pindexFast, false);
    BOOST_CHECK_EQUAL(nFast, ScaledBits(NBITS_EASY, (nInterval - 1) * SPACING + SPACING, (nInterval + 1) * SPACING));

    CBigNum bnSlow, bnFast, bnPrev;
    bnSlow.SetCompact(nSlow);
    bnFast.SetCompact(nFast);
    bnPrev.SetCompact(NBITS_EASY);
    BOOST_CHECK(bnFast < bnPrev);
    BOOST_CHECK(bnSlow > bnPrev);

    // Already at powLimit and slow: stays at powLimit
    CBlockIndex* pindexLimit = chain.Add(pindex4, pindex4->GetBlockTime(), params.powLimit.GetCompact());
    pindexLimit = chain.Add(pindexLimit, pindexLimit->GetBlockTime() + 10 * SPACING, params.powLimit.GetCompact());
    BOOST_CHECK_EQUAL(GetNextTargetRequired(pindexLimit, false), params.powLimit.GetCompact());
}

/* The measured timespan is clamped to [nominal / 4, nominal * 4] */
BOOST_AUTO_TEST_CASE(calculate_next_work_clamps_timespan)
{
    ConsensusGlobalsGuard globals;
    // The active chain is only genesis (height 0), with no blocks at or above the
    // fork, so the difficulty floor is powLimit
    globals.Set(1, 10);
    const Consensus::Params& params = Params().GetConsensus();
    const ::int64_t nNominal = 10 * params.nPowTargetSpacing;
    CBlockIndex last;
    last.nHeight = 100;
    last.nTime = 1700000000;
    last.nBits = NBITS_EASY;

    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, last.nTime - nNominal * 10, params),
                      ScaledBits(NBITS_EASY, nNominal * 4, nNominal));
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&last, last.nTime - nNominal / 10, params),
                      ScaledBits(NBITS_EASY, nNominal / 4, nNominal));
}

/* The floor (1/3 of the highest difficulty since the fork) comes from the block's
 * own chain, ignoring blocks before the fork */
BOOST_AUTO_TEST_CASE(calculate_next_work_floor_ignores_pre_fork_blocks)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;
    CBlockIndex* pindex = chain.Extend(nullptr, 9, SPACING, NBITS_EASY);
    pindex = chain.Extend(pindex, 1, SPACING, NBITS_HARD); // height 10, before the fork
    pindex = chain.Extend(pindex, 19, SPACING, NBITS_EASY);
    chain.Register(pindex);
    chain.SetActiveTip(pindex);

    // Very slow epoch: the retarget would ease 4x, the floor stops it at 3x
    unsigned int nBits = CalculateNextWorkRequired(pindex, pindex->GetBlockTime() - 100 * 10 * SPACING, Params().GetConsensus());
    BOOST_CHECK_EQUAL(nBits, ScaledBits(NBITS_EASY, 3, 1));
}

/* Regression test for #112: during header sync the active chain lags behind, so the
 * floor must also take the highest difficulty from pindexLast's own ancestry */
BOOST_AUTO_TEST_CASE(calculate_next_work_floor_from_header_chain)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;
    CBlockIndex* pindex = chain.Extend(nullptr, 24, SPACING, NBITS_EASY);
    pindex = chain.Extend(pindex, 1, SPACING, NBITS_HARD); // height 25, after the fork
    pindex = chain.Extend(pindex, 14, SPACING, NBITS_EASY);
    chain.Register(pindex);
    // chainActive stays at genesis: headers only

    unsigned int nBits = CalculateNextWorkRequired(pindex, pindex->GetBlockTime() - 100 * 10 * SPACING, Params().GetConsensus());
    BOOST_CHECK_EQUAL(nBits, ScaledBits(NBITS_HARD, 3, 1));
    // Without the ancestry walk the floor would be powLimit and the result 4x the previous target
    BOOST_CHECK(nBits != ScaledBits(NBITS_EASY, 4, 1));
}

/* The floor also takes the active chain into account, even when pindexLast is on a
 * different branch that never had that difficulty. Pins current behaviour: the
 * required work can depend on the node's active chain, not only on the header's
 * ancestry, so two nodes with different active chains can disagree about a
 * header's required work. */
BOOST_AUTO_TEST_CASE(calculate_next_work_floor_from_active_chain_other_branch)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;
    CBlockIndex* pindexFork = chain.Extend(nullptr, 22, SPACING, NBITS_EASY);
    CBlockIndex* pindexActive = chain.Extend(pindexFork, 1, SPACING, NBITS_HARD);
    pindexActive = chain.Extend(pindexActive, 5, SPACING, NBITS_EASY);
    chain.SetActiveTip(pindexActive);
    CBlockIndex* pindexOther = chain.Extend(pindexFork, 10, SPACING, NBITS_EASY);
    chain.Register(pindexOther);

    unsigned int nBits = CalculateNextWorkRequired(pindexOther, pindexOther->GetBlockTime() - 100 * 10 * SPACING, Params().GetConsensus());
    BOOST_CHECK_EQUAL(nBits, ScaledBits(NBITS_HARD, 3, 1));
}

BOOST_AUTO_TEST_CASE(check_proof_of_work)
{
    const Consensus::Params& params = Params().GetConsensus();
    const CBlock& genesis = Params().GenesisBlock();
    BOOST_CHECK(CheckProofOfWork(genesis.GetHash(), genesis.nBits, params));
    // Same hash against a much harder target
    BOOST_CHECK(!CheckProofOfWork(genesis.GetHash(), NBITS_HARD, params));

    // A hash exactly at the target passes, one above it fails
    CBigNum bnTarget;
    bnTarget.SetCompact(NBITS_EASY);
    BOOST_CHECK(CheckProofOfWork(bnTarget.getuint256(), NBITS_EASY, params));
    BOOST_CHECK(!CheckProofOfWork((bnTarget + 1).getuint256(), NBITS_EASY, params));

    // Zero, negative and above-powLimit targets are rejected
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0, params));
    BOOST_CHECK(!CheckProofOfWork(uint256(), 0x1d8fffff, params));
    BOOST_CHECK(!CheckProofOfWork(uint256(), (params.powLimit * 2).GetCompact(), params));
}

BOOST_AUTO_TEST_SUITE_END()
