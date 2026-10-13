// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/consensus.h"
#include "main.h"
#include "net.h"
#include "policy/fees.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

/** Pre-fork reward for a target powLimit / nDivisor */
static ::int64_t PreForkReward(unsigned int nDivisor, ::int64_t nFees = 0)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(Params().GetConsensus().powLimit.GetCompact());
    bnTarget /= nDivisor;
    return GetProofOfWorkReward(bnTarget.GetCompact(), nFees, 1);
}

/** Post-fork reward from a money supply, with the same expression as validation.cpp */
static ::int64_t EpochReward(::int64_t nMoneySupply)
{
    return nMoneySupply * nInflation / nNumberOfBlocksPerYear;
}

static ::int64_t MoneySupplyAt(int nHeight)
{
    return 100000000 * COIN + (::int64_t)nHeight * 1000 * COIN;
}

/** Synthetic chain up to nTipHeight with a known nMoneySupply per height, set as active chain */
static CBlockIndex* BuildSupplyChain(SyntheticChain& chain, int nTipHeight)
{
    CBlockIndex* pindex = chain.Genesis();
    for (int nHeight = 1; nHeight <= nTipHeight; nHeight++) {
        pindex = chain.Add(pindex, pindex->GetBlockTime() + 60, 0x1d0fffff, MoneySupplyAt(nHeight));
    }
    chain.SetActiveTip(pindex);
    return pindex;
}

BOOST_AUTO_TEST_CASE(blocks_per_year)
{
    // 365.25 days of one-minute blocks
    BOOST_CHECK_EQUAL(nNumberOfBlocksPerYear, 525960U);
}

/* Before the fork: 100 YAC at minimum difficulty, halving every 64x difficulty, plus fees */
BOOST_AUTO_TEST_CASE(pre_fork_reward)
{
    ConsensusGlobalsGuard globals;
    globals.Set(1000, 10);

    BOOST_CHECK_EQUAL(PreForkReward(1), MAX_MINT_PROOF_OF_WORK);
    BOOST_CHECK_EQUAL(MAX_MINT_PROOF_OF_WORK, 100 * COIN);
    BOOST_CHECK_EQUAL(PreForkReward(64), 50 * COIN);
    BOOST_CHECK_EQUAL(PreForkReward(64 * 64 * 64 * 64), 625 * CENT);
    BOOST_CHECK_EQUAL(PreForkReward(64, 3 * CENT), 50 * COIN + 3 * CENT);

    // Target 0 bottoms out at the 0.01 YAC search floor
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 1), CENT);

    // Rounded down to whole cents, never rising with difficulty
    ::int64_t nPrevious = MAX_MINT_PROOF_OF_WORK;
    for (unsigned int nShift = 0; nShift < 32; nShift++) {
        ::int64_t nReward = PreForkReward(1U << nShift);
        BOOST_CHECK_EQUAL(nReward % CENT, 0);
        BOOST_CHECK(nReward <= nPrevious);
        BOOST_CHECK(nReward >= CENT);
        nPrevious = nReward;
    }
}

/* Height 0 always takes the pre-fork path, even with the fork at 0 */
BOOST_AUTO_TEST_CASE(reward_height_zero)
{
    ConsensusGlobalsGuard globals;
    globals.Set(0, 10);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(Params().GetConsensus().powLimit.GetCompact(), 0, 0), MAX_MINT_PROOF_OF_WORK);
}

/* After the fork: supply at the end of the previous epoch * 2% / blocks per year,
 * fixed for the whole epoch. Fees are not added (pins current behaviour). */
BOOST_AUTO_TEST_CASE(post_fork_epoch_reward)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;

    // Blocks 20-29: first epoch after the fork, based on the supply at block 19
    for (int nHeight = 20; nHeight <= 29; nHeight++) {
        BuildSupplyChain(chain, nHeight - 1);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, nHeight), EpochReward(MoneySupplyAt(19)));
    }
    // Blocks 30-39: based on the supply at block 29
    for (int nHeight = 30; nHeight <= 39; nHeight++) {
        BuildSupplyChain(chain, nHeight - 1);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, nHeight), EpochReward(MoneySupplyAt(29)));
    }
    BOOST_CHECK(EpochReward(MoneySupplyAt(29)) > EpochReward(MoneySupplyAt(19)));

    // nBits and fees don't matter
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0x1c0fffff, 5 * COIN, 39), EpochReward(MoneySupplyAt(29)));

    // Blocks before the fork still use the pre-fork curve
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(Params().GetConsensus().powLimit.GetCompact(), 0, 19), MAX_MINT_PROOF_OF_WORK);
}

/* Fork inside the first epoch interval: the first epoch starts at the fork */
BOOST_AUTO_TEST_CASE(post_fork_epoch_reward_fork_before_first_interval)
{
    ConsensusGlobalsGuard globals;
    globals.Set(5, 10);
    SyntheticChain chain;
    for (int nHeight = 5; nHeight <= 9; nHeight++) {
        BuildSupplyChain(chain, nHeight - 1);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, nHeight), EpochReward(MoneySupplyAt(4)));
    }
    BuildSupplyChain(chain, 9);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 10), EpochReward(MoneySupplyAt(9)));

    // Fork at 0 (the unit-test default): the first epoch reads the genesis block's supply
    globals.Set(0, 10);
    BuildSupplyChain(chain, 2);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0, 3), EpochReward(chain.Genesis()->nMoneySupply));
    BOOST_CHECK(GetProofOfWorkReward(0, 0, 3) != EpochReward(MoneySupplyAt(2)));
}

/* Block size limits follow the reward after the fork */
BOOST_AUTO_TEST_CASE(max_block_size)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;

    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 10), MAX_GENESIS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, 10), MAX_GENESIS_BLOCK_SIZE / 2);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, 10), MAX_GENESIS_BLOCK_SIZE / 50);

    BuildSupplyChain(chain, 24);
    // About 3.8 YAC per block => 380 kB, below the pre-fork 1 MB
    ::uint64_t nSize = EpochReward(MoneySupplyAt(19)) * 1000 / MIN_TX_FEE;
    BOOST_CHECK(nSize < MAX_GENESIS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 25), nSize);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE_GEN, 25), nSize / 2);
    // The sigops limit never drops below the pre-fork one
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, 25), MAX_GENESIS_BLOCK_SIZE / 50);
    // Height 0 means "the next block on the active chain"
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 0), nSize);

    // 100x the supply => 38 MB blocks, and the sigops limit follows
    {
        LOCK(cs_main);
        chainActive[19]->nMoneySupply *= 100;
    }
    nSize = EpochReward(MoneySupplyAt(19) * 100) * 1000 / MIN_TX_FEE;
    BOOST_CHECK(nSize > MAX_GENESIS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIZE, 25), nSize);
    BOOST_CHECK_EQUAL(GetMaxSize(MAX_BLOCK_SIGOPS, 25), nSize / 50);
}

BOOST_AUTO_TEST_CASE(coinbase_maturity)
{
    ConsensusGlobalsGuard globals;
    globals.Set(20, 10);
    SyntheticChain chain;

    BuildSupplyChain(chain, 19);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturity(), COINBASE_MATURITY_BEFORE_HARDFORK);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturityOffset(), 20);

    BuildSupplyChain(chain, 20);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturity(), COINBASE_MATURITY_AFTER_HARDFORK);
    BOOST_CHECK_EQUAL(GetCoinbaseMaturityOffset(), 0);
}

bool ReturnFalse() { return false; }
bool ReturnTrue() { return true; }

BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool (), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}
BOOST_AUTO_TEST_SUITE_END()
