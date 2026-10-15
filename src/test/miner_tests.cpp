// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Block assembly (BlockAssembler::CreateNewBlock) for YACoin. Bitcoin's version
// of this file relied on hardcoded SHA256 nonces, the 50 BTC subsidy halving and
// BIP68 median-time-past rules, so it was rewritten. Mempool package selection
// is adapted from Bitcoin's TestPackageSelection.

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "miner.h"
#include "policy/fees.h"
#include "pow.h"
#include "script/sign.h"
#include "txmempool.h"
#include "validation.h"

#include "test/test_bitcoin.h"

#include <memory>

#include <boost/test/unit_test.hpp>

/** Regtest chain whose first coinbases are mature. TestingSetup's teardown clears the
 * mempool but not its fee deltas, which this fixture clears itself. */
struct MinerTestingSetup : public TestChain100Setup {
    std::vector<CTransaction> matureCoinbases;
    CScript scriptPubKey;

    MinerTestingSetup()
    {
        scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        // TestChain100Setup mines COINBASE_MATURITY_AFTER_HARDFORK blocks; mine as many
        // again so all of their coinbases can be spent
        matureCoinbases = coinbaseTxns;
        for (int i = 0; i < COINBASE_MATURITY_AFTER_HARDFORK; i++)
            CreateAndProcessBlock({}, scriptPubKey);
    }

    ~MinerTestingSetup()
    {
        LOCK(mempool.cs);
        mempool.mapDeltas.clear();
    }

    /** Hashes of the template's transactions after the coinbase */
    std::vector<uint256> TemplateTxs()
    {
        std::vector<uint256> vHashes;
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
        for (size_t i = 1; i < pblocktemplate->block.vtx.size(); i++)
            vHashes.push_back(pblocktemplate->block.vtx[i].GetHash());
        return vHashes;
    }

    CAmount StoredDelta(const uint256& hash)
    {
        CAmount nDelta = 0;
        mempool.ApplyDelta(hash, nDelta);
        return nDelta;
    }

    /** Signed spend of a mature coinbase back to the coinbase key, paying nFee */
    CTransaction Spend(const CTransaction& prev, CAmount nFee, unsigned int n = 0)
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(prev.GetHash(), n);
        tx.vout.resize(1);
        tx.vout[0].nValue = prev.vout[n].nValue - nFee;
        tx.vout[0].scriptPubKey = scriptPubKey;
        std::vector<unsigned char> vchSig;
        uint256 hash = SignatureHash(prev.vout[n].scriptPubKey, tx, 0, SIGHASH_ALL);
        BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        tx.vin[0].scriptSig << vchSig;
        return CTransaction(tx);
    }

    bool ToMemPool(const CTransaction& tx)
    {
        LOCK(cs_main);
        CValidationState state;
        bool fValid = AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), nullptr);
        if (!fValid) BOOST_TEST_MESSAGE("AcceptToMemoryPool: " + state.GetRejectReason());
        return fValid;
    }

    /** Finish a template like a miner (extra nonce, proof of work), check and submit it.
     * Returns whether it became the new tip; strReason gets TestBlockValidity's reject reason. */
    bool MineTemplate(CBlock& block, std::string* strReason = nullptr)
    {
        unsigned int nExtraNonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, chainActive.Tip(), nExtraNonce);
        }
        while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
        {
            LOCK(cs_main);
            CValidationState state;
            bool fValid = TestBlockValidity(state, Params(), block, chainActive.Tip());
            if (strReason) *strReason = state.GetRejectReason();
            else BOOST_CHECK_MESSAGE(fValid, state.GetRejectReason());
        }
        ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, nullptr);
        LOCK(cs_main);
        return chainActive.Tip()->GetBlockHash() == block.GetHash();
    }
};

BOOST_FIXTURE_TEST_SUITE(miner_tests, MinerTestingSetup)

BOOST_AUTO_TEST_CASE(empty_template)
{
    CBlockIndex* pindexPrev;
    CAmount nGenesisSupply;
    {
        LOCK(cs_main);
        pindexPrev = chainActive.Tip();
        nGenesisSupply = chainActive.Genesis()->nMoneySupply;
    }
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    BOOST_REQUIRE(pblocktemplate);
    CBlock& block = pblocktemplate->block;

    BOOST_CHECK_EQUAL(block.vtx.size(), 1U);
    BOOST_CHECK(block.vtx[0].IsCoinBase());
    BOOST_CHECK(block.vtx[0].vout[0].scriptPubKey == scriptPubKey);
    BOOST_CHECK(block.hashPrevBlock == pindexPrev->GetBlockHash());
    BOOST_CHECK(block.GetBlockTime() > pindexPrev->GetMedianTimePast());
    // The fork is at height 0 in unit tests: 1.0 block version and epoch reward
    BOOST_CHECK_EQUAL(block.nVersion, VERSION_of_block_for_yac_05x_new);
    // First epoch: reward from the money supply at the fork (the genesis block here)
    CAmount nReward = nGenesisSupply * nInflation / nNumberOfBlocksPerYear;
    BOOST_CHECK(nReward > 0);
    BOOST_CHECK_EQUAL(block.vtx[0].vout[0].nValue, nReward);

    BOOST_CHECK(MineTemplate(block));
}

/* Post-fork the coinbase may not claim the fees: the limit is the reward alone */
BOOST_AUTO_TEST_CASE(coinbase_cannot_claim_fees)
{
    const CAmount nFee = 5 * CENT;
    BOOST_CHECK(ToMemPool(Spend(matureCoinbases[0], nFee)));
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    CBlock& block = pblocktemplate->block;
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 2U);
    CAmount nReward = block.vtx[0].vout[0].nValue;

    CBlock greedy = block;
    greedy.vtx[0].vout[0].nValue = nReward + nFee;
    std::string strReason;
    BOOST_CHECK(!MineTemplate(greedy, &strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-cb-amount");

    BOOST_CHECK(MineTemplate(block));
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
}

/* Higher fee rate first; a high-fee child pulls in its low-fee parent */
BOOST_AUTO_TEST_CASE(fee_ordering_and_packages)
{
    CTransaction low = Spend(matureCoinbases[0], GetMinFee(1000));
    CTransaction medium = Spend(matureCoinbases[1], 20 * GetMinFee(1000));
    CTransaction high = Spend(matureCoinbases[2], 50 * GetMinFee(1000));
    for (const CTransaction& tx : {low, medium, high})
        BOOST_CHECK(ToMemPool(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    std::vector<CTransaction>& vtx = pblocktemplate->block.vtx;
    BOOST_REQUIRE_EQUAL(vtx.size(), 4U);
    BOOST_CHECK(vtx[1].GetHash() == high.GetHash());
    BOOST_CHECK(vtx[2].GetHash() == medium.GetHash());
    BOOST_CHECK(vtx[3].GetHash() == low.GetHash());
    // Fees per transaction are reported for getblocktemplate
    BOOST_CHECK_EQUAL(pblocktemplate->vTxFees[1], 50 * GetMinFee(1000));

    // A child paying a high fee for its low-fee parent beats the medium tx as a package
    mempool.clear();
    BOOST_CHECK(ToMemPool(low));
    BOOST_CHECK(ToMemPool(medium));
    CTransaction child = Spend(low, 100 * GetMinFee(1000));
    BOOST_CHECK(ToMemPool(child));
    pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    BOOST_REQUIRE_EQUAL(pblocktemplate->block.vtx.size(), 4U);
    BOOST_CHECK(pblocktemplate->block.vtx[1].GetHash() == low.GetHash());
    BOOST_CHECK(pblocktemplate->block.vtx[2].GetHash() == child.GetHash());
    BOOST_CHECK(pblocktemplate->block.vtx[3].GetHash() == medium.GetHash());

    BOOST_CHECK(MineTemplate(pblocktemplate->block));
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
}

/* Template-only cases with mempool entries that skip mempool validation */
BOOST_AUTO_TEST_CASE(transactions_left_out)
{
    TestMemPoolEntryHelper entry;
    entry.nHeight = 1;
    int nHeight;
    int64_t nTime;
    {
        LOCK(cs_main);
        nHeight = chainActive.Height() + 1;
        nTime = GetAdjustedTime();
    }
    auto fakeTx = [](uint32_t nLockTime, uint32_t nSequence) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(InsecureRand256(), 0);
        tx.vin[0].nSequence = nSequence;
        tx.vout.resize(1);
        tx.vout[0].nValue = COIN;
        tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        tx.nLockTime = nLockTime;
        return CTransaction(tx);
    };

    // Just below the minimum fee, and exactly at it
    CTransaction cheap = fakeTx(0, CTxIn::SEQUENCE_FINAL);
    size_t nSize = ::GetSerializeSize(cheap, SER_NETWORK, PROTOCOL_VERSION);
    mempool.addUnchecked(cheap.GetHash(), entry.Fee(GetMinFee(nSize) - 1).FromTx(cheap));
    CTransaction minFee = fakeTx(0, CTxIn::SEQUENCE_FINAL);
    mempool.addUnchecked(minFee.GetHash(), entry.Fee(GetMinFee(::GetSerializeSize(minFee, SER_NETWORK, PROTOCOL_VERSION))).FromTx(minFee));
    // Not final yet: locked to a future height, and to a time after the block time
    CTransaction heightLocked = fakeTx(nHeight + 5, 0);
    CTransaction timeLocked = fakeTx(nTime + 3600, 0);
    // Locked, but final because every input is SEQUENCE_FINAL
    CTransaction sequenceFinal = fakeTx(nHeight + 5, CTxIn::SEQUENCE_FINAL);
    // Locked to the block being built: a height lock must be below that height
    CTransaction nextHeight = fakeTx(nHeight, 0);
    CTransaction prevHeight = fakeTx(nHeight - 1, 0);
    for (const CTransaction& tx : {heightLocked, timeLocked, sequenceFinal, nextHeight, prevHeight})
        mempool.addUnchecked(tx.GetHash(), entry.Fee(COIN).FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    std::set<uint256> included;
    for (const CTransaction& tx : pblocktemplate->block.vtx) included.insert(tx.GetHash());
    BOOST_CHECK(!included.count(cheap.GetHash()));
    BOOST_CHECK(included.count(minFee.GetHash()));
    BOOST_CHECK(!included.count(heightLocked.GetHash()));
    BOOST_CHECK(!included.count(timeLocked.GetHash()));
    BOOST_CHECK(!included.count(nextHeight.GetHash()));
    BOOST_CHECK(included.count(sequenceFinal.GetHash()));
    BOOST_CHECK(included.count(prevHeight.GetHash()));
}

/* The template stays below the reward-dependent block size limit */
BOOST_AUTO_TEST_CASE(block_size_limit)
{
    const uint64_t nMaxSize = GetMaxSize(MAX_BLOCK_SIZE);
    TestMemPoolEntryHelper entry;
    entry.nHeight = 1;
    uint64_t nTotal = 0, nLargest = 0;
    int nTxs = 0;
    while (nTotal < nMaxSize + 100000) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(InsecureRand256(), 0);
        for (int i = 0; i < 80; i++)
            tx.vin[0].scriptSig << std::vector<unsigned char>(500, i) << OP_DROP;
        tx.vin[0].scriptSig << OP_TRUE;
        tx.vout.resize(1);
        tx.vout[0].nValue = COIN;
        CTransaction ctx(tx);
        size_t nSize = ::GetSerializeSize(ctx, SER_NETWORK, PROTOCOL_VERSION);
        mempool.addUnchecked(ctx.GetHash(), entry.Fee(2 * GetMinFee(nSize)).FromTx(ctx));
        nTotal += nSize;
        nLargest = std::max<uint64_t>(nLargest, nSize);
        nTxs++;
    }

    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    const CBlock& block = pblocktemplate->block;
    BOOST_CHECK(block.vtx.size() > 1);
    BOOST_CHECK((int)block.vtx.size() < nTxs + 1);
    // Filled up to the limit: no further transaction would have fit
    uint64_t nBlockSize = ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK(nBlockSize < nMaxSize);
    BOOST_CHECK(nBlockSize + nLargest + 1000 >= nMaxSize);
}

/* The extra nonce counts up for the same previous block and restarts for a new one */
BOOST_AUTO_TEST_CASE(increment_extra_nonce)
{
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    CBlock& block = pblocktemplate->block;
    LOCK(cs_main);
    CBlockIndex* pindexPrev = chainActive.Tip();
    unsigned int nExtraNonce = 0;

    block.hashPrevBlock = InsecureRand256();
    IncrementExtraNonce(&block, pindexPrev, nExtraNonce);
    BOOST_CHECK_EQUAL(nExtraNonce, 1U);
    uint256 root1 = block.hashMerkleRoot;
    IncrementExtraNonce(&block, pindexPrev, nExtraNonce);
    BOOST_CHECK_EQUAL(nExtraNonce, 2U);
    BOOST_CHECK(block.hashMerkleRoot != root1);
    BOOST_CHECK(block.hashMerkleRoot == block.BuildMerkleTree());
    BOOST_CHECK(block.vtx[0].vin[0].scriptSig ==
                (CScript() << (pindexPrev->nHeight + 1) << CScriptNum(2)) + COINBASE_FLAGS);

    block.hashPrevBlock = InsecureRand256();
    IncrementExtraNonce(&block, pindexPrev, nExtraNonce);
    BOOST_CHECK_EQUAL(nExtraNonce, 1U);
}

/* A fee delta, set before or after the tx enters the mempool, decides its place in the
 * template, while the template still reports the real fee */
BOOST_AUTO_TEST_CASE(prioritised_template_order)
{
    const CAmount k = GetMinFee(1000);
    CTransaction low = Spend(matureCoinbases[0], k);
    CTransaction medium = Spend(matureCoinbases[1], 20 * k);
    CTransaction high = Spend(matureCoinbases[2], 50 * k);
    mempool.PrioritiseTransaction(low.GetHash(), 100 * k);
    BOOST_CHECK(!mempool.exists(low.GetHash()));
    for (const CTransaction& tx : {low, medium, high})
        BOOST_CHECK(ToMemPool(tx));
    BOOST_CHECK_EQUAL(mempool.info(low.GetHash()).nFeeDelta, 100 * k);

    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    BOOST_REQUIRE_EQUAL(pblocktemplate->block.vtx.size(), 4U);
    BOOST_CHECK(pblocktemplate->block.vtx[1].GetHash() == low.GetHash());
    BOOST_CHECK(pblocktemplate->block.vtx[2].GetHash() == high.GetHash());
    BOOST_CHECK(pblocktemplate->block.vtx[3].GetHash() == medium.GetHash());
    BOOST_CHECK_EQUAL(pblocktemplate->vTxFees[1], k);

    mempool.PrioritiseTransaction(high.GetHash(), -45 * k);
    BOOST_CHECK(TemplateTxs() == std::vector<uint256>({low.GetHash(), medium.GetHash(), high.GetHash()}));

    // A modified fee below the minimum keeps the tx out of the block
    mempool.PrioritiseTransaction(medium.GetHash(), -20 * k);
    pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    BOOST_REQUIRE_EQUAL(pblocktemplate->block.vtx.size(), 3U);
    BOOST_CHECK(pblocktemplate->block.vtx[1].GetHash() == low.GetHash());
    BOOST_CHECK(pblocktemplate->block.vtx[2].GetHash() == high.GetHash());

    // Mining forgets the deltas of the mined txs only
    BOOST_CHECK(MineTemplate(pblocktemplate->block));
    BOOST_CHECK_EQUAL(mempool.size(), 1U);
    BOOST_CHECK(mempool.exists(medium.GetHash()));
    BOOST_CHECK_EQUAL(StoredDelta(low.GetHash()), 0);
    BOOST_CHECK_EQUAL(StoredDelta(high.GetHash()), 0);
    BOOST_CHECK_EQUAL(StoredDelta(medium.GetHash()), -20 * k);
}

/* Deltas on a parent and on its child move them between packages */
BOOST_AUTO_TEST_CASE(prioritised_parent_and_child)
{
    const CAmount k = GetMinFee(1000);
    CTransaction parent = Spend(matureCoinbases[0], k);
    CTransaction child = Spend(parent, 4 * k);
    CTransaction other = Spend(matureCoinbases[1], 3 * k);
    for (const CTransaction& tx : {parent, child, other})
        BOOST_CHECK(ToMemPool(tx));
    const uint256 hashP = parent.GetHash(), hashC = child.GetHash(), hashU = other.GetHash();

    // Parent and child as a package (2.5k per tx) lose to the other tx (3k)
    BOOST_CHECK(TemplateTxs() == std::vector<uint256>({hashU, hashP, hashC}));

    // The prioritised parent goes first on its own; the child (4k) then beats the other tx
    mempool.PrioritiseTransaction(hashP, 10 * k);
    BOOST_CHECK(TemplateTxs() == std::vector<uint256>({hashP, hashC, hashU}));
    {
        LOCK(mempool.cs);
        BOOST_CHECK_EQUAL(mempool.mapTx.find(hashC)->GetModFeesWithAncestors(), 11 * k + 4 * k);
    }

    // Lowered to 2k, the child comes after the other tx
    mempool.PrioritiseTransaction(hashC, -2 * k);
    {
        LOCK(mempool.cs);
        BOOST_CHECK_EQUAL(mempool.mapTx.find(hashP)->GetModFeesWithDescendants(), 11 * k + 2 * k);
    }
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(scriptPubKey);
    BOOST_REQUIRE_EQUAL(pblocktemplate->block.vtx.size(), 4U);
    BOOST_CHECK(pblocktemplate->block.vtx[1].GetHash() == hashP);
    BOOST_CHECK(pblocktemplate->block.vtx[2].GetHash() == hashU);
    BOOST_CHECK(pblocktemplate->block.vtx[3].GetHash() == hashC);

    BOOST_CHECK(MineTemplate(pblocktemplate->block));
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
    BOOST_CHECK_EQUAL(StoredDelta(hashP), 0);
    BOOST_CHECK_EQUAL(StoredDelta(hashC), 0);
}

/* A child whose two parents enter the block in separate packages: its package is reduced
 * by each parent, after which it ranks by its own fee rate */
BOOST_AUTO_TEST_CASE(child_of_two_packages)
{
    TestMemPoolEntryHelper entry;
    entry.nHeight = 1;
    auto fakeTx = [](const std::vector<COutPoint>& vPrevouts) {
        CMutableTransaction tx;
        for (const COutPoint& prevout : vPrevouts) tx.vin.push_back(CTxIn(prevout));
        tx.vout.resize(1);
        tx.vout[0].nValue = COIN;
        tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        return CTransaction(tx);
    };
    // Fee rates in multiples of the minimum: parent1 50, parent2 10, child 2, other 3
    CTransaction parent1 = fakeTx({COutPoint(InsecureRand256(), 0)});
    CTransaction parent2 = fakeTx({COutPoint(InsecureRand256(), 0)});
    CTransaction other = fakeTx({COutPoint(InsecureRand256(), 0)});
    CTransaction child = fakeTx({COutPoint(parent1.GetHash(), 0), COutPoint(parent2.GetHash(), 0)});
    for (const auto& txMultiple : std::vector<std::pair<CTransaction, int>>{{parent1, 50}, {parent2, 10}, {other, 3}, {child, 2}}) {
        const CTransaction& tx = txMultiple.first;
        CAmount nFee = txMultiple.second * GetMinFee(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION));
        mempool.addUnchecked(tx.GetHash(), entry.Fee(nFee).FromTx(tx));
    }

    // parent1 first; then parent2 alone beats the child's remaining package (parent2 +
    // child); with both parents in, the child (2) ranks after the other tx (3)
    BOOST_CHECK(TemplateTxs() == std::vector<uint256>({parent1.GetHash(), parent2.GetHash(), other.GetHash(), child.GetHash()}));
}

BOOST_AUTO_TEST_SUITE_END()
