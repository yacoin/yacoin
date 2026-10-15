// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "policy/policy.h"
#include "txmempool.h"
#include "util.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <limits>
#include <list>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mempool_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(MempoolRemoveTest)
{
    // Test CTxMemPool::remove functionality

    TestMemPoolEntryHelper entry;
    // Parent transaction with three children,
    // and three grand-children:
    CMutableTransaction txParent;
    txParent.vin.resize(1);
    txParent.vin[0].scriptSig = CScript() << OP_11;
    txParent.vout.resize(3);
    for (int i = 0; i < 3; i++)
    {
        txParent.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txParent.vout[i].nValue = 33000LL;
    }
    CMutableTransaction txChild[3];
    for (int i = 0; i < 3; i++)
    {
        txChild[i].vin.resize(1);
        txChild[i].vin[0].scriptSig = CScript() << OP_11;
        txChild[i].vin[0].prevout.hash = txParent.GetHash();
        txChild[i].vin[0].prevout.n = i;
        txChild[i].vout.resize(1);
        txChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txChild[i].vout[0].nValue = 11000LL;
    }
    CMutableTransaction txGrandChild[3];
    for (int i = 0; i < 3; i++)
    {
        txGrandChild[i].vin.resize(1);
        txGrandChild[i].vin[0].scriptSig = CScript() << OP_11;
        txGrandChild[i].vin[0].prevout.hash = txChild[i].GetHash();
        txGrandChild[i].vin[0].prevout.n = 0;
        txGrandChild[i].vout.resize(1);
        txGrandChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txGrandChild[i].vout[0].nValue = 11000LL;
    }


    CTxMemPool testPool;

    // Nothing in pool, remove should do nothing:
    unsigned int poolSize = testPool.size();
    testPool.removeRecursive(txParent);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);

    // Just the parent:
    testPool.addUnchecked(txParent.GetHash(), entry.FromTx(txParent));
    poolSize = testPool.size();
    testPool.removeRecursive(txParent);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 1);
    
    // Parent, children, grandchildren:
    testPool.addUnchecked(txParent.GetHash(), entry.FromTx(txParent));
    for (int i = 0; i < 3; i++)
    {
        testPool.addUnchecked(txChild[i].GetHash(), entry.FromTx(txChild[i]));
        testPool.addUnchecked(txGrandChild[i].GetHash(), entry.FromTx(txGrandChild[i]));
    }
    // Remove Child[0], GrandChild[0] should be removed:
    poolSize = testPool.size();
    testPool.removeRecursive(txChild[0]);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 2);
    // ... make sure grandchild and child are gone:
    poolSize = testPool.size();
    testPool.removeRecursive(txGrandChild[0]);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);
    poolSize = testPool.size();
    testPool.removeRecursive(txChild[0]);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize);
    // Remove parent, all children/grandchildren should go:
    poolSize = testPool.size();
    testPool.removeRecursive(txParent);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 5);
    BOOST_CHECK_EQUAL(testPool.size(), 0);

    // Add children and grandchildren, but NOT the parent (simulate the parent being in a block)
    for (int i = 0; i < 3; i++)
    {
        testPool.addUnchecked(txChild[i].GetHash(), entry.FromTx(txChild[i]));
        testPool.addUnchecked(txGrandChild[i].GetHash(), entry.FromTx(txGrandChild[i]));
    }
    // Now remove the parent, as might happen if a block-re-org occurs but the parent cannot be
    // put into the mempool (maybe because it is non-standard):
    poolSize = testPool.size();
    testPool.removeRecursive(txParent);
    BOOST_CHECK_EQUAL(testPool.size(), poolSize - 6);
    BOOST_CHECK_EQUAL(testPool.size(), 0);
}

template<typename name>
void CheckSort(CTxMemPool &pool, std::vector<std::string> &sortedOrder)
{
    BOOST_CHECK_EQUAL(pool.size(), sortedOrder.size());
    typename CTxMemPool::indexed_transaction_set::index<name>::type::iterator it = pool.mapTx.get<name>().begin();
    int count=0;
    for (; it != pool.mapTx.get<name>().end(); ++it, ++count) {
        BOOST_CHECK_EQUAL(it->GetTx().GetHash().ToString(), sortedOrder[count]);
    }
}

BOOST_AUTO_TEST_CASE(MempoolIndexingTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;

    /* 3rd highest fee */
    CMutableTransaction tx1 = CMutableTransaction();
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(tx1.GetHash(), entry.Fee(10000LL).FromTx(tx1));

    /* highest fee */
    CMutableTransaction tx2 = CMutableTransaction();
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx2.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(tx2.GetHash(), entry.Fee(20000LL).FromTx(tx2));

    /* lowest fee */
    CMutableTransaction tx3 = CMutableTransaction();
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx3.vout[0].nValue = 5 * COIN;
    pool.addUnchecked(tx3.GetHash(), entry.Fee(0LL).FromTx(tx3));

    /* 2nd highest fee */
    CMutableTransaction tx4 = CMutableTransaction();
    tx4.vout.resize(1);
    tx4.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx4.vout[0].nValue = 6 * COIN;
    pool.addUnchecked(tx4.GetHash(), entry.Fee(15000LL).FromTx(tx4));

    /* equal fee rate to tx1, but newer */
    CMutableTransaction tx5 = CMutableTransaction();
    tx5.vout.resize(1);
    tx5.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx5.vout[0].nValue = 11 * COIN;
    entry.nTime = 1;
    pool.addUnchecked(tx5.GetHash(), entry.Fee(10000LL).FromTx(tx5));
    BOOST_CHECK_EQUAL(pool.size(), 5);

    std::vector<std::string> sortedOrder;
    sortedOrder.resize(5);
    sortedOrder[0] = tx3.GetHash().ToString(); // 0
    sortedOrder[1] = tx5.GetHash().ToString(); // 10000
    sortedOrder[2] = tx1.GetHash().ToString(); // 10000
    sortedOrder[3] = tx4.GetHash().ToString(); // 15000
    sortedOrder[4] = tx2.GetHash().ToString(); // 20000
    CheckSort<descendant_score>(pool, sortedOrder);

    /* low fee but with high fee child */
    /* tx6 -> tx7 -> tx8, tx9 -> tx10 */
    CMutableTransaction tx6 = CMutableTransaction();
    tx6.vout.resize(1);
    tx6.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx6.vout[0].nValue = 20 * COIN;
    pool.addUnchecked(tx6.GetHash(), entry.Fee(0LL).FromTx(tx6));
    BOOST_CHECK_EQUAL(pool.size(), 6);
    // Check that at this point, tx6 is sorted low
    sortedOrder.insert(sortedOrder.begin(), tx6.GetHash().ToString());
    CheckSort<descendant_score>(pool, sortedOrder);

    CTxMemPool::setEntries setAncestors;
    setAncestors.insert(pool.mapTx.find(tx6.GetHash()));
    CMutableTransaction tx7 = CMutableTransaction();
    tx7.vin.resize(1);
    tx7.vin[0].prevout = COutPoint(tx6.GetHash(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_11;
    tx7.vout.resize(2);
    tx7.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    tx7.vout[1].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx7.vout[1].nValue = 1 * COIN;

    CTxMemPool::setEntries setAncestorsCalculated;
    std::string dummy;
    BOOST_CHECK_EQUAL(pool.CalculateMemPoolAncestors(entry.Fee(2000000LL).FromTx(tx7), setAncestorsCalculated, 100, 1000000, 1000, 1000000, dummy), true);
    BOOST_CHECK(setAncestorsCalculated == setAncestors);

    pool.addUnchecked(tx7.GetHash(), entry.FromTx(tx7), setAncestors);
    BOOST_CHECK_EQUAL(pool.size(), 7);

    // Now tx6 should be sorted higher (high fee child): tx7, tx6, tx2, ...
    sortedOrder.erase(sortedOrder.begin());
    sortedOrder.push_back(tx6.GetHash().ToString());
    sortedOrder.push_back(tx7.GetHash().ToString());
    CheckSort<descendant_score>(pool, sortedOrder);

    /* low fee child of tx7 */
    CMutableTransaction tx8 = CMutableTransaction();
    tx8.vin.resize(1);
    tx8.vin[0].prevout = COutPoint(tx7.GetHash(), 0);
    tx8.vin[0].scriptSig = CScript() << OP_11;
    tx8.vout.resize(1);
    tx8.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx8.vout[0].nValue = 10 * COIN;
    setAncestors.insert(pool.mapTx.find(tx7.GetHash()));
    pool.addUnchecked(tx8.GetHash(), entry.Fee(0LL).Time(2).FromTx(tx8), setAncestors);

    // Now tx8 should be sorted low, but tx6/tx both high
    sortedOrder.insert(sortedOrder.begin(), tx8.GetHash().ToString());
    CheckSort<descendant_score>(pool, sortedOrder);

    /* low fee child of tx7 */
    CMutableTransaction tx9 = CMutableTransaction();
    tx9.vin.resize(1);
    tx9.vin[0].prevout = COutPoint(tx7.GetHash(), 1);
    tx9.vin[0].scriptSig = CScript() << OP_11;
    tx9.vout.resize(1);
    tx9.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx9.vout[0].nValue = 1 * COIN;
    pool.addUnchecked(tx9.GetHash(), entry.Fee(0LL).Time(3).FromTx(tx9), setAncestors);

    // tx9 should be sorted low
    BOOST_CHECK_EQUAL(pool.size(), 9);
    sortedOrder.insert(sortedOrder.begin(), tx9.GetHash().ToString());
    CheckSort<descendant_score>(pool, sortedOrder);

    std::vector<std::string> snapshotOrder = sortedOrder;

    setAncestors.insert(pool.mapTx.find(tx8.GetHash()));
    setAncestors.insert(pool.mapTx.find(tx9.GetHash()));
    /* tx10 depends on tx8 and tx9 and has a high fee*/
    CMutableTransaction tx10 = CMutableTransaction();
    tx10.vin.resize(2);
    tx10.vin[0].prevout = COutPoint(tx8.GetHash(), 0);
    tx10.vin[0].scriptSig = CScript() << OP_11;
    tx10.vin[1].prevout = COutPoint(tx9.GetHash(), 0);
    tx10.vin[1].scriptSig = CScript() << OP_11;
    tx10.vout.resize(1);
    tx10.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx10.vout[0].nValue = 10 * COIN;

    setAncestorsCalculated.clear();
    BOOST_CHECK_EQUAL(pool.CalculateMemPoolAncestors(entry.Fee(200000LL).Time(4).FromTx(tx10), setAncestorsCalculated, 100, 1000000, 1000, 1000000, dummy), true);
    BOOST_CHECK(setAncestorsCalculated == setAncestors);

    pool.addUnchecked(tx10.GetHash(), entry.FromTx(tx10), setAncestors);

    /**
     *  tx8 and tx9 should both now be sorted higher
     *  Final order after tx10 is added:
     *
     *  tx3 = 0 (1)
     *  tx5 = 10000 (1)
     *  tx1 = 10000 (1)
     *  tx4 = 15000 (1)
     *  tx2 = 20000 (1)
     *  tx9 = 200k (2 txs)
     *  tx8 = 200k (2 txs)
     *  tx10 = 200k (1 tx)
     *  tx6 = 2.2M (5 txs)
     *  tx7 = 2.2M (4 txs)
     */
    sortedOrder.erase(sortedOrder.begin(), sortedOrder.begin()+2); // take out tx9, tx8 from the beginning
    sortedOrder.insert(sortedOrder.begin()+5, tx9.GetHash().ToString());
    sortedOrder.insert(sortedOrder.begin()+6, tx8.GetHash().ToString());
    sortedOrder.insert(sortedOrder.begin()+7, tx10.GetHash().ToString()); // tx10 is just before tx6
    CheckSort<descendant_score>(pool, sortedOrder);

    // there should be 10 transactions in the mempool
    BOOST_CHECK_EQUAL(pool.size(), 10);

    // Now try removing tx10 and verify the sort order returns to normal
    pool.removeRecursive(pool.mapTx.find(tx10.GetHash())->GetTx());
    CheckSort<descendant_score>(pool, snapshotOrder);

    pool.removeRecursive(pool.mapTx.find(tx9.GetHash())->GetTx());
    pool.removeRecursive(pool.mapTx.find(tx8.GetHash())->GetTx());
    /* Now check the sort on the mining score index.
     * Final order should be:
     *
     * tx7 (2M)
     * tx2 (20k)
     * tx4 (15000)
     * tx1/tx5 (10000)
     * tx3/6 (0)
     * (Ties resolved by hash)
     */
    sortedOrder.clear();
    sortedOrder.push_back(tx7.GetHash().ToString());
    sortedOrder.push_back(tx2.GetHash().ToString());
    sortedOrder.push_back(tx4.GetHash().ToString());
    if (tx1.GetHash() < tx5.GetHash()) {
        sortedOrder.push_back(tx5.GetHash().ToString());
        sortedOrder.push_back(tx1.GetHash().ToString());
    } else {
        sortedOrder.push_back(tx1.GetHash().ToString());
        sortedOrder.push_back(tx5.GetHash().ToString());
    }
    if (tx3.GetHash() < tx6.GetHash()) {
        sortedOrder.push_back(tx6.GetHash().ToString());
        sortedOrder.push_back(tx3.GetHash().ToString());
    } else {
        sortedOrder.push_back(tx3.GetHash().ToString());
        sortedOrder.push_back(tx6.GetHash().ToString());
    }
    CheckSort<mining_score>(pool, sortedOrder);
}

BOOST_AUTO_TEST_CASE(MempoolAncestorIndexingTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;

    /* 3rd highest fee */
    CTransaction tx1 = CTransaction();
    tx1.vout.resize(1);
    tx1.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx1.vout[0].nValue = 10 * COIN;
    pool.addUnchecked(tx1.GetHash(), entry.Fee(10000LL).FromTx(tx1));

    /* highest fee */
    CTransaction tx2 = CTransaction();
    tx2.vout.resize(1);
    tx2.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx2.vout[0].nValue = 2 * COIN;
    pool.addUnchecked(tx2.GetHash(), entry.Fee(20000LL).FromTx(tx2));
    uint64_t tx2Size = tx2.GetTotalSize();

    /* lowest fee */
    CTransaction tx3 = CTransaction();
    tx3.vout.resize(1);
    tx3.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx3.vout[0].nValue = 5 * COIN;
    pool.addUnchecked(tx3.GetHash(), entry.Fee(0LL).FromTx(tx3));

    /* 2nd highest fee */
    CTransaction tx4 = CTransaction();
    tx4.vout.resize(1);
    tx4.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx4.vout[0].nValue = 6 * COIN;
    pool.addUnchecked(tx4.GetHash(), entry.Fee(15000LL).FromTx(tx4));

    /* equal fee rate to tx1, but newer */
    CTransaction tx5 = CTransaction();
    tx5.vout.resize(1);
    tx5.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx5.vout[0].nValue = 11 * COIN;
    pool.addUnchecked(tx5.GetHash(), entry.Fee(10000LL).FromTx(tx5));
    BOOST_CHECK_EQUAL(pool.size(), 5);

    std::vector<std::string> sortedOrder;
    sortedOrder.resize(5);
    sortedOrder[0] = tx2.GetHash().ToString(); // 20000
    sortedOrder[1] = tx4.GetHash().ToString(); // 15000
    // tx1 and tx5 are both 10000
    // Ties are broken by hash, not timestamp, so determine which
    // hash comes first.
    if (tx1.GetHash() < tx5.GetHash()) {
        sortedOrder[2] = tx1.GetHash().ToString();
        sortedOrder[3] = tx5.GetHash().ToString();
    } else {
        sortedOrder[2] = tx5.GetHash().ToString();
        sortedOrder[3] = tx1.GetHash().ToString();
    }
    sortedOrder[4] = tx3.GetHash().ToString(); // 0

    CheckSort<ancestor_score>(pool, sortedOrder);

    /* low fee parent with high fee child */
    /* tx6 (0) -> tx7 (high) */
    CTransaction tx6 = CTransaction();
    tx6.vout.resize(1);
    tx6.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx6.vout[0].nValue = 20 * COIN;
    uint64_t tx6Size = tx6.GetTotalSize();

    pool.addUnchecked(tx6.GetHash(), entry.Fee(0LL).FromTx(tx6));
    BOOST_CHECK_EQUAL(pool.size(), 6);
    // Ties are broken by hash
    if (tx3.GetHash() < tx6.GetHash())
        sortedOrder.push_back(tx6.GetHash().ToString());
    else
        sortedOrder.insert(sortedOrder.end()-1,tx6.GetHash().ToString());

    CheckSort<ancestor_score>(pool, sortedOrder);

    CTransaction tx7 = CTransaction();
    tx7.vin.resize(1);
    tx7.vin[0].prevout = COutPoint(tx6.GetHash(), 0);
    tx7.vin[0].scriptSig = CScript() << OP_11;
    tx7.vout.resize(1);
    tx7.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx7.vout[0].nValue = 10 * COIN;
    uint64_t tx7Size = tx7.GetTotalSize();

    /* set the fee to just below tx2's feerate when including ancestor */
    CAmount fee = (20000/tx2Size)*(tx7Size + tx6Size) - 1;

    pool.addUnchecked(tx7.GetHash(), entry.Fee(fee).FromTx(tx7));
    BOOST_CHECK_EQUAL(pool.size(), 7);
    sortedOrder.insert(sortedOrder.begin()+1, tx7.GetHash().ToString());
    CheckSort<ancestor_score>(pool, sortedOrder);

    /* after tx6 is mined, tx7 should move up in the sort */
    std::vector<CTransaction> vtx;
    vtx.push_back(tx6);
    pool.removeForBlock(vtx);

    sortedOrder.erase(sortedOrder.begin()+1);
    // Ties are broken by hash
    if (tx3.GetHash() < tx6.GetHash())
        sortedOrder.pop_back();
    else
        sortedOrder.erase(sortedOrder.end()-2);
    sortedOrder.insert(sortedOrder.begin(), tx7.GetHash().ToString());
    CheckSort<ancestor_score>(pool, sortedOrder);
}

/** A tx with nOuts outputs of nValue each, spending vPrevouts (none: a unique random outpoint).
 * All one-input, one-output txs built here have the same size. */
static CMutableTransaction MakeTx(const std::vector<COutPoint>& vPrevouts, CAmount nValue, unsigned int nOuts = 1)
{
    CMutableTransaction tx;
    tx.vin.resize(vPrevouts.empty() ? 1 : vPrevouts.size());
    for (size_t i = 0; i < tx.vin.size(); i++) {
        tx.vin[i].prevout = vPrevouts.empty() ? COutPoint(InsecureRand256(), 0) : vPrevouts[i];
        tx.vin[i].scriptSig = CScript() << OP_11;
    }
    tx.vout.resize(nOuts);
    for (CTxOut& out : tx.vout) {
        out.scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        out.nValue = nValue;
    }
    return tx;
}

static uint64_t Size(const CTransaction& tx) { return tx.GetTotalSize(); }

static const CTxMemPoolEntry& Entry(const CTxMemPool& pool, const uint256& hash)
{
    auto it = pool.mapTx.find(hash);
    BOOST_REQUIRE(it != pool.mapTx.end());
    return *it;
}

/** The delta stored for hash, as AcceptToMemoryPool would apply it */
static CAmount StoredDelta(const CTxMemPool& pool, const uint256& hash)
{
    CAmount nDelta = 0;
    pool.ApplyDelta(hash, nDelta);
    return nDelta;
}

/** Everything a fee delta or a re-link can change in an entry */
struct EntryState {
    CAmount nModFee, nModFeesWithAncestors, nModFeesWithDescendants;
    uint64_t nCountWithAncestors, nSizeWithAncestors, nCountWithDescendants, nSizeWithDescendants;
    int64_t nSigOpCostWithAncestors;

    EntryState(const CTxMemPool& pool, const uint256& hash)
    {
        const CTxMemPoolEntry& e = Entry(pool, hash);
        nModFee = e.GetModifiedFee();
        nModFeesWithAncestors = e.GetModFeesWithAncestors();
        nModFeesWithDescendants = e.GetModFeesWithDescendants();
        nCountWithAncestors = e.GetCountWithAncestors();
        nSizeWithAncestors = e.GetSizeWithAncestors();
        nCountWithDescendants = e.GetCountWithDescendants();
        nSizeWithDescendants = e.GetSizeWithDescendants();
        nSigOpCostWithAncestors = e.GetSigOpCostWithAncestors();
    }
};

static void CheckState(const EntryState& a, const EntryState& b)
{
    BOOST_CHECK_EQUAL(a.nModFee, b.nModFee);
    BOOST_CHECK_EQUAL(a.nModFeesWithAncestors, b.nModFeesWithAncestors);
    BOOST_CHECK_EQUAL(a.nModFeesWithDescendants, b.nModFeesWithDescendants);
    BOOST_CHECK_EQUAL(a.nCountWithAncestors, b.nCountWithAncestors);
    BOOST_CHECK_EQUAL(a.nSizeWithAncestors, b.nSizeWithAncestors);
    BOOST_CHECK_EQUAL(a.nCountWithDescendants, b.nCountWithDescendants);
    BOOST_CHECK_EQUAL(a.nSizeWithDescendants, b.nSizeWithDescendants);
    BOOST_CHECK_EQUAL(a.nSigOpCostWithAncestors, b.nSigOpCostWithAncestors);
}

/* A delta on an in-mempool tx moves its own modified fee, its ancestors' descendant
 * fees and its descendants' ancestor fees by the increment; sizes and counts stay */
BOOST_AUTO_TEST_CASE(MempoolPrioritiseInPoolTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CMutableTransaction txA = MakeTx({}, 10 * COIN);
    CMutableTransaction txB = MakeTx({COutPoint(txA.GetHash(), 0)}, 9 * COIN);
    CMutableTransaction txC = MakeTx({COutPoint(txB.GetHash(), 0)}, 8 * COIN);
    CMutableTransaction txX = MakeTx({}, 7 * COIN);
    const uint256 hashA = txA.GetHash(), hashB = txB.GetHash(), hashC = txC.GetHash(), hashX = txX.GetHash();
    pool.addUnchecked(hashA, entry.Fee(1000).FromTx(txA));
    pool.addUnchecked(hashB, entry.Fee(2000).FromTx(txB));
    pool.addUnchecked(hashC, entry.Fee(3000).FromTx(txC));
    pool.addUnchecked(hashX, entry.Fee(5000).FromTx(txX));
    const std::vector<uint256> hashes = {hashA, hashB, hashC, hashX};
    std::vector<EntryState> before;
    for (const uint256& hash : hashes) before.emplace_back(pool, hash);
    unsigned int nUpdated = pool.GetTransactionsUpdated();

    pool.PrioritiseTransaction(hashB, 500);
    BOOST_CHECK_EQUAL(pool.GetTransactionsUpdated(), nUpdated + 1);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModifiedFee(), 2500);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModFeesWithAncestors(), 1000 + 2500);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModFeesWithDescendants(), 2500 + 3000);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithAncestors(), 1000);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 1000 + 2500 + 3000);
    BOOST_CHECK_EQUAL(Entry(pool, hashC).GetModFeesWithAncestors(), 1000 + 2500 + 3000);
    BOOST_CHECK_EQUAL(Entry(pool, hashC).GetModFeesWithDescendants(), 3000);
    CheckState(EntryState(pool, hashX), before[3]);
    BOOST_CHECK_EQUAL(StoredDelta(pool, hashB), 500);
    // getmempoolinfo-style data reports the real fee rate and the delta separately
    TxMempoolInfo info = pool.info(hashB);
    BOOST_CHECK_EQUAL(info.nFeeDelta, 500);
    BOOST_CHECK(info.feeRate == CFeeRate(2000, Size(txB)));

    // Deltas accumulate, and the state returns exactly to the original at a sum of zero
    pool.PrioritiseTransaction(hashB, -200);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 1000 + 2300 + 3000);
    BOOST_CHECK_EQUAL(Entry(pool, hashC).GetModFeesWithAncestors(), 1000 + 2300 + 3000);
    pool.PrioritiseTransaction(hashB, -300);
    for (size_t i = 0; i < hashes.size(); i++) CheckState(EntryState(pool, hashes[i]), before[i]);
    BOOST_CHECK_EQUAL(StoredDelta(pool, hashB), 0);

    // Root: no ancestors to update; leaf: no descendants to update
    pool.PrioritiseTransaction(hashA, 100);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithAncestors(), 1100);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 6100);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModFeesWithAncestors(), 3100);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModFeesWithDescendants(), 5000);
    BOOST_CHECK_EQUAL(Entry(pool, hashC).GetModFeesWithAncestors(), 6100);
    pool.PrioritiseTransaction(hashC, 10);
    BOOST_CHECK_EQUAL(Entry(pool, hashC).GetModFeesWithAncestors(), 6110);
    BOOST_CHECK_EQUAL(Entry(pool, hashC).GetModFeesWithDescendants(), 3010);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModFeesWithDescendants(), 5010);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 6110);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithAncestors(), 1100);

    // Diamond R -> L, R -> M, (L, M) -> D: the shared relative is updated only once
    CTxMemPool diamond;
    CMutableTransaction txR = MakeTx({}, 10 * COIN, 2);
    CMutableTransaction txL = MakeTx({COutPoint(txR.GetHash(), 0)}, 9 * COIN);
    CMutableTransaction txM = MakeTx({COutPoint(txR.GetHash(), 1)}, 8 * COIN);
    CMutableTransaction txD = MakeTx({COutPoint(txL.GetHash(), 0), COutPoint(txM.GetHash(), 0)}, 7 * COIN);
    for (const CMutableTransaction& tx : {txR, txL, txM, txD})
        diamond.addUnchecked(tx.GetHash(), entry.Fee(1000).FromTx(tx));
    diamond.PrioritiseTransaction(txR.GetHash(), 1000);
    BOOST_CHECK_EQUAL(Entry(diamond, txD.GetHash()).GetModFeesWithAncestors(), 5000);
    BOOST_CHECK_EQUAL(Entry(diamond, txL.GetHash()).GetModFeesWithAncestors(), 3000);
    BOOST_CHECK_EQUAL(Entry(diamond, txR.GetHash()).GetModFeesWithDescendants(), 5000);
    diamond.PrioritiseTransaction(txD.GetHash(), 1000);
    BOOST_CHECK_EQUAL(Entry(diamond, txR.GetHash()).GetModFeesWithDescendants(), 6000);
    BOOST_CHECK_EQUAL(Entry(diamond, txM.GetHash()).GetModFeesWithDescendants(), 3000);
    BOOST_CHECK_EQUAL(Entry(diamond, txD.GetHash()).GetModFeesWithAncestors(), 6000);
}

/* A delta set before the tx arrives is stored and applied when it enters the mempool */
BOOST_AUTO_TEST_CASE(MempoolPrioritiseBeforeEntryTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CMutableTransaction txA = MakeTx({}, 10 * COIN, 2);
    CMutableTransaction txB = MakeTx({COutPoint(txA.GetHash(), 0)}, 9 * COIN);
    CMutableTransaction txC = MakeTx({COutPoint(txA.GetHash(), 1)}, 8 * COIN);
    const uint256 hashA = txA.GetHash(), hashB = txB.GetHash(), hashC = txC.GetHash();

    CAmount nFee = 1000;
    pool.ApplyDelta(hashB, nFee);
    BOOST_CHECK_EQUAL(nFee, 1000);
    unsigned int nUpdated = pool.GetTransactionsUpdated();
    pool.PrioritiseTransaction(hashB, 700);
    BOOST_CHECK_EQUAL(pool.size(), 0U);
    BOOST_CHECK_EQUAL(pool.GetTransactionsUpdated(), nUpdated);
    pool.ApplyDelta(hashB, nFee);
    BOOST_CHECK_EQUAL(nFee, 1700);

    pool.addUnchecked(hashA, entry.Fee(1000).FromTx(txA));
    pool.addUnchecked(hashB, entry.Fee(2000).FromTx(txB));
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModifiedFee(), 2700);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModFeesWithAncestors(), 1000 + 2700);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 1000 + 2700);
    BOOST_CHECK_EQUAL(pool.info(hashB).nFeeDelta, 700);

    // More after entry adds to the stored delta
    pool.PrioritiseTransaction(hashB, 100);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModifiedFee(), 2800);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 1000 + 2800);
    BOOST_CHECK_EQUAL(StoredDelta(pool, hashB), 800);

    // Deltas that cancel out before entry leave the fee as it is
    pool.PrioritiseTransaction(hashC, 700);
    pool.PrioritiseTransaction(hashC, -700);
    pool.addUnchecked(hashC, entry.Fee(3000).FromTx(txC));
    BOOST_CHECK_EQUAL(Entry(pool, hashC).GetModifiedFee(), 3000);
    BOOST_CHECK_EQUAL(Entry(pool, hashC).GetModFeesWithAncestors(), 1000 + 3000);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 1000 + 2800 + 3000);

    // Clearing forgets the stored delta but doesn't reprice a tx still in the mempool
    // (it is called for txs that leave it)
    pool.ClearPrioritisation(hashB);
    BOOST_CHECK_EQUAL(StoredDelta(pool, hashB), 0);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModifiedFee(), 2800);
    // Clearing an unknown hash leaves other deltas alone
    pool.PrioritiseTransaction(hashA, 5);
    pool.ClearPrioritisation(InsecureRand256());
    BOOST_CHECK_EQUAL(StoredDelta(pool, hashA), 5);
}

/* Removal paths: a removed tx keeps its delta unless it was mined or conflicted */
BOOST_AUTO_TEST_CASE(MempoolPrioritiseRemovalTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CMutableTransaction txA = MakeTx({}, 10 * COIN);
    CMutableTransaction txB = MakeTx({COutPoint(txA.GetHash(), 0)}, 9 * COIN);
    const uint256 hashA = txA.GetHash(), hashB = txB.GetHash();
    pool.addUnchecked(hashA, entry.Fee(1000).FromTx(txA));
    pool.addUnchecked(hashB, entry.Fee(2000).FromTx(txB));
    pool.PrioritiseTransaction(hashB, 300);
    CTransactionRef refB = Entry(pool, hashB).GetSharedTx();

    // Removed (e.g. a reorg that drops it): the delta stays for when it comes back
    pool.removeRecursive(*refB);
    BOOST_CHECK_EQUAL(pool.size(), 1U);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 1000);
    BOOST_CHECK_EQUAL(StoredDelta(pool, hashB), 300);
    pool.addUnchecked(hashB, CTxMemPoolEntry(refB, 2000, 0, 1, false, 4, LockPoints()));
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModifiedFee(), 2300);
    BOOST_CHECK_EQUAL(Entry(pool, hashA).GetModFeesWithDescendants(), 1000 + 2300);

    // Mined: the delta goes, also for a block tx that was never in the mempool, and the
    // child's ancestor state loses exactly the parent's modified fee
    CMutableTransaction txU = MakeTx({}, 5 * COIN);
    pool.PrioritiseTransaction(hashA, 400);
    pool.PrioritiseTransaction(txU.GetHash(), 50);
    pool.removeForBlock({CTransaction(txA), CTransaction(txU)});
    BOOST_CHECK(!pool.exists(hashA));
    BOOST_CHECK_EQUAL(StoredDelta(pool, hashA), 0);
    BOOST_CHECK_EQUAL(StoredDelta(pool, txU.GetHash()), 0);
    BOOST_CHECK_EQUAL(StoredDelta(pool, hashB), 300);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetCountWithAncestors(), 1U);
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetSizeWithAncestors(), Size(txB));
    BOOST_CHECK_EQUAL(Entry(pool, hashB).GetModFeesWithAncestors(), 2300);

    // Conflict: T and its child T2 lose to T', which spends T's input; only the delta of
    // the directly conflicting tx goes
    CMutableTransaction txT = MakeTx({}, 4 * COIN);
    CMutableTransaction txT2 = MakeTx({COutPoint(txT.GetHash(), 0)}, 3 * COIN);
    CMutableTransaction txT1 = MakeTx({txT.vin[0].prevout}, 2 * COIN);
    pool.addUnchecked(txT.GetHash(), entry.Fee(1000).FromTx(txT));
    pool.addUnchecked(txT2.GetHash(), entry.Fee(1000).FromTx(txT2));
    pool.PrioritiseTransaction(txT.GetHash(), 100);
    pool.PrioritiseTransaction(txT2.GetHash(), 200);
    pool.PrioritiseTransaction(txT1.GetHash(), 5);
    // A tx doesn't conflict with itself
    pool.removeConflicts(txT);
    BOOST_CHECK_EQUAL(pool.size(), 3U);
    BOOST_CHECK_EQUAL(StoredDelta(pool, txT.GetHash()), 100);
    pool.removeForBlock({CTransaction(txT1)});
    BOOST_CHECK_EQUAL(pool.size(), 1U);
    BOOST_CHECK(!pool.exists(txT.GetHash()));
    BOOST_CHECK(!pool.exists(txT2.GetHash()));
    BOOST_CHECK_EQUAL(StoredDelta(pool, txT.GetHash()), 0);
    BOOST_CHECK_EQUAL(StoredDelta(pool, txT1.GetHash()), 0);
    BOOST_CHECK_EQUAL(StoredDelta(pool, txT2.GetHash()), 200);
}

/* The mining, ancestor and descendant score indexes use the modified fee */
BOOST_AUTO_TEST_CASE(MempoolPrioritiseSortTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CMutableTransaction tx1 = MakeTx({}, 1 * COIN), tx2 = MakeTx({}, 2 * COIN), tx3 = MakeTx({}, 3 * COIN);
    pool.addUnchecked(tx1.GetHash(), entry.Fee(1000).Time(1).FromTx(tx1));
    pool.addUnchecked(tx2.GetHash(), entry.Fee(2000).Time(2).FromTx(tx2));
    pool.addUnchecked(tx3.GetHash(), entry.Fee(3000).Time(3).FromTx(tx3));
    const std::string s1 = tx1.GetHash().ToString(), s2 = tx2.GetHash().ToString(), s3 = tx3.GetHash().ToString();
    std::vector<std::string> order = {s3, s2, s1};
    CheckSort<mining_score>(pool, order);

    pool.PrioritiseTransaction(tx1.GetHash(), 2500);
    order = {s1, s3, s2};
    CheckSort<mining_score>(pool, order);
    CheckSort<ancestor_score>(pool, order);
    order = {s2, s3, s1}; // ascending
    CheckSort<descendant_score>(pool, order);

    // A negative modified fee is allowed and sorts last
    pool.PrioritiseTransaction(tx3.GetHash(), -4000);
    BOOST_CHECK_EQUAL(Entry(pool, tx3.GetHash()).GetModifiedFee(), -1000);
    order = {s1, s2, s3};
    CheckSort<mining_score>(pool, order);

    // A child's delta counts in its parent's descendant score and in its own ancestor score
    CTxMemPool family;
    CMutableTransaction txP = MakeTx({}, 4 * COIN);
    CMutableTransaction txC = MakeTx({COutPoint(txP.GetHash(), 0)}, 3 * COIN);
    CMutableTransaction txQ = MakeTx({}, 5 * COIN);
    family.addUnchecked(txP.GetHash(), entry.Fee(0).Time(1).FromTx(txP));
    family.addUnchecked(txC.GetHash(), entry.Fee(0).Time(2).FromTx(txC));
    family.addUnchecked(txQ.GetHash(), entry.Fee(2000).Time(3).FromTx(txQ));
    family.PrioritiseTransaction(txC.GetHash(), 10000);
    const std::string sP = txP.GetHash().ToString(), sC = txC.GetHash().ToString(), sQ = txQ.GetHash().ToString();
    order = {sQ, sP, sC}; // P: 10000 / (2 sizes) beats Q: 2000 / (1 size)
    CheckSort<descendant_score>(family, order);
    order = {sC, sQ, sP};
    CheckSort<ancestor_score>(family, order);
}

/* queryHashes and infoAll list parents before children, then by modified fee rate */
BOOST_AUTO_TEST_CASE(MempoolDepthAndScoreTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    std::vector<uint256> vtxid(3, InsecureRand256());
    pool.queryHashes(vtxid);
    BOOST_CHECK(vtxid.empty());
    BOOST_CHECK(pool.infoAll().empty());

    CMutableTransaction txA = MakeTx({}, 10 * COIN);
    CMutableTransaction txB = MakeTx({COutPoint(txA.GetHash(), 0)}, 9 * COIN);
    CMutableTransaction txX = MakeTx({}, 8 * COIN), txY = MakeTx({}, 7 * COIN);
    const uint256 hashA = txA.GetHash(), hashB = txB.GetHash(), missing = InsecureRand256();
    pool.addUnchecked(hashA, entry.Fee(1000).Time(1).FromTx(txA));
    pool.addUnchecked(hashB, entry.Fee(50000).Time(2).FromTx(txB));
    pool.addUnchecked(txX.GetHash(), entry.Fee(2000).Time(3).FromTx(txX));
    pool.addUnchecked(txY.GetHash(), entry.Fee(2000).Time(4).FromTx(txY));
    // X and Y have the same fee rate: the larger hash comes first
    const bool fXLower = txX.GetHash() < txY.GetHash();
    const uint256 hi = fXLower ? txY.GetHash() : txX.GetHash(), lo = fXLower ? txX.GetHash() : txY.GetHash();

    pool.queryHashes(vtxid);
    BOOST_CHECK(vtxid == std::vector<uint256>({hi, lo, hashA, hashB}));
    BOOST_CHECK(pool.CompareDepthAndScore(hashA, hashB));
    BOOST_CHECK(!pool.CompareDepthAndScore(hashB, hashA)); // B pays more, but needs A
    BOOST_CHECK(pool.CompareDepthAndScore(hi, hashA));
    BOOST_CHECK(!pool.CompareDepthAndScore(hashA, hi));
    BOOST_CHECK(pool.CompareDepthAndScore(hi, lo));
    BOOST_CHECK(!pool.CompareDepthAndScore(lo, hi));
    BOOST_CHECK(!pool.CompareDepthAndScore(hashA, hashA));
    BOOST_CHECK(!pool.CompareDepthAndScore(missing, hashA));
    BOOST_CHECK(pool.CompareDepthAndScore(hashA, missing));
    BOOST_CHECK(!pool.CompareDepthAndScore(missing, missing));

    // A delta that makes A tie with X and Y puts the three in hash order
    pool.PrioritiseTransaction(hashA, 1000);
    std::vector<uint256> tied = {hashA, hi, lo};
    std::sort(tied.begin(), tied.end(), [](const uint256& a, const uint256& b) { return b < a; });
    tied.push_back(hashB);
    pool.queryHashes(vtxid);
    BOOST_CHECK(vtxid == tied);
    BOOST_CHECK_EQUAL(pool.CompareDepthAndScore(hashA, hi), hi < hashA);

    pool.PrioritiseTransaction(hashA, 4000);
    pool.queryHashes(vtxid);
    BOOST_CHECK(vtxid == std::vector<uint256>({hashA, hi, lo, hashB}));
    BOOST_CHECK(pool.CompareDepthAndScore(hashA, hi));

    std::vector<TxMempoolInfo> infos = pool.infoAll();
    BOOST_REQUIRE_EQUAL(infos.size(), vtxid.size());
    for (size_t i = 0; i < infos.size(); i++) {
        const CTxMemPoolEntry& e = Entry(pool, vtxid[i]);
        BOOST_CHECK(infos[i].tx == e.GetSharedTx());
        BOOST_CHECK_EQUAL(infos[i].nTime, e.GetTime());
        BOOST_CHECK(infos[i].feeRate == CFeeRate(e.GetFee(), e.GetTxSize()));
        BOOST_CHECK_EQUAL(infos[i].nFeeDelta, vtxid[i] == hashA ? 5000 : 0);
    }
    BOOST_CHECK_EQUAL(infos[0].nTime, 1);
    BOOST_CHECK(pool.info(missing).tx == nullptr);
}

/* Each chain limit of CalculateMemPoolAncestors, just over and exactly at the limit */
BOOST_AUTO_TEST_CASE(MempoolAncestorLimitsTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CMutableTransaction txA = MakeTx({}, 10 * COIN);
    CMutableTransaction txB = MakeTx({COutPoint(txA.GetHash(), 0)}, 9 * COIN);
    CMutableTransaction txC = MakeTx({COutPoint(txB.GetHash(), 0)}, 8 * COIN);
    CMutableTransaction txD = MakeTx({COutPoint(txC.GetHash(), 0)}, 7 * COIN);
    for (const CMutableTransaction& tx : {txA, txB, txC})
        pool.addUnchecked(tx.GetHash(), entry.FromTx(tx));
    const CTxMemPoolEntry entryD = entry.FromTx(txD);
    const uint64_t nSum = Size(txA) + Size(txB) + Size(txC) + Size(txD);
    const uint64_t nMax = std::numeric_limits<uint64_t>::max();
    const std::string strA = txA.GetHash().ToString();

    std::string err;
    CTxMemPool::setEntries ancestors;
    auto Calc = [&](const CTxMemPoolEntry& e, uint64_t nAncCount, uint64_t nAncSize, uint64_t nDescCount, uint64_t nDescSize) {
        ancestors.clear();
        err.clear();
        return pool.CalculateMemPoolAncestors(e, ancestors, nAncCount, nAncSize, nDescCount, nDescSize, err);
    };
    BOOST_CHECK(Calc(entryD, nMax, nMax, nMax, nMax));
    BOOST_CHECK_EQUAL(ancestors.size(), 3U);
    BOOST_CHECK(ancestors.count(pool.mapTx.find(txA.GetHash())));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!Calc(entryD, 1, nMax, nMax, nMax));
    BOOST_CHECK_EQUAL(err, "too many unconfirmed parents [limit: 1]");
    BOOST_CHECK(!Calc(entryD, 3, nMax, nMax, nMax));
    BOOST_CHECK_EQUAL(err, "too many unconfirmed ancestors [limit: 3]");
    BOOST_CHECK(Calc(entryD, 4, nMax, nMax, nMax));
    // The limits are checked for every ancestor; here A, the furthest, is the first to fail
    BOOST_CHECK(!Calc(entryD, nMax, nMax, nMax, nSum - 1));
    BOOST_CHECK_EQUAL(err, strprintf("exceeds descendant size limit for tx %s [limit: %u]", strA, nSum - 1));
    BOOST_CHECK(Calc(entryD, nMax, nMax, nMax, nSum));
    BOOST_CHECK(!Calc(entryD, nMax, nMax, 3, nMax));
    BOOST_CHECK_EQUAL(err, strprintf("too many descendants for tx %s [limit: 3]", strA));
    BOOST_CHECK(Calc(entryD, nMax, nMax, 4, nMax));
    BOOST_CHECK(!Calc(entryD, nMax, nSum - 1, nMax, nMax));
    BOOST_CHECK_EQUAL(err, strprintf("exceeds ancestor size limit [limit: %u]", nSum - 1));
    BOOST_CHECK(Calc(entryD, nMax, nSum, nMax, nMax));

    // Direct parents: two different ones count twice, two outputs of one parent once
    CMutableTransaction txR1 = MakeTx({}, 6 * COIN), txR2 = MakeTx({}, 5 * COIN), txR3 = MakeTx({}, 4 * COIN, 2);
    for (const CMutableTransaction& tx : {txR1, txR2, txR3})
        pool.addUnchecked(tx.GetHash(), entry.FromTx(tx));
    const CTxMemPoolEntry entryE = entry.FromTx(MakeTx({COutPoint(txR1.GetHash(), 0), COutPoint(txR2.GetHash(), 0)}, 3 * COIN));
    BOOST_CHECK(!Calc(entryE, 2, nMax, nMax, nMax));
    BOOST_CHECK_EQUAL(err, "too many unconfirmed parents [limit: 2]");
    BOOST_CHECK(Calc(entryE, 3, nMax, nMax, nMax));
    const CTxMemPoolEntry entryF = entry.FromTx(MakeTx({COutPoint(txR3.GetHash(), 0), COutPoint(txR3.GetHash(), 1)}, 2 * COIN));
    BOOST_CHECK(Calc(entryF, 2, nMax, nMax, nMax));
    BOOST_CHECK_EQUAL(ancestors.size(), 1U);
}

/* Descendant walks, input and chain-limit queries, and mempool coins seen through
 * CCoinsViewMemPool */
BOOST_AUTO_TEST_CASE(MempoolQueryHelpersTest)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;
    CMutableTransaction txA = MakeTx({}, 10 * COIN);
    CMutableTransaction txB = MakeTx({COutPoint(txA.GetHash(), 0)}, 9 * COIN);
    pool.addUnchecked(txA.GetHash(), entry.FromTx(txA));
    pool.addUnchecked(txB.GetHash(), entry.FromTx(txB));
    CTxMemPool::txiter itA = pool.mapTx.find(txA.GetHash()), itB = pool.mapTx.find(txB.GetHash());

    // CalculateDescendants doesn't walk what the set already holds
    CTxMemPool::setEntries descendants = {itA};
    pool.CalculateDescendants(itA, descendants);
    BOOST_CHECK(descendants == CTxMemPool::setEntries({itA}));
    descendants = {itB};
    pool.CalculateDescendants(itA, descendants);
    BOOST_CHECK(descendants == CTxMemPool::setEntries({itA, itB}));

    BOOST_CHECK(pool.HasNoInputsOf(CMutableTransaction()));
    BOOST_CHECK(pool.HasNoInputsOf(MakeTx({}, COIN)));
    BOOST_CHECK(!pool.HasNoInputsOf(MakeTx({COutPoint(InsecureRand256(), 0), COutPoint(txA.GetHash(), 0)}, COIN)));

    // Both the ancestor and the descendant count must be below the limit
    BOOST_CHECK(pool.TransactionWithinChainLimit(InsecureRand256(), 2));
    BOOST_CHECK(!pool.TransactionWithinChainLimit(txB.GetHash(), 2));
    BOOST_CHECK(!pool.TransactionWithinChainLimit(txA.GetHash(), 2));
    BOOST_CHECK(pool.TransactionWithinChainLimit(txA.GetHash(), 3));

    // Mempool outputs are visible as coins at MEMPOOL_HEIGHT; others come from the base view
    CCoinsView base;
    CCoinsViewMemPool view(&base, pool);
    Coin coin;
    BOOST_CHECK(view.GetCoin(COutPoint(txA.GetHash(), 0), coin));
    BOOST_CHECK(coin.out == txA.vout[0]);
    BOOST_CHECK(coin.nHeight == MEMPOOL_HEIGHT);
    BOOST_CHECK(!coin.IsCoinBase());
    BOOST_CHECK(!view.GetCoin(COutPoint(txA.GetHash(), 1), coin));
    BOOST_CHECK(!view.GetCoin(COutPoint(InsecureRand256(), 0), coin));
}

/* Txs of a disconnected block re-enter after their in-mempool children: afterwards the
 * state must be as if everything had arrived in order */
BOOST_AUTO_TEST_CASE(MempoolUpdateTransactionsFromBlockTest)
{
    TestMemPoolEntryHelper entry;
    CMutableTransaction txP1 = MakeTx({}, 10 * COIN, 2);
    CMutableTransaction txP2 = MakeTx({COutPoint(txP1.GetHash(), 0)}, 9 * COIN);
    CMutableTransaction txP3 = MakeTx({COutPoint(txP2.GetHash(), 0)}, 8 * COIN);
    CMutableTransaction txC = MakeTx({COutPoint(txP3.GetHash(), 0)}, 7 * COIN);
    CMutableTransaction txC2 = MakeTx({COutPoint(txP1.GetHash(), 1)}, 6 * COIN);
    const std::vector<CMutableTransaction> inOrder = {txP1, txP2, txP3, txC, txC2};

    CTxMemPool reference, reorg;
    // Deltas on a block tx and on an outside child: both pools must sum modified fees
    for (CTxMemPool* pool : {&reference, &reorg}) {
        pool->PrioritiseTransaction(txP2.GetHash(), 600);
        pool->PrioritiseTransaction(txC.GetHash(), 70);
    }
    for (size_t i : {0, 1, 2, 3, 4})
        reference.addUnchecked(inOrder[i].GetHash(), entry.Fee(1000 * (i + 1)).FromTx(inOrder[i]));
    for (size_t i : {3, 4, 0, 1, 2}) // the children first, as during a reorg
        reorg.addUnchecked(inOrder[i].GetHash(), entry.Fee(1000 * (i + 1)).FromTx(inOrder[i]));
    // A block tx that didn't make it back into the mempool is skipped
    reorg.UpdateTransactionsFromBlock({txP1.GetHash(), txP2.GetHash(), txP3.GetHash(), InsecureRand256()});

    for (const CMutableTransaction& tx : inOrder)
        CheckState(EntryState(reorg, tx.GetHash()), EntryState(reference, tx.GetHash()));
    BOOST_CHECK_EQUAL(Entry(reorg, txC.GetHash()).GetCountWithAncestors(), 4U);
    BOOST_CHECK_EQUAL(Entry(reorg, txP1.GetHash()).GetCountWithDescendants(), 5U);
    CTxMemPool::txiter itP3 = reorg.mapTx.find(txP3.GetHash()), itC = reorg.mapTx.find(txC.GetHash());
    BOOST_CHECK(reorg.GetMemPoolChildren(itP3) == CTxMemPool::setEntries({itC}));
    BOOST_CHECK(reorg.GetMemPoolParents(itC) == CTxMemPool::setEntries({itP3}));
    BOOST_CHECK_EQUAL(reorg.GetMemPoolChildren(reorg.mapTx.find(txP1.GetHash())).size(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
