// Copyright (c) 2015-2016 The Bitcoin Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// YACoin computes merkle roots with CBlock::BuildMerkleTree (there is no
// consensus/merkle.h), so Bitcoin's comparison of the old and new code is
// replaced by a comparison with a small reference implementation here.

#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "random.h"
#include "validation.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(merkle_tests, BasicTestingSetup)

/** Reference merkle root: hash pairs level by level, pairing an odd last hash with itself */
static uint256 ReferenceMerkleRoot(std::vector<uint256> level)
{
    if (level.empty()) return uint256();
    while (level.size() > 1) {
        if (level.size() % 2) level.push_back(level.back());
        std::vector<uint256> next;
        for (size_t i = 0; i < level.size(); i += 2)
            next.push_back(Hash(level[i].begin(), level[i].end(), level[i + 1].begin(), level[i + 1].end()));
        level = next;
    }
    return level[0];
}

static std::vector<uint256> TxHashes(const CBlock& block)
{
    std::vector<uint256> hashes;
    for (const CTransaction& tx : block.vtx) hashes.push_back(tx.GetHash());
    return hashes;
}

static inline int ctz(uint32_t i) {
    if (i == 0) return 0;
    int j = 0;
    while (!(i & 1)) {
        j++;
        i >>= 1;
    }
    return j;
}

BOOST_AUTO_TEST_CASE(merkle_test)
{
    for (int i = 0; i < 32; i++) {
        // Try 32 block sizes: all sizes from 0 to 16 inclusive, and then 15 random sizes.
        int ntx = (i <= 16) ? i : 17 + (InsecureRandRange(4000));
        // Try up to 3 mutations.
        for (int mutate = 0; mutate <= 3; mutate++) {
            int duplicate1 = mutate >= 1 ? 1 << ctz(ntx) : 0; // The last how many transactions to duplicate first.
            if (duplicate1 >= ntx) break; // Duplication of the entire tree results in a different root (it adds a level).
            int ntx1 = ntx + duplicate1; // The resulting number of transactions after the first duplication.
            int duplicate2 = mutate >= 2 ? 1 << ctz(ntx1) : 0; // Likewise for the second mutation.
            if (duplicate2 >= ntx1) break;
            int ntx2 = ntx1 + duplicate2;
            int duplicate3 = mutate >= 3 ? 1 << ctz(ntx2) : 0; // And for the third mutation.
            if (duplicate3 >= ntx2) break;
            int ntx3 = ntx2 + duplicate3;
            // Build a block with ntx different transactions.
            CBlock block;
            block.vtx.resize(ntx);
            for (int j = 0; j < ntx; j++) {
                CMutableTransaction mtx;
                mtx.nLockTime = j;
                block.vtx[j] = CTransaction(mtx);
            }
            // Compute the root of the block before mutating it.
            uint256 unmutatedRoot = block.BuildMerkleTree();
            BOOST_CHECK(unmutatedRoot == ReferenceMerkleRoot(TxHashes(block)));
            // Optionally mutate by duplicating the last transactions, resulting in the same merkle root
            // (CVE-2012-2459: CheckBlock rejects such blocks as duplicate transactions instead).
            block.vtx.resize(ntx3);
            for (int j = 0; j < duplicate1; j++) {
                block.vtx[ntx + j] = block.vtx[ntx + j - duplicate1];
            }
            for (int j = 0; j < duplicate2; j++) {
                block.vtx[ntx1 + j] = block.vtx[ntx1 + j - duplicate2];
            }
            for (int j = 0; j < duplicate3; j++) {
                block.vtx[ntx2 + j] = block.vtx[ntx2 + j - duplicate3];
            }
            uint256 root = block.BuildMerkleTree();
            BOOST_CHECK(root == ReferenceMerkleRoot(TxHashes(block)));
            BOOST_CHECK(root == unmutatedRoot);
            BOOST_CHECK((root == uint256()) == (ntx == 0));
            // If no mutation was done (once for every ntx value), try up to 16 branches.
            if (mutate == 0) {
                for (int loop = 0; loop < std::min(ntx, 16); loop++) {
                    // If ntx <= 16, try all branches. Otherwise, try 16 random ones.
                    int mtx = loop;
                    if (ntx > 16) {
                        mtx = InsecureRandRange(ntx);
                    }
                    std::vector<uint256> branch = block.GetMerkleBranch(mtx);
                    BOOST_CHECK(CBlock::CheckMerkleBranch(block.vtx[mtx].GetHash(), branch, mtx) == root);
                    // The branch doesn't prove a different transaction
                    if (ntx > 1) {
                        int other = (mtx + 1) % ntx;
                        BOOST_CHECK(CBlock::CheckMerkleBranch(block.vtx[other].GetHash(), branch, mtx) != root);
                    }
                }
            }
        }
    }
    BOOST_CHECK(CBlock::CheckMerkleBranch(uint256S("0x01"), {}, -1) == uint256());
}

BOOST_AUTO_TEST_CASE(genesis_merkle_root)
{
    for (const std::string& chain : {CBaseChainParams::MAIN, CBaseChainParams::REGTEST}) {
        const auto params = CreateChainParams(chain);
        CBlock genesis = params->GenesisBlock();
        BOOST_CHECK(genesis.BuildMerkleTree() == uint256S("0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f"));
        BOOST_CHECK(genesis.hashMerkleRoot == genesis.BuildMerkleTree());
    }
}

/** A minimal block that passes CheckBlock without proof of work: coinbase plus n spends */
static CBlock BlockWithTxs(int nTxs)
{
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig = CScript() << OP_1 << OP_2;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = COIN;
    block.vtx.push_back(CTransaction(coinbase));
    for (int i = 0; i < nTxs; i++) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(InsecureRand256(), 0);
        tx.vout.resize(1);
        tx.vout[0].nValue = COIN;
        tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        block.vtx.push_back(CTransaction(tx));
    }
    block.nTime = block.GetMaxTransactionTime();
    block.hashMerkleRoot = block.BuildMerkleTree();
    return block;
}

/* The merkle root can't tell a block from one with its last transactions
 * duplicated; CheckBlock has to catch that, without marking the header invalid */
BOOST_AUTO_TEST_CASE(check_block_merkle_and_duplicates)
{
    const Consensus::Params& params = Params().GetConsensus();
    CBlock block = BlockWithTxs(2); // 3 transactions
    CValidationState state;
    BOOST_CHECK(CheckBlock(block, state, params, false, true));

    CBlock mutated = block;
    mutated.vtx.push_back(mutated.vtx.back());
    BOOST_CHECK(mutated.BuildMerkleTree() == block.hashMerkleRoot);
    CValidationState stateDup;
    BOOST_CHECK(!CheckBlock(mutated, stateDup, params, false, true));
    BOOST_CHECK_EQUAL(stateDup.GetRejectReason(), "bad-txns-duplicate");
    BOOST_CHECK(stateDup.CorruptionPossible());

    CBlock badRoot = block;
    badRoot.hashMerkleRoot = InsecureRand256();
    CValidationState stateRoot;
    BOOST_CHECK(!CheckBlock(badRoot, stateRoot, params, false, true));
    BOOST_CHECK_EQUAL(stateRoot.GetRejectReason(), "bad-txnmrklroot");
    BOOST_CHECK(stateRoot.CorruptionPossible());
    // Without the merkle check the wrong root isn't noticed
    CValidationState stateNoCheck;
    BOOST_CHECK(CheckBlock(badRoot, stateNoCheck, params, false, false));
}

BOOST_AUTO_TEST_SUITE_END()
