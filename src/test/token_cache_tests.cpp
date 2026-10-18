// Copyright (c) 2017-2019 The Raven Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Token cache tests: connecting token transactions (AddCoins, as ConnectBlock
// does) and undoing them again (the token part of DisconnectBlock), in memory
// and after the cache was written to the token database. Reissue and LRU
// cases are adapted from Ravencoin's asset_reissue_tests and cache_tests.

#include "coins.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"

#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <boost/test/unit_test.hpp>

struct TokenCacheSetup : public TokenTestingSetup {
    /** Fresh token state with the token index on or off (it is off by default on nodes) */
    void ResetTokens(bool fIndex)
    {
        fTokenIndex = fIndex;
        ClearTokenGlobals();
        ResetTokenDb();
        ptokensCache->Clear();
    }
};

BOOST_FIXTURE_TEST_SUITE(token_cache_tests, TokenCacheSetup)

static const uint256 BLOCK_HASH = uint256S("0xb10c");
static const int BLOCK_HEIGHT = 10;

/** Token coins a tx spends; spending and restoring them is part of connecting and disconnecting it */
typedef std::vector<std::pair<COutPoint, CTxOut> > SpentCoins;

/** The owner token output of the tx builders in token_test_util.h (always output 1) */
static SpentCoins OwnerCoin(const CTransaction& tx)
{
    return {std::make_pair(COutPoint(tx.GetHash(), 1), tx.vout[1])};
}

/** Token side of ConnectBlock for one tx: spend its token inputs (SpendCoin),
 * then AddCoins with the token cache, collecting reissue undo data.
 * ConnectTokenTx and DisconnectTokenTx are hand copies of validation.cpp
 * (ConnectBlock, DisconnectBlock, ApplyTxInUndo): keep them in sync with it. */
static void ConnectTokenTx(CTokensCache& cache, const CTransaction& tx, std::vector<std::pair<std::string, CBlockTokenUndo> >& vUndo, const SpentCoins& vSpent = {})
{
    for (const auto& spent : vSpent)
        BOOST_CHECK(cache.TrySpendCoin(spent.first, spent.second));
    CCoinsView base;
    CCoinsViewCache view(&base);
    std::pair<std::string, CBlockTokenUndo> undo = std::make_pair("", CBlockTokenUndo());
    AddCoins(view, tx, BLOCK_HEIGHT, BLOCK_HASH, false, &cache, &undo);
    if (!undo.first.empty())
        vUndo.push_back(undo);
}

/** Token side of DisconnectBlock for one tx (mirrors validation.cpp DisconnectBlock):
 * undo its token outputs, then give back the token inputs it spent (ApplyTxInUndo).
 * DisconnectBlock also spends the tx's own outputs, but into a throwaway copy of
 * the cache (tempCache), so that has no effect on the token state and is left out. */
static bool DisconnectTokenTx(CTokensCache& cache, const CTransaction& tx, const std::vector<std::pair<std::string, CBlockTokenUndo> >& vUndo, const SpentCoins& vSpent = {})
{
    std::string strAddress;
    if (tx.IsNewToken()) {
        CNewToken token;
        if (!TokenFromTransaction(tx, token, strAddress)) return false;
        if (cache.ContainsToken(token) && !cache.RemoveNewToken(token, strAddress)) return false;
        std::string ownerName, ownerAddress;
        if (!OwnerFromTransaction(tx, ownerName, ownerAddress)) return false;
        if (!cache.RemoveOwnerToken(ownerName, ownerAddress)) return false;
    } else if (tx.IsReissueToken()) {
        CReissueToken reissue;
        if (!ReissueTokenFromTransaction(tx, reissue, strAddress)) return false;
        if (cache.ContainsToken(reissue.strName) &&
            !cache.RemoveReissueToken(reissue, strAddress, COutPoint(tx.GetHash(), tx.vout.size() - 1), vUndo))
            return false;
    } else if (tx.IsNewUniqueToken()) {
        for (const CTxOut& out : tx.vout) {
            CNewToken token;
            if (IsScriptNewUniqueToken(out.scriptPubKey)) {
                if (!TokenFromScript(out.scriptPubKey, token, strAddress)) return false;
                if (cache.ContainsToken(token.strName) && !cache.RemoveNewToken(token, strAddress)) return false;
            }
        }
    }
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        CTokenTransfer transfer;
        if (IsScriptTransferToken(tx.vout[i].scriptPubKey)) {
            if (!TransferTokenFromScript(tx.vout[i].scriptPubKey, transfer, strAddress)) return false;
            if (!cache.RemoveTransfer(transfer, strAddress, COutPoint(tx.GetHash(), i))) return false;
        }
    }
    for (auto it = vSpent.rbegin(); it != vSpent.rend(); ++it) {
        if (!cache.UndoTokenCoin(Coin(it->second, BLOCK_HEIGHT, false, false, 0), it->first)) return false;
    }
    return true;
}

/** Balance as the cache sees it (memory, ptokens or database), -1 if unknown */
static CAmount Balance(CTokensCache& cache, const std::string& name, const std::string& address)
{
    if (!GetBestTokenAddressAmount(cache, name, address)) return -1;
    return cache.mapTokensAddressAmount.at(std::make_pair(name, address));
}

static void CheckMetaData(CTokensCache& cache, const CNewToken& expected)
{
    CNewToken token;
    BOOST_REQUIRE(cache.GetTokenMetaDataIfExists(expected.strName, token));
    BOOST_CHECK_EQUAL(token.strName, expected.strName);
    BOOST_CHECK_EQUAL(token.nAmount, expected.nAmount);
    BOOST_CHECK_EQUAL((int)token.units, (int)expected.units);
    BOOST_CHECK_EQUAL((int)token.nReissuable, (int)expected.nReissuable);
    BOOST_CHECK_EQUAL((int)token.nHasIPFS, (int)expected.nHasIPFS);
    BOOST_CHECK(token.strIPFSHash == expected.strIPFSHash);
}

/** Write the cache to the database the way a chain state flush does, then forget the LRU copy */
static void FlushToDatabase(CTokensCache& cache)
{
    BOOST_CHECK(cache.Flush());
    BOOST_CHECK(ptokens->DumpCacheToDatabase());
    ptokensCache->Clear();
}

BOOST_AUTO_TEST_CASE(issue_and_undo)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        CTokensCache cache;
        const std::string address = TestTokenAddress();
        CNewToken token("ABC", 1000 * COIN, 2, 1, 1, TestIpfsHash());
        CTransaction tx = IssueTx(token);
        BOOST_CHECK(!cache.ContainsToken("ABC"));

        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        ConnectTokenTx(cache, tx, vUndo);
        BOOST_CHECK(vUndo.empty());
        BOOST_CHECK(cache.ContainsToken("ABC"));
        CheckMetaData(cache, token);
        CNewToken stored;
        int nHeight = 0;
        uint256 blockHash;
        BOOST_CHECK(cache.GetTokenMetaDataIfExists("ABC", stored, nHeight, blockHash));
        BOOST_CHECK_EQUAL(nHeight, BLOCK_HEIGHT);
        BOOST_CHECK(blockHash == BLOCK_HASH);
        BOOST_CHECK_EQUAL(Balance(cache, "ABC", address), fIndex ? 1000 * COIN : -1);
        BOOST_CHECK_EQUAL(Balance(cache, "ABC!", address), fIndex ? OWNER_TOKEN_AMOUNT : -1);

        // The same name can't be issued twice
        BOOST_CHECK(!cache.AddNewToken(token, address, BLOCK_HEIGHT, BLOCK_HASH));

        BOOST_CHECK(DisconnectTokenTx(cache, tx, vUndo));
        BOOST_CHECK(!cache.ContainsToken("ABC"));
        BOOST_CHECK(!cache.GetTokenMetaDataIfExists("ABC", stored));
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", address), 0);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC!", address), 0);
        }
        // Removing a token that doesn't exist fails
        BOOST_CHECK(!cache.RemoveNewToken(token, address));

        // After the undo, the name is free again
        ConnectTokenTx(cache, tx, vUndo);
        BOOST_CHECK(cache.ContainsToken("ABC"));
    }
}

BOOST_AUTO_TEST_CASE(unique_issue_and_undo)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        CTokensCache cache;
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        CTransaction issue = IssueTx(CNewToken("ABC", 1000 * COIN, 0, 1, 0, ""));
        ConnectTokenTx(cache, issue, vUndo);

        CTransaction unique = UniqueTx("ABC", {"ONE", "two"});
        BOOST_CHECK(unique.IsNewUniqueToken());
        ConnectTokenTx(cache, unique, vUndo, OwnerCoin(issue));
        BOOST_CHECK(cache.ContainsToken("ABC#ONE"));
        BOOST_CHECK(cache.ContainsToken("ABC#two"));
        CheckMetaData(cache, CNewToken("ABC#ONE", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""));
        if (fIndex)
            BOOST_CHECK_EQUAL(Balance(cache, "ABC#two", TestTokenAddress()), UNIQUE_TOKEN_AMOUNT);

        BOOST_CHECK(DisconnectTokenTx(cache, unique, vUndo, OwnerCoin(issue)));
        BOOST_CHECK(!cache.ContainsToken("ABC#ONE"));
        BOOST_CHECK(!cache.ContainsToken("ABC#two"));
        BOOST_CHECK(cache.ContainsToken("ABC"));
        if (fIndex)
            BOOST_CHECK_EQUAL(Balance(cache, "ABC!", TestTokenAddress()), OWNER_TOKEN_AMOUNT);
    }
}

/* A sub-token issue spends and returns the parent owner token; the undo removes the
 * sub-token and its owner token and gives the parent owner token back */
BOOST_AUTO_TEST_CASE(sub_issue_and_undo)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        CTokensCache cache;
        const std::string address = TestTokenAddress();
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        CTransaction issue = IssueTx(CNewToken("ABC", 1000 * COIN, 0, 1, 0, ""));
        ConnectTokenTx(cache, issue, vUndo);

        CNewToken sub("ABC/SUB", 50 * COIN, 1, 1, 0, "");
        CTransaction subIssue = SubIssueTx(sub, "ABC");
        BOOST_CHECK(subIssue.IsNewToken());
        ConnectTokenTx(cache, subIssue, vUndo, OwnerCoin(issue));
        BOOST_CHECK(vUndo.empty());
        BOOST_CHECK(cache.ContainsToken("ABC/SUB"));
        CheckMetaData(cache, sub);
        // Balance() is -1 without the token index, so those runs only check metadata
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC/SUB", address), 50 * COIN);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC/SUB!", address), OWNER_TOKEN_AMOUNT);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC!", address), OWNER_TOKEN_AMOUNT);
        }

        BOOST_CHECK(DisconnectTokenTx(cache, subIssue, vUndo, OwnerCoin(issue)));
        BOOST_CHECK(!cache.ContainsToken("ABC/SUB"));
        CNewToken stored;
        BOOST_CHECK(!cache.GetTokenMetaDataIfExists("ABC/SUB", stored));
        BOOST_CHECK(cache.ContainsToken("ABC"));
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC/SUB", address), 0);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC/SUB!", address), 0);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC!", address), OWNER_TOKEN_AMOUNT);
        }

        // The parent owner token is spendable again and the sub name is free
        ConnectTokenTx(cache, subIssue, vUndo, OwnerCoin(issue));
        BOOST_CHECK(cache.ContainsToken("ABC/SUB"));
    }
}

/* Each reissue variant is undone back to the original metadata. The undo
 * data for changed units/IPFS comes from AddCoins, as in ConnectBlock. */
BOOST_AUTO_TEST_CASE(reissue_and_undo)
{
    const std::string ipfs = TestIpfsHash();
    const CNewToken original("ABC", 100 * COIN, 2, 1, 0, "");
    struct Case {
        CReissueToken reissue;
        CNewToken after;
    };
    std::vector<Case> cases = {
        {CReissueToken("ABC", COIN, -1, 1, ""), CNewToken("ABC", 101 * COIN, 2, 1, 0, "")},     // amount only
        {CReissueToken("ABC", 0, 4, 1, ""), CNewToken("ABC", 100 * COIN, 4, 1, 0, "")},         // units
        {CReissueToken("ABC", 0, -1, 1, ipfs), CNewToken("ABC", 100 * COIN, 2, 1, 1, ipfs)},    // IPFS
        {CReissueToken("ABC", 5 * COIN, 6, 0, ipfs), CNewToken("ABC", 105 * COIN, 6, 0, 1, ipfs)}, // everything, then final
    };
    for (bool fIndex : {true, false}) {
        for (const Case& c : cases) {
            ResetTokens(fIndex);
            CTokensCache cache;
            std::vector<std::pair<std::string, CBlockTokenUndo> > vUndoIssue, vUndo;
            CTransaction issue = IssueTx(original);
            ConnectTokenTx(cache, issue, vUndoIssue);

            CTransaction tx = ReissueTx(c.reissue);
            BOOST_CHECK(tx.IsReissueToken());
            ConnectTokenTx(cache, tx, vUndo, OwnerCoin(issue));
            BOOST_CHECK_EQUAL(vUndo.size(), (c.reissue.nUnits != -1 || !c.reissue.strIPFSHash.empty()) ? 1U : 0U);
            CheckMetaData(cache, c.after);
            if (fIndex)
                BOOST_CHECK_EQUAL(Balance(cache, "ABC", TestTokenAddress()), c.after.nAmount);

            BOOST_CHECK(DisconnectTokenTx(cache, tx, vUndo, OwnerCoin(issue)));
            CheckMetaData(cache, original);
            if (fIndex) {
                BOOST_CHECK_EQUAL(Balance(cache, "ABC", TestTokenAddress()), original.nAmount);
                BOOST_CHECK_EQUAL(Balance(cache, "ABC!", TestTokenAddress()), OWNER_TOKEN_AMOUNT);
            }
        }
    }
}

/* Two reissues in consecutive blocks, undone newest first */
BOOST_AUTO_TEST_CASE(reissue_twice_and_undo)
{
    const std::string ipfs = TestIpfsHash();
    const CNewToken original("ABC", 100 * COIN, 2, 1, 0, "");
    CTokensCache cache;
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo0, vUndo1, vUndo2;
    CTransaction issue = IssueTx(original);
    ConnectTokenTx(cache, issue, vUndo0);
    CTransaction tx1 = ReissueTx(CReissueToken("ABC", COIN, 3, 1, ipfs));
    CTransaction tx2 = ReissueTx(CReissueToken("ABC", 2 * COIN, 5, 1, ""));
    ConnectTokenTx(cache, tx1, vUndo1, OwnerCoin(issue));
    ConnectTokenTx(cache, tx2, vUndo2, OwnerCoin(tx1));
    CheckMetaData(cache, CNewToken("ABC", 103 * COIN, 5, 1, 1, ipfs));

    BOOST_CHECK(DisconnectTokenTx(cache, tx2, vUndo2, OwnerCoin(tx1)));
    CheckMetaData(cache, CNewToken("ABC", 101 * COIN, 3, 1, 1, ipfs));
    BOOST_CHECK(DisconnectTokenTx(cache, tx1, vUndo1, OwnerCoin(issue)));
    CheckMetaData(cache, original);
    BOOST_CHECK_EQUAL(Balance(cache, "ABC", TestTokenAddress()), 100 * COIN);
}

/* Spending token coins and undoing the spend (SpendCoin / DisconnectBlock's ApplyTxInUndo) */
BOOST_AUTO_TEST_CASE(spend_and_undo_coins)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        CTokensCache cache;
        const std::string addr1 = TestTokenAddress(1), addr2 = TestTokenAddress(2);
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        CTransaction issue = IssueTx(CNewToken("ABC", 1000 * COIN, 0, 1, 0, ""));
        ConnectTokenTx(cache, issue, vUndo);

        // Spend the issued coin into two transfers
        Coin issued(issue.vout[2], BLOCK_HEIGHT, false, false, 0);
        COutPoint issuedOut(issue.GetHash(), 2);
        BOOST_CHECK(cache.TrySpendCoin(issuedOut, issued.out));
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(issuedOut));
        mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 300 * COIN), 2)));
        mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 700 * COIN), 1)));
        CTransaction transfer(mtx);
        ConnectTokenTx(cache, transfer, vUndo);
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", addr1), 700 * COIN);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", addr2), 300 * COIN);
            BOOST_CHECK_EQUAL(cache.vSpentTokens.size(), 1U);
        } else {
            BOOST_CHECK(cache.vSpentTokens.empty());
        }

        // Undo: remove the transfers, then give the spent coin back
        BOOST_CHECK(DisconnectTokenTx(cache, transfer, vUndo));
        BOOST_CHECK(cache.UndoTokenCoin(issued, issuedOut));
        BOOST_CHECK_EQUAL(cache.vUndoTokenAmount.size(), 1U);
        if (fIndex) {
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", addr1), 1000 * COIN);
            BOOST_CHECK_EQUAL(Balance(cache, "ABC", addr2), 0);
            // Undoing the same transfer again would make a balance negative
            BOOST_CHECK(!cache.RemoveTransfer(CTokenTransfer("ABC", 300 * COIN), addr2, COutPoint(transfer.GetHash(), 0)));
        }

        // Owner coin: spending it moves the whole owner token
        Coin owner(issue.vout[1], BLOCK_HEIGHT, false, false, 0);
        COutPoint ownerOut(issue.GetHash(), 1);
        BOOST_CHECK(cache.TrySpendCoin(ownerOut, owner.out));
        if (fIndex) BOOST_CHECK_EQUAL(Balance(cache, "ABC!", addr1), 0);
        BOOST_CHECK(cache.UndoTokenCoin(owner, ownerOut));
        if (fIndex) BOOST_CHECK_EQUAL(Balance(cache, "ABC!", addr1), OWNER_TOKEN_AMOUNT);

        // Plain YAC coins are ignored when spent, and can't be "undone" as tokens
        Coin plain(CTxOut(COIN, TestTokenScriptBase()), BLOCK_HEIGHT, false, false, 0);
        BOOST_CHECK(cache.TrySpendCoin(COutPoint(uint256S("0x04"), 0), plain.out));
        BOOST_CHECK(!cache.UndoTokenCoin(plain, COutPoint(uint256S("0x04"), 0)));
    }
}

/* The realistic reorg case: the block was already flushed to the token
 * database, and the undo starts from a fresh cache that reads it back. */
BOOST_AUTO_TEST_CASE(undo_after_flush_to_database)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        const std::string addr1 = TestTokenAddress(1), addr2 = TestTokenAddress(2);
        const CNewToken token("ABC", 1000 * COIN, 0, 1, 0, "");
        CTransaction issue = IssueTx(token);
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
        {
            CTokensCache cache;
            ConnectTokenTx(cache, issue, vUndo);
            FlushToDatabase(cache);
        }

        CNewToken stored;
        int nHeight;
        uint256 blockHash;
        BOOST_CHECK(ptokensdb->ReadTokenData("ABC", stored, nHeight, blockHash));
        BOOST_CHECK_EQUAL(stored.nAmount, 1000 * COIN);
        BOOST_CHECK_EQUAL(nHeight, BLOCK_HEIGHT);
        CAmount nQuantity = 0;
        BOOST_CHECK_EQUAL(ptokensdb->ReadTokenAddressQuantity("ABC", addr1, nQuantity), fIndex);
        if (fIndex) BOOST_CHECK_EQUAL(nQuantity, 1000 * COIN);

        // Second block: a transfer, flushed too
        Coin issued(issue.vout[2], BLOCK_HEIGHT, false, false, 0);
        COutPoint issuedOut(issue.GetHash(), 2);
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(issuedOut));
        mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 400 * COIN), 2)));
        mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 600 * COIN), 1)));
        CTransaction transfer(mtx);
        {
            CTokensCache cache;
            BOOST_CHECK(cache.TrySpendCoin(issuedOut, issued.out));
            ConnectTokenTx(cache, transfer, vUndo);
            FlushToDatabase(cache);
        }
        if (fIndex) {
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC", addr2, nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, 400 * COIN);
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC", addr1, nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, 600 * COIN);
        }

        // Disconnect the transfer block from a fresh cache
        {
            CTokensCache cache;
            BOOST_CHECK(cache.ContainsToken("ABC"));
            BOOST_CHECK(DisconnectTokenTx(cache, transfer, vUndo));
            BOOST_CHECK(cache.UndoTokenCoin(issued, issuedOut));
            FlushToDatabase(cache);
        }
        if (fIndex) {
            BOOST_CHECK(!ptokensdb->ReadTokenAddressQuantity("ABC", addr2, nQuantity));
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC", addr1, nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, 1000 * COIN);
        }

        // Disconnect the issue block: the token is gone from the database
        {
            CTokensCache cache;
            BOOST_CHECK(DisconnectTokenTx(cache, issue, vUndo));
            FlushToDatabase(cache);
        }
        BOOST_CHECK(!ptokensdb->ReadTokenData("ABC", stored, nHeight, blockHash));
        BOOST_CHECK(!ptokensdb->ReadTokenAddressQuantity("ABC", addr1, nQuantity));
        BOOST_CHECK(!ptokensdb->ReadTokenAddressQuantity("ABC!", addr1, nQuantity));
        CTokensCache fresh;
        BOOST_CHECK(!fresh.ContainsToken("ABC"));
    }
}

BOOST_AUTO_TEST_CASE(reissue_undo_after_flush_to_database)
{
    for (bool fIndex : {true, false}) {
        ResetTokens(fIndex);
        const CNewToken original("ABC", 100 * COIN, 2, 1, 0, "");
        CTransaction issue = IssueTx(original);
        CTransaction reissue = ReissueTx(CReissueToken("ABC", COIN, 4, 1, TestIpfsHash()));
        std::vector<std::pair<std::string, CBlockTokenUndo> > vUndoIssue, vUndo;
        {
            CTokensCache cache;
            ConnectTokenTx(cache, issue, vUndoIssue);
            FlushToDatabase(cache);
        }
        {
            CTokensCache cache;
            ConnectTokenTx(cache, reissue, vUndo, OwnerCoin(issue));
            FlushToDatabase(cache);
        }
        // ConnectBlock stores the reissue undo data per block, DisconnectBlock reads it back
        BOOST_REQUIRE_EQUAL(vUndo.size(), 1U);
        BOOST_CHECK(ptokensdb->WriteBlockUndoTokenData(BLOCK_HASH, vUndo));
        vUndo.clear();
        BOOST_CHECK(ptokensdb->ReadBlockUndoTokenData(BLOCK_HASH, vUndo));
        BOOST_REQUIRE_EQUAL(vUndo.size(), 1U);
        BOOST_CHECK_EQUAL(vUndo[0].first, "ABC");
        BOOST_CHECK(vUndo[0].second.fChangedIPFS && vUndo[0].second.fChangedUnits);
        BOOST_CHECK_EQUAL(vUndo[0].second.nUnits, original.units);
        CNewToken stored;
        int nHeight;
        uint256 blockHash;
        BOOST_CHECK(ptokensdb->ReadTokenData("ABC", stored, nHeight, blockHash));
        BOOST_CHECK_EQUAL(stored.nAmount, 101 * COIN);
        BOOST_CHECK_EQUAL((int)stored.units, 4);
        BOOST_CHECK_EQUAL((int)stored.nHasIPFS, 1);
        {
            CTokensCache cache;
            BOOST_CHECK(DisconnectTokenTx(cache, reissue, vUndo, OwnerCoin(issue)));
            FlushToDatabase(cache);
        }
        BOOST_CHECK(ptokensdb->ReadTokenData("ABC", stored, nHeight, blockHash));
        BOOST_CHECK_EQUAL(stored.nAmount, original.nAmount);
        BOOST_CHECK_EQUAL((int)stored.units, (int)original.units);
        BOOST_CHECK_EQUAL((int)stored.nHasIPFS, 0);
        BOOST_CHECK_EQUAL(stored.strIPFSHash, "");
        if (fIndex) {
            CAmount nQuantity = 0;
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC", TestTokenAddress(), nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, 100 * COIN);
            BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("ABC!", TestTokenAddress(), nQuantity));
            BOOST_CHECK_EQUAL(nQuantity, OWNER_TOKEN_AMOUNT);
        }
    }
}

BOOST_AUTO_TEST_CASE(contextual_checks)
{
    CTokensCache cache;
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
    ConnectTokenTx(cache, IssueTx(CNewToken("ABC", 100 * COIN, 2, 1, 0, "")), vUndo);
    ConnectTokenTx(cache, IssueTx(CNewToken("FIXED", 100 * COIN, 0, 0, 0, "")), vUndo);
    std::string strError;

    // New tokens: the name must be free, also in the mempool when asked to check it
    BOOST_CHECK(ContextualCheckNewToken(&cache, CNewToken("NEW", COIN, 0, 1, 0, ""), strError));
    BOOST_CHECK(!ContextualCheckNewToken(&cache, CNewToken("ABC", COIN, 0, 1, 0, ""), strError));
    mempool.mapTokenToHash["NEW"] = uint256S("0x05");
    BOOST_CHECK(ContextualCheckNewToken(&cache, CNewToken("NEW", COIN, 0, 1, 0, ""), strError, false));
    BOOST_CHECK(!ContextualCheckNewToken(&cache, CNewToken("NEW", COIN, 0, 1, 0, ""), strError, true));
    BOOST_CHECK(ContextualCheckNewToken(&cache, CNewToken("NEWIPFS", COIN, 0, 1, 1, TestIpfsHash()), strError));
    BOOST_CHECK(!ContextualCheckNewToken(&cache, CNewToken("NEWIPFS", COIN, 0, 1, 1, "too short"), strError));
    BOOST_CHECK(!ContextualCheckNewToken(&cache, CNewToken("NEWIPFS", COIN, 0, 1, 1, std::string(34, 'x')), strError));
    BOOST_CHECK(ContextualCheckUniqueToken(&cache, CNewToken("ABC#TAG", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""), strError));

    // Reissues (adapted from Ravencoin's reissue_isvalid_test)
    BOOST_CHECK(ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, 2, 1, TestIpfsHash()), strError));
    BOOST_CHECK(ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, -1, 1, ""), strError));
    BOOST_CHECK(ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, 6, 1, ""), strError));
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("NOTEXIST", COIN, 2, 1, ""), strError));
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("FIXED", COIN, 0, 1, ""), strError));
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, 1, 1, ""), strError)); // fewer units
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN + 1, -1, 1, ""), strError)); // amount vs units
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("ABC", MAX_MONEY - 50 * COIN, -1, 1, ""), strError)); // total > MAX_MONEY
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, CReissueToken("ABC", COIN, -1, 1, "short"), strError));

    // The variant used by CheckTxTokens checks the given reissue, and fails if the tx isn't a reissue
    CTransaction tx = ReissueTx(CReissueToken("ABC", COIN, -1, 1, ""));
    CReissueToken reissue("ABC", COIN, -1, 1, "");
    BOOST_CHECK(ContextualCheckReissueToken(&cache, reissue, strError, tx));
    BOOST_CHECK(!ContextualCheckReissueToken(&cache, reissue, strError, IssueTx(CNewToken("XYZ", COIN))));

    // Transfers only need a valid name and a positive amount here
    BOOST_CHECK(ContextualCheckTransferToken(&cache, CTokenTransfer("ABC", 1), TestTokenAddress(), strError));
    BOOST_CHECK(!ContextualCheckTransferToken(&cache, CTokenTransfer("ABC", 0), TestTokenAddress(), strError));
    BOOST_CHECK(!ContextualCheckTransferToken(&cache, CTokenTransfer("abc", 1), TestTokenAddress(), strError));
}

BOOST_AUTO_TEST_CASE(unique_tx_contextual_check)
{
    CTokensCache cache;
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndo;
    CTransaction issue = IssueTx(CNewToken("ABC", 100 * COIN, 0, 1, 0, ""));
    ConnectTokenTx(cache, issue, vUndo);
    ConnectTokenTx(cache, UniqueTx("ABC", {"TAG1"}), vUndo, OwnerCoin(issue));
    std::string strError;

    // Only unique token outputs are checked: a tx without outputs passes, and so does a
    // plain issue, even of a name that already exists (that is checked elsewhere)
    BOOST_CHECK(ContextualCheckUniqueTokenTx(&cache, strError, CTransaction(CMutableTransaction())));
    BOOST_CHECK_EQUAL(strError, "");
    BOOST_CHECK(ContextualCheckUniqueTokenTx(&cache, strError, issue));
    BOOST_CHECK_EQUAL(strError, "");
    BOOST_CHECK(ContextualCheckUniqueTokenTx(&cache, strError, UniqueTx("ABC", {"NEW1", "NEW2"})));

    // Each unique output must be a new, valid unique token; the second one fails here
    BOOST_CHECK(!ContextualCheckUniqueTokenTx(&cache, strError, UniqueTx("ABC", {"NEW1", "TAG1"})));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: token_name 'ABC#TAG1' has already been used");
    BOOST_CHECK(!ContextualCheckUniqueToken(&cache, CNewToken("ABC#TAG1", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""), strError));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: token_name 'ABC#TAG1' has already been used");

    CMutableTransaction big(UniqueTx("ABC", {"NEW1"}));
    big.vout.back() = CTxOut(0, NewTokenScript(CNewToken("ABC#BIG", 2 * UNIQUE_TOKEN_AMOUNT, 0, 0, 0, "")));
    BOOST_CHECK(!ContextualCheckUniqueTokenTx(&cache, strError, CTransaction(big)));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: amount must be 1000000");
    CMutableTransaction units(UniqueTx("ABC", {"NEW1"}));
    units.vout.back() = CTxOut(0, NewTokenScript(CNewToken("ABC#UNITS", UNIQUE_TOKEN_AMOUNT, 1, 0, 0, "")));
    BOOST_CHECK(!ContextualCheckUniqueTokenTx(&cache, strError, CTransaction(units)));
    BOOST_CHECK_EQUAL(strError, "Invalid parameter: units must be 0");
}

/* Adapted from Ravencoin's cache_tests, with a small cache */
BOOST_AUTO_TEST_CASE(lru_cache_eviction)
{
    CLRUCache<std::string, CNewToken> cache(10);
    for (int i = 0; i < 10; i++) {
        CNewToken token("TEST" + std::to_string(i), CAmount(1));
        cache.Put(token.strName, token);
    }
    BOOST_CHECK_EQUAL(cache.Size(), 10U);
    BOOST_CHECK(cache.Exists("TEST0"));

    // Reading TEST0 makes TEST1 the least recently used entry
    BOOST_CHECK_EQUAL(cache.Get("TEST0").strName, "TEST0");
    cache.Put("NEW", CNewToken("NEW", CAmount(1)));
    BOOST_CHECK_EQUAL(cache.Size(), 10U);
    BOOST_CHECK(cache.Exists("NEW"));
    BOOST_CHECK(cache.Exists("TEST0"));
    BOOST_CHECK(!cache.Exists("TEST1"));

    cache.Erase("NEW");
    BOOST_CHECK(!cache.Exists("NEW"));
    cache.Clear();
    BOOST_CHECK_EQUAL(cache.Size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
