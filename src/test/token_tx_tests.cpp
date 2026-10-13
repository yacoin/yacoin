// Copyright (c) 2017-2019 The Raven Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Consensus rules for token transactions: the structural checks in
// CheckTransaction (VerifyNewToken, VerifyReissueToken, VerifyNewUniqueToken,
// IsNewOwnerTxValid) and the input/output balance in Consensus::CheckTxTokens,
// including the transfer overflow fixed in #112. Balance cases adapted from
// Ravencoin's asset_tx_tests.

#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "tokens/tokens.h"

#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <limits>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(token_tx_tests, TokenTestingSetup)

static bool CheckTx(const CTransaction& tx, std::string& strReason)
{
    CValidationState state;
    bool fValid = CheckTransaction(tx, state);
    strReason = state.GetRejectReason();
    return fValid;
}

static bool CheckTx(const CMutableTransaction& mtx)
{
    std::string strReason;
    return CheckTx(CTransaction(mtx), strReason);
}

/** CheckTransaction rejects a failed VerifyNewToken without a reject reason; get it directly */
static std::string VerifyIssueError(const CMutableTransaction& mtx)
{
    std::string strError;
    CTransaction(mtx).VerifyNewToken(strError);
    return strError;
}

static bool Contains(const std::string& str, const std::string& part)
{
    return str.find(part) != std::string::npos;
}

BOOST_AUTO_TEST_CASE(issue_structure)
{
    std::string strReason;
    const CNewToken token("ABC", 1000 * COIN, 0, 1, 0, "");
    CTransaction issue = IssueTx(token);
    BOOST_CHECK(issue.IsNewToken());
    BOOST_CHECK(CheckTx(issue, strReason));
    std::string strError;
    BOOST_CHECK(issue.VerifyNewToken(strError));
    BOOST_CHECK(IsNewOwnerTxValid(issue, "ABC", TestTokenAddress(), strError));

    // No YAC lock, or one that is too small
    CMutableTransaction noLock(issue);
    noLock.vout[0] = CTxOut(noLock.vout[0].nValue, TestTokenScriptBase());
    BOOST_CHECK(CTransaction(noLock).IsNewToken());
    BOOST_CHECK(!CheckTx(noLock));
    BOOST_CHECK_EQUAL(VerifyIssueError(noLock), "bad-txns-issue-timelock-not-found");
    CMutableTransaction smallLock(issue);
    smallLock.vout[0].nValue -= 1;
    BOOST_CHECK(!CheckTx(smallLock));
    BOOST_CHECK_EQUAL(VerifyIssueError(smallLock), "bad-txns-issue-timelock-not-found");

    // The owner token must belong to the same token and address
    CMutableTransaction wrongOwner(issue);
    wrongOwner.vout[1].scriptPubKey = OwnerTokenScript(CNewToken("XYZ", COIN));
    BOOST_CHECK(!CheckTx(wrongOwner));
    BOOST_CHECK_EQUAL(VerifyIssueError(wrongOwner), "bad-txns-issue-owner-name-doesn't-match");
    CMutableTransaction ownerElsewhere(issue);
    ownerElsewhere.vout[1].scriptPubKey = OwnerTokenScript(token, 2);
    BOOST_CHECK(!CheckTx(CTransaction(ownerElsewhere), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-owner-address-mismatch");

    // Token outputs carry no YAC
    CMutableTransaction valued(issue);
    valued.vout[2].nValue = 1;
    BOOST_CHECK(!CheckTx(CTransaction(valued), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-token-issued-amount-isn't-zero");

    // Exactly one new token per issue
    CMutableTransaction twoIssues(issue);
    twoIssues.vout.insert(twoIssues.vout.begin(), CTxOut(0, NewTokenScript(CNewToken("XYZ", COIN))));
    BOOST_CHECK(!CheckTx(twoIssues));
    BOOST_CHECK_EQUAL(VerifyIssueError(twoIssues), "bad-txns-failed-issue-token-formatting-check");

    // Invalid token data
    BOOST_CHECK(!CheckTx(IssueTx(CNewToken("ABC", COIN, 7, 1, 0, "")), strReason));
    BOOST_CHECK(Contains(strReason, "units must be between 0-6"));
    BOOST_CHECK(!CheckTx(IssueTx(CNewToken("ABC", COIN + 1, 0, 1, 0, "")), strReason));
    BOOST_CHECK(Contains(strReason, "divisible by the smaller unit"));
}

BOOST_AUTO_TEST_CASE(sub_token_needs_parent_owner)
{
    CTransaction sub = IssueTx(CNewToken("ABC/SUB", COIN, 0, 1, 0, ""));
    BOOST_CHECK(!CheckTx(CMutableTransaction(sub)));
    BOOST_CHECK_EQUAL(VerifyIssueError(CMutableTransaction(sub)), "bad-txns-issue-new-token-missing-owner-token");

    CMutableTransaction withOwner(sub);
    withOwner.vout.insert(withOwner.vout.begin(), CTxOut(0, TransferTokenScript(CTokenTransfer("ABC!", OWNER_TOKEN_AMOUNT))));
    BOOST_CHECK(CheckTx(withOwner));

    // Another token's owner doesn't count
    CMutableTransaction otherOwner(sub);
    otherOwner.vout.insert(otherOwner.vout.begin(), CTxOut(0, TransferTokenScript(CTokenTransfer("XYZ!", OWNER_TOKEN_AMOUNT))));
    BOOST_CHECK(!CheckTx(otherOwner));
    BOOST_CHECK_EQUAL(VerifyIssueError(otherOwner), "bad-txns-issue-new-token-missing-owner-token");
}

BOOST_AUTO_TEST_CASE(reissue_structure)
{
    std::string strReason;
    CTransaction reissue = ReissueTx(CReissueToken("ABC", COIN, -1, 1, ""));
    BOOST_CHECK(reissue.IsReissueToken());
    BOOST_CHECK(CheckTx(reissue, strReason));

    CMutableTransaction noOwner(reissue);
    noOwner.vout[1].scriptPubKey = TransferTokenScript(CTokenTransfer("XYZ!", OWNER_TOKEN_AMOUNT));
    BOOST_CHECK(!CheckTx(CTransaction(noOwner), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-reissue-owner-outpoint-not-found");

    CMutableTransaction noLock(reissue);
    noLock.vout[0].nValue = COIN;
    BOOST_CHECK(!CheckTx(CTransaction(noLock), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-reissue-timelock-outpoint-not-found");

    CMutableTransaction twoReissues(reissue);
    twoReissues.vout.insert(twoReissues.vout.begin(), twoReissues.vout.back());
    BOOST_CHECK(!CheckTx(CTransaction(twoReissues), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-failed-reissue-token-formatting-check");

    // CheckReissueToken rejects amounts >= MAX_MONEY (its message says "must be 0 or larger")
    BOOST_CHECK(!CheckTx(ReissueTx(CReissueToken("ABC", MAX_MONEY, -1, 1, "")), strReason));
    BOOST_CHECK(Contains(strReason, "Unable to reissue token: amount"));
}

BOOST_AUTO_TEST_CASE(unique_structure)
{
    std::string strReason;
    CTransaction unique = UniqueTx("ABC", {"ONE", "TWO", "three"});
    BOOST_CHECK(unique.IsNewUniqueToken());
    BOOST_CHECK(!unique.IsNewToken());
    BOOST_CHECK(CheckTx(unique, strReason));

    CMutableTransaction duplicate(UniqueTx("ABC", {"ONE", "ONE"}));
    BOOST_CHECK(!CheckTx(CTransaction(duplicate), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-issue-unique-duplicate-name-in-same-tx");

    // The lock must cover every new token
    CMutableTransaction shortLock(unique);
    shortLock.vout[0] = TokenLockOutput(ETokenType::UNIQUE, 2);
    BOOST_CHECK(!CheckTx(CTransaction(shortLock), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-issue-unique-token-timelock-outpoints-not-found");

    CMutableTransaction noOwner(unique);
    noOwner.vout[1].scriptPubKey = TransferTokenScript(CTokenTransfer("XYZ!", OWNER_TOKEN_AMOUNT));
    BOOST_CHECK(!CheckTx(CTransaction(noOwner), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-issue-unique-token-missing-owner-token");

    // All unique tokens must share the parent
    CMutableTransaction mixed(unique);
    mixed.vout.back().scriptPubKey = NewTokenScript(CNewToken("XYZ#ONE", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""));
    BOOST_CHECK(!CheckTx(CTransaction(mixed), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-issue-unique-token-compare-failed");
}

BOOST_AUTO_TEST_CASE(transfer_outputs)
{
    std::string strReason;
    auto transferTx = [](const CTokenTransfer& transfer, CAmount nValue) {
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x06"), 0)));
        mtx.vout.push_back(CTxOut(nValue, TransferTokenScript(transfer)));
        return CTransaction(mtx);
    };
    BOOST_CHECK(CheckTx(transferTx(CTokenTransfer("ABC", 5), 0), strReason));
    BOOST_CHECK(CheckTx(transferTx(CTokenTransfer("ABC!", OWNER_TOKEN_AMOUNT), 0), strReason));

    BOOST_CHECK(!CheckTx(transferTx(CTokenTransfer("ABC", 5), 1), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-token-transfer-amount-isn't-zero");
    BOOST_CHECK(!CheckTx(transferTx(CTokenTransfer("ABC!", 2 * OWNER_TOKEN_AMOUNT), 0), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-owner-amount-was-not-1");
    BOOST_CHECK(!CheckTx(transferTx(CTokenTransfer("ABC#TAG", 2 * UNIQUE_TOKEN_AMOUNT), 0), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-unique-amount-was-not-1");
    BOOST_CHECK(!CheckTx(transferTx(CTokenTransfer("abc", 5), 0), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-name-invalid");

    // Coinbases can't carry tokens
    CMutableTransaction coinbase;
    coinbase.vin.push_back(CTxIn());
    coinbase.vin[0].scriptSig = CScript() << 1 << 2;
    coinbase.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer("ABC", 5))));
    BOOST_CHECK(!CheckTx(CTransaction(coinbase), strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-coinbase-contains-token-txes");
}

/* Consensus::CheckTxTokens: token inputs must equal token outputs, per token */
struct TokenBalanceSetup {
    CCoinsView base;
    CCoinsViewCache view;
    CTokensCache cache;
    int nCoins = 0;

    TokenBalanceSetup() : view(&base)
    {
        // ABC allows 6 decimals, which makes the unit check a no-op (as in feature_token_overflow.py)
        BOOST_CHECK(cache.AddNewToken(CNewToken("ABC", 1000 * COIN, 6, 1, 0, ""), TestTokenAddress(), 1, uint256()));
        BOOST_CHECK(cache.AddNewToken(CNewToken("WHOLE", 1000 * COIN, 0, 1, 0, ""), TestTokenAddress(), 1, uint256()));
    }

    COutPoint AddCoin(const CScript& script, CAmount nValue = 0)
    {
        COutPoint out(uint256S("0xc0"), nCoins++);
        view.AddCoin(out, Coin(CTxOut(nValue, script), 1, false, false, 0), false);
        return out;
    }

    COutPoint AddTokenCoin(const std::string& name, CAmount nAmount)
    {
        return AddCoin(TransferTokenScript(CTokenTransfer(name, nAmount)));
    }

    bool Check(const std::vector<COutPoint>& inputs, const std::vector<CTokenTransfer>& outputs, std::string& strReason)
    {
        CMutableTransaction mtx;
        for (const COutPoint& in : inputs) mtx.vin.push_back(CTxIn(in));
        for (const CTokenTransfer& transfer : outputs) mtx.vout.push_back(CTxOut(0, TransferTokenScript(transfer, 2)));
        mtx.vout.push_back(CTxOut(COIN, TestTokenScriptBase()));
        CValidationState state;
        std::vector<std::pair<std::string, uint256> > vReissues;
        bool fValid = Consensus::CheckTxTokens(CTransaction(mtx), state, view, &cache, false, vReissues);
        strReason = state.GetRejectReason();
        return fValid;
    }
};

BOOST_AUTO_TEST_CASE(token_balance)
{
    TokenBalanceSetup s;
    std::string strReason;
    COutPoint ten = s.AddTokenCoin("ABC", 10 * COIN);
    COutPoint yac = s.AddCoin(TestTokenScriptBase(), COIN);

    BOOST_CHECK(s.Check({ten}, {CTokenTransfer("ABC", 4 * COIN), CTokenTransfer("ABC", 6 * COIN)}, strReason));
    BOOST_CHECK(s.Check({yac}, {}, strReason));

    // Creating tokens
    BOOST_CHECK(!s.Check({ten}, {CTokenTransfer("ABC", 11 * COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason.substr(0, 30), "bad-tx-inputs-outputs-mismatch");
    BOOST_CHECK(!s.Check({yac}, {CTokenTransfer("ABC", COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason.substr(0, 30), "bad-tx-inputs-outputs-mismatch");
    // Burning some, or all
    BOOST_CHECK(!s.Check({ten}, {CTokenTransfer("ABC", 9 * COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason.substr(0, 30), "bad-tx-inputs-outputs-mismatch");
    BOOST_CHECK(!s.Check({ten}, {}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-tx-token-inputs-size-does-not-match-outputs-size");

    // Unknown token, wrong units, owner amount
    BOOST_CHECK(!s.Check({yac}, {CTokenTransfer("XYZ", COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-not-exist");
    COutPoint whole = s.AddTokenCoin("WHOLE", 10 * COIN);
    BOOST_CHECK(!s.Check({whole}, {CTokenTransfer("WHOLE", 10 * COIN - 1), CTokenTransfer("WHOLE", 1)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-amount-not-match-units");
    COutPoint owner = s.AddTokenCoin("ABC!", OWNER_TOKEN_AMOUNT);
    BOOST_CHECK(s.Check({owner}, {CTokenTransfer("ABC!", OWNER_TOKEN_AMOUNT)}, strReason));
    BOOST_CHECK(!s.Check({owner}, {CTokenTransfer("ABC!", 2 * OWNER_TOKEN_AMOUNT)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-owner-amount-was-not-1");

    // Two tokens in one tx are balanced separately
    BOOST_CHECK(s.Check({ten, whole}, {CTokenTransfer("WHOLE", 10 * COIN), CTokenTransfer("ABC", 10 * COIN)}, strReason));
    BOOST_CHECK(!s.Check({ten, whole}, {CTokenTransfer("WHOLE", 11 * COIN), CTokenTransfer("ABC", 9 * COIN)}, strReason));
    BOOST_CHECK_EQUAL(strReason.substr(0, 30), "bad-tx-inputs-outputs-mismatch");

    // Missing inputs (rejected without a DoS score or reject reason)
    BOOST_CHECK(!s.Check({COutPoint(uint256S("0xdead"), 0)}, {}, strReason));
}

/* Regression tests for the Token Transfer Quantity Overflow fixed in #112:
 * without range checks the signed sums of amounts wrap around, so outputs
 * worth ~9.2e12 tokens could be made from a 1-unit input. */
BOOST_AUTO_TEST_CASE(token_amount_overflow)
{
    TokenBalanceSetup s;
    std::string strReason;
    COutPoint one = s.AddTokenCoin("ABC", 1);
    const CAmount nMax = std::numeric_limits<int64_t>::max();

    // The original attack: INT64_MAX + INT64_MAX + 3 wraps to 1
    BOOST_CHECK(!s.Check({one}, {CTokenTransfer("ABC", nMax), CTokenTransfer("ABC", nMax), CTokenTransfer("ABC", 3)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-amount-toolarge");
    BOOST_CHECK(!s.Check({one}, {CTokenTransfer("ABC", MAX_MONEY + 1)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-amount-toolarge");

    // Each output within range, but their sum isn't
    COutPoint max = s.AddTokenCoin("ABC", MAX_MONEY);
    BOOST_CHECK(s.Check({max}, {CTokenTransfer("ABC", MAX_MONEY)}, strReason));
    BOOST_CHECK(!s.Check({max}, {CTokenTransfer("ABC", MAX_MONEY), CTokenTransfer("ABC", MAX_MONEY)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-transfer-token-totalOutputs-toolarge");

    // The same on the input side
    COutPoint max2 = s.AddTokenCoin("ABC", MAX_MONEY);
    BOOST_CHECK(!s.Check({max, max2}, {CTokenTransfer("ABC", MAX_MONEY)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-input-token-totalInputs-toolarge");
    COutPoint tooLarge = s.AddTokenCoin("ABC", MAX_MONEY + 1);
    BOOST_CHECK(!s.Check({tooLarge}, {CTokenTransfer("ABC", MAX_MONEY)}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-input-token-amount-toolarge");
    COutPoint negative = s.AddTokenCoin("ABC", -1);
    BOOST_CHECK(!s.Check({negative}, {}, strReason));
    BOOST_CHECK_EQUAL(strReason, "bad-txns-input-token-amount-negative");

    // Zero and negative outputs are rejected by ContextualCheckTransferToken before the
    // sums, so CheckTxTokens' own "transfer-token-amount-negative" branch is unreachable
    BOOST_CHECK(!s.Check({one}, {CTokenTransfer("ABC", 2), CTokenTransfer("ABC", -1)}, strReason));
    BOOST_CHECK(Contains(strReason, "can't be equal to or less than zero"));
    BOOST_CHECK(!s.Check({one}, {CTokenTransfer("ABC", 1), CTokenTransfer("ABC", 0)}, strReason));
    BOOST_CHECK(Contains(strReason, "can't be equal to or less than zero"));
}

/* Only one reissue of a token may be pending at a time (mapReissuedTokens) */
BOOST_AUTO_TEST_CASE(reissue_chaining)
{
    TokenBalanceSetup s;
    CTransaction reissue = ReissueTx(CReissueToken("ABC", COIN, -1, 1, ""));
    CValidationState state;
    std::vector<std::pair<std::string, uint256> > vReissues;
    // The owner token input that the reissue spends
    CMutableTransaction mtx(reissue);
    mtx.vin[0] = CTxIn(s.AddTokenCoin("ABC!", OWNER_TOKEN_AMOUNT));
    CTransaction tx(mtx);
    BOOST_CHECK(Consensus::CheckTxTokens(tx, state, s.view, &s.cache, false, vReissues));
    BOOST_REQUIRE_EQUAL(vReissues.size(), 1U);
    BOOST_CHECK(vReissues[0].first == "ABC" && vReissues[0].second == tx.GetHash());

    // Another reissue of ABC while that one is recorded
    mapReissuedTokens["ABC"] = tx.GetHash();
    CMutableTransaction other(mtx);
    other.vout[2].scriptPubKey = ReissueTokenScript(CReissueToken("ABC", 2 * COIN, -1, 1, ""));
    vReissues.clear();
    BOOST_CHECK(!Consensus::CheckTxTokens(CTransaction(other), state, s.view, &s.cache, false, vReissues));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-tx-reissue-chaining-not-allowed");
    // The recorded tx itself still passes
    CValidationState state2;
    BOOST_CHECK(Consensus::CheckTxTokens(tx, state2, s.view, &s.cache, false, vReissues));
}

BOOST_AUTO_TEST_SUITE_END()
