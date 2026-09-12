// Copyright (c) 2017-2017 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokens/tokens.h"
//#include "script/standard.h"
#include "script/script.h"
#include "util.h"
#include "validation.h"
#include "tx_verify.h"
#include "chainparams.h"

#include "consensus.h"
#include "primitives/transaction.h"
#include "policy/fees.h"
#include "pow.h"
//#include "script/interpreter.h"
#include "../validation.h"
#include "wallet/wallet.h"
#include "base58.h"
#include "tinyformat.h"

// TODO remove the following dependencies
#include "chain.h"
#include "coins.h"
#include "utilmoneystr.h"

#include <cmath>

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            // TODO: Enforce timelock according to median time
            // TODO: Support LOCKTIME_MEDIAN_TIME_PAST in future (affect consensus rule)
//            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetBlockTime();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    // TODO: Enforce timelock according to median time
    // TODO: Support LOCKTIME_MEDIAN_TIME_PAST in future (affect consensus rule)
//    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    int64_t nBlockTime = block.pprev->GetBlockTime();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx);

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs);
    }

    return nSigOps;
}

bool CheckTransactionSize(const CTransaction& tx, CValidationState &state, ::int32_t blockHeight)
{
    // Size limits
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > GetMaxSize(MAX_BLOCK_SIZE, blockHeight))
        return state.DoS(100, error("CheckTransactionSize() : size limits failed"), REJECT_INVALID, "bad-txns-oversize");
    return true;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, error("CheckTransaction() : vin empty"), REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, error("CheckTransaction() : vout empty"), REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (moved to CheckTransactionSize)
//    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > GetMaxSize(MAX_BLOCK_SIZE))
//        return state.DoS(100, error("CheckTransaction() : size limits failed"), REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    ::int64_t
        nValueOut = 0;

    /** YAC_TOKEN START */
    std::set<std::string> setTokenTransferNames;
    /** YAC_TOKEN END */

    // Check transaction output
    for (unsigned int i = 0; i < tx.vout.size(); ++i)
    {
        const CTxOut
            & txout = tx.vout[i];

        if (txout.IsEmpty() && !tx.IsCoinBase() && !tx.IsCoinStake())
            return state.DoS(100, error("CheckTransaction() : txout empty for user transaction"), REJECT_INVALID, "bad-txns-vout-empty");

        if (txout.nValue < 0)
            return state.DoS(100, error("CheckTransaction() : txout.nValue is negative"), REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, error("CheckTransaction() : txout.nValue too high"), REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, error("CheckTransaction() : txout total out of range"), REJECT_INVALID, "bad-txns-txouttotal-toolarge");

        /** YAC_TOKEN START */
        if (AreTokensDeployed())
        {
            bool isToken = false;
            int nType;
            bool fIsOwner;
            if (txout.scriptPubKey.IsTokenScript(nType, fIsOwner))
                isToken = true;

            // Check for transfers that don't meet the tokens units only if the tokenCache is not null
            if (isToken) {
                // Get the transfer transaction data from the scriptPubKey
                if (nType == TX_TRANSFER_TOKEN) {
                    CTokenTransfer transfer;
                    std::string address;
                    if (!TransferTokenFromScript(txout.scriptPubKey, transfer, address))
                        return state.DoS(100, error("bad-txns-transfer-token-bad-deserialize"), REJECT_INVALID, "bad-txns-transfer-token-bad-deserialize");

                    // insert into set, so that later on we can check token null data transactions
                    setTokenTransferNames.insert(transfer.strName);

                    // Check token name validity and get type
                    ETokenType tokenType;
                    if (!IsTokenNameValid(transfer.strName, tokenType)) {
                        return state.DoS(100, error("bad-txns-transfer-token-name-invalid"), REJECT_INVALID, "bad-txns-transfer-token-name-invalid");
                    }

                    // If the transfer is an ownership token. Check to make sure that it is OWNER_TOKEN_AMOUNT
                    if (IsTokenNameAnOwner(transfer.strName)) {
                        if (transfer.nAmount != OWNER_TOKEN_AMOUNT)
                            return state.DoS(100, error("bad-txns-transfer-owner-amount-was-not-1"), REJECT_INVALID, "bad-txns-transfer-owner-amount-was-not-1");
                    }

                    // If the transfer is a unique token. Check to make sure that it is UNIQUE_TOKEN_AMOUNT
                    if (tokenType == ETokenType::UNIQUE) {
                        if (transfer.nAmount != UNIQUE_TOKEN_AMOUNT)
                            return state.DoS(100, error("bad-txns-transfer-unique-amount-was-not-1"), REJECT_INVALID, "bad-txns-transfer-unique-amount-was-not-1");
                    }

                    // Specific check and error message to go with to make sure the amount is 0
                    if (txout.nValue != 0)
                        return state.DoS(100, error("bad-txns-token-transfer-amount-isn't-zero"), REJECT_INVALID, "bad-txns-token-transfer-amount-isn't-zero");
                } else if (nType == TX_NEW_TOKEN) {
                    // Specific check and error message to go with to make sure the amount is 0
                    if (txout.nValue != 0)
                        return state.DoS(100, error("bad-txns-token-issued-amount-isn't-zero"), REJECT_INVALID, "bad-txns-token-issued-amount-isn't-zero");
                } else if (nType == TX_REISSUE_TOKEN) {
                    // Specific check and error message to go with to make sure the amount is 0
                    if (txout.nValue != 0) {
                        return state.DoS(0, error("bad-txns-token-reissued-amount-isn't-zero"), REJECT_INVALID, "bad-txns-token-reissued-amount-isn't-zero");
                    }
                } else {
                    return state.DoS(0, error("bad-token-type-not-any-of-the-main-three"), REJECT_INVALID, "bad-token-type-not-any-of-the-main-three");
                }
            }
        }
        /** YAC_TOKEN END */
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto& txin : tx.vin)
        {
            if (!vInOutPoints.insert(txin.prevout).second)
                return state.DoS(100, error("CheckTransaction() : duplicate inputs"), REJECT_INVALID, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, error("CheckTransaction() : coinbase script size is invalid"), REJECT_INVALID, "bad-cb-length");
        for (auto cbVout : tx.vout) {
            if (cbVout.scriptPubKey.IsTokenScript()) {
                return state.DoS(0, error("CheckTransaction(): coinbase contains token transaction"), REJECT_INVALID, "bad-txns-coinbase-contains-token-txes");
            }
        }
    }
    else
    {
        for(const CTxIn& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, error("CheckTransaction() : prevout is null"), REJECT_INVALID, "bad-txns-prevout-null");
    }

    /* YAC_TOKEN START */
    if (AreTokensDeployed())
    {
        if (tx.IsNewToken()) {
            /** Verify the reissue tokens data */
            std::string strError = "";
            if(!tx.VerifyNewToken(strError))
                return state.DoS(100, error(strError.c_str()));

            CNewToken token;
            std::string strAddress;
            if (!TokenFromTransaction(tx, token, strAddress))
                return state.DoS(100, error("bad-txns-issue-token-from-transaction"), REJECT_INVALID, "bad-txns-issue-token-from-transaction");

            // Validate the new tokens information
            if (!IsNewOwnerTxValid(tx, token.strName, strAddress, strError))
                return state.DoS(100, error(strError.c_str()), REJECT_INVALID, strError);

            if(!CheckNewToken(token, strError))
                return state.DoS(100, error(strError.c_str()), REJECT_INVALID, strError);

        } else if (tx.IsReissueToken()) {

            /** Verify the reissue tokens data */
            std::string strError;
            if (!tx.VerifyReissueToken(strError))
                return state.DoS(100, error(strError.c_str()), REJECT_INVALID, strError);

            CReissueToken reissue;
            std::string strAddress;
            if (!ReissueTokenFromTransaction(tx, reissue, strAddress))
                return state.DoS(100, error("bad-txns-reissue-token"), REJECT_INVALID, "bad-txns-reissue-token");

            if (!CheckReissueToken(reissue, strError))
                return state.DoS(100, error(strError.c_str()), REJECT_INVALID, strError);

            // Get the tokenType
            ETokenType type;
            IsTokenNameValid(reissue.strName, type);

        } else if (tx.IsNewUniqueToken()) {

            /** Verify the unique tokens data */
            std::string strError = "";
            if (!tx.VerifyNewUniqueToken(strError)) {
                return state.DoS(100, error(strError.c_str()), REJECT_INVALID, strError);
            }


            for (auto out : tx.vout)
            {
                if (IsScriptNewUniqueToken(out.scriptPubKey))
                {
                    CNewToken token;
                    std::string strAddress;
                    if (!TokenFromScript(out.scriptPubKey, token, strAddress))
                        return state.DoS(100, error("bad-txns-check-transaction-issue-unique-token-serialization"), REJECT_INVALID, "bad-txns-check-transaction-issue-unique-token-serialization");

                    if (!CheckNewToken(token, strError))
                        return state.DoS(100, error(strError.c_str()), REJECT_INVALID, "bad-txns-issue-unique" + strError);
                }
            }
        }
        else {
            // Fail if transaction contains any non-transfer token scripts and hasn't conformed to one of the
            // above transaction types.  Also fail if it contains OP_YAC_TOKEN opcode but wasn't a valid script.
            for (auto out : tx.vout) {
                int nType;
                bool _isOwner;
                if (out.scriptPubKey.IsTokenScript(nType, _isOwner)) {
                    if (nType != TX_TRANSFER_TOKEN) {
                        return state.DoS(100, error("bad-txns-bad-token-transaction"), REJECT_INVALID, "bad-txns-bad-token-transaction");
                    }
                } else {
                    if (out.scriptPubKey.Find(OP_YAC_TOKEN)) {
                        if (out.scriptPubKey[0] != OP_YAC_TOKEN) {
                            return state.DoS(100, error("bad-txns-op-yac-token-not-in-right-script-location"), REJECT_INVALID, "bad-txns-op-yac-token-not-in-right-script-location");
                        }
                    }
                }
            }
        }
    }
    /* YAC_TOKEN END */

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, const CBlockIndex* pindexBlock)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!inputs.HaveInputs(tx))
        return state.Invalid(error("Consensus::CheckTxInputs: Inputs unavailable"), 0, "", "Inputs unavailable");

    CAmount nValueIn = 0;
    CAmount nFees = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase or coinstake, check that it's matured
        if ((coin.IsCoinBase() || coin.IsCoinStake()) && nSpendHeight - coin.nHeight < GetCoinbaseMaturity()) {
            return state.Invalid(false,
                REJECT_INVALID, "bad-txns-premature-spend-of-coinbase/coinstake",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // ppcoin: check transaction timestamp
        if (coin.nTime > tx.nTime)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-spent-too-early", false, strprintf("%s : transaction timestamp earlier than input transaction", __func__));

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");

    }

    if (tx.IsCoinStake())
    {
        // ppcoin: coin stake tx earns reward instead of paying fee
        uint64_t nCoinAge;
        if (!GetCoinAge(tx, inputs, nCoinAge))
            return state.DoS(100, false, REJECT_INVALID, "unable to get coin age for coinstake");

        unsigned int nTxSize = (tx.nTime > VALIDATION_SWITCH_TIME || fTestNet) ? ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) : 0;
        CAmount nReward = tx.GetValueOut() - nValueIn;
        CAmount nCalculatedReward = GetProofOfStakeReward(nCoinAge, pindexBlock->nBits, tx.nTime) - GetMinFee(nTxSize) + CENT;

        if (nReward > nCalculatedReward)
            return state.DoS(100, error("Consensus::CheckTxInputs: coinstake pays too much(actual=%lld, calculated=%lld)", nReward, nCalculatedReward), REJECT_INVALID, "bad-txns-coinstake-too-large");
    }
    else
    {
        const CAmount value_out = tx.GetValueOut();
        if (nValueIn < value_out) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
        }
        // Tally transaction fees
        CAmount nTxFee = nValueIn - tx.GetValueOut();
        if (nTxFee < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    }

    return true;
}

//! Check to make sure that the inputs and outputs CAmount match exactly.
bool Consensus::CheckTxTokens(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, CTokensCache* tokenCache, bool fCheckMempool, std::vector<std::pair<std::string, uint256> >& vPairReissueTokens)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!inputs.HaveInputs(tx))
        return state.Invalid(error("Consensus::CheckTxTokens: Inputs unavailable"), 0, "", "Inputs unavailable");

    // Create map that stores the amount of an token transaction input. Used to verify no tokens are burned
    std::map<std::string, CAmount> totalInputs;
    std::map<std::string, std::string> mapAddresses;

    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        if (coin.IsToken()) {
            CTokenOutputEntry data;
            if (!GetTokenData(coin.out.scriptPubKey, data))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-failed-to-get-token-from-script", false, "bad-txns-failed-to-get-token-from-script");

            // Reject out-of-range token input amounts. Without this, a crafted amount can be summed
            // into totalInputs below and wrap the signed 64-bit accumulator (Token Transfer Quantity Overflow).
            if (data.nAmount < 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-input-token-amount-negative", false, "bad-txns-input-token-amount-negative");
            if (data.nAmount > MAX_MONEY)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-input-token-amount-toolarge", false, "bad-txns-input-token-amount-toolarge");

            // Add to the total value of tokens in the inputs
            if (totalInputs.count(data.tokenName))
                totalInputs.at(data.tokenName) += data.nAmount;
            else
                totalInputs.insert(make_pair(data.tokenName, data.nAmount));

            // Re-check the running total after each addition, so an overflow of the accumulator itself is caught.
            if (!MoneyRange(totalInputs.at(data.tokenName)))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-input-token-totalInputs-toolarge", false, "bad-txns-input-token-totalInputs-toolarge");
        }
    }

    // Create map that stores the amount of an token transaction output. Used to verify no tokens are burned
    std::map<std::string, CAmount> totalOutputs;
    int index = 0;
    int64_t currentTime = GetTime();
    std::string strError = "";
    int i = 0;
    for (const auto& txout : tx.vout) {
        i++;
        bool fIsToken = false;
        int nType = 0;
        bool fIsOwner = false;
        if (txout.scriptPubKey.IsTokenScript(nType, fIsOwner))
            fIsToken = true;

        if (tokenCache)
        {
            if (fIsToken && !AreTokensDeployed())
            {
                LogPrintf("WARNING: bad-txns-is-token-and-token-not-active\n");
                continue;
            }
        }

        if (nType == TX_TRANSFER_TOKEN)
        {
            CTokenTransfer transfer;
            std::string address = "";
            if (!TransferTokenFromScript(txout.scriptPubKey, transfer, address))
                return state.DoS(100, false, REJECT_INVALID, "bad-tx-token-transfer-bad-deserialize", false, "bad-tx-token-transfer-bad-deserialize");

            if (!ContextualCheckTransferToken(tokenCache, transfer, address, strError))
                return state.DoS(100, false, REJECT_INVALID, strError, false, strError);

            // Reject out-of-range token transfer amounts. ContextualCheckTransferToken only rejects
            // amounts <= 0, so without an upper bound a crafted amount can wrap the signed 64-bit
            // accumulator below and defeat the inputs-equal-outputs check (Token Transfer Quantity Overflow).
            if (transfer.nAmount < 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-transfer-token-amount-negative", false, "bad-txns-transfer-token-amount-negative");
            if (transfer.nAmount > MAX_MONEY)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-transfer-token-amount-toolarge", false, "bad-txns-transfer-token-amount-toolarge");

            // Add to the total value of tokens in the outputs
            if (totalOutputs.count(transfer.strName))
                totalOutputs.at(transfer.strName) += transfer.nAmount;
            else
                totalOutputs.insert(make_pair(transfer.strName, transfer.nAmount));

            // Re-check the running total after each addition, so an overflow of the accumulator itself is caught.
            if (!MoneyRange(totalOutputs.at(transfer.strName)))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-transfer-token-totalOutputs-toolarge", false, "bad-txns-transfer-token-totalOutputs-toolarge");

            if (IsTokenNameAnOwner(transfer.strName))
            {
                if (transfer.nAmount != OWNER_TOKEN_AMOUNT)
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-transfer-owner-amount-was-not-1", false, "bad-txns-transfer-owner-amount-was-not-1");
            }
            else
            {
                // For all other types of tokens, make sure they are sending the right type of units
                CNewToken token;
                if (!tokenCache->GetTokenMetaDataIfExists(transfer.strName, token))
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-transfer-token-not-exist", false, "bad-txns-transfer-token-not-exist");

                if (token.strName != transfer.strName)
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-token-database-corrupted", false, "bad-txns-token-database-corrupted");

                if (!CheckAmountWithUnits(transfer.nAmount, token.units))
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-transfer-token-amount-not-match-units", false, "bad-txns-transfer-token-amount-not-match-units");
            }
        }
        else if (nType == TX_REISSUE_TOKEN)
        {
            CReissueToken reissue;
            std::string address;
            if (!ReissueTokenFromScript(txout.scriptPubKey, reissue, address))
                return state.DoS(100, false, REJECT_INVALID, "bad-tx-token-reissue-bad-deserialize", false, "bad-tx-token-reissue-bad-deserialize");

            if (mapReissuedTokens.count(reissue.strName))
            {
                if (mapReissuedTokens.at(reissue.strName) != tx.GetHash())
                    return state.DoS(100, false, REJECT_INVALID, "bad-tx-reissue-chaining-not-allowed", false, "bad-tx-reissue-chaining-not-allowed");
            }
            else
            {
                vPairReissueTokens.emplace_back(std::make_pair(reissue.strName, tx.GetHash()));
            }
        }
        index++;
    }

    if (tokenCache)
    {
        if (tx.IsNewToken())
        {
            // Get the token type
            CNewToken token;
            std::string address;
            if (!TokenFromScript(tx.vout[tx.vout.size() - 1].scriptPubKey, token, address)) {
                error("%s : Failed to get new token from transaction: %s", __func__, tx.GetHash().GetHex());
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-issue-serialzation-failed", false, "bad-txns-issue-serialzation-failed");
            }

            ETokenType tokenType;
            IsTokenNameValid(token.strName, tokenType);

            if (!ContextualCheckNewToken(tokenCache, token, strError, fCheckMempool))
                return state.DoS(100, false, REJECT_INVALID, strError, false, strError);

        }
        else if (tx.IsReissueToken())
        {
            CReissueToken reissue_token;
            std::string address;
            if (!ReissueTokenFromScript(tx.vout[tx.vout.size() - 1].scriptPubKey, reissue_token, address)) {
                error("%s : Failed to get new token from transaction: %s", __func__, tx.GetHash().GetHex());
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-reissue-serialzation-failed", false, "bad-txns-reissue-serialzation-failed");
            }
            if (!ContextualCheckReissueToken(tokenCache, reissue_token, strError, tx))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-reissue-contextual-" + strError, false, "bad-txns-reissue-contextual-" + strError);
        }
        else if (tx.IsNewUniqueToken())
        {
            if (!ContextualCheckUniqueTokenTx(tokenCache, strError, tx))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-issue-unique-contextual-" + strError, false, "bad-txns-issue-unique-contextual-" + strError);
        }
        else {
            for (auto out : tx.vout)
            {
                int nType;
                bool _isOwner;
                if (out.scriptPubKey.IsTokenScript(nType, _isOwner))
                {
                    if (nType != TX_TRANSFER_TOKEN) {
                        return state.DoS(100, false, REJECT_INVALID, "bad-txns-bad-token-transaction", false, "bad-txns-bad-token-transaction");
                    }
                }
                else
                {
                    if (out.scriptPubKey.Find(OP_YAC_TOKEN))
                    {
                        return state.DoS(100, false, REJECT_INVALID, "bad-txns-bad-token-script", false, "bad-txns-bad-token-script");
                    }
                }
            }
        }
    }

    for (const auto& outValue : totalOutputs)
    {
        if (!totalInputs.count(outValue.first))
        {
            std::string errorMsg;
            errorMsg = strprintf("Bad Transaction - Trying to create outpoint for token that you don't have: %s", outValue.first);
            return state.DoS(100, false, REJECT_INVALID, "bad-tx-inputs-outputs-mismatch " + errorMsg, false, "bad-tx-inputs-outputs-mismatch " + errorMsg);
        }

        if (totalInputs.at(outValue.first) != outValue.second)
        {
            std::string errorMsg;
            errorMsg = strprintf("Bad Transaction - Tokens would be burnt %s", outValue.first);
            return state.DoS(100, false, REJECT_INVALID, "bad-tx-inputs-outputs-mismatch " + errorMsg, false, "bad-tx-inputs-outputs-mismatch " + errorMsg);
        }
    }

    // Check the input size and the output size
    if (totalOutputs.size() != totalInputs.size())
    {
        return state.DoS(100, false, REJECT_INVALID, "bad-tx-token-inputs-size-does-not-match-outputs-size", false, "bad-tx-token-inputs-size-does-not-match-outputs-size");
    }
    return true;
}
