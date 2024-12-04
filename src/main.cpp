// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_CHECKPOINT_H
 #include "checkpoints.h"
#endif

#ifndef BITCOIN_DB_H
 #include "db.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb-leveldb.h"
#endif

#ifndef BITCOIN_INIT_H
 #include "init.h"
#endif

#ifndef CHECKQUEUE_H
 #include "checkqueue.h"
#endif

#ifndef PPCOIN_KERNEL_H
 #include "kernel.h"
#endif

#ifdef QT_GUI
 #include "explorer.h"
#endif

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/math/special_functions/round.hpp>

#ifndef BITCOIN_MAIN_H
 #include "main.h"
#endif

#include "reverse_iterator.h"
#include "random.h"
#include "streams.h"
#include "validationinterface.h"
#include "net_processing.h"

using namespace boost;

using std::list;
using std::set;
using std::string;
using std::vector;
using std::runtime_error;
using std::map;
using std::pair;
using std::make_pair;
using std::max;
using std::min;
using std::multimap;
using std::deque;


//
// FOR UPDATE TRANSACTION MEMPOOL IN REORG
//
/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

static void UpdateMempoolForReorg(CTxDB& txdb, DisconnectedBlockTransactions &disconnectpool, bool fAddToMempool)
{
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        CTransactionRef tx = *it;
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!fAddToMempool || tx->IsCoinBase() || tx->IsCoinStake() || !tx->AcceptToMemoryPool(stateDummy, txdb)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(*tx, MemPoolRemovalReason::REORG);
        } else if (mempool.exists(tx->GetHash())) {
            vHashUpdate.push_back(tx->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);
    // We also need to remove any now-immature transactions
    mempool.removeForReorg(chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
}
//
// END OF FOR UPDATE TRANSACTION MEMPOOL IN REORG
//

//
// GLOBAL VARIABLES USED FOR TOKEN MANAGEMENT SYSTEM
//
CTokensDB *ptokensdb = nullptr;
CTokensCache *ptokens = nullptr;
CLRUCache<std::string, CDatabasedTokenData> *ptokensCache = nullptr;
bool fTokenIndex = false;
bool fAddressIndex = false;
//
// END OF GLOBAL VARIABLES USED FOR TOKEN MANAGEMENT SYSTEM
//

//
// FUNCTIONS USED FOR TOKEN MANAGEMENT SYSTEM
//
/** Flush all state, indexes and buffers to disk. */
bool FlushTokenToDisk()
{
    // Flush the tokenstate
    if (AreTokensDeployed()) {
        // Flush the tokenstate
        auto currentActiveTokenCache = GetCurrentTokenCache();
        if (currentActiveTokenCache) {
            if (!currentActiveTokenCache->DumpCacheToDatabase())
                return error("FlushTokenToDisk(): Failed to write to token database");
        }
    }

    // Write the reissue mempool data to database
    if (ptokensdb)
        ptokensdb->WriteReissuedMempoolState();
}

bool AreTokensDeployed()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nTokenSupportBlockNumber)
    {
        return true;
    }
    return false;
}

CTokensCache* GetCurrentTokenCache()
{
    return ptokens;
}

bool CheckTxTokens(const CTransaction &tx, CValidationState &state,
        MapPrevTx inputs, CTokensCache *tokenCache, bool fCheckMempool,
        std::vector<std::pair<std::string, uint256>> &vPairReissueTokens)
{
    // Create map that stores the amount of an token transaction input. Used to verify no tokens are burned
    std::map<std::string, CAmount> totalInputs;
    std::map<std::string, std::string> mapAddresses;

    for (unsigned int i = 0; i < tx.vin.size(); ++i)
    {
        const COutPoint &prevout = tx.vin[i].prevout;
        Yassert(inputs.count(prevout.COutPointGetHash()) > 0);
        CTxIndex &txindex = inputs[prevout.COutPointGetHash()].first;
        CTransaction &txPrev = inputs[prevout.COutPointGetHash()].second;
        CTxOut &txPrevOut = txPrev.vout[prevout.COutPointGet_n()];

        if (!txindex.vSpent[prevout.COutPointGet_n()].IsNull())
            return state.Invalid(
                    error("CTransaction::CheckTxTokens() : %s prev tx already used at %s",
                          tx.GetHash().ToString().substr(0, 10).c_str(),
                          txindex.vSpent[prevout.COutPointGet_n()].ToString().c_str()));

        if (txPrevOut.scriptPubKey.IsTokenScript())
        {
            CTokenOutputEntry data;
            if (!GetTokenData(txPrevOut.scriptPubKey, data))
                return state.DoS(100, error("bad-txns-failed-to-get-token-from-script"));

            // Add to the total value of tokens in the inputs
            if (totalInputs.count(data.tokenName))
                totalInputs.at(data.tokenName) += data.nAmount;
            else
                totalInputs.insert(std::make_pair(data.tokenName, data.nAmount));
        }
    }

    // Create map that stores the amount of an token transaction output. Used to
    // verify no tokens are burned
    std::map<std::string, CAmount> totalOutputs;
    int index = 0;
    int64_t currentTime = GetTime();
    std::string strError = "";
    int i = 0;
    for (const auto &txout : tx.vout)
    {
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
                return state.DoS(100, error("bad-tx-token-transfer-bad-deserialize"));

            if (!ContextualCheckTransferToken(tokenCache, transfer, address, strError))
                return state.DoS(100, error(strError.c_str()));

            // Add to the total value of tokens in the outputs
            if (totalOutputs.count(transfer.strName))
                totalOutputs.at(transfer.strName) += transfer.nAmount;
            else
                totalOutputs.insert(std::make_pair(transfer.strName, transfer.nAmount));

            if (IsTokenNameAnOwner(transfer.strName))
            {
                if (transfer.nAmount != OWNER_TOKEN_AMOUNT)
                    return state.DoS(100, error("bad-txns-transfer-owner-amount-was-not-1"));
            }
            else
            {
                // For all other types of tokens, make sure they are sending the right
                // type of units
                CNewToken token;
                if (!tokenCache->GetTokenMetaDataIfExists(transfer.strName, token))
                    return state.DoS(100, error("bad-txns-transfer-token-not-exist"));

                if (token.strName != transfer.strName)
                    return state.DoS(100, error("bad-txns-token-database-corrupted"));

                if (!CheckAmountWithUnits(transfer.nAmount, token.units))
                    return state.DoS(100, error("bad-txns-transfer-token-amount-not-match-units"));
            }
        }
        else if (nType == TX_REISSUE_TOKEN)
        {
            CReissueToken reissue;
            std::string address;
            if (!ReissueTokenFromScript(txout.scriptPubKey, reissue, address))
                return state.DoS(100, error("bad-tx-token-reissue-bad-deserialize"));

            if (mapReissuedTokens.count(reissue.strName))
            {
                if (mapReissuedTokens.at(reissue.strName) != tx.GetHash())
                    return state.DoS(100, error("bad-tx-reissue-chaining-not-allowed"));
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
                return state.DoS(100, error("bad-txns-issue-serialzation-failed"));
            }

            ETokenType tokenType;
            IsTokenNameValid(token.strName, tokenType);

            if (!ContextualCheckNewToken(tokenCache, token, strError, fCheckMempool))
                return state.DoS(100, error(strError.c_str()));

        }
        else if (tx.IsReissueToken())
        {
            CReissueToken reissue_token;
            std::string address;
            if (!ReissueTokenFromScript(tx.vout[tx.vout.size() - 1].scriptPubKey, reissue_token, address))
            {
                error("%s : Failed to get new token from transaction: %s", __func__, tx.GetHash().GetHex());
                return state.DoS(100, error("bad-txns-reissue-serialzation-failed"));
            }
            if (!ContextualCheckReissueToken(tokenCache, reissue_token, strError, tx))
                return state.DoS(100, error("bad-txns-reissue-contextual-"));
        }
        else if (tx.IsNewUniqueToken())
        {
            if (!ContextualCheckUniqueTokenTx(tokenCache, strError, tx))
                return state.DoS(100, error("bad-txns-issue-unique-contextual-"));
        }
        else
        {
            for (auto out : tx.vout)
            {
                int nType;
                bool _isOwner;
                if (out.scriptPubKey.IsTokenScript(nType, _isOwner))
                {
                    if (nType != TX_TRANSFER_TOKEN)
                    {
                        return state.DoS(100, error("bad-txns-bad-token-transaction"));
                    }
                }
                else
                {
                    if (out.scriptPubKey.Find(OP_YAC_TOKEN))
                    {
                        return state.DoS(100, error("bad-txns-bad-token-script"));
                    }
                }
            }
        }
    }

    for (const auto &outValue : totalOutputs)
    {
        if (!totalInputs.count(outValue.first))
        {
            std::string errorMsg;
            errorMsg =
                    strprintf("Bad Transaction - Trying to create outpoint for token that you don't have: %s", outValue.first);
            return state.DoS(100, error("bad-tx-inputs-outputs-mismatch "));
        }

        if (totalInputs.at(outValue.first) != outValue.second)
        {
            std::string errorMsg;
            errorMsg = strprintf("Bad Transaction - Tokens would be burnt %s", outValue.first);
            return state.DoS(100, error("bad-tx-inputs-outputs-mismatch "));
        }
    }

    // Check the input size and the output size
    if (totalOutputs.size() != totalInputs.size())
    {
        return state.DoS(100, error("bad-tx-token-inputs-size-does-not-match-outputs-size"));
    }
    return true;
}

void UpdateTokenInfo(const CTransaction& tx, MapPrevTx& prevInputs, int nHeight, uint256 blockHash, CTokensCache* tokensCache, std::pair<std::string, CBlockTokenUndo>* undoTokenData)
{
    // Iterate through tx inputs and update token info
    if (!tx.IsCoinBase()) {
        for (const CTxIn &txin : tx.vin) {
            const COutPoint&
                prevout = txin.prevout;
            const CTransaction
                & txPrev = prevInputs[prevout.COutPointGetHash()].second;
            UpdateTokenInfoFromTxInputs(prevout,txPrev.vout[prevout.COutPointGet_n()], tokensCache);
        }
    }

    // Update token info from Tx outputs
    UpdateTokenInfoFromTxOutputs(tx, nHeight, blockHash, tokensCache, undoTokenData);
}

void UpdateTokenInfoFromTxInputs(const COutPoint& outpoint, const CTxOut& txOut, CTokensCache* tokensCache)
{
    if (AreTokensDeployed()) {
        if (tokensCache) {
            if (!tokensCache->TrySpendCoin(outpoint, txOut)) {
                error("%s : Failed to try and spend the token. COutPoint : %s", __func__, outpoint.ToString());
            }
        }
    }
}

void UpdateTokenInfoFromTxOutputs(const CTransaction& tx, int nHeight, uint256 blockHash, CTokensCache* tokensCache, std::pair<std::string, CBlockTokenUndo>* undoTokenData)
{
    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();

    if (AreTokensDeployed()) {
        if (tokensCache) {
            if (tx.IsNewToken()) { // This works are all new yatoken tokens, sub token, and restricted tokens
                CNewToken token;
                std::string strAddress;
                TokenFromTransaction(tx, token, strAddress);

                std::string ownerName;
                std::string ownerAddress;
                OwnerFromTransaction(tx, ownerName, ownerAddress);

                // Add the new token to cache
                if (!tokensCache->AddNewToken(token, strAddress, nHeight, blockHash))
                    error("%s : Failed at adding a new token to our cache. token: %s", __func__,
                          token.strName);

                // Add the owner token to cache
                if (!tokensCache->AddOwnerToken(ownerName, ownerAddress))
                    error("%s : Failed at adding a new token to our cache. token: %s", __func__,
                          token.strName);

            } else if (tx.IsReissueToken()) {
                CReissueToken reissue;
                std::string strAddress;
                ReissueTokenFromTransaction(tx, reissue, strAddress);

                int reissueIndex = tx.vout.size() - 1;

                // Get the token before we change it
                CNewToken token;
                if (!tokensCache->GetTokenMetaDataIfExists(reissue.strName, token))
                    error("%s: Failed to get the original token that is getting reissued. Token Name : %s",
                          __func__, reissue.strName);

                if (!tokensCache->AddReissueToken(reissue, strAddress, COutPoint(txid, reissueIndex)))
                    error("%s: Failed to reissue an token. Token Name : %s", __func__, reissue.strName);

                // Set the old IPFSHash for the blockundo
                bool fIPFSChanged = !reissue.strIPFSHash.empty();
                bool fUnitsChanged = reissue.nUnits != -1;

                // If any of the following items were changed by reissuing, we need to database the old values so it can be undone correctly
                if (fIPFSChanged || fUnitsChanged) {
                    undoTokenData->first = reissue.strName; // Token Name
                    undoTokenData->second = CBlockTokenUndo {fIPFSChanged, fUnitsChanged, token.strIPFSHash, token.units}; // ipfschanged, unitchanged, Old Tokens IPFSHash, old units
                }
            } else if (tx.IsNewUniqueToken()) {
                for (int n = 0; n < (int)tx.vout.size(); n++) {
                    auto out = tx.vout[n];

                    CNewToken token;
                    std::string strAddress;

                    if (IsScriptNewUniqueToken(out.scriptPubKey)) {
                        TokenFromScript(out.scriptPubKey, token, strAddress);

                        // Add the new token to cache
                        if (!tokensCache->AddNewToken(token, strAddress, nHeight, blockHash))
                            error("%s : Failed at adding a new token to our cache. token: %s", __func__,
                                  token.strName);
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (AreTokensDeployed()) {
            if (tokensCache) {
                CTokenOutputEntry tokenData;
                if (GetTokenData(tx.vout[i].scriptPubKey, tokenData)) {

                    // If this is a transfer token, and the amount is greater than zero
                    // We want to make sure it is added to the token addresses database if (fTokenIndex == true)
                    if (tokenData.type == TX_TRANSFER_TOKEN && tokenData.nAmount > 0) {
                        // Create the objects needed from the tokenData
                        CTokenTransfer tokenTransfer(tokenData.tokenName, tokenData.nAmount);
                        std::string address = EncodeDestination(tokenData.destination);

                        // Add the transfer token data to the token cache
                        if (!tokensCache->AddTransferToken(tokenTransfer, address, COutPoint(txid, i), tx.vout[i]))
                            error("%s : ERROR - Failed to add transfer token CTxOut: %s\n", __func__,
                                      tx.vout[i].ToString());
                    }
                }
            }
        }
    }
}

bool GetAddressIndex(uint160 addressHash, int type,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex, int start, int end)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    CTxDB txdb;
    if (!txdb.ReadAddressIndex(addressHash, type, addressIndex, start, end))
        return error("unable to get txids for address");

    return true;
}

bool GetAddressIndex(uint160 addressHash, int type, std::string tokenName,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex, int start, int end)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    CTxDB txdb;
    if (!txdb.ReadAddressIndex(addressHash, type, tokenName, addressIndex, start, end))
        return error("unable to get txids for address");

    return true;
}
bool GetAddressUnspent(uint160 addressHash, int type, std::string tokenName,
                       std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    CTxDB txdb;
    if (!txdb.ReadAddressUnspentIndex(addressHash, type, tokenName, unspentOutputs))
        return error("unable to get txids for address");

    return true;
}

bool GetAddressUnspent(uint160 addressHash, int type,
                       std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    CTxDB txdb;
    if (!txdb.ReadAddressUnspentIndex(addressHash, type, unspentOutputs))
        return error("unable to get txids for address");

    return true;
}
boost::filesystem::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetDataDir() / strprintf("%s%04u.dat", prefix, pos.nFile);
}
//
// END OF FUNCTIONS USED FOR TOKEN MANAGEMENT SYSTEM
//

// PoS constants
const unsigned int nStakeMaxAge = 90 * nSecondsPerDay;  // 60 * 60 * 24 * 90; // 90 days as full weight
const unsigned int nOnedayOfAverageBlocks = (nSecondsPerDay / nStakeTargetSpacing) / 10;  // the old 144
const unsigned int nStakeMinAge = 30 * nSecondsPerDay; // 60 * 60 * 24 * 30, 30 days as zero time weight
const unsigned int nStakeTargetSpacing = 1 * nSecondsperMinute; // 1 * 60; // 1-minute stake spacing
const unsigned int nPoWTargetSpacing = nStakeTargetSpacing;
const unsigned int nModifierInterval = 6 * nSecondsPerHour; // 6 * 60 * 60, time to elapse before new modifier is computed

int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;

const ::int64_t 
    nSimulatedMOneySupplyAtFork = 124460820773591;  //124,460,820.773591 YAC
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    const int64_t INITIAL_MONEY_SUPPLY = 0;
#else
    const int64_t INITIAL_MONEY_SUPPLY = 1E14;
#endif

const uint256 
  hashGenesisBlockTestNet( "0x1dc29b112550069ecb870e1be78c8d0c166e5f4e41433283e74dcf30b510c1f3" ),
  hashGenesisMerkleRootTestNet( "0xd6ab993974b85898d45cfd850c8865fefa342450b4b38dca9eaafb515920baf7" ),
  hashGenesisMerkleRootMainNet( "0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f");

const ::uint32_t 
    nTestNetGenesisNonce = 0x1F656; // = 128,598 decimal
/*
Read best chain
block.nNonce == 0001F66B
block.nNonce == 0001F66B (128619 dec) after 31 tries
block.GetHash() ==
0bd0495ffce47a76504f338692b70dfcd8fabc5176a49cc646f3f28478b132dc
block.nBits ==
0fffff0000000000000000000000000000000000000000000000000000000000
block.hashMerkleRoot ==
389003d67b17d9a38a9c83b9289225f5e5469b9f6a2d70fc7c97ee6e8f995f23
*/
//
const int
    nBigLinearTrailingAverageLength = 2100, // arbitrary but 35 hours
    nNewBigLinearTrailingAverageLength = 10 * nBigLinearTrailingAverageLength, // 21000 arbitrary but 350 hours!!
    nExponentialTrailingAverageLength = 8;  //arbitrary
int 
    nStatisticsNumberOfBlocks2000 = 2000,
    nStatisticsNumberOfBlocks1000 = 1000,
    nStatisticsNumberOfBlocks200 = 200,
    nStatisticsNumberOfBlocks100 = 100,
    nStatisticsNumberOfBlocks,  // = nBigLinearTrailingAverageLength,    
    nConsecutiveStakeSwitchHeight = 420000;  // see timesamps.h

CCriticalSection cs_vpwalletRegistered;
vector<CWallet*> vpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;

BlockMap mapBlockIndex;
// are all of these undocumented numbers a function of Nfactor?  Cpu power? Other???
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
CBigNum bnProofOfWorkLimit(~uint256(0) >> 20);
#else
CBigNum bnProofOfWorkLimit(~uint256(0) >> 3);
#endif

CBigNum bnProofOfStakeLegacyLimit(~uint256(0) >> 24); 
CBigNum bnProofOfStakeLimit(~uint256(0) >> 27); 
CBigNum bnProofOfStakeHardLimit(~uint256(0) >> 30); // fix minimal proof of stake difficulty at 0.25

//  CBigNum bnProofOfWorkLimitTestNet(~uint256(0) >> 16);    
//                           IS IT A MAX OR A MIN? 
//                           IS IT AN EASE? 
//                           IS IT A DIFFICULTY??????
//                           can you say NFD

                                            // this is the number used by TestNet 0.5.0.x
const uint256 nPoWeasiestTargetLimitTestNet = ((~uint256( 0 )) >> 3 );
CBigNum bnProofOfWorkLimitTestNet( nPoWeasiestTargetLimitTestNet );

// YACOIN TODO
::int64_t nBlockRewardPrev = 0;
::uint32_t nMinEase = bnProofOfWorkLimit.GetCompact();
bool recalculateBlockReward = false;
bool recalculateMinEase = false;

static CBigNum bnProofOfStakeTestnetLimit(~uint256(0) >> 20);

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
static CBigNum bnInitialHashTarget(~uint256(0) >> 20);
#else
static CBigNum bnInitialHashTarget(~uint256(0) >> 8);
#endif

static CBigNum bnInitialHashTargetTestNet(~uint256(0) >> 8);    // test
//static CBigNum bnInitialHashTarget(~uint256(0) >> 16);

int
    nCoinbaseMaturityInBlocks = 500;

int 
    nCoinbaseMaturity = nCoinbaseMaturityInBlocks;  //500;
                                                    // @~1 blk/minute, ~8.33 hrs        

int
    nCoinbaseMaturityAfterHardfork = 6;

CChain chainActive;

CBigNum bnBestChainTrust(0);
CBlockIndex *pindexBestInvalid;

uint256 hashBestChain = 0;
// The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS or better that are at least
// as good as our current tip. Entries may be failed, though.
set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates; // may contain all CBlockIndex*'s that have validness >=BLOCK_VALID_TRANSACTIONS, and must contain those who aren't failed
// Best header we've seen so far (used for getheaders queries' starting points).
CBlockIndex *pindexBestHeader = NULL;
// Number of nodes with fSyncStarted.
int nSyncStarted = 0;
// All pairs A->B, where A (or one if its ancestors) misses transactions, but B has transactions.
multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;
int nScriptCheckThreads = 0;

CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

map<uint256, uint256> mapProofOfStake;

CCheckQueue<CScriptCheck> scriptcheckqueue(128);

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Yacoin Signed Message:\n";

// Settings
::int64_t nTransactionFee = MIN_TX_FEE;
::int64_t nMinimumInputValue = MIN_TX_FEE;

// Ping and address broadcast intervals
::int64_t nPingInterval = 10 * nSecondsPerMinute;  // 10 mins

::int64_t nBroadcastInterval = nOneDayInSeconds;    // can be from 6 days in seconds down to 0!

::int64_t
    nLongAverageBP2000 = 0,
    nLongAverageBP1000 = 0,
    nLongAverageBP200 = 0,
    nLongAverageBP100 = 0,
    nLongAverageBP = 0;

extern enum Checkpoints::CPMode CheckpointsMode;

// Blocks that are in flight, and that are in the queue to be downloaded.
// Protected by cs_main.
struct QueuedBlock {
    uint256 hash;
    CBlockIndex *pindex; // Optional.
    int64_t nTime;  // Time of "getdata" request in microseconds.
};

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state)
{
    return strprintf("%s (code %i)",
        state.GetRejectReason().c_str(),
        state.GetRejectCode());
}

void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_vpwalletRegistered);
        vpwalletRegistered.push_back(pwalletIn);
    }
}

void CloseWallets()
{
    {
        LOCK(cs_vpwalletRegistered);
        BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
            delete pwallet;
        vpwalletRegistered.clear();
    }
}

// check whether the passed transaction is from us
bool static IsFromMe(CTransaction& tx)
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}

// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        if (pwallet->GetTransaction(hashTx,wtx))
            return true;
    return false;
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fConnect)
{
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
                if (pwallet->IsFromMe(tx))
                    pwallet->DisableTransaction(tx);
        }
        return;
    }

    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
    // Preloaded coins cache invalidation
    fCoinsDataActual = false;
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        pwallet->PrintWallet(block);
}

// notify wallets about an incoming inventory (for request counts)
void Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void ResendWalletTransactions()
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        pwallet->ResendWalletTransactions();
}

/**
 * Calculates the block height and previous block's time at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
static std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx,
        int flags, std::vector<int> *prevHeights, const CBlockIndex &block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++)
    {
        const CTxIn &txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            CBlockIndex *pbi = FindBlockByHeight(std::max(nCoinHeight - 1, 0));
            int64_t nCoinTime = pbi->GetBlockTime();
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
            // txout being spent, which is the time of the block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        }
        else
        {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

static bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetBlockTime();
    if (lockPair.first >= block.nHeight)
    {
        LogPrintf("EvaluateSequenceLocks, failed to use relative time-lock coins, current block height  = %d"
                ", the coin inputs can only be used in a block with height > %d\n", block.nHeight, lockPair.first);
        return false;
    }
    else if (lockPair.second >= nBlockTime)
    {
        LogPrintf("EvaluateSequenceLocks, failed to use relative time-lock coins, current block time  = %ld (%s)"
                ", the coin inputs can only be used after a block with block time > %ld (%s) is mined\n",
                nBlockTime, DateTimeStrFormat(nBlockTime),
                lockPair.second, DateTimeStrFormat(lockPair.second));
        return false;
    }

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool TestLockPointValidity(const LockPoints* lp)
{
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!chainActive.Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    LOCK2(cs_main, mempool.cs);

    CBlockIndex* tip = chainActive.Tip();
    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Tip()->nHeight+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Tip()->nHeight
    index.nHeight = chainActive.Tip()->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            COutPoint prevout = tx.vin[txinIndex].prevout;

            // Check from both mempool and db
            if (mempool.exists(prevout.COutPointGetHash()))
            {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = chainActive.Tip()->nHeight + 1;
            }
            else // Check from txdb
            {
                CTransaction txPrev;
                CTxIndex txindex;
                CTxDB txdb("r");
                if (!txPrev.ReadFromDisk(txdb, prevout, txindex))
                {
                    // Can't find transaction index
                    return error("CheckSequenceLocks : ReadFromDisk tx %s failed", prevout.COutPointGetHash().ToString().substr(0,10).c_str());
                }

                uint256 hashBlock = 0;
                CBlock block;
                if (!block.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos(), false))
                {
                    return error("CheckSequenceLocks : ReadFromDisk block containing tx %s failed", prevout.COutPointGetHash().ToString().substr(0,10).c_str());
                }
                else
                {
                    hashBlock = block.GetHash();
                }

                BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
                if (mi != mapBlockIndex.end() && (*mi).second)
                {
                    CBlockIndex* pindex = (*mi).second;
                    prevheights[txinIndex] = pindex->nHeight;
                }
                else
                {
                    return error("CheckSequenceLocks : mapBlockIndex doesn't contains block %s", hashBlock.ToString().substr(0,10).c_str());
                }
            }
        }

        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }

    return EvaluateSequenceLocks(index, lockPair);
}

int GetCoinbaseMaturity()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
    {
        return nCoinbaseMaturityAfterHardfork;
    }
    else
    {
        return nCoinbaseMaturity;
    }
}

int GetCoinbaseMaturityOffset()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
    {
        return 0;
    }
    else
    {
        return 20;
    }
}
//////////////////////////////////////////////////////////////////////////////
//
// CTxIndex
//

int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    CBlock blockTmp;
    if (pblock == NULL)
    {
        // Load the block this tx is in
        CTxIndex txindex;
        if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
            return 0;
        if (!blockTmp.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos()))
            return 0;
        pblock = &blockTmp;
    }

    // Update the tx's hashBlock
    hashBlock = pblock->GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
        if (pblock->vtx[nIndex] == *(CTransaction*)this)
            break;
    if (nIndex == (int)pblock->vtx.size())
    {
        vMerkleBranch.clear();
        nIndex = -1;
        LogPrintf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
        return 0;
    }

    // Fill in merkle branch
    vMerkleBranch = pblock->GetMerkleBranch(nIndex);

    // Is the tx in a block that's in the main chain
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return chainActive.Tip()->nHeight - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return chainActive.Height() - pindex->nHeight + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    return max(
                0, 
                fTestNet?
                (GetCoinbaseMaturity() +  0) - GetDepthInMainChain():   //<<<<<<<<<<< test
                (GetCoinbaseMaturity() + GetCoinbaseMaturityOffset()) - GetDepthInMainChain()    // why is this 20?
              );                                                    // what is this 20 from? For?
}


bool CMerkleTx::AcceptToMemoryPool(CTxDB& txdb)
{
    CValidationState state;
    return CTransaction::AcceptToMemoryPool(state, txdb);
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb);
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb)
{

    {
        LOCK(mempool.cs);
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptToMemoryPool(txdb);
            }
        }
        return AcceptToMemoryPool(txdb);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(pos.Get_CDiskTxPos_nFile(), pos.Get_CDiskTxPos_nBlockPos(), false))
        return 0;
    // Find the block in the index
    BlockMap::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + chainActive.Height() - pindex->nHeight;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    {
        LOCK(cs_main);
        {
            LOCK(mempool.cs);
            if (mempool.exists(hash))
            {
                tx = mempool.get(hash);
                return true;
            }
        }
        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos(), false))
                hashBlock = block.GetHash();
            return true;
        }
    }
    return false;
}








//////////////////////////////////////////////////////////////////////////////
//
// CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;
CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    // Check input parameter
    if (nHeight <= 0)
        return chainActive.Genesis();
    if (nHeight >= chainActive.Tip()->nHeight)
        return chainActive.Tip();

    if (nHeight < chainActive.Height() / 2)
        pblockindex = chainActive.Genesis();
    else
        pblockindex = chainActive.Tip();
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
        pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

arith_uint256 GetBlockProof(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip)
{
    arith_uint256 r;
    int sign = 1;
    if (to.bnChainTrust > from.bnChainTrust) {
        CBigNum result = to.bnChainTrust - from.bnChainTrust;
        r = UintToArith256(result.getuint256());
    } else {
        CBigNum result = from.bnChainTrust - to.bnChainTrust;
        r = UintToArith256(result.getuint256());
        sign = -1;
    }
    r = r * arith_uint256(nPoWTargetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}

// yacoin: increasing Nfactor gradually
const unsigned char minNfactor = 4;
const unsigned char maxNfactor = MAXIMUM_N_FACTOR;
                                        //30; since uint32_t fails on 07 Feb 2106 06:28:15 GMT
                                        //    when stored as an uint32_t in a block
                                        //    so there is no point going past Nf = 25
const unsigned char maxNfactorYc1dot0 = 21;

unsigned char GetNfactor(::int64_t nTimestamp, bool fYac1dot0BlockOrTx)
{
	if (fYac1dot0BlockOrTx)
	{
		return MAXIMUM_YAC1DOT0_N_FACTOR;
	}

    int
        nBitCount = 0;

    if (
        ( nTimestamp <= (fTestNet? nChainStartTimeTestNet: nChainStartTime) )
        || fTestNet
       )    //was just nTimestamp <= nChainStartTime)
#if defined(Yac1dot0)
            return Nfactor_1dot0;
#else
            return minNfactor;
#endif

    ::int64_t
        nAgeOfBlockOrTxInSeconds = nTimestamp - (fTestNet? nChainStartTimeTestNet: nChainStartTime);
        //nChainStartTime, nSavedAgeOfBlockOrTxInSeconds = nAgeOfBlockOrTxInSeconds;

    while ((nAgeOfBlockOrTxInSeconds >> 1) > 3)     // nAgeOfBlockOrTxInSeconds / 2 is 4 or more
    {
        nBitCount += 1;
        nAgeOfBlockOrTxInSeconds >>= 1;             // /2 again
    }
    nAgeOfBlockOrTxInSeconds &= 0x03;   //3;    // really a mask on the low 2 bits.  But why?

    int                             // is 3 max
        n = ( (nBitCount * 170) + (nAgeOfBlockOrTxInSeconds * 25) - 2320) / 100;

    if (n < 0)
        n = 0;
    if (n > 255)
        LogPrintf("GetNfactor (%"PRId64") - something wrong(n == %d)\n", nTimestamp, n); // for g++

    // so n is between 0 and 0xff
    unsigned char N = (unsigned char)n;
#ifdef _DEBUG
    if(
        false &&    // just a quick way to turn it off
        fDebug &&
        fPrintToConsole
      )
    {
        LogPrintf(
                "GetNfactor: %"PRI64d" -> %d %"PRId64" : %d / %d\n",
                nTimestamp - (fTestNet? nChainStartTimeTestNet: nChainStartTime), //nChainStartTime,   // 64 bit int
                nBitCount,
                nAgeOfBlockOrTxInSeconds,
                n,
                (unsigned int)min(
                                    max(
                                        N,
                                        minNfactor
                                       ),
                                    maxNfactor
                                 )
                );
    }
#endif
    return min(max(N, minNfactor), maxNfactor);
}

// select stake target limit according to hard-coded conditions
CBigNum inline GetProofOfStakeLimit(int nHeight, unsigned int nTime)
{
    if(fTestNet) // separate proof of stake target limit for testnet
        return bnProofOfStakeTestnetLimit;  //bnProofOfStakeLimit;
    if(nTime > TARGETS_SWITCH_TIME)
        return bnProofOfStakeLimit; 

    return bnProofOfStakeHardLimit; // YAC has always been 30 
}

// Before hardfork, miner's coin base reward based on nBits
// After hardfork, calculate coinbase reward based on nHeight. If not specify nHeight, always
// calculate coinbase reward based on chainActive.Tip()->nHeight + 1 (reward of next best block)
::int64_t GetProofOfWorkReward(unsigned int nBits, ::int64_t nFees, unsigned int nHeight)
{
#ifdef Yac1dot0
    // Get reward of a specific block height
    if (nHeight != 0 && nHeight >= nMainnetNewLogicBlockNumber)
    {
        ::int32_t startEpochBlockHeight = (nHeight / nEpochInterval) * nEpochInterval;
        const CBlockIndex* pindexMoneySupplyBlock = FindBlockByHeight(startEpochBlockHeight - 1);
        return (pindexMoneySupplyBlock->nMoneySupply * nInflation / nNumberOfBlocksPerYear);
    }

    if (chainActive.Tip() && (chainActive.Tip()->nHeight + 1) >= nMainnetNewLogicBlockNumber)
    {
        // Get reward of current mining block
        ::int64_t nBlockRewardExcludeFees;
        if (recalculateBlockReward) // Reorg through two or many epochs
        {
            recalculateBlockReward = false;
            bool reorgToHardforkBlock = false;
            if (chainActive.Tip()->nHeight / nEpochInterval == nMainnetNewLogicBlockNumber / nEpochInterval)
            {
                reorgToHardforkBlock = true;
            }
            ::int32_t startEpochBlockHeight = (chainActive.Tip()->nHeight / nEpochInterval) * nEpochInterval;
            ::int32_t moneySupplyBlockHeight =
                reorgToHardforkBlock ? nMainnetNewLogicBlockNumber - 1 : startEpochBlockHeight - 1;
            const CBlockIndex* pindexMoneySupplyBlock = FindBlockByHeight(moneySupplyBlockHeight);
            nBlockRewardExcludeFees = (::int64_t)(pindexMoneySupplyBlock->nMoneySupply * nInflation / nNumberOfBlocksPerYear);
            nBlockRewardPrev = nBlockRewardExcludeFees;
        }
        else // normal case
        {
            // Default: nEpochInterval = 21000 blocks, recalculated with each epoch
            if ((chainActive.Tip()->nHeight + 1) % nEpochInterval == 0 || (chainActive.Tip()->nHeight + 1) == nMainnetNewLogicBlockNumber)
            {
                // recalculated
                // PoW reward is 2%
                nBlockRewardExcludeFees = (::int64_t)(chainActive.Tip()->nMoneySupply * nInflation / nNumberOfBlocksPerYear);
                nBlockRewardPrev = nBlockRewardExcludeFees;
            }
            else
            {
                nBlockRewardExcludeFees = (::int64_t)nBlockRewardPrev;
                if (!nBlockRewardPrev)
                {
                    const CBlockIndex* pindexMoneySupplyBlock =
                        FindBlockByHeight(nMainnetNewLogicBlockNumber ? nMainnetNewLogicBlockNumber - 1 : 0);
                    nBlockRewardExcludeFees =
                        (::int64_t)(pindexMoneySupplyBlock->nMoneySupply * nInflation / nNumberOfBlocksPerYear);
                }
            }
        }
        return nBlockRewardExcludeFees;
    }
#endif
    CBigNum bnSubsidyLimit = MAX_MINT_PROOF_OF_WORK;

    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    CBigNum bnTargetLimit = bnProofOfWorkLimit;
    bnTargetLimit.SetCompact(bnTargetLimit.GetCompact());

    // NovaCoin: subsidy is cut in half every 64x multiply of PoW difficulty
    // A reasonably continuous curve is used to avoid shock to market
    // (nSubsidyLimit / nSubsidy) ** 6 == bnProofOfWorkLimit / bnTarget
    //
    // Human readable form:
    //
    // nSubsidy = 100 / (diff ^ 1/6)
    CBigNum bnLowerBound = CENT;
    CBigNum bnUpperBound = bnSubsidyLimit;
    while (bnLowerBound + CENT <= bnUpperBound)
    {
        CBigNum bnMidValue = (bnLowerBound + bnUpperBound) / 2;
        if (fDebug && gArgs.GetBoolArg("-printcreation"))
          LogPrintf("GetProofOfWorkReward() : lower=%" PRId64 " upper=%" PRId64
                    " mid=%" PRId64 "\n",
                    bnLowerBound.getuint64(), bnUpperBound.getuint64(),
                    bnMidValue.getuint64());
        if (bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue *
                bnMidValue * bnTargetLimit >
            bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit *
                bnSubsidyLimit * bnSubsidyLimit * bnTarget)
          bnUpperBound = bnMidValue;
        else
            bnLowerBound = bnMidValue;
    }

    ::int64_t nSubsidy = bnUpperBound.getuint64();

    nSubsidy = (nSubsidy / CENT) * CENT;
    if (fDebug && gArgs.GetBoolArg("-printcreation"))
      LogPrintf(
          "GetProofOfWorkReward() : create=%s nBits=0x%08x nSubsidy=%" PRId64
          "\n",
          FormatMoney(nSubsidy), nBits, nSubsidy);

    return min(nSubsidy, MAX_MINT_PROOF_OF_WORK) + nFees;
}

// ppcoin: miner's coin stake is rewarded based on coin age spent (coin-days)
::int64_t GetProofOfStakeReward(::int64_t nCoinAge)
{
    static ::int64_t
        nRewardCoinYear = 5 * CENT;  // creation amount per coin-year

    ::int64_t 
        nSubsidy = nCoinAge * 33 / (365 * 33 + 8) * nRewardCoinYear;
    if (fDebug && gArgs.GetBoolArg("-printcreation"))
      LogPrintf("GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64 "\n",
                FormatMoney(nSubsidy), nCoinAge);
    return nSubsidy;
}
// miner's coin stake reward based on nBits and coin age spent (coin-days)
::int64_t GetProofOfStakeReward(::int64_t nCoinAge, unsigned int nBits, ::int64_t nTime, bool bCoinYearOnly)
{
    ::int64_t nRewardCoinYear, nSubsidy, nSubsidyLimit = 10 * COIN;

    if(
        fTestNet || 
        ((::uint64_t)nTime > (::uint64_t)STAKE_SWITCH_TIME)
        // is this the same as
        //(::uint64_t)nTime > (::uint64_t)STAKE_SWITCH_TIME
        // ?.  It seems not??
      )
    {
        // Stage 2 of emission process is PoS-based. It will be active on mainNet since 20 Jun 2013.

        CBigNum 
            bnRewardCoinYearLimit = MAX_MINT_PROOF_OF_STAKE; // Base stake mint rate, 100% year interest

        CBigNum 
            bnTarget;

        bnTarget.SetCompact(nBits);

        CBigNum 
            bnTargetLimit = GetProofOfStakeLimit(0, nTime);

        bnTargetLimit.SetCompact(bnTargetLimit.GetCompact());

        // NovaCoin: A reasonably continuous curve is used to avoid shock to market

        CBigNum 
            bnLowerBound = 1 * CENT, // Lower interest bound is 1% per year
            bnUpperBound = bnRewardCoinYearLimit, // Upper interest bound is 100% per year
            bnMidPart, bnRewardPart;

        while (bnLowerBound + CENT <= bnUpperBound)
        {
            CBigNum 
                bnMidValue = (bnLowerBound + bnUpperBound) / 2;

            if (fDebug && gArgs.GetBoolArg("-printcreation"))
              LogPrintf("GetProofOfStakeReward() : lower=%" PRId64
                        " upper=%" PRId64 " mid=%" PRId64 "\n",
                        bnLowerBound.getuint64(), bnUpperBound.getuint64(),
                        bnMidValue.getuint64());

            if(
                !fTestNet && 
                nTime < STAKECURVE_SWITCH_TIME
              )
            {
                //
                // Until 20 Oct 2013: reward for coin-year is cut in half 
                // every 64x multiply of PoS difficulty
                //
                // (nRewardCoinYearLimit / nRewardCoinYear) ** 6 == bnProofOfStakeLimit / bnTarget
                //
                // Human readable form: nRewardCoinYear = 1 / (posdiff ^ 1/6)
                //

                bnMidPart = bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue;
                bnRewardPart = bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit;
            }
            else
            {
                //
                // Since 20 Oct 2013: reward for coin-year is cut in half 
                // every 8x multiply of PoS difficulty
                //
                // (nRewardCoinYearLimit / nRewardCoinYear) ** 3 == bnProofOfStakeLimit / bnTarget
                //
                // Human readable form: nRewardCoinYear = 1 / (posdiff ^ 1/3)
                //

                bnMidPart = bnMidValue * bnMidValue * bnMidValue;
                bnRewardPart = bnRewardCoinYearLimit * bnRewardCoinYearLimit * bnRewardCoinYearLimit;
            }

            if (
                (bnMidPart * bnTargetLimit) > (bnRewardPart * bnTarget)
               )
                bnUpperBound = bnMidValue;
            else
                bnLowerBound = bnMidValue;
        }

        nRewardCoinYear = bnUpperBound.getuint64();
        nRewardCoinYear = min((nRewardCoinYear / CENT) * CENT, MAX_MINT_PROOF_OF_STAKE);
    }
    else
    {
        // Old creation amount per coin-year, 5% fixed stake mint rate
        nRewardCoinYear = 5 * CENT;
    }

    if(bCoinYearOnly)
        return nRewardCoinYear;

    nSubsidy = nCoinAge * nRewardCoinYear * 33 / (365 * 33 + 8);

    // Set reasonable reward limit for large inputs since 20 Oct 2013
    //
    // This will stimulate large holders to use smaller inputs, 
    // that's good for the network protection
    if(
        fTestNet || 
        (STAKECURVE_SWITCH_TIME < nTime)
        // is this the same as
        //(::uint64_t)STAKECURVE_SWITCH_TIME > (::uint64_t)nTime
        // ?.  It seems not??
      )
    {
        if (fDebug && gArgs.GetBoolArg("-printcreation") && nSubsidyLimit < nSubsidy)
          LogPrintf(
              "GetProofOfStakeReward(): %s is greater than %s, coinstake "
              "reward will be truncated\n",
              FormatMoney(nSubsidy),
              FormatMoney(nSubsidyLimit));

        nSubsidy = min(nSubsidy, nSubsidyLimit);
    }

    if (fDebug && gArgs.GetBoolArg("-printcreation"))
      LogPrintf("GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64
                " nBits=%d\n",
                FormatMoney(nSubsidy), nCoinAge, nBits);
    return nSubsidy;
}

static const ::int64_t nTargetTimespan = 7 * 24 * 60 * 60;  // one week
static const ::int64_t nTargetSpacingWorkMax = 12 * nStakeTargetSpacing; // 2-hour BS, 12 minutes!

// get proof of work blocks max spacing according to hard-coded conditions
::int64_t inline GetTargetSpacingWorkMax(int nHeight, unsigned int nTime)
{
    if(nTime > TARGETS_SWITCH_TIME)
        return 3 * nStakeTargetSpacing; // 30 minutes on mainNet since 20 Jul 2013 00:00:00

    if(fTestNet)
        return 3 * nStakeTargetSpacing; // 15 minutes on testNet

    return 12 * nStakeTargetSpacing; // 2 hours otherwise
}

//
// maximum nBits value could possible be required nTime after
//
unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, ::int64_t nTime)
{
    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
        // Maximum 200% adjustment per day...
        bnResult *= 2;
        nTime -= 24 * 60 * 60;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

//
// minimum amount of work that could possibly be required nTime after
// minimum proof-of-work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, ::int64_t nTime)
{
    return ComputeMaxBits(bnProofOfWorkLimit, nBase, nTime);
}

//
// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int ComputeMinStake(unsigned int nBase, ::int64_t nTime, unsigned int nBlockTime)
{
    return ComputeMaxBits(GetProofOfStakeLimit(0, nBlockTime), nBase, nTime);
}

// ppcoin: find last block index up to pindex
// Wouldn't this be a more correct comment?
// ppcoin: find last block index of type fProofOfStake up to and including pindex?
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (
           pindex &&                                    // there is a block
           pindex->pprev &&                             // there is a previous block 
           (pindex->IsProofOfStake() != fProofOfStake)  // the block is a !fProofOfStake
          )
        pindex = pindex->pprev;                         // go back
    return pindex;
}
const CBlockIndex* GetLastPoSBlockIndex( const CBlockIndex* pindex )
{
    return GetLastBlockIndex( pindex, true);
}
const CBlockIndex* GetLastPoWBlockIndex( const CBlockIndex* pindex )
{
    return GetLastBlockIndex( pindex, false);
}

/*****************/
static unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, ::int64_t nFirstBlockTime)
{
    //if (params.fPowNoRetargeting)   // disguised testnet, again
    //    return pindexLast->nBits;

    const ::int64_t 
        nAverageBlockperiod = nStakeTargetSpacing;  // 1 minute in seconds

    ::int64_t 
        nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime,
        nNominalTimespan = nDifficultyInterval * nAverageBlockperiod;

    if (nActualTimespan < nNominalTimespan / 4)
        nActualTimespan = nNominalTimespan / 4;
    if (nActualTimespan > nNominalTimespan * 4)
        nActualTimespan = nNominalTimespan * 4;

    // Calculate to target 1 minute/block for the previous 'epoch's 21,000 blocks
    uint256 
        bnPrev = CBigNum().SetCompact(pindexLast->nBits).getuint256();

    CBigNum
        bnPrevTarget;
    bnPrevTarget.setuint256( bnPrev );

    bnPrevTarget *= nActualTimespan;
    bnPrevTarget /= nNominalTimespan;

    // Calculate maximum target of all blocks, it corresponds to 1/3 highest difficulty (or 3 minimum ease)
    uint256 bnMaximum = CBigNum().SetCompact(nMinEase).getuint256();
    CBigNum bnMaximumTarget;
    bnMaximumTarget.setuint256(bnMaximum);
    bnMaximumTarget *= 3;

    // Compare 1/3 highest difficulty with 0.4.9 min difficulty (genesis block difficulty), choose the higher
    if (bnMaximumTarget > bnProofOfWorkLimit)
    {
        bnMaximumTarget = bnProofOfWorkLimit;
    }

    // Choose higher difficulty (higher difficulty have smaller target)
    CBigNum bnNewTarget = min(bnPrevTarget, bnMaximumTarget);
    LogPrintf(
                 "PoW new constant target %s\n"
                 ""
                 , CBigNum( bnNewTarget ).getuint256().ToString().substr(0,16)
                );

    // Update minimum ease for next target calculation
    ::uint32_t nNewEase = bnNewTarget.GetCompact();
    if (nMinEase > nNewEase)
    {
        nMinEase = nNewEase;
    }

    return nNewEase;
}
/*****************/
static unsigned int GetNextTargetRequired044(const CBlockIndex* pindexLast, bool fProofOfStake)
{
	// First three blocks will have following targets:
	// genesis (zeroth) block: bnEasiestTargetLimit
	// first block and second block: bnInitialHashTarget (~uint256(0) >> 8)
    CBigNum 
        bnEasiestTargetLimit = fProofOfStake? 
                            (fTestNet? 
                             bnProofOfStakeTestnetLimit: //bnProofOfStakeHardLimit: // <<<< test
                             bnProofOfStakeHardLimit
                            ): 
                            (fTestNet?
                             bnProofOfWorkLimitTestNet:
                             bnProofOfWorkLimit
                            );

    if (pindexLast == NULL)
    {
        return bnEasiestTargetLimit.GetCompact(); // genesis (zeroth) block
    }

    const CBlockIndex
        * pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);

    if (pindexPrev->pprev == NULL)
    {
        return bnInitialHashTarget.GetCompact(); // first block
    }

    const CBlockIndex
        * pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);

    if (pindexPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block

    // so there are more than 3 blocks
    ::int64_t
        nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    CBigNum 
        bnNewTarget;
    ::uint32_t
        nEase = pindexLast->nBits;
    CBigNum
        bnNew;
    uint256
        nTarget = CBigNum().SetCompact( nEase ).getuint256(),
        nRelativeTargetDelta = (nTarget >> 3);  // i.e. 1/8 of the current target

    // Yacoind version 1.0.0
    if ((pindexLast->nHeight + 1) >= nMainnetNewLogicBlockNumber)
    {
        // COMMENT THIS BLOCK CODE OUT , WE MAY USE IT IN CASE OF AN EMERGENCY HARDFORK
//        const ::int64_t
//            nAverageBlockperiod = nStakeTargetSpacing;  // 1 minute in seconds

        // Recalculate nMinEase if reorg through two or many epochs
        if (recalculateMinEase)
        {
            recalculateMinEase = false;
            ::int32_t currentEpochNumber = chainActive.Tip()->nHeight / nEpochInterval;
            ::int32_t firstEpochNumberSinceHardfork = nMainnetNewLogicBlockNumber / nEpochInterval;
            ::uint32_t tempMinEase = bnEasiestTargetLimit.GetCompact();
            for (int i = firstEpochNumberSinceHardfork; i < currentEpochNumber; i++)
            {
                CBlockIndex* pbi = FindBlockByHeight(i*nEpochInterval);
                if (tempMinEase > pbi->nBits)
                {
                    tempMinEase = pbi->nBits;
                }
            }
            nMinEase = tempMinEase;
        }

        // From block 3, the target is only recalculated every 21000 blocks
        int nBlocksToGo = (pindexLast->nHeight + 1) % nDifficultyInterval;
        // Only change once per difficulty adjustment interval, first at block 21000
        if (0 != nBlocksToGo) // the btc-ltc 2016 blocks
        {                     // don't change the target
            bnNewTarget.setuint256(nTarget);

            LogPrintf("PoW constant target %s"
                         " (%d block"
                         "%s to go)"
                         "\n"
                         "",
                         nTarget.ToString().substr(0, 16), (nDifficultyInterval - nBlocksToGo),
                         (1 != nBlocksToGo) ? "s" : "");
            return bnNewTarget.GetCompact();
        }
        else // actually do a DAA
        {
            // Hardfork happens
            if ((pindexLast->nHeight + 1) == nMainnetNewLogicBlockNumber)
            {
                return bnProofOfWorkLimit.GetCompact();
            }
            // Go back by what we want to be 14 days worth of blocks
            const CBlockIndex* pindexFirst = pindexLast;

            if (pindexLast->nHeight > nDifficultyInterval + 1)
            {
                for (int i = 0; pindexFirst && i < nDifficultyInterval; ++i)
                    pindexFirst = pindexFirst->pprev;
            }
            else // get block #0
            {
                CBlockIndex* pbi = chainActive.Genesis();
                CBlock block;

                block.ReadFromDisk(pbi);
                pindexFirst = pbi;
            }
            Yassert(pindexFirst);

            return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime());
        }
    }
    else
    {
        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        //
        // I don't understand how this code is an exponential weighting?
        //
        bnNewTarget.SetCompact(pindexPrev->nBits);

        ::int64_t
            nTargetSpacing = fProofOfStake?
                             nStakeTargetSpacing :
                             min(                       // what is this PoW value?
                                nTargetSpacingWorkMax,  //12 minutes
                                (::int64_t) nStakeTargetSpacing *
                                            (1 + pindexLast->nHeight - pindexPrev->nHeight)
                                );

        ::int64_t
            nInterval = nTargetTimespan / nTargetSpacing;   // this is the one week / nTargetSpacing

        bnNewTarget *= (((nInterval - 1) * nTargetSpacing) + nActualSpacing + nActualSpacing);
        bnNewTarget /=  ((nInterval + 1) * nTargetSpacing);
    }

    if (bnNewTarget > bnEasiestTargetLimit)
        bnNewTarget = bnEasiestTargetLimit;

    return bnNewTarget.GetCompact();
}
//_____________________________________________________________________________
// yacoin2015 upgrade: penalize ignoring ProofOfStake blocks with high difficulty.
// requires adjusted PoW-PoS ratio (GetSpacingThreshold), PoW target moving average (nBitsMA)
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    return GetNextTargetRequired044( pindexLast, fProofOfStake );
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    LogPrintf("CheckProofOfWork: nBits: %d\n",nBits);
    // Check range
    if (
        (bnTarget <= 0 )
        || 
        (bnTarget > ( fTestNet? bnProofOfWorkLimitTestNet: bnProofOfWorkLimit) )
       )
        return error("CheckProofOfWork() : nBits below minimum work");
    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash > target nBits");

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload()
{
    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    if (chainActive.Tip() == nullptr)
        return true;
    if (chainActive.Height() < Checkpoints::GetTotalBlocksEstimate())
        return true;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    latchToFalse.store(true, std::memory_order_relaxed);
    return false;
}

bool CScriptCheck::operator()() const 
{
    const CScript 
        &scriptSig = ptxTo->vin[nIn].scriptSig;
    if (!VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, nHashType))
        return error("CScriptCheck() : %s VerifySignature failed", 
                     ptxTo->GetHash().ToString().substr(0,10).c_str()
                    );
    return true;
}

bool VerifySignature(
                     const CTransaction& txFrom, 
                     const CTransaction& txTo, 
                     unsigned int nIn, 
                     unsigned int flags, 
                     int nHashType
                    )
{
    return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();
}

void ThreadScriptCheck(void*) 
{
    ++vnThreadsRunning[THREAD_SCRIPTCHECK];
    RenameThread("yacoin-scriptch");
    scriptcheckqueue.Thread();
    --vnThreadsRunning[THREAD_SCRIPTCHECK];
}

void ThreadScriptCheckQuit() 
{
    scriptcheckqueue.Quit();
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (!pindexBestInvalid || pindexNew->bnChainTrust > pindexBestInvalid->bnChainTrust)
    {
        pindexBestInvalid = pindexNew;
        CTxDB().WriteBestInvalidTrust(pindexBestInvalid->bnChainTrust);
#ifdef QT_GUI
        //uiInterface.NotifyBlocksChanged();
#endif
    }

    CBigNum bnBestInvalidBlockTrust = pindexNew->bnChainTrust - pindexNew->pprev->bnChainTrust;
    CBigNum bnBestBlockTrust = chainActive.Tip()->nHeight != 0 ? (chainActive.Tip()->bnChainTrust - chainActive.Tip()->pprev->bnChainTrust) : chainActive.Tip()->bnChainTrust;

    LogPrintf(
        "InvalidChainFound: invalid block=%s  height=%d  trust=%s  "
        "blocktrust=%" PRId64 "  date=%s\n",
        pindexNew->GetBlockHash().ToString().substr(0, 20),
        pindexNew->nHeight, (pindexNew->bnChainTrust).ToString(),
        bnBestInvalidBlockTrust.getuint64(),
        DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()));
    LogPrintf(
        "InvalidChainFound:  current best=%s  height=%d  trust=%s  "
        "blocktrust=%" PRId64 "  date=%s\n",
        hashBestChain.ToString().substr(0, 20), chainActive.Height(),
        (chainActive.Tip()->bnChainTrust).ToString(),
        bnBestBlockTrust.getuint64(),
        DateTimeStrFormat("%x %H:%M:%S", chainActive.Tip()->GetBlockTime()));
}

void static InvalidBlockFound(const CValidationState &state, CTxDB& txdb, CBlockIndex *pindex) {
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        InvalidChainFound(pindex);
        // Write to disk block index
        txdb.WriteBlockIndex(CDiskBlockIndex(pindex));
        if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindex)))
        {
            LogPrintf("InvalidBlockFound(): Can't WriteBlockHash\n");
        }
        if (!txdb.TxnCommit()) {
            LogPrintf("InvalidBlockFound(): TxnCommit failed\n");
        }
        setBlockIndexCandidates.erase(pindex);
    }
}

bool static WriteChainState(CTxDB& txdb, CBlockIndex *pindexNew) {
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("WriteChainState() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return error("WriteChainState() : TxnCommit failed");
    return true;
}

void static UpdateTip(CBlockIndex *pindexNew) {
    uint256 hash = pindexNew->GetBlockHash();
    // Update best block in wallet (so we can detect restored wallets)
    bool
        fIsInitialDownload = IsInitialBlockDownload();

    if (!fIsInitialDownload)
    {
        ::SetBestChain(chainActive.GetLocator());
    }

   // New best block
    hashBestChain = hash;
    pblockindexFBBHLast = NULL;
    // Reorg through two or many epochs
    if ((abs(chainActive.Tip()->nHeight - pindexNew->nHeight) >= 2) &&
        (abs((::int32_t)(chainActive.Height() / nEpochInterval) - (::int32_t)(pindexNew->nHeight / nEpochInterval)) >= 1))
    {
        recalculateBlockReward = true;
        recalculateMinEase = true;
    }
    // Update minimum ease for next target calculation
    if ((pindexNew->nHeight >= nMainnetNewLogicBlockNumber)
        && (nMinEase > pindexNew->nBits))
    {
        nMinEase = pindexNew->nBits;
    }
    chainActive.SetTip(pindexNew);

    bnBestChainTrust = pindexNew->bnChainTrust;
    mempool.AddTransactionsUpdated(1);

    CBigNum bnBestBlockTrust =
        (chainActive.Tip()->nHeight != 0)?
        (chainActive.Tip()->bnChainTrust - chainActive.Tip()->pprev->bnChainTrust):
        chainActive.Tip()->bnChainTrust;

    LogPrintf(
            "UpdateTip: new best=%s height=%d trust=%s\nblocktrust=%" PRId64 "  date=%s\n",
            hashBestChain.ToString().substr(0,20), chainActive.Height(),
            bnBestChainTrust.ToString(),
            bnBestBlockTrust.getuint64(),
            DateTimeStrFormat("%x %H:%M:%S",
            chainActive.Tip()->GetBlockTime())
          );

#ifdef QT_GUI
    //uiInterface.NotifyBlocksChanged();
#endif

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = chainActive.Tip();
        for (int i = 0; i < 100 && pindex != NULL; ++i)
        {
            // TODO: Temporary fix to avoid warning for yacoind 1.0.0. Because in yacoind 1.0.0, there are two times
            // block version is upgraded:
            // 1) At the time installing yacoind 1.0.0
            // 2) At the time happening hardfork
            // Need update this line at next yacoin version
            if (pindex->nVersion > VERSION_of_block_for_yac_05x_new)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            LogPrintf("UpdateTip: %d of last 100 blocks above version %d\n", nUpgraded, CURRENT_VERSION_of_block);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

}

// Disconnect chainActive's tip.
bool static DisconnectTip(CValidationState &state, CTxDB& txdb, DisconnectedBlockTransactions *disconnectpool) {
    CBlockIndex *pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    CBlock block;
    {
        CTokensCache tokenCache;
        if (!block.ReadFromDisk(pindexDelete))
            return state.Abort(_("DisconnectTip() : ReadFromDisk for disconnect failed"));
        if (!block.DisconnectBlock(state, txdb, pindexDelete, &tokenCache))
            return error("DisconnectTip() : DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString().substr(0,20).c_str());
        // Write the chain state to disk, if necessary.
        if (!WriteChainState(txdb, pindexDelete->pprev))
            return false;
        bool tokensFlushed = tokenCache.Flush();
        assert(tokensFlushed);
    }

    LogPrintf("DisconnectTip, disconnect block (height: %d, hash: %s)\n", pindexDelete->nHeight, block.GetHash().GetHex());

//    BOOST_FOREACH(CTransaction &tx, block.vtx) {
//        // ignore validation errors in resurrected transactions
//        CValidationState stateDummy;
//        if (!(tx.IsCoinBase() || tx.IsCoinStake()))
//        {
//            tx.AcceptToMemoryPool(stateDummy, txdb, false);
//        }
//    }

    // Ressurect mempool transactions from the disconnected block.
    // Save transactions to re-add to mempool at end of reorg
    if (disconnectpool) {
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            const CTransaction& tx = *it;
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                LogPrintf("DisconnectTip, Add tx %s to disconnectpool\n", tx.GetHash().ToString());
                disconnectpool->addTransaction(tx);
            }
        }
    }

    // Disconnect shorter branch, SPECIFIC FOR YACOIN
    if (pindexDelete->pprev)
        pindexDelete->pprev->pnext = NULL;

    // Update chainActive and related variables.
    UpdateTip(pindexDelete->pprev);
    return true;
}

// Connect a new block to chainActive.
bool static ConnectTip(CValidationState &state, CTxDB& txdb, CBlockIndex *pindexNew, ConnectTrace& connectTrace, DisconnectedBlockTransactions *disconnectpool)
{
    uint256 hash = pindexNew->GetBlockHash();

    if ((chainActive.Genesis() == NULL)
            && (hash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)))
    {
        if (!WriteChainState(txdb, pindexNew))
            return false;
        chainActive.SetTip(pindexNew);
        UpdateTip(pindexNew);
    }
    else
    {
        assert(pindexNew->pprev == chainActive.Tip());
        // Read block from disk.
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!pblockNew->ReadFromDisk(pindexNew))
            return state.Abort(_("ConnectTip() : ReadFromDisk for connect failed"));

        /** YAC_TOKEN START */
        // Initialize sets used from removing token entries from the mempool
        ConnectedBlockTokenData tokenDataFromBlock;

        // Create the empty token cache, that will be sent into the connect block
        // All new data will be added to the cache, and will be flushed back into ptokens after a successful
        // Connect Block cycle
        CTokensCache tokenCache;
        /** YAC_TOKEN END */

        // Apply the block atomically to the chain state.
        CInv inv(MSG_BLOCK, hash);
        bool rv = pblockNew->ConnectBlock(state, txdb, pindexNew, &tokenCache);
        GetMainSignals().BlockChecked(*pblockNew, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(state, txdb, pindexNew);
            return error("ConnectTip() : ConnectBlock %s failed", pindexNew->GetBlockHash().ToString().substr(0,20).c_str());
        }

        /** YAC_TOKEN START */
        // Get the newly created tokens, from the connectblock tokenCache so we can remove the correct tokens from the mempool
        tokenDataFromBlock = {tokenCache.setNewTokensToAdd};

        // Remove all tx hashes, that were marked as reissued script from the mapReissuedTx.
        // Without this check, you wouldn't be able to reissue for those tokens again, as this maps block it
        for (const auto& tx : pblockNew->vtx) {
            const uint256& txHash = tx.GetHash();
            if (mapReissuedTx.count(txHash))
            {
                mapReissuedTokens.erase(mapReissuedTx.at(txHash));
                mapReissuedTx.erase(txHash);
            }
        }

        // Flush token to global token cache ptokens
        bool tokenFlushed = tokenCache.Flush();
        assert(tokenFlushed);
        /** YAC_TOKEN END */

        // Write the chain state to disk, if necessary.
        if (!WriteChainState(txdb, pindexNew))
            return false;

        // Flush token data to disk
        if (!FlushTokenToDisk())
            return false;

        // Remove conflicting transactions from the mempool.
        mempool.removeForBlock(pblockNew->vtx, tokenDataFromBlock);
        disconnectpool->removeForBlock(pblockNew->vtx);

        // Connect longer branch, SPECIFIC FOR YACOIN
        if (pindexNew->pprev)
            pindexNew->pprev->pnext = pindexNew;
        // Update chainActive & related variables.
        UpdateTip(pindexNew);

        connectTrace.BlockConnected(pindexNew, pblockNew);
    }
    return true;
}

// Return the tip of the chain with the most work in it, that isn't
// known to be invalid (it's however far from certain to be valid).
static CBlockIndex* FindMostWorkChain() {
    do {
        CBlockIndex *pindexNew = NULL;

        // Find the best candidate header.
        {
            set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return NULL;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !chainActive.Contains(pindexTest)) {
            assert(pindexTest->nStatus & BLOCK_HAVE_DATA);
            assert(pindexTest->validTx || pindexTest->nHeight == 0);
            if (pindexTest->nStatus & BLOCK_FAILED_MASK) {
                // Candidate has an invalid ancestor, remove entire chain from the set.
                if (pindexBestInvalid == NULL || pindexNew->bnChainTrust > pindexBestInvalid->bnChainTrust)
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                while (pindexTest != pindexFailed) {
                    pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
static void PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

// Try to make some progress towards making pindexMostWork the active block.
static bool ActivateBestChainStep(CValidationState &state, CTxDB& txdb, CBlockIndex *pindexMostWork, ConnectTrace& connectTrace) {
//    bool fInvalidFound = false;
    CBlockIndex *pindexOldTip = chainActive.Tip();
    CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!txdb.TxnBegin()) {
            return error("ActivateBestChainStep () : TxnBegin 1 failed");
        }

        if (!DisconnectTip(state, txdb, &disconnectpool)) // Disconnect the latest block on the chain
        {
            error("ActivateBestChainStep, failed to disconnect block");
            txdb.TxnAbort();
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(txdb, disconnectpool, false);
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex *pindexConnect : reverse_iterate(vpindexToConnect)) {
            if (!txdb.TxnBegin()) {
                return error("ActivateBestChainStep () : TxnBegin 2 failed");
            }
            if (!ConnectTip(state, txdb, pindexConnect, connectTrace, &disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpindexToConnect.back());
                    state = CValidationState();
    //                fInvalidFound = true;
                    txdb.TxnAbort();
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    txdb.TxnAbort();
                    UpdateMempoolForReorg(txdb, disconnectpool, false);
                    return false;
                }
            }
            else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || chainActive.Tip()->bnChainTrust > pindexOldTip->bnChainTrust) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        LogPrintf(
            "ActivateBestChainStep, reorg completed (best header = %s, height "
            "= %d), update mempool\n",
            chainActive.Tip()->GetBlockHash().GetHex(),
            chainActive.Height());
        UpdateMempoolForReorg(txdb, disconnectpool, true);
    }
    // Callbacks/notifications for a new best chain.
//    if (fInvalidFound)
//        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
//    else
//        CheckForkWarningConditions();

    return true;
}

bool ActivateBestChain(CValidationState &state, CTxDB& txdb) {
    CBlockIndex *pindexNewTip = NULL;
    CBlockIndex *pindexMostWork = NULL;
    do {
        boost::this_thread::interruption_point();

        const CBlockIndex *pindexFork;
        bool fInitialDownload;
        {
            LOCK(cs_main);
            ConnectTrace connectTrace(mempool); // Destructed before cs_main is unlocked

            CBlockIndex *pindexOldTip = chainActive.Tip();
            if (pindexMostWork == nullptr) {
                pindexMostWork = FindMostWorkChain();
            }

            // Whether we have anything to do at all.
            if (pindexMostWork == nullptr || pindexMostWork == chainActive.Tip())
                return true;

            if (!ActivateBestChainStep(state, txdb, pindexMostWork, connectTrace))
                return false;

            pindexNewTip = chainActive.Tip();
            pindexFork = chainActive.FindFork(pindexOldTip);
            fInitialDownload = IsInitialBlockDownload();

            for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                assert(trace.pblock && trace.pindex);
                GetMainSignals().BlockConnected(trace.pblock, trace.pindex, *trace.conflictedTxs);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without cs_main

        // Notify external listeners about the new tip.
        GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);
#ifdef QT_GUI
        static ::int8_t counter = 0;
        if(
           ((++counter & 0x0F) == 0) ||     // every 16 blocks, why?
           !fInitialDownload
          ) // repaint every 16 blocks if not in initial block download
        {
            //uiInterface.NotifyBlocksChanged();
        }
        else
        {
        //uiInterface.NotifyBlocksChanged();
        }
#endif
    } while(pindexMostWork != chainActive.Tip());

    return true;
}

bool ProcessBlock(CValidationState &state, CBlock* pblock, bool fForceProcessing, bool *fNewBlock, CDiskBlockPos *dbp)
{
    if (fNewBlock) *fNewBlock = false;
    // Preliminary checks
    bool checked = pblock->CheckBlock(state, true, true, (pblock->nTime > Checkpoints::GetLastCheckpointTime()));
    {
        LOCK(cs_main);
        if (!checked) {
            return error("ProcessBlock() : CheckBlock FAILED");
        }

        uint256 hash = pblock->GetHash();
        // ppcoin: verify hash target and signature of coinstake tx
        if (pblock->IsProofOfStake())
        {
            uint256 hashProofOfStake = 0, targetProofOfStake = 0;
            if (!CheckProofOfStake(state, pblock->vtx[1], pblock->nBits, hashProofOfStake, targetProofOfStake))
            {
              LogPrintf(
                  "WARNING: ProcessBlock (): "
                  "check proof-of-stake failed for block %s (%s)\n",
                  hash.ToString(),
                  DateTimeStrFormat(" %Y-%m-%d %H:%M:%S", pblock->nTime));
              return false;  // do not error here as we expect this during
                             // initial block download
            }
            if (!mapProofOfStake.count(hash)) // add to mapProofOfStake
                mapProofOfStake.insert(make_pair(hash, hashProofOfStake));
        }

        // Store to disk
        CBlockIndex *pindex = NULL;
        bool ret = pblock->AcceptBlock(state, &pindex, fForceProcessing, fNewBlock, dbp);
        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED", __func__);
        }
    }

    CTxDB txdb;
    // New best
    if (!ActivateBestChain(state, txdb))
        return error("ProcessBlock() : ActivateBestChain failed");
    LogPrintf("ProcessBlock: ACCEPTED %s BLOCK\n", pblock->IsProofOfStake()?"POS":"POW");
#ifdef QT_GUI
    //uiInterface.NotifyBlocksChanged();
#endif

    return true;
}

bool CheckDiskSpace(::uint64_t nAdditionalBytes)
{
    ::uint64_t nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low!");
        strMiscWarning = strMessage;
        LogPrintf("*** %s\n", strMessage);
        uiInterface.ThreadSafeMessageBox(strMessage, "Yacoin", CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        StartShutdown();
        return false;
    }
    return true;
}

static filesystem::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);
    return GetDataDir() / strBlockFn;
}

bool AbortNode(const std::string &strMessage) {
    strMiscWarning = strMessage;
    LogPrintf("*** %s\n", strMessage);
    StartShutdown();
    return false;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1) || (nFile == (unsigned int) -1))
        return NULL;
    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    while (true)
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

void UnloadBlockIndex()
{
    mapBlockIndex.clear();
    bnBestChainTrust = CBigNum(0);
    setBlockIndexCandidates.clear();
    pindexBestInvalid = NULL;
    hashBestChain = 0;
    chainActive.SetTip(NULL);
}

bool LoadBlockIndex(bool fAllowNew)
{
//    if (fTestNet)
//    {
//        pchMessageStart[0] = 0xcd;
//        pchMessageStart[1] = 0xf2;
//        pchMessageStart[2] = 0xc0;
//        pchMessageStart[3] = 0xef;
//
//        bnProofOfWorkLimit = bnProofOfWorkLimitTestNet; // 16 bits PoW target limit for testnet
//        bnInitialHashTarget = bnInitialHashTargetTestNet;
//        nStakeMinAge = 2 * nSecondsPerHour;             // 2 hours (to what?)
//        nModifierInterval =  10 * nSecondsperMinute;    // 10 minutes, for what?
//        nCoinbaseMaturity = 6; // test maturity is 6 blocks + nCoinbaseMaturity(20) = 26
//        nStakeTargetSpacing = 1 * nSecondsperMinute;    // 1 minute average block period target
//        nConsecutiveStakeSwitchHeight = 4200;           // 4200 blocks until what?
//    }

    //
    // Load block index
    //
    CTxDB txdb("cr+");
    if (!txdb.LoadBlockIndex()) // true is no error,whether it does anything or not!
        return false;           // this is then the error return

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())  // there is no mapBlockIndex, so (re)create genesis block
    {
        if (!fAllowNew)
            return false;

        // Genesis block

        // MainNet:

        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, 
        //        nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), 
        //          coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e
        
        //TODO
        
        // TestNet:

        //CBlock(hash=0000c763e402f2436da9ed36c7286f62c3f6e5dbafce9ff289bd43d7459327eb, 
        //       ver=1, 
        //       hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, 
        //       hashMerkleRoot=4cb33b3b6a861dcbc685d3e614a9cafb945738d6833f182855679f2fad02057b, 
        //       nTime=1360105017, nBits=1f00ffff, nNonce=46534, vtx=1, vchBlockSig=)
        //  Coinbase(
        //       hash=4cb33b3b6a, nTime=1360105017, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //    CTxIn(COutPoint(0000000000, 4294967295), 
        //          coinbase 04ffff001d020f274468747470733a2f2f626974636f696e74616c6b2e6f72672f696e6465782e7068703f746f7069633d3133343137392e6d736731353032313936236d736731353032313936)
        //    CTxOut(empty)
        //  vMerkleTree: 4cb33b3b6a

        const char* 
            pszTimestamp = "https://bitcointalk.org/index.php?topic=196196";
        CTransaction 
            txNew;

        txNew.nTime = (::uint32_t)( fTestNet? nChainStartTimeTestNet: nChainStartTime );
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = 
            CScript()           // what is being constructed here?????
            << (!fTestNet?  486604799:      // is this a time? 1985?
                            1464032600)  // how about a more current time????  If it is a time???????
            << CScriptNum(9999)    // what is this??
            << vector<unsigned char>((const unsigned char*)pszTimestamp, 
                                     (const unsigned char*)pszTimestamp + strlen(pszTimestamp)
                                    );
      //txNew.vout[0].scriptPubKey = CScript() << ParseHex("04a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0a") << OP_CHECKSIG;
        txNew.vout[0].SetEmpty();

        //Yassert( NULL != pwalletMain );
        //CReserveKey 
        //    reservekey(pwalletMain);

        //txNew.vout[0].nValue = nSimulatedMOneySupplyAtFork; //estimate 1/25/2019 7:00PM EST
        //txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

#ifdef Yac1dot0
        txNew.print();
#endif
        CBlock 
            block;

        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;  // was 1; which is strange?
        block.nTime    = (::uint32_t)( fTestNet?
                                       nChainStartTimeTestNet + 20: 
                                       nChainStartTime + 20 
                                      );   // why + 20??
        block.nBits    = bnProofOfWorkLimit.GetCompact();
        block.nNonce   = !fTestNet ? 
                            127357 :        // main net genesis block nonce
							nTestNetGenesisNonce;
                                            //0x1F653; //for 0.5.0.04 TestNet
                                            //0x1F652; //for 0.5.0.03 TestNet
                                            //0x1f650;  13D93;    //67103;

        CBigNum 
            bnTarget;

        bnTarget.SetCompact( block.nBits );

        uint256
            the_target = bnTarget.getuint256();
    
        uint256
            the_hash = block.GetHash();
////////////////////////////////////
// This little section of code allows any node to create a genesis block
// Is this too much?  Will this causes forks from block 0?
// Or should only one node create a single block 0, and all others must 
// use that one block 0?
// if all block 0s created from this code are identical, then there should 
// be no problem!
        ::uint32_t
            nCount = 0;
		while( the_hash > the_target )
		{
			++(block.nNonce);
            ++nCount;
            the_hash = block.GetHash();
            LogPrintf(
                    "block.nNonce == %08X"
                    "\r", 
                    block.nNonce
                  );		
		}
		LogPrintf(
                "\n" 
                "block.nNonce == %08X (%u dec) after %u tries"
                "\n", 
                block.nNonce,
                block.nNonce,
                nCount
              );		
////////////////////////////////////

        // debug print
		LogPrintf("block.GetHash() ==\n%s\n", the_hash.ToString());
		LogPrintf("block.nBits ==\n%s\n", the_target.ToString());
		LogPrintf("block.hashMerkleRoot ==\n%s\n", block.hashMerkleRoot.ToString());

        Yassert(block.hashMerkleRoot == uint256(
                            fTestNet?
                            hashGenesisMerkleRootTestNet:
                            hashGenesisMerkleRootMainNet
                                               )
              );
        block.SignBlock(*pwalletMain);
        block.print();
        Yassert(block.GetHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet));
        CValidationState stateDummy;
        Yassert(block.CheckBlock(stateDummy));
        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        CBlockIndex *pindex = block.AddToBlockIndex();
        if (!block.ReceivedBlockTransactions(stateDummy, nFile, nBlockPos, pindex))
            return error("LoadBlockIndex() : genesis block not accepted");
        CValidationState state;
        if (!ActivateBestChain(state, txdb))
            return error("LoadBlockIndex() : genesis block cannot be activated");
        // initialize synchronized checkpoint
        if (!Checkpoints::WriteSyncCheckpoint((!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)))
            return error("LoadBlockIndex() : failed to init sync checkpoint");

        // upgrade time set to zero if txdb initialized
        {
            if (!txdb.WriteModifierUpgradeTime(0))
                return error("LoadBlockIndex() : failed to init upgrade info");
            LogPrintf(" Upgrade Info: ModifierUpgradeTime txdb initialization\n");
        }
    }

    {
        CTxDB txdb("r+");

        // upgrade time set to zero if blocktreedb initialized
        if (txdb.ReadModifierUpgradeTime(nModifierUpgradeTime))
        {
            if (nModifierUpgradeTime)
                LogPrintf(" Upgrade Info: blocktreedb upgrade detected at timestamp %d\n", nModifierUpgradeTime);
            else
                LogPrintf(" Upgrade Info: no blocktreedb upgrade detected.\n");
        }
        else
        {
            nModifierUpgradeTime = GetTime();
            LogPrintf(" Upgrade Info: upgrading blocktreedb at timestamp %u\n", nModifierUpgradeTime);
            if (!txdb.WriteModifierUpgradeTime(nModifierUpgradeTime))
                return error("LoadBlockIndex() : failed to write upgrade info");
        }
    }

    return true;
}



void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (BlockMap::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, chainActive.Genesis()));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                LogPrintf("| ");
            LogPrintf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                LogPrintf("| ");
            LogPrintf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            LogPrintf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        LogPrintf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %" PRIszu "\n",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()),
            FormatMoney(pindex->nMint),
            block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*GetMaxSize(MAX_BLOCK_SIZE), GetMaxSize(MAX_BLOCK_SIZE)+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(pchMessageStart[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, pchMessageStart, CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > GetMaxSize(MAX_BLOCK_SIZE))
                {
                    continue;
                }
            } catch (const std::exception &) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                CBlock block;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // SHA256 doesn't cost much cpu usage to calculate
                uint256 hash;
                uint256 sha256HashBlock = block.GetSHA256Hash();
                map<uint256, uint256>::iterator mi = mapHash.find(sha256HashBlock);
                if (mi != mapHash.end())
                {
                    hash = (*mi).second;
                    block.blockHash = hash;
                }
                else
                {
                    hash = block.GetHash();
                    mapHash.insert(make_pair(sha256HashBlock, hash));
                }

                // detect out of order blocks, and store them for later
                if (hash != (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet) && mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end()) {
                  LogPrintf("reindex",
                            "%s: Out of order block %s, parent %s not known\n",
                            __func__, hash.ToString(),
                            block.hashPrevBlock.ToString());
                  if (dbp)
                    mapBlocksUnknownParent.insert(
                        std::make_pair(block.hashPrevBlock, *dbp));
                  continue;
                }

                // process in case the block isn't known yet
                if (mapBlockIndex.count(hash) == 0 || (mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0) {
                    CValidationState state;
                    if (ProcessBlock(state, &block, true, nullptr, dbp))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } else if (hash != (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet) && mapBlockIndex[hash]->nHeight % 1000 == 0) {
                  LogPrintf("Block Import: already had block %s at height %d\n",
                            hash.ToString(),
                            mapBlockIndex[hash]->nHeight);
                }

                // Recursively process earlier encountered successors of this block
                deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        CBlock block;
                        if (block.ReadFromDisk(it->second.nFile, it->second.nPos))
                        {
                          LogPrintf(
                              "%s: Processing out of order child %s of %s\n",
                              __func__, block.GetHash().ToString(),
                              head.ToString());
                          CValidationState dummy;
                          if (ProcessBlock(dummy, &block, true, nullptr, &it->second)) {
                            nLoaded++;
                            queue.push_back(block.GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                    }
                }
            } catch (std::exception &e) {
                LogPrintf("%s : Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch(std::runtime_error &e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

string GetWarnings(string strFor)
{
    string strStatusBar;
    string strRPC;

    if (gArgs.GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        strStatusBar = strMiscWarning;
    }

    // if detected unmet upgrade requirement enter safe mode
    // Note: Modifier upgrade requires blockchain redownload if past protocol switch
    if (IsFixedModifierInterval(nModifierUpgradeTime + 60*60*24)) // 1 day margin
    {
        strStatusBar = strRPC = "WARNING: Blockchain redownload required approaching or past v.0.4.5 upgrade deadline.";
    }

    // if detected invalid checkpoint enter safe mode
    if (Checkpoints::hashInvalidCheckpoint != 0)
    {
        strStatusBar = strRPC = _("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    Yassert(!"GetWarnings() : invalid parameter");
    return "error";
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;
//_____________________________________________________________________________

void releaseModeAssertionfailure( 
                                 const char* pFileName, 
                                 const int nL, 
                                 const std::string strFunctionName,
                                 const char * booleanExpression 
                                )
{   //Assertion failed: (fAssertBoolean), file l:\backups\senadjyac045.2\yacoin\src\init.cpp, line 1368
  LogPrintf(
      "\n"
      "Release mode\n"
      "Assertion failed: (%s), file %s, line %d,\n"
      "function %s()"
      "\n"
      "\n"
      "",
      booleanExpression, pFileName  //__FILE__
      ,
      nL  //__LINE__
      ,
      strFunctionName  // __FUNCTION__
  );
  StartShutdown();  // maybe there are other ways??
}
//_____________________________________________________________________________
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
