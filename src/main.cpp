// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef _BITCOINALERT_H_
 #include "alert.h"
#endif

#ifndef BITCOIN_CHECKPOINT_H
 #include "checkpoints.h"
#endif

#ifndef BITCOIN_DB_H
 #include "db.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb.h"
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
// GLOBAL VARIABLES USED FOR ASSET MANAGEMENT SYSTEM
//
CAssetsDB *passetsdb = nullptr;
CAssetsCache *passets = nullptr;
CLRUCache<std::string, CDatabasedAssetData> *passetsCache = nullptr;
bool fAssetIndex = false;
bool fAddressIndex = false;
//
// END OF GLOBAL VARIABLES USED FOR ASSET MANAGEMENT SYSTEM
//

//
// FUNCTIONS USED FOR ASSET MANAGEMENT SYSTEM
//
/** Flush all state, indexes and buffers to disk. */
bool FlushAssetToDisk()
{
    // Flush the assetstate
    if (AreAssetsDeployed()) {
        // Flush the assetstate
        auto currentActiveAssetCache = GetCurrentAssetCache();
        if (currentActiveAssetCache) {
            if (!currentActiveAssetCache->DumpCacheToDatabase())
                return error("FlushAssetToDisk(): Failed to write to asset database");
        }
    }

    // Write the reissue mempool data to database
    if (passetsdb)
        passetsdb->WriteReissuedMempoolState();
}

bool AreAssetsDeployed()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nAssetSupportBlockNumber)
    {
        return true;
    }
    return false;
}

CAssetsCache* GetCurrentAssetCache()
{
    return passets;
}

bool CheckTxAssets(const CTransaction &tx, CValidationState &state,
        MapPrevTx inputs, CAssetsCache *assetCache, bool fCheckMempool,
        std::vector<std::pair<std::string, uint256>> &vPairReissueAssets)
{
    // Create map that stores the amount of an asset transaction input. Used to verify no assets are burned
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
                    error("CTransaction::CheckTxAssets() : %s prev tx already used at %s",
                          tx.GetHash().ToString().substr(0, 10).c_str(),
                          txindex.vSpent[prevout.COutPointGet_n()].ToString().c_str()));

        if (txPrevOut.scriptPubKey.IsAssetScript())
        {
            CAssetOutputEntry data;
            if (!GetAssetData(txPrevOut.scriptPubKey, data))
                return state.DoS(100, error("bad-txns-failed-to-get-asset-from-script"));

            // Add to the total value of assets in the inputs
            if (totalInputs.count(data.assetName))
                totalInputs.at(data.assetName) += data.nAmount;
            else
                totalInputs.insert(std::make_pair(data.assetName, data.nAmount));
        }
    }

    // Create map that stores the amount of an asset transaction output. Used to
    // verify no assets are burned
    std::map<std::string, CAmount> totalOutputs;
    int index = 0;
    int64_t currentTime = GetTime();
    std::string strError = "";
    int i = 0;
    for (const auto &txout : tx.vout)
    {
        i++;
        bool fIsAsset = false;
        int nType = 0;
        bool fIsOwner = false;
        if (txout.scriptPubKey.IsAssetScript(nType, fIsOwner))
            fIsAsset = true;

        if (assetCache)
        {
            if (fIsAsset && !AreAssetsDeployed())
                return state.DoS(100, error("bad-txns-is-asset-and-asset-not-active"));
        }

        if (nType == TX_TRANSFER_ASSET)
        {
            CAssetTransfer transfer;
            std::string address = "";
            if (!TransferAssetFromScript(txout.scriptPubKey, transfer, address))
                return state.DoS(100, error("bad-tx-asset-transfer-bad-deserialize"));

            if (!ContextualCheckTransferAsset(assetCache, transfer, address, strError))
                return state.DoS(100, error(strError.c_str()));

            // Add to the total value of assets in the outputs
            if (totalOutputs.count(transfer.strName))
                totalOutputs.at(transfer.strName) += transfer.nAmount;
            else
                totalOutputs.insert(std::make_pair(transfer.strName, transfer.nAmount));

            if (IsAssetNameAnOwner(transfer.strName))
            {
                if (transfer.nAmount != OWNER_ASSET_AMOUNT)
                    return state.DoS(100, error("bad-txns-transfer-owner-amount-was-not-1"));
            }
            else
            {
                // For all other types of assets, make sure they are sending the right
                // type of units
                CNewAsset asset;
                if (!assetCache->GetAssetMetaDataIfExists(transfer.strName, asset))
                    return state.DoS(100, error("bad-txns-transfer-asset-not-exist"));

                if (asset.strName != transfer.strName)
                    return state.DoS(100, error("bad-txns-asset-database-corrupted"));

                if (!CheckAmountWithUnits(transfer.nAmount, asset.units))
                    return state.DoS(100, error("bad-txns-transfer-asset-amount-not-match-units"));
            }
        }
        else if (nType == TX_REISSUE_ASSET)
        {
            CReissueAsset reissue;
            std::string address;
            if (!ReissueAssetFromScript(txout.scriptPubKey, reissue, address))
                return state.DoS(100, error("bad-tx-asset-reissue-bad-deserialize"));

            if (mapReissuedAssets.count(reissue.strName))
            {
                if (mapReissuedAssets.at(reissue.strName) != tx.GetHash())
                    return state.DoS(100, error("bad-tx-reissue-chaining-not-allowed"));
            }
            else
            {
                vPairReissueAssets.emplace_back(std::make_pair(reissue.strName, tx.GetHash()));
            }
        }
        index++;
    }

    if (assetCache)
    {
        if (tx.IsNewAsset())
        {
            // Get the asset type
            CNewAsset asset;
            std::string address;
            if (!AssetFromScript(tx.vout[tx.vout.size() - 1].scriptPubKey, asset, address)) {
                error("%s : Failed to get new asset from transaction: %s", __func__, tx.GetHash().GetHex());
                return state.DoS(100, error("bad-txns-issue-serialzation-failed"));
            }

            AssetType assetType;
            IsAssetNameValid(asset.strName, assetType);

            if (!ContextualCheckNewAsset(assetCache, asset, strError, fCheckMempool))
                return state.DoS(100, error(strError.c_str()));

        }
        else if (tx.IsReissueAsset())
        {
            CReissueAsset reissue_asset;
            std::string address;
            if (!ReissueAssetFromScript(tx.vout[tx.vout.size() - 1].scriptPubKey, reissue_asset, address))
            {
                error("%s : Failed to get new asset from transaction: %s", __func__, tx.GetHash().GetHex());
                return state.DoS(100, error("bad-txns-reissue-serialzation-failed"));
            }
            if (!ContextualCheckReissueAsset(assetCache, reissue_asset, strError, tx))
                return state.DoS(100, error("bad-txns-reissue-contextual-"));
        }
        else if (tx.IsNewUniqueAsset())
        {
            if (!ContextualCheckUniqueAssetTx(assetCache, strError, tx))
                return state.DoS(100, error("bad-txns-issue-unique-contextual-"));
        }
        else
        {
            for (auto out : tx.vout)
            {
                int nType;
                bool _isOwner;
                if (out.scriptPubKey.IsAssetScript(nType, _isOwner))
                {
                    if (nType != TX_TRANSFER_ASSET)
                    {
                        return state.DoS(100, error("bad-txns-bad-asset-transaction"));
                    }
                }
                else
                {
                    if (out.scriptPubKey.Find(OP_YAC_ASSET))
                    {
                        return state.DoS(100, error("bad-txns-bad-asset-script"));
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
                    strprintf("Bad Transaction - Trying to create outpoint for asset that you don't have: %s", outValue.first);
            return state.DoS(100, error("bad-tx-inputs-outputs-mismatch "));
        }

        if (totalInputs.at(outValue.first) != outValue.second)
        {
            std::string errorMsg;
            errorMsg = strprintf("Bad Transaction - Assets would be burnt %s", outValue.first);
            return state.DoS(100, error("bad-tx-inputs-outputs-mismatch "));
        }
    }

    // Check the input size and the output size
    if (totalOutputs.size() != totalInputs.size())
    {
        return state.DoS(100, error("bad-tx-asset-inputs-size-does-not-match-outputs-size"));
    }
    return true;
}

void UpdateAssetInfo(const CTransaction& tx, MapPrevTx& prevInputs, int nHeight, uint256 blockHash, CAssetsCache* assetsCache, std::pair<std::string, CBlockAssetUndo>* undoAssetData)
{
    // Iterate through tx inputs and update asset info
    if (!tx.IsCoinBase()) {
        for (const CTxIn &txin : tx.vin) {
            const COutPoint&
                prevout = txin.prevout;
            const CTransaction
                & txPrev = prevInputs[prevout.COutPointGetHash()].second;
            UpdateAssetInfoFromTxInputs(prevout,txPrev.vout[prevout.COutPointGet_n()], assetsCache);
        }
    }

    // Update asset info from Tx outputs
    UpdateAssetInfoFromTxOutputs(tx, nHeight, blockHash, assetsCache, undoAssetData);
}

void UpdateAssetInfoFromTxInputs(const COutPoint& outpoint, const CTxOut& txOut, CAssetsCache* assetsCache)
{
    if (AreAssetsDeployed()) {
        if (assetsCache) {
            if (!assetsCache->TrySpendCoin(outpoint, txOut)) {
                error("%s : Failed to try and spend the asset. COutPoint : %s", __func__, outpoint.ToString());
            }
        }
    }
}

void UpdateAssetInfoFromTxOutputs(const CTransaction& tx, int nHeight, uint256 blockHash, CAssetsCache* assetsCache, std::pair<std::string, CBlockAssetUndo>* undoAssetData)
{
    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();

    if (AreAssetsDeployed()) {
        if (assetsCache) {
            if (tx.IsNewAsset()) { // This works are all new root assets, sub asset, and restricted assets
                CNewAsset asset;
                std::string strAddress;
                AssetFromTransaction(tx, asset, strAddress);

                std::string ownerName;
                std::string ownerAddress;
                OwnerFromTransaction(tx, ownerName, ownerAddress);

                // Add the new asset to cache
                if (!assetsCache->AddNewAsset(asset, strAddress, nHeight, blockHash))
                    error("%s : Failed at adding a new asset to our cache. asset: %s", __func__,
                          asset.strName);

                // Add the owner asset to cache
                if (!assetsCache->AddOwnerAsset(ownerName, ownerAddress))
                    error("%s : Failed at adding a new asset to our cache. asset: %s", __func__,
                          asset.strName);

            } else if (tx.IsReissueAsset()) {
                CReissueAsset reissue;
                std::string strAddress;
                ReissueAssetFromTransaction(tx, reissue, strAddress);

                int reissueIndex = tx.vout.size() - 1;

                // Get the asset before we change it
                CNewAsset asset;
                if (!assetsCache->GetAssetMetaDataIfExists(reissue.strName, asset))
                    error("%s: Failed to get the original asset that is getting reissued. Asset Name : %s",
                          __func__, reissue.strName);

                if (!assetsCache->AddReissueAsset(reissue, strAddress, COutPoint(txid, reissueIndex)))
                    error("%s: Failed to reissue an asset. Asset Name : %s", __func__, reissue.strName);

                // Set the old IPFSHash for the blockundo
                bool fIPFSChanged = !reissue.strIPFSHash.empty();
                bool fUnitsChanged = reissue.nUnits != -1;

                // If any of the following items were changed by reissuing, we need to database the old values so it can be undone correctly
                if (fIPFSChanged || fUnitsChanged) {
                    undoAssetData->first = reissue.strName; // Asset Name
                    undoAssetData->second = CBlockAssetUndo {fIPFSChanged, fUnitsChanged, asset.strIPFSHash, asset.units}; // ipfschanged, unitchanged, Old Assets IPFSHash, old units
                }
            } else if (tx.IsNewUniqueAsset()) {
                for (int n = 0; n < (int)tx.vout.size(); n++) {
                    auto out = tx.vout[n];

                    CNewAsset asset;
                    std::string strAddress;

                    if (IsScriptNewUniqueAsset(out.scriptPubKey)) {
                        AssetFromScript(out.scriptPubKey, asset, strAddress);

                        // Add the new asset to cache
                        if (!assetsCache->AddNewAsset(asset, strAddress, nHeight, blockHash))
                            error("%s : Failed at adding a new asset to our cache. asset: %s", __func__,
                                  asset.strName);
                    }
                }
            }
        }
    }

    for (size_t i = 0; i < tx.vout.size(); ++i) {
        if (AreAssetsDeployed()) {
            if (assetsCache) {
                CAssetOutputEntry assetData;
                if (GetAssetData(tx.vout[i].scriptPubKey, assetData)) {

                    // If this is a transfer asset, and the amount is greater than zero
                    // We want to make sure it is added to the asset addresses database if (fAssetIndex == true)
                    if (assetData.type == TX_TRANSFER_ASSET && assetData.nAmount > 0) {
                        // Create the objects needed from the assetData
                        CAssetTransfer assetTransfer(assetData.assetName, assetData.nAmount);
                        std::string address = EncodeDestination(assetData.destination);

                        // Add the transfer asset data to the asset cache
                        if (!assetsCache->AddTransferAsset(assetTransfer, address, COutPoint(txid, i), tx.vout[i]))
                            error("%s : ERROR - Failed to add transfer asset CTxOut: %s\n", __func__,
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

bool GetAddressIndex(uint160 addressHash, int type, std::string assetName,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex, int start, int end)
{
    if (!fAddressIndex)
        return error("address index not enabled");

    CTxDB txdb;
    if (!txdb.ReadAddressIndex(addressHash, type, assetName, addressIndex, start, end))
        return error("unable to get txids for address");

    return true;
}
//
// END OF FUNCTIONS USED FOR ASSET MANAGEMENT SYSTEM
//

const ::int64_t 
    nSimulatedMOneySupplyAtFork = 124460820773591;  //124,460,820.773591 YAC

const uint256 
  //hashGenesisBlockTestNet("0xfe20c2c2fc02b36d2473e1f51dba1fb123d41ff42966e2a4edabb98fdd7107e6"),
    // change here           ^^^^^^^^^^^^^
  //hashGenesisBlockTestNet( "0x0000fb514c55539c42aed840fb46fedf49ce9c8a81f2ab29bd8e5b0e7134467f" ),
  //hashGenesisBlockTestNet( "0x000026ab43bff071f9c5432b754ab00c90f520a9569007e9205d1ee13cde973d" ),

//hashGenesisBlockTestNet( "0bd0495ffce47a76504f338692b70dfcd8fabc5176a49cc646f3f28478b132dc" ),

                            // version 0.5.0.03
//hashGenesisBlockTestNet( "056ce89e39622e2577f35117eef4118f5b4a35b98a16ebc218d31d55fd018c1b" ),
                            // version 0.5.0.04
//hashGenesisBlockTestNet( "0x049a99dd896cbaa9004c790d8b3855e714ede6328b0555c55d08b94fda187f1e" ),
//hashGenesisBlockTestNet( "0x0619394c5fc682ef90f64a256a48b428636246010cf898b59491465e47d3b49e" ),
  hashGenesisBlockTestNet( "0x1dc29b112550069ecb870e1be78c8d0c166e5f4e41433283e74dcf30b510c1f3" ),
    
                            // version 0.5.0.03
//hashGenesisMerkleRootTestNet( "0xf87fdba660d8d4cf099c09bc684968249311611ff18c92ddce3d44ccf8df0c28" ),
                            // version 0.5.0.04
//hashGenesisMerkleRootTestNet( "0x389003d67b17d9a38a9c83b9289225f5e5469b9f6a2d70fc7c97ee6e8f995f23" ),
                            // old 0.4.9
  hashGenesisMerkleRootTestNet( "0xd6ab993974b85898d45cfd850c8865fefa342450b4b38dca9eaafb515920baf7" ),
                            // new 0.5.5
  //hashGenesisMerkleRootMainNet( "0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f" );
//   hashGenesisMerkleRootMainNet( "0x97a5a4d34dc12eff03febfd7c906b31740ac3412c820950a431b25ee1b874cb6" );
//   hashGenesisMerkleRootMainNet( "0x5b1c7339ef15a2c8ad96b672e345a8cd316cc8ee019ea7edeef4f0cd1e8116eb");
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
unsigned int nTransactionsUpdated = 0;

map<uint256, CBlockIndex*> mapBlockIndex;
boost::mutex mapHashmutex;
map<uint256, uint256> mapHash;
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
// Median starting height of all connected peers.
int nMedianStartingHeight = 0;
// All pairs A->B, where A (or one if its ancestors) misses transactions, but B has transactions.
multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;
::int64_t nTimeBestReceived = 0;
int nScriptCheckThreads = 0;
int nHashCalcThreads = 0;

CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

map<uint256, uint256> mapProofOfStake;

map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Yacoin Signed Message:\n";

// Settings
::int64_t nTransactionFee = MIN_TX_FEE;
::int64_t nMinimumInputValue = MIN_TX_FEE;

// Ping and address broadcast intervals
::int64_t nPingInterval = 30 * nSecondsPerMinute;  // I presume 30 minutes????

::int64_t nBroadcastInterval = nOneDayInSeconds;    // can be from 6 days in seconds down to 0!

::int64_t
    nLongAverageBP2000 = 0,
    nLongAverageBP1000 = 0,
    nLongAverageBP200 = 0,
    nLongAverageBP100 = 0,
    nLongAverageBP = 0;

extern enum Checkpoints::CPMode CheckpointsMode;

// Sources of received blocks, to be able to send them reject messages or ban
// them, if processing happens afterwards. Protected by cs_main.
map<uint256, NodeId> mapBlockSource;
// Blocks that are in flight, and that are in the queue to be downloaded.
// Protected by cs_main.
struct QueuedBlock {
    uint256 hash;
    CBlockIndex *pindex; // Optional.
    int64_t nTime;  // Time of "getdata" request in microseconds.
};
map<uint256, pair<NodeId, list<QueuedBlock>::iterator> > mapBlocksInFlight;

/** Number of blocks that can be requested at any given time from a single peer. */
int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 500;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
unsigned int BLOCK_DOWNLOAD_WINDOW = MAX_BLOCKS_IN_TRANSIT_PER_PEER * 64; //32000
unsigned int FETCH_BLOCK_DOWNLOAD = MAX_BLOCKS_IN_TRANSIT_PER_PEER * 8; //4000
// Trigger sending getblocks from other peers when header > block + HEADER_BLOCK_DIFFERENCES_TRIGGER_GETDATA
unsigned int HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS = 10000;
/** Headers download timeout expressed in microseconds
 *  Timeout = base + per_header * (expected number of headers) */
int64_t HEADERS_DOWNLOAD_TIMEOUT_BASE = 10 * 60 * 1000000; // 10 minutes
int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE = HEADERS_DOWNLOAD_TIMEOUT_BASE; // 10 minutes
//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state)
{
    return strprintf("%s (code %i)",
        state.GetRejectReason(),
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

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        pwallet->EraseFromWallet(hash);
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
void static Inventory(const uint256& hash)
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

//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

namespace {

// Maintain validation-specific state about nodes, protected by cs_main, instead
// by CNode's own locks. This simplifies asynchronous operation, where
// processing of incoming data is done after the ProcessMessage call returns,
// and we're no longer holding the node's locks.
struct CNodeState {
    // Accumulated misbehaviour score for this peer.
    int nMisbehavior;
    // Whether this peer should be disconnected and banned.
    bool fShouldBan;
    // String name of this peer (debugging/logging purposes).
    std::string name;
    // The best known block we know this peer has announced.
    CBlockIndex *pindexBestKnownHeader;
    // The hash of the last unknown block this peer has announced.
    uint256 hashLastUnknownBlock;
    // The last full block we both have.
    CBlockIndex *pindexLastCommonBlock;
    // Whether we've started headers synchronization with this peer.
    bool fSyncStarted;
    //! When to potentially disconnect peer for stalling headers download
    int64_t nHeadersSyncTimeout;
    //! When to potentially send the next getblocks
    int64_t nLastTimeSendingGetBlocks;
    // Since when we're stalling block download progress (in microseconds), or 0.
    int64_t nStallingSince;
    list<QueuedBlock> vBlocksInFlight;
    int nBlocksInFlight;

    CNodeState() {
        nMisbehavior = 0;
        fShouldBan = false;
        pindexBestKnownHeader = NULL;
        hashLastUnknownBlock = uint256(0);
        pindexLastCommonBlock = NULL;
        fSyncStarted = false;
        nHeadersSyncTimeout = 0;
        nStallingSince = 0;
        nBlocksInFlight = 0;
        nLastTimeSendingGetBlocks = 0;
    }
};

// Map maintaining per-node state. Requires cs_main.
map<NodeId, CNodeState> mapNodeState;

// Requires cs_main.
CNodeState *State(NodeId pnode) {
    map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end())
        return NULL;
    return &it->second;
}

void InitializeNode(NodeId nodeid, const CNode *pnode) {
    LOCK(cs_main);
    CNodeState &state = mapNodeState.insert(std::make_pair(nodeid, CNodeState())).first->second;
    state.name = pnode->addrName;
}

void FinalizeNode(NodeId nodeid) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    printf("FinalizeNode for peer=%s\n", state->name.c_str());

    if (state->fSyncStarted)
        nSyncStarted--;

    BOOST_FOREACH(const QueuedBlock& entry, state->vBlocksInFlight)
        mapBlocksInFlight.erase(entry.hash);
    mapNodeState.erase(nodeid);
}

// Requires cs_main.
void MarkBlockAsReceived(const uint256 &hash, NodeId nodeFrom = -1) {
    map<uint256, pair<NodeId, list<QueuedBlock>::iterator> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end()) {
        CNodeState *state = State(itInFlight->second.first);
        state->vBlocksInFlight.erase(itInFlight->second.second);
        state->nBlocksInFlight--;
        state->nStallingSince = 0;
        mapBlocksInFlight.erase(itInFlight);
    }

}

// Requires cs_main.
void MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, CBlockIndex *pindex = NULL) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Make sure it's not listed somewhere already.
    MarkBlockAsReceived(hash);

    QueuedBlock newentry = {hash, pindex, GetTimeMicros()};
    list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(), newentry);
    state->nBlocksInFlight++;
    mapBlocksInFlight[hash] = std::make_pair(nodeid, it);
}

/** Check whether the last unknown block a peer advertized is not yet known. */
void ProcessBlockAvailability(NodeId nodeid) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    if (state->hashLastUnknownBlock != 0) {
        map<uint256, CBlockIndex*>::iterator itOld = mapBlockIndex.find(state->hashLastUnknownBlock);
        if (itOld != mapBlockIndex.end() && itOld->second->bnChainTrust > 0) {
            if (state->pindexBestKnownHeader == NULL || itOld->second->bnChainTrust >= state->pindexBestKnownHeader->bnChainTrust)
                state->pindexBestKnownHeader = itOld->second;
            state->hashLastUnknownBlock = uint256(0);
        }
    }
}

/** Update tracking information about which blocks a peer is assumed to have. */
void UpdateBlockAvailability(NodeId nodeid, const uint256 &hash) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    ProcessBlockAvailability(nodeid);

    map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end() && it->second->bnChainTrust > 0) {
        // An actually better block was announced.
        if (state->pindexBestKnownHeader == NULL || it->second->bnChainTrust >= state->pindexBestKnownHeader->bnChainTrust)
            state->pindexBestKnownHeader = it->second;
    } else {
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-NULL. */
CBlockIndex* LastCommonAncestor(CBlockIndex* pa, CBlockIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

/** Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks, until it has
 *  at most count entries. */
void FindNextBlocksToDownload(NodeId nodeid, unsigned int count, std::vector<CBlockIndex*>& vBlocks, NodeId& nodeStaller) {
    if (count == 0)
        return;

    vBlocks.reserve(vBlocks.size() + count);
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Make sure pindexBestKnownHeader is up to date, we'll need it.
    ProcessBlockAvailability(nodeid);

    if (state->pindexBestKnownHeader == NULL || state->pindexBestKnownHeader->bnChainTrust < chainActive.Tip()->bnChainTrust) {
        // This peer has nothing interesting.
        return;
    }

    if (state->pindexLastCommonBlock == NULL) {
        // Bootstrap quickly by guessing a parent of our best tip is the forking point.
        // Guessing wrong in either direction is not a problem.
        state->pindexLastCommonBlock = chainActive[std::min(state->pindexBestKnownHeader->nHeight, chainActive.Height())];
    }

    // If the peer reorganized, our previous pindexLastCommonBlock may not be an ancestor
    // of their current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBlock = LastCommonAncestor(state->pindexLastCommonBlock, state->pindexBestKnownHeader);
    if (state->pindexLastCommonBlock == state->pindexBestKnownHeader)
        return;

    std::vector<CBlockIndex*> vToFetch;
    CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
    // Never fetch further than the best block we know the peer has, or more than BLOCK_DOWNLOAD_WINDOW + 1 beyond the last
    // linked block we have in common with this peer. The +1 is so we can detect stalling, namely if we would be able to
    // download that next block if the window were 1 larger.
    int nWindowEnd = state->pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW;
    int nMaxHeight = std::min<int>(state->pindexBestKnownHeader->nHeight, nWindowEnd + 1);
    NodeId waitingfor = -1;
    while (pindexWalk->nHeight < nMaxHeight) {
        // Read up to 4000 (or more, if more blocks than that are needed) successors of pindexWalk (towards
        // pindexBestKnownHeader) into vToFetch. We fetch 4000, because CBlockIndex::GetAncestor may be as expensive
        // as iterating over ~100 CBlockIndex* entries anyway.
        int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight, std::max<int>(count - vBlocks.size(), FETCH_BLOCK_DOWNLOAD));
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownHeader->GetAncestor(pindexWalk->nHeight + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--) {
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those blocks in vToFetch (in forward direction), adding the ones that
        // are not yet downloaded and not in flight to vBlocks. In the mean time, update
        // pindexLastCommonBlock as long as all ancestors are already downloaded.
        BOOST_FOREACH(CBlockIndex* pindex, vToFetch) {
            if (pindex->nStatus & BLOCK_HAVE_DATA) {
                if (pindex->validTx)
                    state->pindexLastCommonBlock = pindex;
            } else if (mapBlocksInFlight.count(pindex->GetBlockHash()) == 0) {
                // The block is not already downloaded, and not yet in flight.
                if (pindex->nHeight > nWindowEnd) {
                    // We reached the end of the window.
                    if (vBlocks.size() == 0 && waitingfor != nodeid) {
                        // We aren't able to fetch anything, but we would be if the download window was one larger.
                        nodeStaller = waitingfor;
                    }
                    return;
                }
                vBlocks.push_back(pindex);
                if (vBlocks.size() == count) {
                    return;
                }
            } else if (waitingfor == -1) {
                // This is the first already-in-flight block.
                waitingfor = mapBlocksInFlight[pindex->GetBlockHash()].first;
            }
        }
    }
}
}

bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    if (state == NULL)
        return false;
    stats.nMisbehavior = state->nMisbehavior;
    stats.nSyncHeight = state->pindexBestKnownHeader ? state->pindexBestKnownHeader->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBlock ? state->pindexLastCommonBlock->nHeight : -1;
    BOOST_FOREACH(const QueuedBlock& queue, state->vBlocksInFlight) {
        if (queue.pindex)
            stats.vHeightInFlight.push_back(queue.pindex->nHeight);
    }
    return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

void RegisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.ProcessMessages.connect(&ProcessMessages);
    nodeSignals.SendMessages.connect(&SendMessages);
    nodeSignals.InitializeNode.connect(&InitializeNode);
    nodeSignals.FinalizeNode.connect(&FinalizeNode);
}

void UnregisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.ProcessMessages.disconnect(&ProcessMessages);
    nodeSignals.SendMessages.disconnect(&SendMessages);
    nodeSignals.InitializeNode.disconnect(&InitializeNode);
    nodeSignals.FinalizeNode.disconnect(&FinalizeNode);
}



//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION_of_Tx);

    if (nSize > 5000)
    {
        printf("ignoring large orphan tx (size: %" PRIszu ", hash: %s)\n", nSize, hash.ToString().substr(0,10).c_str());
        return false;
    }

    mapOrphanTransactions[hash] = tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.COutPointGetHash()].insert(hash);

    printf("stored orphan tx %s (mapsz %" PRIszu ")\n", hash.ToString().substr(0,10).c_str(),
        mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CTransaction& tx = mapOrphanTransactions[hash];
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.COutPointGetHash()].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.COutPointGetHash()].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.COutPointGetHash());
    }
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
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
        printf("EvaluateSequenceLocks, failed to use relative time-lock coins, current block height  = %d"
                ", the coin inputs can only be used in a block with height > %d\n", block.nHeight, lockPair.first);
        return false;
    }
    else if (lockPair.second >= nBlockTime)
    {
        printf("EvaluateSequenceLocks, failed to use relative time-lock coins, current block time  = %ld (%s)"
                ", the coin inputs can only be used after a block with block time > %ld (%s) is mined\n",
                nBlockTime, DateTimeStrFormat(nBlockTime).c_str(),
                lockPair.second, DateTimeStrFormat(lockPair.second).c_str());
        return false;
    }

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool CheckSequenceLocks(const CTransaction &tx, int flags)
{
    LOCK2(cs_main, mempool.cs);

    CBlockIndex index;
    index.pprev = chainActive.Tip();
    // CheckSequenceLocks() uses chainActive.Tip()->nHeight+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Tip()->nHeight
    index.nHeight = chainActive.Tip()->nHeight + 1;

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

            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
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

    std::pair<int, int64_t> lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
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

bool isHardforkHappened()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
    {
        return true;
    }
    else
    {
        return false;
    }
}
//////////////////////////////////////////////////////////////////////////////
//
// CTxIndex
//

int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
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
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return chainActive.Tip()->nHeight - pindex->nHeight + 1;
}

bool CTxMemPool::accept(CValidationState &state, CTxDB& txdb, CTransaction &tx, bool fCheckInputs,
                        bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    /** YAC_ASSET START */
    std::vector<std::pair<std::string, uint256>> vReissueAssets;
    /** YAC_ASSET END */

    if (tx.nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old && isHardforkHappened())
        return error("CTxMemPool::accept() : Not accept transaction with old version");

    if (!tx.CheckTransaction(state))
        return error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return state.DoS(100, error("CTxMemPool::accept() : coinstake as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((::int64_t)tx.nLockTime > std::numeric_limits<int>::max())
        return error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    string strNonStd;
    if (!fTestNet && !tx.IsStandard(strNonStd))
        return error("CTxMemPool::accept() : nonstandard transaction (%s)", strNonStd.c_str());

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!tx.IsFinal())
        return error("CTxMemPool::accept() : non-final transaction");

    // Do we already have it?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash))
            return false;
    }
    if (fCheckInputs)
        if (txdb.ContainsTx(hash))
            return false;

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].GetPtx();
            if (ptxOld->IsFinal())
                return false;
            if (!tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].GetPtx() != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (!tx.FetchInputs(state, txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
                return error("CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return false;
        }

        // Only accept BIP68 sequence locked transactions that can be mined in the next
        // block; we don't want our mempool filled up with transactions that can't
        // be mined yet.
        if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        {
            return error("CTxMemPool::accept() : non-BIP68-final transaction");
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(mapInputs) && !fTestNet)
            return error("CTxMemPool::accept() : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

        ::int64_t nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        ::int64_t txMinFee = tx.GetMinFee(nSize);
        if (nFees < txMinFee)
            return error("CTxMemPool::accept() : not enough fees %s, %" PRId64 " < %" PRId64,
                         hash.ToString().c_str(),
                         nFees, txMinFee);

        /** YAC_ASSET START */
        if (!AreAssetsDeployed()) {
            for (auto out : tx.vout) {
                if (out.scriptPubKey.IsAssetScript())
                    return state.DoS(100, error("bad-txns-contained-asset-when-not-active"));
            }
        }

        if (AreAssetsDeployed()) {
            if (!CheckTxAssets(tx, state, mapInputs, GetCurrentAssetCache(), true, vReissueAssets))
                return error("%s: CheckTxAssets: %s, %s", __func__, tx.GetHash().ToString(),
                             FormatStateMessage(state));
        }
        /** YAC_ASSET END */

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (
            !tx.ConnectInputs(state,
                              txdb, 
                              mapInputs, 
                              mapUnused, 
                              CDiskTxPos(1,1,1), 
                              chainActive.Tip(), 
                              false, 
                              false, 
                              true, 
                              SIG_SWITCH_TIME < tx.nTime ? STRICT_FLAGS : SOFT_FLAGS
                             )
           )
        {
            return error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
        }
    }

    // Store transaction in memory
    {
        LOCK(cs);
        if (ptxOld)
        {
            printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            ConnectedBlockAssetData connectedBlockData;
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
    }

    // TODO: Add memory address index
//    if (fAddressIndex) {
//        pool.addAddressIndex(entry, view);
//    }

    /** YAC_ASSET START */
    for (auto out : vReissueAssets) {
        mapReissuedAssets.insert(out);
        mapReissuedTx.insert(std::make_pair(out.second, out.first));
    }
    if (AreAssetsDeployed()) {
        for (auto out : tx.vout) {
            if (out.scriptPubKey.IsAssetScript()) {
                CAssetOutputEntry data;
                if (!GetAssetData(out.scriptPubKey, data))
                    continue;
                if (data.type == TX_NEW_ASSET && !IsAssetNameAnOwner(data.assetName)) {
                    mapAssetToHash[data.assetName] = hash;
                    mapHashToAsset[hash] = data.assetName;
                }
            }
        }
    }
    /** YAC_ASSET END */

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());

    printf("CTxMemPool::accept() : accepted %s (poolsz %" PRIszu ")\n",
           hash.ToString().substr(0,10).c_str(),
           mapTx.size());
#ifdef QT_GUI
    {
        LOCK(cs);

    lastTxHash.storeLasthash( hash );
    //uiInterface.NotifyBlocksChanged();
    }
#endif

    return true;
}

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}

void CTxMemPool::removeUnchecked(const CTransaction& tx, const uint256& hash)
{
    for (const CTxIn& txin :tx.vin)
    {
        mapNextTx.erase(txin.prevout);
    }
    mapTx.erase(hash);
    nTransactionsUpdated++;

    /** YAC_ASSET START */
    // If the transaction being removed from the mempool is locking other reissues. Free them
    if (mapReissuedTx.count(hash)) {
        if (mapReissuedAssets.count(mapReissuedTx.at(hash))) {
            mapReissuedAssets.erase(mapReissuedTx.at((hash)));
            mapReissuedTx.erase(hash);
        }
    }

    // Erase from the asset mempool maps if they match txid
    if (mapHashToAsset.count(hash)) {
        mapAssetToHash.erase(mapHashToAsset.at(hash));
        mapHashToAsset.erase(hash);
    }
    /** YAC_ASSET END */
}

void CTxMemPool::remove(const CTransaction& tx)
{
    ConnectedBlockAssetData connectedBlockData;
    std::vector<CTransaction> vtx = {tx};
    remove(vtx, connectedBlockData);
}

void CTxMemPool::remove(const std::vector<CTransaction>& vtx)
{
    ConnectedBlockAssetData connectedBlockData;
    remove(vtx, connectedBlockData);
}

void CTxMemPool::remove(const std::vector<CTransaction>& vtx, ConnectedBlockAssetData& connectedBlockData)
{
    // Remove transaction from memory pool
    for(const CTransaction& tx : vtx)
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            removeUnchecked(tx, hash);
        }
    }

    /** YAC_ASSET START */
    // Remove newly added asset issue transactions from the mempool if they haven't been removed already    std::vector<CTransaction> trans;
    for (auto it : connectedBlockData.newAssetsToAdd) {
        if (mapAssetToHash.count(it.asset.strName)) {
            const uint256& hash = mapAssetToHash.at(it.asset.strName);
            auto itMapTx = mapTx.find(hash);
            if (itMapTx != mapTx.end()) {
                removeUnchecked(itMapTx->second, hash);
            }
        }
    }
    /** YAC_ASSET END */
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}




int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
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


bool CMerkleTx::AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs)
{
    CValidationState state;
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptToMemoryPool(state, txdb, false);
    }
    else
    {
        return CTransaction::AcceptToMemoryPool(state, txdb, fCheckInputs);
    }
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb);
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
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
                    tx.AcceptToMemoryPool(txdb, fCheckInputs);
            }
        }
        return AcceptToMemoryPool(txdb, fCheckInputs);
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
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
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
                tx = mempool.lookup(hash);
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
      //printf("GetNfactor (%ld) - something wrong(n == %d)\n", nTimestamp, n);
        printf("GetNfactor (%"PRId64") - something wrong(n == %d)\n", nTimestamp, n); // for g++

    // so n is between 0 and 0xff
    unsigned char N = (unsigned char)n;
#ifdef _DEBUG
    if(
        false &&    // just a quick way to turn it off
        fDebug &&
        fPrintToConsole
      )
    {
        printf(
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
        if (fDebug && GetBoolArg("-printcreation"))
            printf("GetProofOfWorkReward() : lower=%" PRId64 " upper=%" PRId64 " mid=%" PRId64 "\n", bnLowerBound.getuint64(), bnUpperBound.getuint64(), bnMidValue.getuint64());
        if (bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnTargetLimit > bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnTarget)
            bnUpperBound = bnMidValue;
        else
            bnLowerBound = bnMidValue;
    }

    ::int64_t nSubsidy = bnUpperBound.getuint64();

    nSubsidy = (nSubsidy / CENT) * CENT;
    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfWorkReward() : create=%s nBits=0x%08x nSubsidy=%" PRId64 "\n", FormatMoney(nSubsidy).c_str(), nBits, nSubsidy);

    return min(nSubsidy, MAX_MINT_PROOF_OF_WORK) + nFees;
}

::uint64_t GetMaxSize(enum GetMaxSize_mode mode)
{
    ::uint64_t nMaxSize = 0;
    if (chainActive.Genesis() == NULL || (chainActive.Tip()->nHeight + 1) < nMainnetNewLogicBlockNumber)
    {
        nMaxSize = MAX_GENESIS_BLOCK_SIZE;
    }
    else
    {
        nMaxSize = (GetProofOfWorkReward() * 1000 / MIN_TX_FEE);
    }

    switch (mode)
    {
        case MAX_BLOCK_SIZE_GEN:
            nMaxSize /= 2;
            break;

        case MAX_BLOCK_SIGOPS:
            nMaxSize = max(nMaxSize, (::uint64_t)MAX_GENESIS_BLOCK_SIZE) / 50;
            break;

        case MAX_BLOCK_SIZE:
        default:
            break;
    }
    return nMaxSize;
}

// ppcoin: miner's coin stake is rewarded based on coin age spent (coin-days)
::int64_t GetProofOfStakeReward(::int64_t nCoinAge)
{
    static ::int64_t
        nRewardCoinYear = 5 * CENT;  // creation amount per coin-year

    ::int64_t 
        nSubsidy = nCoinAge * 33 / (365 * 33 + 8) * nRewardCoinYear;
    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeReward(): create=%s nCoinAge=%"PRId64"\n", FormatMoney(nSubsidy).c_str(), nCoinAge);
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

            if (fDebug && GetBoolArg("-printcreation"))
                printf("GetProofOfStakeReward() : lower=%" PRId64 " upper=%" PRId64 " mid=%" PRId64 "\n", bnLowerBound.getuint64(), bnUpperBound.getuint64(), bnMidValue.getuint64());

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
        if (fDebug && GetBoolArg("-printcreation") && nSubsidyLimit < nSubsidy)
            printf("GetProofOfStakeReward(): %s is greater than %s, coinstake reward will be truncated\n", FormatMoney(nSubsidy).c_str(), FormatMoney(nSubsidyLimit).c_str());

        nSubsidy = min(nSubsidy, nSubsidyLimit);
    }

    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64 " nBits=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge, nBits);
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

//_____________________________________________________________________________
bool HaveWeSwitchedToNewLogicRules( bool &fUsingOld044Rules )
{
    bool
        fReturn = false;

    if (true == fUsingOld044Rules)         // should we switch to new rules
    {
        if(
           fTestNet &&    // may use new rules, ATM only in TestNet
           (
            fTestNetNewLogic &&
            (nMainnetNewLogicBlockNumber <= chainActive.Height())
           )
          )
        {
            fUsingOld044Rules = false;
            fReturn = true;
            if (fDebug)
            {
#ifdef WIN32
                (void)printf(
                     "\n"
                     "fUseOld044Rules is "
                     "%s"
                     "\n"
                     "\n"
                     , fUsingOld044Rules? "true": "false"
                            );
#endif
            }
        }
    }
    return fReturn;
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
    (void)printf(
                 "PoW new constant target %s\n"
                 ""
                 , CBigNum( bnNewTarget ).getuint256().ToString().substr(0,16).c_str()
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

            (void)printf("PoW constant target %s"
                         " (%d block"
                         "%s to go)"
                         "\n"
                         "",
                         nTarget.ToString().substr(0, 16).c_str(), (nDifficultyInterval - nBlocksToGo),
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

    printf("CheckProofOfWork: nBits: %d\n",nBits);
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
    LOCK(cs_main);
    bool
        fIsIBD = true;      // presume still downloading blocks

    if (
        chainActive.Tip() == NULL || 
        (chainActive.Height() < Checkpoints::GetTotalBlocksEstimate())
       )
        return fIsIBD;

    fIsIBD = false;         // presume downloading blocks is done
    if( 
        (0 == chainActive.Height()) 
      )
        return fIsIBD;

    ::int64_t
        nTimeOfBestBlockInSeconds = chainActive.Tip()->GetBlockTime(),
        nCurrentTime = GetTime();

    const ::int64_t 
        nOnedayAgoInSeconds = nCurrentTime - nOneDayInSeconds,
        nTwoHoursAgoInSeconds = nCurrentTime - nTwoHoursInSeconds,
        n12MinutesAgo = nCurrentTime - (12 * nSecondsPerMinute);

    bool 
        fIsBestBlockYoungEnough = (nTimeOfBestBlockInSeconds >= nOnedayAgoInSeconds)? true: false;

    if( fIsBestBlockYoungEnough )   // being young enough means "caught up"
    {                               // i.e. done with the "initial block download"
        fIsBestBlockYoungEnough =   // it's within a day of now, so is it within 12 minutes
            (nTimeOfBestBlockInSeconds >= n12MinutesAgo)? 
            true: 
            false;
    }

    if( !fIsBestBlockYoungEnough )  // i.e. we think IBD is still happening
    {                               // maybe it isn't, so let's try some trickery!
        const ::int64_t
            nTenSeconds = 10;
        static ::int64_t
            nLastUpdate;
        static CBlockIndex
            * pindexLastBest;
        if (chainActive.Tip() != pindexLastBest)   // we just got a new block
        {                           // first time through, we set the values
            pindexLastBest = chainActive.Tip();
            nLastUpdate = GetTime();
        }
        //else  // nLastUpdate gets older & older
        fIsBestBlockYoungEnough =
              !(
                ((GetTime() - nLastUpdate) < nTenSeconds) && // < 10 seconds between calls?
                (chainActive.Tip()->GetBlockTime() < (GetTime() - nOneDayInSeconds)) // block is > 1 day old
               );                                   // we take this to mean still IBD, I think???
    }
    //else  // fIsBestBlockYoungEnough is true, meaning done with IBD
    return !fIsBestBlockYoungEnough;
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

bool CHashCalculation::operator()()
{
    // Hash calculation takes much time to finish. So checking fShutdown node regularly to quickly shut down node during hash calculation
    if (fShutdown) {
        return true;
    }

    unsigned long threadId = getThreadId();
    uint256 blockSHA256Hash = pBlock->GetSHA256Hash();

    {
        boost::mutex::scoped_lock lock(mapHashmutex);
        map<uint256, uint256>::iterator mi = mapHash.find(blockSHA256Hash);
        if (mi != mapHash.end())
        {
            pBlock->blockHash = (*mi).second;
            printf("[HashCalcThread:%ld] Already have header %s (sha256: %s)\n", threadId, pBlock->blockHash.ToString().c_str(), blockSHA256Hash.ToString().c_str());
        }
    }

    if (pBlock->blockHash == 0)
    {
        uint256 blockHash = pBlock->GetHash();
        printf("[HashCalcThread:%ld] Received header %s (sha256: %s) from node %s\n", threadId, blockHash.ToString().c_str(), blockSHA256Hash.ToString().c_str(), pNode->addrName.c_str());
        boost::mutex::scoped_lock lock(mapHashmutex);
        mapHash.insert(make_pair(blockSHA256Hash, blockHash));
    }

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

static CCheckQueue<CHashCalculation> hashCalculationQueue(200);

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

void ThreadHashCalculation(void*)
{
    ++vnThreadsRunning[THREAD_HASHCALCULATION];
    RenameThread("yacoin-hashcalc");
    hashCalculationQueue.Thread();
    --vnThreadsRunning[THREAD_HASHCALCULATION];
}

void ThreadHashCalculationQuit()
{
    hashCalculationQueue.Quit();
}

// Requires cs_main.
void Misbehaving(NodeId pnode, int howmuch)
{
    if (howmuch == 0)
        return;

    CNodeState *state = State(pnode);
    if (state == NULL)
        return;

    state->nMisbehavior += howmuch;
    if (state->nMisbehavior >= GetArg("-banscore", nDEFAULT_BAN_SCORE))
    {
        printf("Misbehaving: %s (%d -> %d) BAN THRESHOLD EXCEEDED\n", state->name.c_str(), state->nMisbehavior-howmuch, state->nMisbehavior);
        printf("(Node %s) Close connection to node due to misbehaving\n",
                state->name.c_str());
        state->fShouldBan = true;
    } else
        printf("Misbehaving: %s (%d -> %d)\n", state->name.c_str(), state->nMisbehavior-howmuch, state->nMisbehavior);
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

    printf("InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      (pindexNew->bnChainTrust).ToString().c_str(), bnBestInvalidBlockTrust.getuint64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    printf("InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), chainActive.Height(),
      (chainActive.Tip()->bnChainTrust).ToString().c_str(),
      bnBestBlockTrust.getuint64(),
      DateTimeStrFormat("%x %H:%M:%S", chainActive.Tip()->GetBlockTime()).c_str());
}

void static InvalidBlockFound(const CValidationState &state, CTxDB& txdb, CBlockIndex *pindex) {
    int nDoS = 0;
    if (state.IsInvalid(nDoS)) {
        std::map<uint256, NodeId>::iterator it = mapBlockSource.find(pindex->GetBlockHash());
        if (it != mapBlockSource.end() && State(it->second) && nDoS > 0) {
            Misbehaving(it->second, nDoS);
        }
    }
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        InvalidChainFound(pindex);
        // Write to disk block index
        txdb.WriteBlockIndex(CDiskBlockIndex(pindex));
        if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindex)))
        {
            printf("InvalidBlockFound(): Can't WriteBlockHash\n");
        }
        if (!txdb.TxnCommit()) {
            printf("InvalidBlockFound(): TxnCommit failed\n");
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
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;

    CBigNum bnBestBlockTrust =
        (chainActive.Tip()->nHeight != 0)?
        (chainActive.Tip()->bnChainTrust - chainActive.Tip()->pprev->bnChainTrust):
        chainActive.Tip()->bnChainTrust;

    printf(
            "UpdateTip: new best=%s height=%d trust=%s\nblocktrust=%" PRId64 "  date=%s\n",
            hashBestChain.ToString().substr(0,20).c_str(), chainActive.Height(),
            bnBestChainTrust.ToString().c_str(),
            bnBestBlockTrust.getuint64(),
            DateTimeStrFormat("%x %H:%M:%S",
            chainActive.Tip()->GetBlockTime()).c_str()
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
            printf("UpdateTip: %d of last 100 blocks above version %d\n", nUpgraded, CURRENT_VERSION_of_block);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

}

// Disconnect chainActive's tip.
bool static DisconnectTip(CValidationState &state, CTxDB& txdb) {
    CBlockIndex *pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    CBlock block;
    {
        CAssetsCache assetCache;
        if (!block.ReadFromDisk(pindexDelete))
            return state.Abort(_("DisconnectTip() : ReadFromDisk for disconnect failed"));
        if (!block.DisconnectBlock(state, txdb, pindexDelete, &assetCache))
            return error("DisconnectTip() : DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString().substr(0,20).c_str());
        // Write the chain state to disk, if necessary.
        if (!WriteChainState(txdb, pindexDelete->pprev))
            return false;
        bool assetsFlushed = assetCache.Flush();
        assert(assetsFlushed);
    }

    printf("DisconnectTip, disconnect block (height: %d, hash: %s)\n", pindexDelete->nHeight, block.GetHash().GetHex());
    // Ressurect mempool transactions from the disconnected block.
    BOOST_FOREACH(CTransaction &tx, block.vtx) {
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!(tx.IsCoinBase() || tx.IsCoinStake()))
        {
            tx.AcceptToMemoryPool(stateDummy, txdb, false);
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
bool static ConnectTip(CValidationState &state, CTxDB& txdb, CBlockIndex *pindexNew)
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
        CBlock block;
        if (!block.ReadFromDisk(pindexNew))
            return state.Abort(_("ConnectTip() : ReadFromDisk for connect failed"));

        /** YAC_ASSET START */
        // Initialize sets used from removing asset entries from the mempool
        ConnectedBlockAssetData assetDataFromBlock;

        // Create the empty asset cache, that will be sent into the connect block
        // All new data will be added to the cache, and will be flushed back into passets after a successful
        // Connect Block cycle
        CAssetsCache assetCache;
        /** YAC_ASSET END */

        // Apply the block atomically to the chain state.
        CInv inv(MSG_BLOCK, hash);
        if (!block.ConnectBlock(state, txdb, pindexNew, &assetCache)) {
            if (state.IsInvalid())
                InvalidBlockFound(state, txdb, pindexNew);
            return error("ConnectTip() : ConnectBlock %s failed", pindexNew->GetBlockHash().ToString().substr(0,20).c_str());
        }
        mapBlockSource.erase(inv.hash);

        /** YAC_ASSET START */
        // Get the newly created assets, from the connectblock assetCache so we can remove the correct assets from the mempool
        assetDataFromBlock = {assetCache.setNewAssetsToAdd};

        // Remove all tx hashes, that were marked as reissued script from the mapReissuedTx.
        // Without this check, you wouldn't be able to reissue for those assets again, as this maps block it
        for (const auto& tx : block.vtx) {
            const uint256& txHash = tx.GetHash();
            if (mapReissuedTx.count(txHash))
            {
                mapReissuedAssets.erase(mapReissuedTx.at(txHash));
                mapReissuedTx.erase(txHash);
            }
        }

        // Flush asset to global asset cache passets
        bool assetFlushed = assetCache.Flush();
        assert(assetFlushed);
        /** YAC_ASSET END */

        // Write the chain state to disk, if necessary.
        if (!WriteChainState(txdb, pindexNew))
            return false;

        // Flush asset data to disk
        if (!FlushAssetToDisk())
            return false;

        // Remove conflicting transactions from the mempool.
        mempool.remove(block.vtx, assetDataFromBlock);

        // Connect longer branch, SPECIFIC FOR YACOIN
        if (pindexNew->pprev)
            pindexNew->pprev->pnext = pindexNew;
        // Update chainActive & related variables.
        UpdateTip(pindexNew);
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

// Try to make some progress towards making pindexMostWork the active block.
static bool ActivateBestChainStep(CValidationState &state, CTxDB& txdb, CBlockIndex *pindexMostWork) {
//    bool fInvalidFound = false;
    CBlockIndex *pindexOldTip = chainActive.Tip();
    CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!txdb.TxnBegin()) {
            return error("ActivateBestChainStep () : TxnBegin 1 failed");
        }
        if (!DisconnectTip(state, txdb)) // Disconnect the latest block on the chain
        {
            error("ActivateBestChainStep, failed to disconnect block");
            txdb.TxnAbort();
            return false;
        }
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
        BOOST_REVERSE_FOREACH(CBlockIndex *pindexConnect, vpindexToConnect) {
            if (!txdb.TxnBegin()) {
                return error("ActivateBestChainStep () : TxnBegin 2 failed");
            }
            if (!ConnectTip(state, txdb, pindexConnect)) {
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
                    txdb.TxnAbort();
                    return false;
                }
            }
            else {
                // Delete all entries in setBlockIndexValid that are worse than our new current block.
                // Note that we can't delete the current block itself, as we may need to return to it later in case a
                // reorganization to a better block fails.
                set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
                while (setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
                    setBlockIndexCandidates.erase(it++);
                }
                // Either the current tip or a successor of it we're working towards is left in setBlockIndexValid.
                assert(!setBlockIndexCandidates.empty());
                if (!pindexOldTip || chainActive.Tip()->bnChainTrust > pindexOldTip->bnChainTrust) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
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

        bool fInitialDownload;
        {
            LOCK(cs_main);
            pindexMostWork = FindMostWorkChain();

            // Whether we have anything to do at all.
            if (pindexMostWork == NULL || pindexMostWork == chainActive.Tip())
                return true;

            if (!ActivateBestChainStep(state, txdb, pindexMostWork))
                return false;

            pindexNewTip = chainActive.Tip();
            fInitialDownload = IsInitialBlockDownload();
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without cs_main
        if (!fInitialDownload) {
            uint256 hashNewTip = pindexNewTip->GetBlockHash();
            // Relay inventory, but don't relay old inventory during initial block download.
            int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
                if (chainActive.Height() > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                    pnode->PushInventory(CInv(MSG_BLOCK, hashNewTip));

            std::string strCmd = GetArg("-blocknotify", "");
            if (!strCmd.empty()) {
                boost::replace_all(strCmd, "%s", hashNewTip.GetHex());
                boost::thread t(runCommand, strCmd); // thread runs free
            }
        }
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
//////////////////////////////////////////////////////////////////////////////
//
// CChain implementation
//
/** Efficiently check whether a block is present in this chain. */
bool CChain::Contains(const CBlockIndex *pindex) const {
    return (*this)[pindex->nHeight] == pindex;
}

/** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
CBlockIndex *CChain::Next(const CBlockIndex *pindex) const {
    if (Contains(pindex))
        return (*this)[pindex->nHeight + 1];
    else
        return NULL;
}

CBlockIndex *CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == NULL) {
        vChain.clear();
        return NULL;
    }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
    return pindex;
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);
    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->nHeight == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }
    return CBlockLocator(vHave);
}

CBlockIndex *CChain::FindFork(const CBlockLocator &locator) const {
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256& hash, locator.vHave) {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (Contains(pindex))
                return pindex;
        }
    }
    return Genesis();
}

CBlockIndex *CChain::FindFork(CBlockIndex *pindex) const {
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

// yacoin2015 GetBlockTrust upgrade
CBigNum CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    if (bnTarget <= 0)
        return CBigNum(0);

    // saironiq: new trust rules (since CONSECUTIVE_STAKE_SWITCH_TIME on mainnet and always on testnet)
    if (
        fTestNet
        ||
        (GetBlockTime() >= CONSECUTIVE_STAKE_SWITCH_TIME)
       ) 
    {
        // first block trust - for future compatibility (i.e., forks :P)
        if (pprev == NULL)
            return CBigNum(1);

        // PoS after PoS? no trust for ya!
        // (no need to explicitly disallow consecutive PoS
        // blocks now as they won't get any trust anyway)
        if (IsProofOfStake() && pprev->IsProofOfStake())
            return CBigNum(0);

        // PoS after PoW? trust = prev_trust + 1!
        if (IsProofOfStake() && pprev->IsProofOfWork())
            return pprev->GetBlockTrust() + 1;  //<<<<<<<<<<<<< does this mean this is recursive??????
                                                // sure looks thatway!  Is this the intent?
        // PoW trust calculation
        if (IsProofOfWork()) 
        {
            // set trust to the amount of work done in this block
            CBigNum bnTrust = bnProofOfWorkLimit / bnTarget;

            // double the trust if previous block was PoS
            // (to prevent orphaning of PoS)
            if (pprev->IsProofOfStake())
                bnTrust *= 2;

            return bnTrust;
        }
        // what the hell?!
        return CBigNum(0);
    }
    return (IsProofOfStake()? (CBigNum(1)<<256) / (bnTarget+1) : CBigNum(1));
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    if (height > nHeight || height < 0)
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (heightSkip == height ||
            (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                      heightSkipPrev >= height))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock)
{
    // Preliminary checks
    bool checked = pblock->CheckBlock(state, true, true, (pblock->nTime > Checkpoints::GetLastCheckpointTime()));
    {
        LOCK(cs_main);
        MarkBlockAsReceived(pblock->GetHash());
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
                printf("WARNING: ProcessBlock (): "
                       "check proof-of-stake failed for block %s (%s)\n",
                        hash.ToString().c_str()
                        , DateTimeStrFormat( " %Y-%m-%d %H:%M:%S",
                                            pblock->nTime
                                           ).c_str()
                      );
                return false; // do not error here as we expect this during initial block download
            }
            if (!mapProofOfStake.count(hash)) // add to mapProofOfStake
                mapProofOfStake.insert(make_pair(hash, hashProofOfStake));
        }

        // Store to disk
        CBlockIndex *pindex = NULL;
        bool ret = pblock->AcceptBlock(state, &pindex);
        if (pindex && pfrom) {
            mapBlockSource[pindex->GetBlockHash()] = pfrom->GetId();
        }
        if (!ret)
            return error("ProcessBlock() : AcceptBlock FAILED");
    }

    CTxDB txdb;
    // New best
    if (!ActivateBestChain(state, txdb))
        return error("ProcessBlock() : ActivateBestChain failed");
    printf("ProcessBlock: ACCEPTED %s BLOCK\n", pblock->IsProofOfStake()?"POS":"POW");
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
        printf("*** %s\n", strMessage.c_str());
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
    printf("*** %s\n", strMessage.c_str());
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
{   // by default fUseOld044Rules are false, i.e new rules are true
    if (
        !fTestNet ||    // may use new rules, ATM only in TestNet
        (
         (GetTime() < (::int64_t)YACOIN_NEW_LOGIC_SWITCH_TIME)   // before the new PoW/PoS rules date-time
         &&
         !fTestNetNewLogic      // (0 == nMainnetNewLogicBlockNumber )  // if fTestNetNewLogic is true, we
        )                                                               // will use it in TestNet
       )
        fUseOld044Rules = true;
    // the implied else is that
    // new rules if TestNet AND 


    if (fTestNet)
    {
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;

        bnProofOfWorkLimit = bnProofOfWorkLimitTestNet; // 16 bits PoW target limit for testnet
        bnInitialHashTarget = bnInitialHashTargetTestNet;
        nStakeMinAge = 2 * nSecondsPerHour;             // 2 hours (to what?)
        nModifierInterval =  10 * nSecondsperMinute;    // 10 minutes, for what?
        nCoinbaseMaturity = 6; // test maturity is 6 blocks + nCoinbaseMaturity(20) = 26
        nStakeTargetSpacing = 1 * nSecondsperMinute;    // 1 minute average block period target
        nConsecutiveStakeSwitchHeight = 4200;           // 4200 blocks until what?
    }

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
            printf(
                    "block.nNonce == %08X"
                    "\r", 
                    block.nNonce
                  );		
		}
        printf(
                "\n" 
                "block.nNonce == %08X (%u dec) after %u tries"
                "\n", 
                block.nNonce,
                block.nNonce,
                nCount
              );		
////////////////////////////////////

        // debug print
        printf("block.GetHash() ==\n%s\n", the_hash.ToString().c_str());
        printf("block.nBits ==\n%s\n", the_target.ToString().c_str());
        printf("block.hashMerkleRoot ==\n%s\n", block.hashMerkleRoot.ToString().c_str());

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
            printf(" Upgrade Info: ModifierUpgradeTime txdb initialization\n");
        }
    }

    {
        CTxDB txdb("r+");

        // upgrade time set to zero if blocktreedb initialized
        if (txdb.ReadModifierUpgradeTime(nModifierUpgradeTime))
        {
            if (nModifierUpgradeTime)
                printf(" Upgrade Info: blocktreedb upgrade detected at timestamp %d\n", nModifierUpgradeTime);
            else
                printf(" Upgrade Info: no blocktreedb upgrade detected.\n");
        }
        else
        {
            nModifierUpgradeTime = GetTime();
            printf(" Upgrade Info: upgrading blocktreedb at timestamp %u\n", nModifierUpgradeTime);
            if (!txdb.WriteModifierUpgradeTime(nModifierUpgradeTime))
                return error("LoadBlockIndex() : failed to write upgrade info");
        }

#ifndef USE_LEVELDB
        txdb.Close();
#endif
    }

    return true;
}



void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
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
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %" PRIszu "",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().c_str(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            FormatMoney(pindex->nMint).c_str(),
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

bool LoadExternalBlockFile(FILE* fileIn)
{
    ::int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(cs_main);
        try 
        {
            CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);
            unsigned int nPos = 0;
            while (
                  //(nPos != (unsigned int)-1) && 
                    (nPos != UINT_MAX) && 
                    blkdat.good() && 
                    !fRequestShutdown
                  )
            {
              //unsigned char pchData[65536];   // is there anything special about this #??
                unsigned char pchData[ (int)1 << 16 ];   
                do 
                {
                    (void)fseek(blkdat, nPos, SEEK_SET);    // who cares if it fails!  What silly code!!
                    int 
                        nRead = fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8)
                    {
                        nPos = UINT_MAX;
                        break;
                    }
                    void
                        * nFind = memchr(
                                         pchData, 
                                         pchMessageStart[ 0 ], 
                                         nRead + 1 - sizeof( pchMessageStart )
                                        );
                    if (nFind)
                    {
                        if (memcmp(nFind, pchMessageStart, sizeof(pchMessageStart))==0)
                        {
                            nPos += ((unsigned char*)nFind - pchData) + sizeof(pchMessageStart);
                            break;
                        }
                        nPos += ((unsigned char*)nFind - pchData) + 1;
                    }
                    else
                        nPos += sizeof(pchData) - sizeof(pchMessageStart) + 1;
                } 
                while(!fRequestShutdown);
                if (nPos == UINT_MAX)
                    break;
                (void)fseek(blkdat, nPos, SEEK_SET);  // again, what seek error!
                unsigned int nSize;
                blkdat >> nSize;
                if (
                    (nSize > 0) && (nSize <= GetMaxSize(MAX_BLOCK_SIZE))
                   )
                {
                    CBlock block;
                    blkdat >> block;
                    CValidationState state;
                    if (ProcessBlock(state, NULL,&block))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (std::exception &e) 
        {
            printf("%s() : Deserialize or I/O error caught during load\n",
                   BOOST_CURRENT_FUNCTION);
        }
    }
    printf("Loaded %i blocks from external file in %" PRId64 "ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // if detected unmet upgrade requirement enter safe mode
    // Note: Modifier upgrade requires blockchain redownload if past protocol switch
    if (IsFixedModifierInterval(nModifierUpgradeTime + 60*60*24)) // 1 day margin
    {
        nPriority = 5000;
        strStatusBar = strRPC = "WARNING: Blockchain redownload required approaching or past v.0.4.5 upgrade deadline.";
    }

    // if detected invalid checkpoint enter safe mode
    if (Checkpoints::hashInvalidCheckpoint != 0)
    {
        nPriority = 3000;
        strStatusBar = strRPC = _("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000)
                    strRPC = strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    Yassert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
        bool txInMap = false;
            {
            LOCK(mempool.cs);
            txInMap = (mempool.exists(inv.hash));
            }
        return txInMap ||
               mapOrphanTransactions.count(inv.hash) ||
               txdb.ContainsTx(inv.hash);
        }

    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xd9, 0xe6, 0xe7, 0xe5 };

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    RandAddSeedPerfmon();
    if (fDebug)
        printf("received: %s (%" PRIszu " bytes) from node %s\n", strCommand.c_str(), vRecv.size(), pfrom->addrName.c_str());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

/******************
    if (strCommand == "version")
    else if (strCommand == "verack")
    else if (strCommand == "addr")
    else if (strCommand == "inv")
    else if (strCommand == "getdata")
    else if (strCommand == "getblocks")
    else if (strCommand == "checkpoint")
    else if (strCommand == "getheaders")
    else if (strCommand == "tx")
    else if (strCommand == "block")
    else if (strCommand == "getaddr")
    else if (strCommand == "mempool")
    else if (strCommand == "checkorder")
    else if (strCommand == "reply")
    else if (strCommand == "ping")
    else if (strCommand == "alert")
    else
    {
        // Ignore unknown commands for extensibility
    }
******************/ 
    string arrayOfAllowedMessages[] = {
                                        "addr"
                                      , "alert"
                                      , "block"
                                      , "checkorder"
                                      , "checkpoint"
                                      , "verack"
                                      , "getaddr"
                                      , "getblocks"
                                      , "getdata"
                                      , "getheaders"
                                      , "inv"
                                      , "mempool"
                                      , "ping"
                                      , "reply"
                                      , "tx"
                                      };
    // int nSize = sizeof( arrayOfAllowedMessages ) / sizeof( arrayOfAllowedMessages[ 0 ]);
    // for( int index = 0; index < nSize; ++index )
    // {
    //      if( "addr" == arrayOfAllowedMessages[ index ] )
    //      {
    //          
    //      }
    // }

    // rx'ed a version response
    if (strCommand == "version")
    {
        // a general form might be
        // bool fReturnFromProcessMessage( string strCommand, bool & return_value )
        // if( fReturnFromProcessMessage( string strCommand, bool & return_value ) )
        //      return return value;
        // a particular form might be
        // if( fReturnFrom_version_Message( bool & return_value ) )
        //      return return value;

        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            Misbehaving(pfrom->GetId(), 1);
            return false;
        }

        ::int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        ::uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
        {
            // Since February 20, 2012, the protocol is initiated at version 209,
            // and earlier versions are no longer supported
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty())
            vRecv >> pfrom->strSubVer;
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        if (pfrom->nVersion < MIN_PEER_BUGGY_VERSION)   // i.e. 60005 and lower disconnected.
        {
            printf("partner %s using a buggy client %d, disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return true;
        }
        // else this node is version 60006 or higher

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable())
            addrSeenByPeer = addrMe;

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || 
                pfrom->nVersion >= CADDR_TIME_VERSION || 
                addrman.size() < 1000
               )
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } 
        else 
        {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        // Relay sync-checkpoint
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (!Checkpoints::checkpointMessage.IsNull())
                Checkpoints::checkpointMessage.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        // Send hash of transactions in mempool to the connected node
        {
            std::vector<uint256>
                vtxid;

            mempool.queryHashes(vtxid);

            vector<CInv>
                vInv;

            for (unsigned int i = 0; i < vtxid.size(); ++i)
            {
                CInv
                    inv(MSG_TX, vtxid[i]);

                vInv.push_back(inv);
                if (i == (MAX_INV_SZ - 1))
                        break;
            }
            if (vInv.size() > 0)
                pfrom->PushMessage("inv", vInv);
        }

        printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", 
                pfrom->nVersion, 
                pfrom->nStartingHeight, 
                addrMe.ToString().c_str(), 
                addrFrom.ToString().c_str(), 
                pfrom->addr.ToString().c_str()
              );

        LOCK(cs_main);
        cPeerBlockCounts.input(pfrom->nStartingHeight);
    }

    // rx'ed something from pfrom other than version

    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        printf("Misbehaving received version = 0\n");
        Misbehaving(pfrom->GetId(), 1);      // tell me what the 1 means? Or intends?? If anything???
        return false;
    }

    //_________________________________________________________________________
    // rx'ed a ver(sion)ack

    else if (strCommand == "verack")
    {
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }


    //_________________________________________________________________________
    // rx'ed a node addr(esses) response

    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (
            (pfrom->nVersion < CADDR_TIME_VERSION) && 
            (addrman.size() > 1000)
           )
            return true;    // meaning what?
        if (vAddr.size() > 1000)
        {
            Misbehaving(pfrom->GetId(), 20);
            return error("message addr size() = %" PRIszu " too big!?", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> 
            vAddrOk;

        ::int64_t 
            nNow = GetAdjustedTime();
        ::int64_t 
            nSince = nNow - 10 * 60;

        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            if (fShutdown)
                return true;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);

            bool 
                fReachable = IsReachable(addr);

            if (
                (addr.nTime > nSince) && 
                !pfrom->fGetAddr && 
                (vAddr.size() <= 10) && 
                addr.IsRoutable()
               )
            {
                // Relay to a limited number of other nodes
                {{
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 
                        hashSalt;

                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    
                    ::uint64_t 
                        hashAddr = addr.GetHash();

                    uint256 
                        hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));

                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    
                    multimap<uint256, CNode*> 
                        mapMix;

                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;

                        unsigned int 
                            nPointer;

                        memcpy(&nPointer, &pnode, sizeof(nPointer));

                        uint256 
                            hashKey = hashRand ^ nPointer;

                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int 
                        nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)

                    for (
                        multimap<uint256, CNode*>::iterator mi = mapMix.begin(); 
                        (mi != mapMix.end()) && (nRelayNodes-- > 0); 
                        ++mi
                        )
                    {
                        ((*mi).second)->PushAddress(addr);
                    }
                }}
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60); // what is the intent here?
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)                // what is the logic here?
        {
            printf("Node (%s) is oneshot client\n", pfrom->addrName.c_str());
            pfrom->fDisconnect = true;
        }
    }
    //_________________________________________________________________________

    // rx'ed an inv(entory) of Tx's or Blocks

    else if (strCommand == "inv")
    {
        vector<CInv> vInv;

        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            Misbehaving(pfrom->GetId(), 20);
            return error("message inv size() = %" PRIszu " too big!", vInv.size());
        }

        LOCK(cs_main);
        CTxDB txdb("r");

        std::vector<CInv> vToFetch;

        for (unsigned int nInv = 0; nInv < vInv.size(); ++nInv)
        {
            const CInv &inv = vInv[nInv];

            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(txdb, inv);

            if (fDebug)
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(),
                       fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave && inv.type != MSG_BLOCK)
                pfrom->AskFor(inv);

            // TODO: improve the logic to detect stalling initial-headers-sync peer
            if (inv.type == MSG_BLOCK) {
                UpdateBlockAvailability(pfrom->GetId(), inv.hash);
                // When receiving "inv" message, we only send "getheaders" to get new block headers and "getdata" to get new block data if
                // 1) The node isn't in initial-block sync. It means that the best header must be closed to today, within 48 hours.
                //    I choose 48 hours here to avoid any problem happens (connection timeout, ...) at the time the node transits from "initial-block sync" to "nearly synced completely"
                //    If there is any problems which make the node can't sync latest headers/blocks from other peers, the node can continue to sync headers/blocks when it receives "inv" messages from other peers
                // 2) The node is at the beginning of initial-block-sync (pindexBestHeader->nHeight == 0 && nSyncStarted == 0)
                if (!fAlreadyHave && !mapBlocksInFlight.count(inv.hash) && ((pindexBestHeader->GetBlockTime() > GetAdjustedTime() - 48 * 60 * 60) || (pindexBestHeader->nHeight == 0 && nSyncStarted == 0))) {
                    // First request the headers preceeding the announced block. In the normal fully-synced
                    // case where a new block is announced that succeeds the current tip (no reorganization),
                    // there are no such headers.
                    // Secondly, and only when we are close to being synced, we request the announced block directly,
                    // to avoid an extra round-trip. Note that we must *first* ask for the headers, so by the
                    // time the block arrives, the header chain leading up to it is already validated. Not
                    // doing this will result in the received block being rejected as an orphan in case it is
                    // not a direct successor.
                    pfrom->PushMessage("getheaders", chainActive.GetLocator(pindexBestHeader), inv.hash);
                    if (chainActive.Tip()->GetBlockTime() > GetAdjustedTime() - 48 * 60 * 60) {
                        vToFetch.push_back(inv);
                        // Mark block as in flight already, even though the actual "getdata" message only goes out
                        // later (within the same cs_main lock, though).
                        MarkBlockAsInFlight(pfrom->GetId(), inv.hash);
                    }
                    printf("getheaders (%d) %s to peer=%s\n", pindexBestHeader->nHeight, inv.hash.ToString().c_str(), pfrom->addrName.c_str());
                }
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
        if (!vToFetch.empty())
            pfrom->PushMessage("getdata", vToFetch);
    }

    //_________________________________________________________________________
    // rx'ed a getdata request

    else if (strCommand == "getdata") {
      vector<CInv> vInv;
      vRecv >> vInv; // how does this allocate into a vector?
      if (vInv.size() > MAX_INV_SZ) {
        Misbehaving(pfrom->GetId(),
                    20); // OK, what's the magic 20 about? units? intent??
        return error("message getdata size() = %" PRIszu " too big!",
                     vInv.size());
      }

      if (fDebugNet || (vInv.size() != 1)) // what if it is 1?
        printf("rx'd a getdata request (%" PRIszu " invsz) from %s\n",
               vInv.size(), pfrom->addr.ToString().c_str());

      LOCK(cs_main);
      BOOST_FOREACH (const CInv &inv, vInv) {
        if (fShutdown)
          return true;
        if (fDebugNet || (vInv.size() == 1))
          printf("rx'd a getdata request for: %s from %s\n",
                 inv.ToString().c_str(), pfrom->addr.ToString().c_str());
        // there are only 2 types" a block or a transaction being requested as
        // inventory
        if (inv.type ==
            MSG_BLOCK) // I persume this means the node requested a block
        {
          // Send block from disk
          map<uint256, CBlockIndex *>::iterator mi =
              mapBlockIndex.find(inv.hash);

          if (mi != mapBlockIndex.end()) // means we found it
          {
            CBlock block;

            block.ReadFromDisk((*mi).second);
            pfrom->PushMessage("block", block);

            // Trigger them to send a getblocks request for the next batch of
            // inventory what does that mean, exactly?
            if (inv.hash == pfrom->hashContinue) {
              // ppcoin: send latest proof-of-work block to allow the
              // download node to accept as orphan (proof-of-stake
              // block might be rejected by stake connection check)
              vector<CInv> vInv;

              vInv.push_back(CInv(
                  MSG_BLOCK,
                  GetLastBlockIndex(chainActive.Tip(), false)->GetBlockHash()));
              pfrom->PushMessage("inv", vInv);
              pfrom->hashContinue = 0;
            }
          }
          Sleep(nOneMillisecond);     // just to test if RPC can run?
        } else if (inv.IsKnownType()) // it must be a transaction
        {
          // Send stream from relay memory
          bool pushed = false;
          {
            LOCK(cs_mapRelay);
            map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);

            if (mi != mapRelay.end()) // we found it
            {
              pfrom->PushMessage(inv.GetCommand(), (*mi).second);
              pushed = true;
            }
          }
          if (!pushed &&           // not from relay memory
              (inv.type == MSG_TX) // by analogy, I presume a Tx is requested?
              )                    // inventory is not here
          {
            LOCK(mempool.cs);
            if (mempool.exists(inv.hash)) {
              CTransaction tx = mempool.lookup(inv.hash);

              CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

              ss.reserve(1000); // is this related to anything else?
              ss << tx;
              pfrom->PushMessage("tx", ss);
            }
          }
        }

        // Track requests for our stuff
        Inventory(inv.hash);
      }
    }

    //_________________________________________________________________________
    // rx'ed a getblocks request for blocks

    else if (strCommand == "getblocks")
    {
        CBlockLocator 
            locator;
        uint256 
            hashStop;

        vRecv >> locator >> hashStop;

        LOCK(cs_main);
        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = chainActive.FindFork(locator);

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;  // how does this do "the rest"?

        int 
            nLimit = 500;

        printf("getblocks request for %d to %s limit %d from %s\n", 
               (pindex ? pindex->nHeight : -1), 
               hashStop.ToString().substr(0,20).c_str(), 
               nLimit
               , pfrom->addr.ToString().c_str()
              );
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks request stopping at %d %s\n", 
                       pindex->nHeight, 
                       pindex->GetBlockHash().ToString().substr(0,20).c_str()
                      );
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (
                    (hashStop != hashBestChain) && 
                    ((pindex->GetBlockTime() + nStakeMinAge) > chainActive.Tip()->GetBlockTime())
                   )
                    pfrom->PushInventory(CInv(MSG_BLOCK, hashBestChain));
                break;
            }
            pfrom->PushInventory(
                                CInv(
                                    MSG_BLOCK, 
                                    pindex->GetBlockHash()
                                    )
                                );
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s\n", 
                        pindex->nHeight, 
                        pindex->GetBlockHash().ToString().substr(0,20).c_str()
                      );
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }

    //_________________________________________________________________________
    // rx'ed a getheaders request

    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);
        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = chainActive.FindFork(locator);
            if (pindex)
                pindex = chainActive.Next(pindex);
        }

        vector<CBlock> vHeaders;
        int nLimit = MAX_HEADERS_RESULTS;
        printf("getheaders request %d to %s from %s\n", 
                (pindex ? pindex->nHeight : -1), 
                hashStop.ToString().substr(0,20).c_str()
                , pfrom->addr.ToString().c_str()
              );
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }

    //_________________________________________________________________________
    // rx'ed a Tx

    else if (strCommand == "tx")
    {
        vector<uint256> 
            vWorkQueue;

        vector<uint256> 
            vEraseQueue;

        CDataStream vMsg(vRecv);
        CTxDB txdb("r");
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);
        bool 
            fMissingInputs = false;
        CValidationState state;
        if (tx.AcceptToMemoryPool(state, txdb, true, &fMissingInputs))
        {
            SyncWithWallets(tx, NULL, true);
            RelayTransaction(tx, inv.hash);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); ++i)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {   //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< this part is different???????????????????
                    const uint256
                        & orphanTxHash = *mi;

                    CTransaction
                        & orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool 
                        fMissingInputs2 = false;

                    CValidationState tmpState;
                    if (orphanTx.AcceptToMemoryPool(tmpState, txdb, true, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                        SyncWithWallets(tx, NULL, true);
                        RelayTransaction(orphanTx, orphanTxHash);
                        mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanTxHash));
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid orphan
                        vEraseQueue.push_back(orphanTxHash);
                        printf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        int nDoS = 0;
        if (state.IsInvalid(nDoS))
        {
            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);
        }
    }

    //_________________________________________________________________________
    // rx'ed a header

    else if (strCommand == "headers")
    {
        // Receive headers from peer, reset the timeout so we can't trigger disconnect due to the hash calculation takes much time
        CNodeState &state = *State(pfrom->GetId());
        state.nHeadersSyncTimeout = std::numeric_limits<int64_t>::max();

        std::vector<CBlock> headers;
        // Bypass the normal CBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            Misbehaving(pfrom->GetId(), 20);
            return error("headers message size = %u", nCount);
        }
        headers.resize(nCount);
        for (unsigned int n = 0; n < nCount; n++) {
            vRecv >> headers[n];
            //ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
            //ReadCompactSize(vRecv); // ignore vchBlockSig; assume it is 0.
        }

        if (nCount == 0) {
            // Nothing interesting. Stop asking this peers for more headers.
            return true;
        }

        // Calculate header hash
        printf("Start calculating hash for %d block headers\n", nCount);
        if (nHashCalcThreads > 1)
        {
            CCheckQueueControl<CHashCalculation> control(&hashCalculationQueue);
            std::vector<CHashCalculation> vHashCalc;
            vHashCalc.reserve(nCount);

            int index = 0;
            BOOST_FOREACH(CBlock& header, headers) {
                CHashCalculation hashCalc(&header, pfrom);
                vHashCalc.push_back(CHashCalculation());
                hashCalc.swap(vHashCalc.back());
                index++;
            }
            control.Add(vHashCalc);
            control.Wait();

            // Hash calculation takes much time to finish. So checking fShutdown node regularly to quickly shut down node during hash calculation
            if (fShutdown) {
                return true;
            }
        }
        else
        {
            BOOST_FOREACH(CBlock& header, headers) {
                // SHA256 doesn't cost much cpu usage to calculate
                uint256 blockSHA256Hash = header.GetSHA256Hash();

                map<uint256, uint256>::iterator mi = mapHash.find(blockSHA256Hash);
                if (mi != mapHash.end())
                {
                    header.blockHash = (*mi).second;
                    printf("Already have header %s (sha256: %s)\n", header.blockHash.ToString().c_str(), blockSHA256Hash.ToString().c_str());
                }

                if (header.blockHash == 0)
                {
                    uint256 blockHash = header.GetHash();
                    printf("Received header %s (sha256: %s) from node %s\n", blockHash.ToString().c_str(), blockSHA256Hash.ToString().c_str(), pfrom->addrName.c_str());
                    mapHash.insert(make_pair(blockSHA256Hash, blockHash));
                }

                // Hash calculation takes much time to finish. So checking fShutdown node regularly to quickly shut down node during hash calculation
                if (fShutdown) {
                    return true;
                }
            }
        }
        printf("Finish calculating hash for %d block headers\n", nCount);

        LOCK(cs_main);

        CBlockIndex *pindexLast = NULL;
        BOOST_FOREACH(CBlock& header, headers) {
            std::map<uint256, CBlockIndex *>::iterator miBlockIndex = mapBlockIndex.find(header.GetHash());
            if (miBlockIndex != mapBlockIndex.end())
            {
                pindexLast = miBlockIndex->second;
                continue;
            }

            CValidationState state;
            if (pindexLast != NULL && header.hashPrevBlock != pindexLast->GetBlockHash()) {
                Misbehaving(pfrom->GetId(), 20);
                return error("non-continuous headers sequence");
            }
            if (!header.AcceptBlockHeader(state, &pindexLast)) {
                int nDoS;
                if (state.IsInvalid(nDoS)) {
                    if (nDoS > 0)
                        Misbehaving(pfrom->GetId(), nDoS);
                    return error("invalid header received");
                }
            }
        }

        if (pindexLast)
            UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());

        // During initial block sync, if this node has starting height < nMedianStartingHeight, we should stop syncing headers from it.
        if ((pindexBestHeader->GetBlockTime() < GetAdjustedTime() - 24 * 60 * 60) && (pfrom->nStartingHeight < nMedianStartingHeight))
        {
            state.fSyncStarted = false;
            nSyncStarted--;
            state.nHeadersSyncTimeout = 0;
            printf(
                    "Stop syncing headers from peer=%s, it may not have latest blockchain (startheight=%d < nMedianStartingHeight=%d), current best header has height = %d\n",
                    pfrom->addrName.c_str(), pfrom->nStartingHeight,
                    nMedianStartingHeight, pindexBestHeader->nHeight);
        }
        else if (nCount == MAX_HEADERS_RESULTS && pindexLast) {
            // Headers message had its maximum size; the peer may have more headers.
            // TODO: optimize: if pindexLast is an ancestor of chainActive.Tip or pindexBestHeader, continue
            // from there instead.
            // Set the timeout to trigger disconnect logic
            state.nHeadersSyncTimeout = GetTimeMicros() + HEADERS_DOWNLOAD_TIMEOUT_BASE;
            printf("more getheaders (%d) to end to peer=%s (startheight:%d), current best header has height = %d\n", pindexLast->nHeight, pfrom->addrName.c_str(), pfrom->nStartingHeight);
            pfrom->PushMessage("getheaders", chainActive.GetLocator(pindexLast), uint256(0), pindexBestHeader->nHeight);
        }
        else if (nCount < MAX_HEADERS_RESULTS && pindexBestHeader->nHeight < nMedianStartingHeight)
        {
            // This node doesn't have latest blockchain or there is an error with this node which make it not send full 2000 headers
            state.fSyncStarted = false;
            nSyncStarted--;
            state.nHeadersSyncTimeout = 0;
            printf(
                    "Stop syncing headers from peer=%s, this node doesn't have latest blockchain or there is an error with this node which make it only send %d headers"
                    "(startheight=%d, nMedianStartingHeight=%d), current best header has height = %d\n",
                    pfrom->addrName.c_str(), nCount, pfrom->nStartingHeight,
                    nMedianStartingHeight, pindexBestHeader->nHeight);
        }
    }

    //_________________________________________________________________________
    // rx'ed a block

    else if (strCommand == "block")
    {
        CBlock 
            block;

        vRecv >> block;
        // SHA256 doesn't cost much cpu usage to calculate
        uint256 hashBlock;
        uint256 sha256HashBlock = block.GetSHA256Hash();
        map<uint256, uint256>::iterator mi = mapHash.find(sha256HashBlock);
        if (mi != mapHash.end())
        {
            hashBlock = (*mi).second;
            block.blockHash = hashBlock;
        }
        else
        {
            hashBlock = block.GetHash();
            mapHash.insert(make_pair(sha256HashBlock, hashBlock));
        }

        printf(
            "received block %s (sha256: %s) (%s) from %s\n",
              //hashBlock.ToString().substr(0,20).c_str()
                hashBlock.ToString().c_str(),
                sha256HashBlock.ToString().c_str()
                , DateTimeStrFormat( "%Y-%m-%d %H:%M:%S", block.GetBlockTime() ).c_str()
                , pfrom->addr.ToString().c_str()
              );
        // block.print();
        CInv 
            inv(MSG_BLOCK, hashBlock);

        pfrom->AddInventoryKnown(inv);

        MeasureTime processBlock;
        CValidationState state;
        ProcessBlock(state, pfrom, &block);
        processBlock.mEnd.stamp();

        printf("Process block message, total time for ProcessBlock = %lu us\n",
                processBlock.getExecutionTime());
    }

    //_________________________________________________________________________
    // rx'ed a getaddr(esses) request

    else if (strCommand == "getaddr")
    {   //<<<<<<<<<<<<<<<<<<<<<<<<<< this is different
        // Don't return addresses older than nCutOff timestamp
        ::int64_t 
            nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);

        pfrom->vAddrToSend.clear();
        
        vector<CAddress> 
            vAddr = addrman.GetAddr();

        BOOST_FOREACH(const CAddress &addr, vAddr)
            if(addr.nTime > nCutOff)
                pfrom->PushAddress(addr);
    }

    //_________________________________________________________________________
    // rx'ed a mempool request UTXO

    else if (strCommand == "mempool")
    {
        std::vector<uint256> 
            vtxid;

        mempool.queryHashes(vtxid);
        
        vector<CInv> 
            vInv;

        for (unsigned int i = 0; i < vtxid.size(); ++i) 
        {
            CInv 
                inv(MSG_TX, vtxid[i]);

            vInv.push_back(inv);
            if (i == (MAX_INV_SZ - 1))
                    break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }

    //_________________________________________________________________________
    // rx'ed a checkorder?

    else if (strCommand == "checkorder")
    {
        static map<CService, CPubKey> 
            mapReuseKey;

        uint256 hashReply;
        vRecv >> hashReply;

        if (!GetBoolArg("-allowreceivebyip"))
        {
            pfrom->PushMessage("reply", hashReply, (int)2, string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr))
            pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }

    //_________________________________________________________________________
    // rx'ed a reply?

    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        {
            LOCK(pfrom->cs_mapRequests);
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }

    //_________________________________________________________________________
    // rx'ed a ping request

    else if (strCommand == "ping")
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            ::uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }

    //_________________________________________________________________________
    // rx'ed an alert

    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {{
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }}
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                Misbehaving(pfrom->GetId(), 10);
            }
        }
    }

    // rx'ed all other unknown commands

    //_________________________________________________________________________
    else
    {
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (
            strCommand == "version" || 
            strCommand == "addr" || 
            strCommand == "inv" || 
                //    strCommand == "block" ||    //TEST<<<<<<<<<<<<<<
            strCommand == "getdata" || 
            strCommand == "ping"
           )                                    // why these only?
            AddressCurrentlyConnected(pfrom->addr); // what does this accomplish?

    return true;
}

bool ProcessMessages(CNode* pfrom)
{
    CDataStream& 
        vRecv = pfrom->vRecv;

    if (vRecv.empty())
        return true;
    //if (fDebug)
    //    printf("ProcessMessages(%u bytes)\n", vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //

    while (true)
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->vSend.size() >= SendBufferSize())
            break;

        // Scan for message start
        CDataStream::iterator 
            pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));

        int 
            nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());

        if (vRecv.end() - pstart < nHeaderSize)
        {
            if ((int)vRecv.size() > nHeaderSize)
            {
                printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            printf("\n\nPROCESSMESSAGE SKIPPED %" PRIpdd " BYTES\n\n", pstart - vRecv.begin());
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        vector<char> 
            vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);

        CMessageHeader 
            hdr;

        vRecv >> hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int 
            nMessageSize = hdr.nMessageSize;

        if (nMessageSize > MAX_SIZE)
        {
            printf("ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE\n", 
                    strCommand.c_str(), 
                    nMessageSize
                  );
            continue;
        }
        if (nMessageSize > vRecv.size())
        {
            // Rewind and wait for rest of message
            vRecv.insert(
                        vRecv.begin(), 
                        vHeaderSave.begin(), 
                        vHeaderSave.end()
                        );
            break;
        }

        // Checksum
        uint256 
            hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);

        unsigned int 
            nChecksum = 0;

        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Copy message to its own buffer
        CDataStream 
            vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);

        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try
        {
            {
                fRet = ProcessMessage(pfrom, strCommand, vMsg);
            }
            if (fShutdown)
                return true;
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {   // Allow exceptions from under-length message on vRecv
                printf(
                        "ProcessMessages(%s, %u bytes) : "
                        "Exception '%s' caught, normally caused by "
                        "a message being shorter than its stated length"
                        "\n", 
                        strCommand.c_str(), 
                        nMessageSize, 
                        e.what()
                      );
            }
            else 
            {
                if (strstr(e.what(), "size too large"))
                {   // Allow exceptions from over-long size
                    printf(
                            "ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", 
                            strCommand.c_str(), 
                            nMessageSize, 
                            e.what()
                          );
                }
                else
                {
                    PrintExceptionContinue(&e, "ProcessMessages()");
                }
            }
        }
        catch (std::exception& e) 
        {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } 
        catch (...) 
        {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
    }

    vRecv.Compact();
    return true;
}

bool SendMessages(CNode *pto, bool fSendTrickle)
{
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (pto->nLastSend && ((GetTime() - pto->nLastSend) > nPingInterval) &&
            pto->vSend.empty())
        {
            ::uint64_t nonce = 0;

            if (pto->nVersion > BIP0031_VERSION)
                pto->PushMessage("ping", nonce);
            else
                pto->PushMessage("ping");
        }

        // Resend wallet transactions that haven't gotten in a block yet
        ResendWalletTransactions();

        TRY_LOCK(cs_main, lockMain); // Acquire cs_main for IsInitialBlockDownload() and CNodeState()
        if (!lockMain)
            return true;
        // Address refresh broadcast
        static ::int64_t nLastRebroadcast; // remember, statics are initialized to 0
        if (!IsInitialBlockDownload() &&
            ((GetTime() - nLastRebroadcast) > nBroadcastInterval))
        {
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH (CNode *pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }
            nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH (const CAddress &addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000) // why? What does 1000 mean?
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }

        CNodeState &state = *State(pto->GetId());
        if (state.fShouldBan) {
            if (pto->addr.IsLocal())
                printf("Warning: not banning local node %s!\n", pto->addrName.c_str());
            else {
                pto->fDisconnect = true;
                CNode::Ban(pto->addr);
            }
            state.fShouldBan = false;
        }

        // Start block sync
        if (pindexBestHeader == NULL)
            pindexBestHeader = chainActive.Tip();
        // Allow to fetch for both inbound and outbound connection
//        bool fFetch = !pto->fInbound || (pindexBestHeader && (state.pindexLastCommonBlock ? state.pindexLastCommonBlock->nHeight : 0) + 1440 > pindexBestHeader->nHeight);
        bool fFetch = true;
        if (!state.fSyncStarted && !pto->fClient && fFetch) {
            // Only actively request headers from a single peer, unless we're close to today.
            if ((nSyncStarted == 0 || pindexBestHeader->GetBlockTime() > GetAdjustedTime() - 24 * 60 * 60) && pto->nStartingHeight >= nMedianStartingHeight ) {
                state.fSyncStarted = true;
                state.nHeadersSyncTimeout = GetTimeMicros() + HEADERS_DOWNLOAD_TIMEOUT_BASE;
                nSyncStarted++;
                CBlockIndex *pindexStart = pindexBestHeader->pprev ? pindexBestHeader->pprev : pindexBestHeader;
                printf("initial getheaders (%d) to peer=%s (startheight:%d)\n", pindexStart->nHeight, pto->addrName.c_str(), pto->nStartingHeight);
                pto->PushMessage("getheaders", chainActive.GetLocator(pindexStart), uint256(0));
            }
        }

        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH (const CInv &inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;

                    if (hashSalt == 0)
                        hashSalt = GetRandHash();

                    uint256 hashRand = inv.hash ^ hashSalt;

                    hashRand = Hash(BEGIN(hashRand), END(hashRand));

                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;

                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);

        // Detect whether we're stalling
        ::int64_t nNow = GetTimeMicros();
        if (!pto->fDisconnect && state.nStallingSince && state.nStallingSince < nNow - 1000000 * BLOCK_STALLING_TIMEOUT) {
            // Stalling only triggers when the block download window cannot move. During normal steady state,
            // the download window should be much larger than the to-be-downloaded set of blocks, so disconnection
            // should only happen during initial block download.
            printf("Peer=%d is stalling block download, disconnecting\n", pto->id);
            pto->fDisconnect = true;
        }

        // Check for headers sync timeouts
        if (state.fSyncStarted && state.nHeadersSyncTimeout < std::numeric_limits<int64_t>::max()) {
            // Detect whether this is a stalling initial-headers-sync peer
            if (pindexBestHeader->GetBlockTime() <= GetAdjustedTime() - 24*60*60) {
                if (nNow > state.nHeadersSyncTimeout && nSyncStarted == 1) {
                    // Note: If all our peers are inbound, then we won't
                    // disconnect our sync peer for stalling; we have bigger
                    // problems if we can't get any outbound peers.
                    if (pto->fInbound) {
                        printf("Timeout downloading headers from inbound peer=%s, disconnecting\n", pto->addrName.c_str());
                        pto->fDisconnect = true;
                        return true;
                    } else {
                        printf("Timeout downloading headers from outbound peer=%s, not disconnecting\n", pto->addrName.c_str());
                        // Reset the headers sync state so that we have a
                        // chance to try downloading from a different peer.
                        // Note: this will also result in at least one more
                        // getheaders message to be sent to
                        // this peer (eventually).
                        state.fSyncStarted = false;
                        nSyncStarted--;
                        state.nHeadersSyncTimeout = 0;
                    }
                }
            } else {
                // After we've caught up once, reset the timeout so we can't trigger
                // disconnect later.
                state.nHeadersSyncTimeout = std::numeric_limits<int64_t>::max();
            }
        }

        // Check for block sync timeouts
        if (!pto->fDisconnect && state.vBlocksInFlight.size() > 0 && (state.vBlocksInFlight.front().nTime + BLOCK_DOWNLOAD_TIMEOUT_BASE) < nNow && pto->vRecv.empty()) {
            printf("Timeout downloading block %s from peer=%d, disconnecting\n", state.vBlocksInFlight.front().hash.ToString().c_str(), pto->addrName.c_str());
            pto->fDisconnect = true;
        }

        //
        // Message: getdata (blocks)
        //
        vector<CInv> vGetData;
        if (!pto->fDisconnect && !pto->fClient && fFetch && state.nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER
                && (!state.fSyncStarted || (pindexBestHeader->GetBlockTime() > GetAdjustedTime() - 24 * 60 * 60) || vNodes.size() == 1)) { // Not download block from initial-header-sync node, unless best header close to today or there is only 1 connected node
            vector<CBlockIndex*> vToDownload;
            NodeId staller = -1;
            FindNextBlocksToDownload(pto->GetId(), MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.nBlocksInFlight, vToDownload, staller);
            BOOST_FOREACH(CBlockIndex *pindex, vToDownload) {
                vGetData.push_back(CInv(MSG_BLOCK, pindex->GetBlockHash()));
                MarkBlockAsInFlight(pto->GetId(), pindex->GetBlockHash(), pindex);
                printf("Requesting block %s (height = %d) peer=%s\n", pindex->GetBlockHash().ToString().c_str(), pindex->nHeight, pto->addrName.c_str());
            }
            if (state.nBlocksInFlight == 0) {
                // Stalling due to other peer
                if (staller != -1)
                {
                    if (State(staller)->nStallingSince == 0)
                    {
                        State(staller)->nStallingSince = nNow;
                        printf("Stall started peer=%d\n", staller);
                    }
                }
                else
                {
                    int bestHeaderHeight = pindexBestHeader ? pindexBestHeader->nHeight : -1;
                    int bestBlockHeight = chainActive.Height();
                    int nSyncHeight = state.pindexBestKnownHeader ? state.pindexBestKnownHeader->nHeight : -1;
                    /* Trigger sending "getblocks" from other peers when
                     * 1) bestHeaderHeight > bestBlockHeight + HEADER_BLOCK_DIFFERENCES_TRIGGER_GETDATA (default = 400000)
                     * 2) synced_headers < bestHeaderHeight
                     */
                    if ((bestHeaderHeight > bestBlockHeight + HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS) &&
                            (nSyncHeight < bestHeaderHeight) &&
                            state.nLastTimeSendingGetBlocks < nNow - 60 * 1000000) // avoid spamming getblocks, just send every 1 minute
                    {
                        pto->PushMessage("getblocks", chainActive.GetLocator(pindexBestHeader->pprev->pprev), pindexBestHeader->GetBlockHash());
                        state.nLastTimeSendingGetBlocks = GetTimeMicros();
                    }
                }

            }
        }

        //
        // Message: getdata
        //
        CTxDB txdb("r");

        while (!pto->fDisconnect && !pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv &inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
                mapAlreadyAskedFor[inv] = nNow;
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);
    }
    return true;
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() 
    {
        if (fDebug)
        {
#ifdef _MSC_VER
            (void)printf( "~CMainCleanup() destructor...\n" );
#endif
        }
#ifdef _MSC_VER
            unsigned int
                nCount = 0,
    #ifdef _DEBUG
                nUpdatePeriod = 100,
    #else
                nUpdatePeriod = 3000, //10000,   // pure guess for a decent update period ~1 second
    #endif
                nEstimate;

            unsigned __int64
                nSize = (unsigned __int64)mapBlockIndex.size();
#endif
            // block headers
            std::map<uint256, CBlockIndex*>::iterator 
                it1 = mapBlockIndex.begin();

            for (; it1 != mapBlockIndex.end(); ++it1)
            {
                delete (*it1).second;
                if (fDebug)
                {
    #ifdef _MSC_VER
                    ++nCount;
                    nEstimate = (unsigned int)( ( 100 * nCount ) / nSize );
                    if( 0 == (nCount % nUpdatePeriod) )
                    {
                        (void)printf( "~CMainCleanup() progess ~%-u%%" 
                                      "\r",
                                      nEstimate
                                    );
                    }
    #endif
                }
            }
            mapBlockIndex.clear();
            if (fDebug)
            {
    #ifdef _MSC_VER
                (void)printf( "~CMainCleanup() progess ~100%%" 
                              "\r"
                            );
    #endif
            }

            // orphan transactions
            mapOrphanTransactions.clear();
        if (fDebug)
        {
#ifdef _MSC_VER
            (void)printf( "\ndone\n" );
#endif
        }
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
    (void)printf( 
                 "\n"
                 "Release mode\n"
                 "Assertion failed: (%s), file %s, line %d,\n"
                 "function %s()"
                 "\n"
                 "\n"
                 ""
                 , booleanExpression
                 , pFileName                //__FILE__
                 , nL                       //__LINE__
                 , strFunctionName.c_str()  // __FUNCTION__
                );
    StartShutdown();    // maybe there are other ways??
}
//_____________________________________________________________________________
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
