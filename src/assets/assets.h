// Copyright (c) 2017-2021 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef YACOIN_ASSET_PROTOCOL_H
#define YACOIN_ASSET_PROTOCOL_H

#include "amount.h"
//#include "tinyformat.h"
#include "assettypes.h"
#include "LibBoolEE.h"

#include <string>
#include <set>
#include <map>
#include <unordered_map>
#include <list>

#define YAC_Y 121
#define YAC_A 97
#define YAC_C 99
#define YAC_Q 113
#define YAC_T 116
#define YAC_O 111
#define YAC_R 114

#define DEFAULT_UNITS 0
#define DEFAULT_REISSUABLE 1
#define DEFAULT_HAS_IPFS 0
#define DEFAULT_IPFS ""
#define MIN_ASSET_LENGTH 3
#define MAX_ASSET_LENGTH 32
#define OWNER_TAG "!"
#define OWNER_LENGTH 1
#define OWNER_UNITS 0
#define OWNER_ASSET_AMOUNT 1 * COIN
#define UNIQUE_ASSET_AMOUNT 1 * COIN
#define UNIQUE_ASSET_UNITS 0
#define UNIQUE_ASSETS_REISSUABLE 0

#define ASSET_TRANSFER_STRING "transfer_asset"
#define ASSET_NEW_STRING "new_asset"
#define ASSET_REISSUE_STRING "reissue_asset"

class CScript;
class CDataStream;
class CTransaction;
class CTxOut;
class Coin;
class CWallet;
class CReserveKey;
class CWalletTx;
struct CAssetOutputEntry;
class CCoinControl;
struct CBlockAssetUndo;
class COutput;

// 2500 * 82 Bytes == 205 KB (kilobytes) of memory
#define MAX_CACHE_ASSETS_SIZE 2500

// Create map that store that state of current reissued transaction that the mempool as accepted.
// If an asset name is in this map, any other reissue transactions wont be accepted into the mempool
extern std::map<uint256, std::string> mapReissuedTx;
extern std::map<std::string, uint256> mapReissuedAssets;

class CAssets {
public:
    std::map<std::pair<std::string, std::string>, CAmount> mapAssetsAddressAmount; // pair < Asset Name , Address > -> Quantity of tokens in the address

    // Dirty, Gets wiped once flushed to database
    std::map<std::string, CNewAsset> mapReissuedAssetData; // Asset Name -> New Asset Data

    CAssets(const CAssets& assets) {
        this->mapAssetsAddressAmount = assets.mapAssetsAddressAmount;
        this->mapReissuedAssetData = assets.mapReissuedAssetData;
    }

    CAssets& operator=(const CAssets& other) {
        mapAssetsAddressAmount = other.mapAssetsAddressAmount;
        mapReissuedAssetData = other.mapReissuedAssetData;
        return *this;
    }

    CAssets() {
        SetNull();
    }

    void SetNull() {
        mapAssetsAddressAmount.clear();
        mapReissuedAssetData.clear();
    }
};

std::string GetUserErrorString(const ErrorReport& report);

class CAssetsCache : public CAssets
{
private:
    bool AddBackSpentAsset(const std::string& assetName, const std::string& address, const CAmount& nAmount);
    void AddToAssetBalance(const std::string& strName, const std::string& address, const CAmount& nAmount);
    bool UndoTransfer(const CAssetTransfer& transfer, const std::string& address, const COutPoint& outToRemove);
public :
    //! These are memory only containers that show dirty entries that will be databased when flushed
    std::vector<CAssetCacheUndoAssetAmount> vUndoAssetAmount;
    std::vector<CAssetCacheSpendAsset> vSpentAssets;

    //! New Assets Caches
    std::set<CAssetCacheNewAsset> setNewAssetsToRemove;
    std::set<CAssetCacheNewAsset> setNewAssetsToAdd;

    //! New Reissue Caches
    std::set<CAssetCacheReissueAsset> setNewReissueToRemove;
    std::set<CAssetCacheReissueAsset> setNewReissueToAdd;

    //! Ownership Assets Caches
    std::set<CAssetCacheNewOwner> setNewOwnerAssetsToAdd;
    std::set<CAssetCacheNewOwner> setNewOwnerAssetsToRemove;

    //! Transfer Assets Caches
    std::set<CAssetCacheNewTransfer> setNewTransferAssetsToAdd;
    std::set<CAssetCacheNewTransfer> setNewTransferAssetsToRemove;

    CAssetsCache() : CAssets()
    {
        SetNull();
        ClearDirtyCache();
    }

    CAssetsCache(const CAssetsCache& cache) : CAssets(cache)
    {
        //! Copy dirty cache also
        this->vSpentAssets = cache.vSpentAssets;
        this->vUndoAssetAmount = cache.vUndoAssetAmount;

        //! Transfer Caches
        this->setNewTransferAssetsToAdd = cache.setNewTransferAssetsToAdd;
        this->setNewTransferAssetsToRemove = cache.setNewTransferAssetsToRemove;

        //! Issue Caches
        this->setNewAssetsToRemove = cache.setNewAssetsToRemove;
        this->setNewAssetsToAdd = cache.setNewAssetsToAdd;

        //! Reissue Caches
        this->setNewReissueToRemove = cache.setNewReissueToRemove;
        this->setNewReissueToAdd = cache.setNewReissueToAdd;

        //! Owner Caches
        this->setNewOwnerAssetsToAdd = cache.setNewOwnerAssetsToAdd;
        this->setNewOwnerAssetsToRemove = cache.setNewOwnerAssetsToRemove;
    }

    CAssetsCache& operator=(const CAssetsCache& cache)
    {
        this->mapAssetsAddressAmount = cache.mapAssetsAddressAmount;
        this->mapReissuedAssetData = cache.mapReissuedAssetData;

        //! Copy dirty cache also
        this->vSpentAssets = cache.vSpentAssets;
        this->vUndoAssetAmount = cache.vUndoAssetAmount;

        //! Transfer Caches
        this->setNewTransferAssetsToAdd = cache.setNewTransferAssetsToAdd;
        this->setNewTransferAssetsToRemove = cache.setNewTransferAssetsToRemove;

        //! Issue Caches
        this->setNewAssetsToRemove = cache.setNewAssetsToRemove;
        this->setNewAssetsToAdd = cache.setNewAssetsToAdd;

        //! Reissue Caches
        this->setNewReissueToRemove = cache.setNewReissueToRemove;
        this->setNewReissueToAdd = cache.setNewReissueToAdd;

        //! Owner Caches
        this->setNewOwnerAssetsToAdd = cache.setNewOwnerAssetsToAdd;
        this->setNewOwnerAssetsToRemove = cache.setNewOwnerAssetsToRemove;

        return *this;
    }

    //! Cache only undo functions
    bool RemoveNewAsset(const CNewAsset& asset, const std::string address);
    bool RemoveTransfer(const CAssetTransfer& transfer, const std::string& address, const COutPoint& out);
    bool RemoveOwnerAsset(const std::string& assetsName, const std::string address);
    bool RemoveReissueAsset(const CReissueAsset& reissue, const std::string address, const COutPoint& out, const std::vector<std::pair<std::string, CBlockAssetUndo> >& vUndoIPFS);
    bool UndoAssetCoin(const CTxOut& prevTxout, const COutPoint& out);

    //! Cache only add asset functions
    bool AddNewAsset(const CNewAsset& asset, const std::string address, const int& nHeight, const uint256& blockHash);
    bool AddTransferAsset(const CAssetTransfer& transferAsset, const std::string& address, const COutPoint& out, const CTxOut& txOut);
    bool AddOwnerAsset(const std::string& assetsName, const std::string address);
    bool AddReissueAsset(const CReissueAsset& reissue, const std::string address, const COutPoint& out);

    //! Cache only validation functions
    bool TrySpendCoin(const COutPoint& out, const CTxOut& coin);

    //! Help functions
    bool ContainsAsset(const CNewAsset& asset);
    bool ContainsAsset(const std::string& assetName);

    //! Returns true if an asset with this name already exists
    bool CheckIfAssetExists(const std::string& name, bool fForceDuplicateCheck = true);

    //! Returns true if an asset with the name exists, and it was able to get the asset metadata from database
    bool GetAssetMetaDataIfExists(const std::string &name, CNewAsset &asset);
    bool GetAssetMetaDataIfExists(const std::string &name, CNewAsset &asset, int& nHeight, uint256& blockHash);

    //! Calculate the size of the CAssets (in bytes)
    size_t DynamicMemoryUsage() const;

    //! Get the size of the none databased cache
    size_t GetCacheSize() const;
    size_t GetCacheSizeV2() const;

    //! Flush all new cache entries into the passets global cache
    bool Flush();

    //! Write asset cache data to database
    bool DumpCacheToDatabase();

    //! Clear all dirty cache sets, vetors, and maps
    void ClearDirtyCache() {

        vUndoAssetAmount.clear();
        vSpentAssets.clear();

        setNewAssetsToRemove.clear();
        setNewAssetsToAdd.clear();

        setNewReissueToAdd.clear();
        setNewReissueToRemove.clear();

        setNewTransferAssetsToAdd.clear();
        setNewTransferAssetsToRemove.clear();

        setNewOwnerAssetsToAdd.clear();
        setNewOwnerAssetsToRemove.clear();

        mapReissuedAssetData.clear();
        mapAssetsAddressAmount.clear();
    }

    std::string CacheToString() const {

        return strprintf(
                "vNewAssetsToRemove size : %d, vNewAssetsToAdd size : %d, vNewTransfer size : %d, vSpentAssets : %d\n",
                setNewAssetsToRemove.size(), setNewAssetsToAdd.size(),
                setNewTransferAssetsToAdd.size(), vSpentAssets.size());
    }
};

//! Functions to be used to get access to the current lock amount required for specific asset issuance transactions
CAmount GetIssueAssetLockAmount();
CAmount GetReissueAssetLockAmount();
CAmount GetIssueSubAssetLockAmount();
CAmount GetIssueUniqueAssetLockAmount();
CAmount GetLockAmount(const AssetType type);
CAmount GetLockAmount(const int nType);

//! Functions to be used to get access to the lock duration for a given asset type issuance
uint32_t GetLockDuration(const AssetType type);
uint32_t GetLockDuration(const int nType);

void GetTxOutAssetTypes(const std::vector<CTxOut>& vout, int& issues, int& reissues, int& transfers, int& owners);

//! Check is an asset name is valid, and being able to return the asset type if needed
bool IsAssetNameValid(const std::string& name);
bool IsAssetNameValid(const std::string& name, AssetType& assetType);
bool IsAssetNameValid(const std::string& name, AssetType& assetType, std::string& error);

//! Check if an unique tagname is valid
bool IsUniqueTagValid(const std::string& tag);

//! Check if an asset is an owner
bool IsAssetNameAnOwner(const std::string& name);

bool IsAssetNameARoot(const std::string& name);

//! Get the root name of an asset
std::string GetParentName(const std::string& name); // Gets the parent name of a subasset TEST/TESTSUB would return TEST

//! Build a unique asset buy giving the root name, and the tag name (ROOT, TAG) => ROOT#TAG
std::string GetUniqueAssetName(const std::string& parent, const std::string& tag);

//! Given a type, and an asset name, return if that name is valid based on the type
bool IsTypeCheckNameValid(const AssetType type, const std::string& name, std::string& error);

//! These types of asset tx, have specific metadata at certain indexes in the transaction.
//! These functions pull data from the scripts at those indexes
bool AssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress);
bool OwnerFromTransaction(const CTransaction& tx, std::string& ownerName, std::string& strAddress);
bool ReissueAssetFromTransaction(const CTransaction& tx, CReissueAsset& reissue, std::string& strAddress);
bool UniqueAssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress);

//! Get specific asset type metadata from the given scripts
bool TransferAssetFromScript(const CScript& scriptPubKey, CAssetTransfer& assetTransfer, std::string& strAddress);
bool AssetFromScript(const CScript& scriptPubKey, CNewAsset& asset, std::string& strAddress);
bool OwnerAssetFromScript(const CScript& scriptPubKey, std::string& assetName, std::string& strAddress);
bool ReissueAssetFromScript(const CScript& scriptPubKey, CReissueAsset& reissue, std::string& strAddress);

//! Check to make sure the script contains the burn transaction
bool CheckIssueLockTx(const CTxOut& txOut, const AssetType& type, const int numberIssued);
bool CheckIssueLockTx(const CTxOut& txOut, const AssetType& type);

// TODO, maybe remove this function and input that check into the CheckIssueLockTx.
//! Check to make sure the script contains the reissue lock data
bool CheckReissueLockTx(const CTxOut& txOut);

//! issue asset scripts to make sure script meets the standards
bool CheckIssueDataTx(const CTxOut& txOut); // OP_RAVEN_ASSET RVNQ (That is a Q as in Que not an O)
bool CheckOwnerDataTx(const CTxOut& txOut);// OP_RAVEN_ASSET RVNO
bool CheckReissueDataTx(const CTxOut& txOut);// OP_RAVEN_ASSET RVNR
bool CheckTransferOwnerTx(const CTxOut& txOut);// OP_RAVEN_ASSET RVNT

//! Check the Encoded hash and make sure it is either an IPFS hash or a OIP hash
bool CheckEncoded(const std::string& hash, std::string& strError);

//! Checks the amount and units, and makes sure that the amount uses the correct decimals
bool CheckAmountWithUnits(const CAmount& nAmount, const int8_t nUnits);

//! Check script and see if it matches the asset issuance template
bool IsScriptNewAsset(const CScript& scriptPubKey);
bool IsScriptNewAsset(const CScript& scriptPubKey, int& nStartingIndex);

//! Check script and see if it matches the unquie issuance template
bool IsScriptNewUniqueAsset(const CScript& scriptPubKey);
bool IsScriptNewUniqueAsset(const CScript &scriptPubKey, int &nStartingIndex);

//! Check script and see if it matches the owner issuance template
bool IsScriptOwnerAsset(const CScript& scriptPubKey);
bool IsScriptOwnerAsset(const CScript& scriptPubKey, int& nStartingIndex);

//! Check script and see if it matches the reissue template
bool IsScriptReissueAsset(const CScript& scriptPubKey);
bool IsScriptReissueAsset(const CScript& scriptPubKey, int& nStartingIndex);

//! Check script and see if it matches the transfer asset template
bool IsScriptTransferAsset(const CScript& scriptPubKey);
bool IsScriptTransferAsset(const CScript& scriptPubKey, int& nStartingIndex);

bool IsNewOwnerTxValid(const CTransaction& tx, const std::string& assetName, const std::string& address, std::string& errorMsg);

void GetAllAdministrativeAssets(CWallet *pwallet, std::vector<std::string> &names, int nMinConf = 1);
void GetAllMyAssets(CWallet* pwallet, std::vector<std::string>& names, int nMinConf = 1, bool fIncludeAdministrator = false, bool fOnlyAdministrator = false);

bool GetAssetInfoFromCoin(const Coin& coin, std::string& strName, CAmount& nAmount);
bool GetAssetInfoFromScript(const CScript& scriptPubKey, std::string& strName, CAmount& nAmount);

bool GetAssetData(const CScript& script, CAssetOutputEntry& data);

bool GetBestAssetAddressAmount(CAssetsCache& cache, const std::string& assetName, const std::string& address);


//! Decode and Encode IPFS hashes, or OIP hashes
std::string DecodeAssetData(std::string encoded);
std::string EncodeAssetData(std::string decoded);
std::string DecodeIPFS(std::string encoded);
std::string EncodeIPFS(std::string decoded);


bool GetAllMyAssetBalances(std::map<std::string, std::vector<COutput> >& outputs, std::map<std::string, CAmount>& amounts, const int confirmations = 0, const std::string& prefix = "");
bool GetMyAssetBalance(const std::string& name, CAmount& balance, const int& confirmations);

//! Creates new asset issuance transaction
bool CreateAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const CNewAsset& asset, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired);
bool CreateAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const std::vector<CNewAsset> assets, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired);

//! Create a reissue asset transaction
bool CreateReissueAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const CReissueAsset& asset, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired);


//! Create a transfer asset transaction
bool CreateTransferAssetTransaction(CWallet* pwallet, const CCoinControl& coinControl, const std::vector< std::pair<CAssetTransfer, std::string> >vTransfers, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired);

//! Send any type of asset transaction to the network
bool SendAssetTransaction(CWallet* pwallet, CWalletTx& transaction, CReserveKey& reserveKey, std::pair<int, std::string>& error, std::string& txid);

/** Verifies that this wallet owns the give asset */
bool VerifyWalletHasAsset(const std::string& asset_name, std::pair<int, std::string>& pairError);

/** Helper method for extracting address bytes, asset name and amount from an asset script */
bool ParseAssetScript(CScript scriptPubKey, uint160 &hashBytes, std::string &assetName, CAmount &assetAmount);

//// Non Contextual Check functions
bool CheckNewAsset(const CNewAsset& asset, std::string& strError);
bool CheckReissueAsset(const CReissueAsset& asset, std::string& strError);

//// Contextual Check functions
bool ContextualCheckNewAsset(CAssetsCache* assetCache, const CNewAsset& asset, std::string& strError, bool fCheckMempool = false);
bool ContextualCheckTransferAsset(CAssetsCache* assetCache, const CAssetTransfer& transfer, const std::string& address, std::string& strError);
bool ContextualCheckReissueAsset(CAssetsCache* assetCache, const CReissueAsset& reissue_asset, std::string& strError, const CTransaction& tx);
bool ContextualCheckReissueAsset(CAssetsCache* assetCache, const CReissueAsset& reissue_asset, std::string& strError);
bool ContextualCheckUniqueAssetTx(CAssetsCache* assetCache, std::string& strError, const CTransaction& tx);
bool ContextualCheckUniqueAsset(CAssetsCache* assetCache, const CNewAsset& unique_asset, std::string& strError);

#endif //YACOIN_ASSET_PROTOCOL_H
