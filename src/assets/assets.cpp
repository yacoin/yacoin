// Copyright (c) 2017-2021 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <regex>
#include <script/script.h>
#include <version.h>

//#include <streams.h>
#include <serialize.h>

#include <primitives/transaction.h>
#include <iostream>

//#include <script/standard.h>
#include <script/script.h>

#include "util.h"
#include "base58.h"

//#include <chainparams.h>
//#include <validation.h>
//#include <txmempool.h>
//#include <tinyformat.h>
//#include <consensus/validation.h>
#include "main.h"
#include "memusage.h"

//#include <wallet/wallet.h>
//#include "wallet/coincontrol.h"
//#include "wallet/wallet.h"
#include <wallet.h>

#include <boost/algorithm/string.hpp>
#include <boost/variant.hpp>

//#include <rpc/protocol.h>
#include <bitcoinrpc.h>

#include <net.h>
#include "assets.h"
#include "assetdb.h"
#include "assettypes.h"
#include "coins.h"
#include "coincontrol.h"
#include "protocol.h"
//#include "utilmoneystr.h" -> replaced with util.h
//#include "coins.h" -> not have coinsview
#include "LibBoolEE.h"

#define SIX_MONTHS 15780000 // Six months worth of seconds

#define OFFSET_THREE 3
#define OFFSET_FOUR 4
#define OFFSET_TWENTY_THREE 23


std::map<uint256, std::string> mapReissuedTx;
std::map<std::string, uint256> mapReissuedAssets;

// Fee lock amount and Fee lock time
static const uint32_t feeLockTime = 21000; // 21000 blocks
static const CAmount feeLockAmount = 21000 * COIN; // 21000 YAC

// excluding owner tag ('!')
static const auto MAX_NAME_LENGTH = 31;
static const auto MAX_CHANNEL_NAME_LENGTH = 12;

// min lengths are expressed by quantifiers
static const std::regex ROOT_NAME_CHARACTERS("^[A-Z0-9._]{3,}$");
static const std::regex SUB_NAME_CHARACTERS("^[A-Z0-9._]+$");
static const std::regex UNIQUE_TAG_CHARACTERS("^[-A-Za-z0-9@$%&*()[\\]{}_.?:]+$");
static const std::regex VOTE_TAG_CHARACTERS("^[A-Z0-9._]+$");

static const std::regex DOUBLE_PUNCTUATION("^.*[._]{2,}.*$");
static const std::regex LEADING_PUNCTUATION("^[._].*$");
static const std::regex TRAILING_PUNCTUATION("^.*[._]$");

static const std::string SUB_NAME_DELIMITER = "/";
static const std::string UNIQUE_TAG_DELIMITER = "#";
static const std::string VOTE_TAG_DELIMITER = "^";

static const std::regex UNIQUE_INDICATOR(R"(^[^^~#!]+#[^~#!\/]+$)");
static const std::regex OWNER_INDICATOR(R"(^[^^~#!]+!$)");
static const std::regex VOTE_INDICATOR(R"(^[^^~#!]+\^[^~#!\/]+$)");

static const std::regex RAVEN_NAMES("^YAC$|^YACOIN$|^#YAC$|^#YACOIN$");

bool IsRootNameValid(const std::string& name)
{
    return std::regex_match(name, ROOT_NAME_CHARACTERS)
        && !std::regex_match(name, DOUBLE_PUNCTUATION)
        && !std::regex_match(name, LEADING_PUNCTUATION)
        && !std::regex_match(name, TRAILING_PUNCTUATION)
        && !std::regex_match(name, RAVEN_NAMES);
}

bool IsSubNameValid(const std::string& name)
{
    return std::regex_match(name, SUB_NAME_CHARACTERS)
        && !std::regex_match(name, DOUBLE_PUNCTUATION)
        && !std::regex_match(name, LEADING_PUNCTUATION)
        && !std::regex_match(name, TRAILING_PUNCTUATION);
}

bool IsUniqueTagValid(const std::string& tag)
{
    return std::regex_match(tag, UNIQUE_TAG_CHARACTERS);
}

bool IsVoteTagValid(const std::string& tag)
{
    return std::regex_match(tag, VOTE_TAG_CHARACTERS);
}

bool IsNameValidBeforeTag(const std::string& name)
{
    std::vector<std::string> parts;
    boost::split(parts, name, boost::is_any_of(SUB_NAME_DELIMITER));

    if (!IsRootNameValid(parts.front())) return false;

    if (parts.size() > 1)
    {
        for (unsigned long i = 1; i < parts.size(); i++)
        {
            if (!IsSubNameValid(parts[i])) return false;
        }
    }

    return true;
}

bool IsAssetNameASubasset(const std::string& name)
{
    std::vector<std::string> parts;
    boost::split(parts, name, boost::is_any_of(SUB_NAME_DELIMITER));

    if (!IsRootNameValid(parts.front())) return false;

    return parts.size() > 1;
}

bool IsAssetNameValid(const std::string& name, AssetType& assetType, std::string& error)
{
    // Do a max length check first to stop the possibility of a stack exhaustion.
    // We check for a value that is larger than the max asset name
    if (name.length() > 40)
        return false;

    assetType = AssetType::INVALID;
    if (std::regex_match(name, UNIQUE_INDICATOR))
    {
        bool ret = IsTypeCheckNameValid(AssetType::UNIQUE, name, error);
        if (ret)
            assetType = AssetType::UNIQUE;

        return ret;
    }
    else if (std::regex_match(name, OWNER_INDICATOR))
    {
        bool ret = IsTypeCheckNameValid(AssetType::OWNER, name, error);
        if (ret)
            assetType = AssetType::OWNER;

        return ret;
    }
    else if (std::regex_match(name, VOTE_INDICATOR))
    {
        bool ret = IsTypeCheckNameValid(AssetType::VOTE, name, error);
        if (ret)
            assetType = AssetType::VOTE;

        return ret;
    }
    else
    {
        auto type = IsAssetNameASubasset(name) ? AssetType::SUB : AssetType::ROOT;
        bool ret = IsTypeCheckNameValid(type, name, error);
        if (ret)
            assetType = type;

        return ret;
    }
}

bool IsAssetNameValid(const std::string& name)
{
    AssetType _assetType;
    std::string _error;
    return IsAssetNameValid(name, _assetType, _error);
}

bool IsAssetNameValid(const std::string& name, AssetType& assetType)
{
    std::string _error;
    return IsAssetNameValid(name, assetType, _error);
}

bool IsAssetNameARoot(const std::string& name)
{
    AssetType type;
    return IsAssetNameValid(name, type) && type == AssetType::ROOT;
}

bool IsAssetNameAnOwner(const std::string& name)
{
    return IsAssetNameValid(name) && std::regex_match(name, OWNER_INDICATOR);
}

// TODO get the string translated below
bool IsTypeCheckNameValid(const AssetType type, const std::string& name, std::string& error)
{
    if (type == AssetType::UNIQUE) {
        if (name.size() > MAX_NAME_LENGTH) { error = "Name is greater than max length of " + std::to_string(MAX_NAME_LENGTH); return false; }
        std::vector<std::string> parts;
        boost::split(parts, name, boost::is_any_of(UNIQUE_TAG_DELIMITER));
        bool valid = IsNameValidBeforeTag(parts.front()) && IsUniqueTagValid(parts.back());
        if (!valid) { error = "Unique name contains invalid characters (Valid characters are: A-Z a-z 0-9 @ $ % & * ( ) [ ] { } _ . ? : -)";  return false; }
        return true;
    } else if (type == AssetType::OWNER) {
        if (name.size() > MAX_NAME_LENGTH) { error = "Name is greater than max length of " + std::to_string(MAX_NAME_LENGTH); return false; }
        bool valid = IsNameValidBeforeTag(name.substr(0, name.size() - 1));
        if (!valid) { error = "Owner name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can't be the first or last characters)";  return false; }
        return true;
    } else if (type == AssetType::VOTE) {
        if (name.size() > MAX_NAME_LENGTH) { error = "Name is greater than max length of " + std::to_string(MAX_NAME_LENGTH); return false; }
        std::vector<std::string> parts;
        boost::split(parts, name, boost::is_any_of(VOTE_TAG_DELIMITER));
        bool valid = IsNameValidBeforeTag(parts.front()) && IsVoteTagValid(parts.back());
        if (!valid) { error = "Vote name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can't be the first or last characters)";  return false; }
        return true;
    } else {
        if (name.size() > MAX_NAME_LENGTH - 1) { error = "Name is greater than max length of " + std::to_string(MAX_NAME_LENGTH - 1); return false; }  //Assets and sub-assets need to leave one extra char for OWNER indicator
        if (!IsAssetNameASubasset(name) && name.size() < MIN_ASSET_LENGTH) { error = "Name must be contain " + std::to_string(MIN_ASSET_LENGTH) + " characters"; return false; }
        bool valid = IsNameValidBeforeTag(name);
        if (!valid && IsAssetNameASubasset(name) && name.size() < 3) { error = "Name must have at least 3 characters (Valid characters are: A-Z 0-9 _ .)";  return false; }
        if (!valid) { error = "Name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can't be the first or last characters)";  return false; }
        return true;
    }
}

std::string GetParentName(const std::string& name)
{
    AssetType type;
    if (!IsAssetNameValid(name, type))
        return "";

    auto index = std::string::npos;
    if (type == AssetType::SUB) {
        index = name.find_last_of(SUB_NAME_DELIMITER);
    } else if (type == AssetType::UNIQUE) {
        index = name.find_last_of(UNIQUE_TAG_DELIMITER);
    } else if (type == AssetType::VOTE) {
        index = name.find_last_of(VOTE_TAG_DELIMITER);
    } else if (type == AssetType::ROOT) {
        return name;
    }

    if (std::string::npos != index)
    {
        return name.substr(0, index);
    }

    return name;
}

std::string GetUniqueAssetName(const std::string& parent, const std::string& tag)
{
    std::string unique = parent + "#" + tag;

    AssetType type;
    if (!IsAssetNameValid(unique, type)) {
        return "";
    }

    if (type != AssetType::UNIQUE)
        return "";

    return unique;
}

bool CNewAsset::IsNull() const
{
    return strName == "";
}

CNewAsset::CNewAsset(const CNewAsset& asset)
{
    this->strName = asset.strName;
    this->nAmount = asset.nAmount;
    this->units = asset.units;
    this->nHasIPFS = asset.nHasIPFS;
    this->nReissuable = asset.nReissuable;
    this->strIPFSHash = asset.strIPFSHash;
}

CNewAsset& CNewAsset::operator=(const CNewAsset& asset)
{
    this->strName = asset.strName;
    this->nAmount = asset.nAmount;
    this->units = asset.units;
    this->nHasIPFS = asset.nHasIPFS;
    this->nReissuable = asset.nReissuable;
    this->strIPFSHash = asset.strIPFSHash;
    return *this;
}

std::string CNewAsset::ToString()
{
    std::stringstream ss;
    ss << "Printing an asset" << "\n";
    ss << "name : " << strName << "\n";
    ss << "amount : " << nAmount << "\n";
    ss << "units : " << std::to_string(units) << "\n";
    ss << "reissuable : " << std::to_string(nReissuable) << "\n";
    ss << "has_ipfs : " << std::to_string(nHasIPFS) << "\n";

    if (nHasIPFS)
        ss << "ipfs_hash : " << strIPFSHash;

    return ss.str();
}

CNewAsset::CNewAsset(const std::string& strName, const CAmount& nAmount, const int& units, const int& nReissuable, const int& nHasIPFS, const std::string& strIPFSHash)
{
    this->SetNull();
    this->strName = strName;
    this->nAmount = nAmount;
    this->units = int8_t(units);
    this->nReissuable = int8_t(nReissuable);
    this->nHasIPFS = int8_t(nHasIPFS);
    this->strIPFSHash = strIPFSHash;
}
CNewAsset::CNewAsset(const std::string& strName, const CAmount& nAmount)
{
    this->SetNull();
    this->strName = strName;
    this->nAmount = nAmount;
    this->units = int8_t(DEFAULT_UNITS);
    this->nReissuable = int8_t(DEFAULT_REISSUABLE);
    this->nHasIPFS = int8_t(DEFAULT_HAS_IPFS);
    this->strIPFSHash = DEFAULT_IPFS;
}

CDatabasedAssetData::CDatabasedAssetData(const CNewAsset& asset, const int& nHeight, const uint256& blockHash)
{
    this->SetNull();
    this->asset = asset;
    this->nHeight = nHeight;
    this->blockHash = blockHash;
}

CDatabasedAssetData::CDatabasedAssetData()
{
    this->SetNull();
}

/**
 * Constructs a CScript that carries the asset name and quantity and adds to to the end of the given script
 * @param dest - The destination that the asset will belong to
 * @param script - This script needs to be a pay to address script
 */
void CNewAsset::ConstructTransaction(CScript& script) const
{
    CDataStream ssAsset(SER_NETWORK, PROTOCOL_VERSION);
    ssAsset << *this;

    std::vector<unsigned char> vchMessage;
    vchMessage.push_back(YAC_Y); // y
    vchMessage.push_back(YAC_A); // a
    vchMessage.push_back(YAC_C); // c
    vchMessage.push_back(YAC_Q); // q

    vchMessage.insert(vchMessage.end(), ssAsset.begin(), ssAsset.end());
    script << OP_YAC_ASSET << ToByteVector(vchMessage) << OP_DROP;
}

void CNewAsset::ConstructOwnerTransaction(CScript& script) const
{
    CDataStream ssOwner(SER_NETWORK, PROTOCOL_VERSION);
    ssOwner << std::string(this->strName + OWNER_TAG);

    std::vector<unsigned char> vchMessage;
    vchMessage.push_back(YAC_Y); // y
    vchMessage.push_back(YAC_A); // a
    vchMessage.push_back(YAC_C); // c
    vchMessage.push_back(YAC_O); // o

    vchMessage.insert(vchMessage.end(), ssOwner.begin(), ssOwner.end());
    script << OP_YAC_ASSET << ToByteVector(vchMessage) << OP_DROP;
}

bool AssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress)
{
    // Check to see if the transaction is an new asset issue tx
    if (!tx.IsNewAsset())
        return false;

    // Get the scriptPubKey from the last tx in vout
    CScript scriptPubKey = tx.vout[tx.vout.size() - 1].scriptPubKey;

    return AssetFromScript(scriptPubKey, asset, strAddress);
}

bool ReissueAssetFromTransaction(const CTransaction& tx, CReissueAsset& reissue, std::string& strAddress)
{
    // Check to see if the transaction is a reissue tx
    if (!tx.IsReissueAsset())
        return false;

    // Get the scriptPubKey from the last tx in vout
    CScript scriptPubKey = tx.vout[tx.vout.size() - 1].scriptPubKey;

    return ReissueAssetFromScript(scriptPubKey, reissue, strAddress);
}

bool UniqueAssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress)
{
    // Check to see if the transaction is an new asset issue tx
    if (!tx.IsNewUniqueAsset())
        return false;

    // Get the scriptPubKey from the last tx in vout
    CScript scriptPubKey = tx.vout[tx.vout.size() - 1].scriptPubKey;

    return AssetFromScript(scriptPubKey, asset, strAddress);
}

bool IsNewOwnerTxValid(const CTransaction& tx, const std::string& assetName, const std::string& address, std::string& errorMsg)
{
    // TODO when ready to ship. Put the owner validation code in own method if needed
    std::string ownerName;
    std::string ownerAddress;
    if (!OwnerFromTransaction(tx, ownerName, ownerAddress)) {
        errorMsg = "bad-txns-bad-owner";
        return false;
    }

    int size = ownerName.size();

    if (ownerAddress != address) {
        errorMsg = "bad-txns-owner-address-mismatch";
        return false;
    }

    if (size < OWNER_LENGTH + MIN_ASSET_LENGTH) {
        errorMsg = "bad-txns-owner-asset-length";
        return false;
    }

    if (ownerName != std::string(assetName + OWNER_TAG)) {
        errorMsg = "bad-txns-owner-name-mismatch";
        return false;
    }

    return true;
}

bool OwnerFromTransaction(const CTransaction& tx, std::string& ownerName, std::string& strAddress)
{
    // Check to see if the transaction is an new asset issue tx
    if (!tx.IsNewAsset())
        return false;

    // Get the scriptPubKey from the last tx in vout
    CScript scriptPubKey = tx.vout[tx.vout.size() - 2].scriptPubKey;

    return OwnerAssetFromScript(scriptPubKey, ownerName, strAddress);
}

bool TransferAssetFromScript(const CScript& scriptPubKey, CAssetTransfer& assetTransfer, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptTransferAsset(scriptPubKey, nStartingIndex)) {
        return false;
    }

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);

    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchTransferAsset;

    vchTransferAsset.insert(vchTransferAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());

    CDataStream ssAsset(vchTransferAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssAsset >> assetTransfer;
    } catch(std::exception& e) {
        error("Failed to get the transfer asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool AssetFromScript(const CScript& scriptPubKey, CNewAsset& assetNew, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptNewAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);

    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchNewAsset;
    vchNewAsset.insert(vchNewAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssAsset(vchNewAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssAsset >> assetNew;
    } catch(std::exception& e) {
        error("Failed to get the asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool OwnerAssetFromScript(const CScript& scriptPubKey, std::string& assetName, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptOwnerAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);

    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchOwnerAsset;
    vchOwnerAsset.insert(vchOwnerAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssOwner(vchOwnerAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssOwner >> assetName;
    } catch(std::exception& e) {
        error("Failed to get the owner asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool ReissueAssetFromScript(const CScript& scriptPubKey, CReissueAsset& reissue, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptReissueAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);

    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchReissueAsset;
    vchReissueAsset.insert(vchReissueAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssReissue(vchReissueAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssReissue >> reissue;
    } catch(std::exception& e) {
        error("Failed to get the reissue asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

//! Call VerifyNewAsset if this function returns true
bool CTransaction::IsNewAsset() const
{
    // New Asset transaction will always have at least three outputs.
    // 1. Owner Token output
    // 2. Issue Asset output
    // 3. YAC Burn Fee
    if (vout.size() < 3) {
        return false;
    }

    // Check for the assets data CTxOut. This will always be the last output in the transaction
    if (!CheckIssueDataTx(vout[vout.size() - 1]))
        return false;

    // Check to make sure the owner asset is created
    if (!CheckOwnerDataTx(vout[vout.size() - 2]))
        return false;

    // Don't overlap with IsNewUniqueAsset()
    CScript script = vout[vout.size() - 1].scriptPubKey;
    if (IsScriptNewUniqueAsset(script))
        return false;

    return true;
}

//! Make sure to call VerifyNewUniqueAsset if this call returns true
bool CTransaction::IsNewUniqueAsset() const
{
    // Check trailing outpoint for issue data with unique asset name
    if (!CheckIssueDataTx(vout[vout.size() - 1]))
        return false;

    if (!IsScriptNewUniqueAsset(vout[vout.size() - 1].scriptPubKey))
        return false;

    return true;
}

//! Call this function after IsNewUniqueAsset
bool CTransaction::VerifyNewUniqueAsset(std::string& strError) const
{
    // Must contain at least 3 outpoints (YAC burn, owner change and one or more new unique assets that share a root (should be in trailing position))
    if (vout.size() < 3) {
        strError  = "bad-txns-unique-vout-size-to-small";
        return false;
    }

    // check for (and count) new unique asset outpoints.  make sure they share a root.
    std::set<std::string> setUniqueAssets;
    std::string assetRoot = "";
    int assetOutpointCount = 0;

    for (auto out : vout) {
        if (IsScriptNewUniqueAsset(out.scriptPubKey)) {
            CNewAsset asset;
            std::string address;
            if (!AssetFromScript(out.scriptPubKey, asset, address)) {
                strError = "bad-txns-issue-unique-asset-from-script";
                return false;
            }
            std::string root = GetParentName(asset.strName);
            if (assetRoot.compare("") == 0)
                assetRoot = root;
            if (assetRoot.compare(root) != 0) {
                strError = "bad-txns-issue-unique-asset-compare-failed";
                return false;
            }

            // Check for duplicate unique assets in the same transaction
            if (setUniqueAssets.count(asset.strName)) {
                strError = "bad-txns-issue-unique-duplicate-name-in-same-tx";
                return false;
            }

            setUniqueAssets.insert(asset.strName);
            assetOutpointCount += 1;
        }
    }

    if (assetOutpointCount == 0) {
        strError = "bad-txns-issue-unique-asset-bad-outpoint-count";
        return false;
    }

    // check for burn outpoint (must account for each new asset)
    bool fBurnOutpointFound = false;
    for (auto out : vout) {
        if (CheckIssueBurnTx(out, AssetType::UNIQUE, assetOutpointCount)) {
            fBurnOutpointFound = true;
            break;
        }
    }

    if (!fBurnOutpointFound) {
        strError = "bad-txns-issue-unique-asset-burn-outpoints-not-found";
        return false;
    }

    // check for owner change outpoint that matches root
    bool fOwnerOutFound = false;
    for (auto out : vout) {
        CAssetTransfer transfer;
        std::string transferAddress;
        if (TransferAssetFromScript(out.scriptPubKey, transfer, transferAddress)) {
            if (assetRoot + OWNER_TAG == transfer.strName) {
                fOwnerOutFound = true;
                break;
            }
        }
    }

    if (!fOwnerOutFound) {
        strError = "bad-txns-issue-unique-asset-missing-owner-asset";
        return false;
    }

    // Loop through all of the vouts and make sure only the expected asset creations are taking place
    int nTransfers = 0;
    int nOwners = 0;
    int nIssues = 0;
    int nReissues = 0;
    GetTxOutAssetTypes(vout, nIssues, nReissues, nTransfers, nOwners);

    if (nOwners > 0 || nReissues > 0 || nIssues != assetOutpointCount) {
        strError = "bad-txns-failed-unique-asset-formatting-check";
        return false;
    }

    return true;
}

//! To be called on CTransactions where IsNewAsset returns true
bool CTransaction::VerifyNewAsset(std::string& strError) const {
    // Issuing an Asset must contain at least 3 CTxOut( Raven Burn Tx, Any Number of other Outputs ..., Owner Asset Tx, New Asset Tx)
    if (vout.size() < 3) {
        strError = "bad-txns-issue-vout-size-to-small";
        return false;
    }

    // Check for the assets data CTxOut. This will always be the last output in the transaction
    if (!CheckIssueDataTx(vout[vout.size() - 1])) {
        strError = "bad-txns-issue-data-not-found";
        return false;
    }

    // Check to make sure the owner asset is created
    if (!CheckOwnerDataTx(vout[vout.size() - 2])) {
        strError = "bad-txns-issue-owner-data-not-found";
        return false;
    }

    // Get the asset type
    CNewAsset asset;
    std::string address;
    if (!AssetFromScript(vout[vout.size() - 1].scriptPubKey, asset, address)) {
        strError = "bad-txns-issue-serialzation-failed";
        return error("%s : Failed to get new asset from transaction: %s", __func__, this->GetHash().GetHex());
    }

    AssetType assetType;
    IsAssetNameValid(asset.strName, assetType);

    std::string strOwnerName;
    if (!OwnerAssetFromScript(vout[vout.size() - 2].scriptPubKey, strOwnerName, address)) {
        strError = "bad-txns-issue-owner-serialzation-failed";
        return false;
    }

    if (strOwnerName != asset.strName + OWNER_TAG) {
        strError = "bad-txns-issue-owner-name-doesn't-match";
        return false;
    }

    // Check for the Burn CTxOut in one of the vouts ( This is needed because the change CTxOut is places in a random position in the CWalletTx
    bool fFoundIssueBurnTx = false;
    for (auto out : vout) {
        if (CheckIssueBurnTx(out, assetType)) {
            fFoundIssueBurnTx = true;
            break;
        }
    }

    if (!fFoundIssueBurnTx) {
        strError = "bad-txns-issue-burn-not-found";
        return false;
    }

    if (assetType == AssetType::SUB) {
        std::string root = GetParentName(asset.strName);
        bool fOwnerOutFound = false;
        for (auto out : this->vout) {
            CAssetTransfer transfer;
            std::string transferAddress;
            if (TransferAssetFromScript(out.scriptPubKey, transfer, transferAddress)) {
                if (root + OWNER_TAG == transfer.strName) {
                    fOwnerOutFound = true;
                    break;
                }
            }
        }

        if (!fOwnerOutFound) {
            strError = "bad-txns-issue-new-asset-missing-owner-asset";
            return false;
        }
    }

    // Loop through all of the vouts and make sure only the expected asset creations are taking place
    int nTransfers = 0;
    int nOwners = 0;
    int nIssues = 0;
    int nReissues = 0;
    GetTxOutAssetTypes(vout, nIssues, nReissues, nTransfers, nOwners);

    if (nOwners != 1 || nIssues != 1 || nReissues > 0) {
        strError = "bad-txns-failed-issue-asset-formatting-check";
        return false;
    }

    return true;
}

bool CTransaction::IsReissueAsset() const
{
    // Check for the reissue asset data CTxOut. This will always be the last output in the transaction
    if (!CheckReissueDataTx(vout[vout.size() - 1]))
        return false;

    return true;
}

//! To be called on CTransactions where IsReissueAsset returns true
bool CTransaction::VerifyReissueAsset(std::string& strError) const
{
    // Reissuing an Asset must contain at least 3 CTxOut ( Raven Burn Tx, Any Number of other Outputs ..., Reissue Asset Tx, Owner Asset Change Tx)
    if (vout.size() < 3) {
        strError  = "bad-txns-vout-size-to-small";
        return false;
    }

    // Check for the reissue asset data CTxOut. This will always be the last output in the transaction
    if (!CheckReissueDataTx(vout[vout.size() - 1])) {
        strError  = "bad-txns-reissue-data-not-found";
        return false;
    }

    CReissueAsset reissue;
    std::string address;
    if (!ReissueAssetFromScript(vout[vout.size() - 1].scriptPubKey, reissue, address)) {
        strError  = "bad-txns-reissue-serialization-failed";
        return false;
    }

    // Reissuing a regular asset checks the reissue_asset_name + "!"
    AssetType asset_type = AssetType::INVALID;
    IsAssetNameValid(reissue.strName, asset_type);

    // This is going to be the asset name that we need to verify that the owner token of was added to the transaction
    std::string asset_name_to_check = reissue.strName;

    // Check that there is an asset transfer, this will be the owner asset change
    bool fOwnerOutFound = false;
    for (auto out : vout) {
        CAssetTransfer transfer;
        std::string transferAddress;
        if (TransferAssetFromScript(out.scriptPubKey, transfer, transferAddress)) {
            if (asset_name_to_check + OWNER_TAG == transfer.strName) {
                fOwnerOutFound = true;
                break;
            }
        }
    }

    if (!fOwnerOutFound) {
        strError  = "bad-txns-reissue-owner-outpoint-not-found";
        return false;
    }

    // Check for the Burn CTxOut in one of the vouts ( This is needed because the change CTxOut is placed in a random position in the CWalletTx
    bool fFoundReissueBurnTx = false;
    for (auto out : vout) {
        if (CheckReissueBurnTx(out)) {
            fFoundReissueBurnTx = true;
            break;
        }
    }

    if (!fFoundReissueBurnTx) {
        strError = "bad-txns-reissue-burn-outpoint-not-found";
        return false;
    }

    // Loop through all of the vouts and make sure only the expected asset creations are taking place
    int nTransfers = 0;
    int nOwners = 0;
    int nIssues = 0;
    int nReissues = 0;
    GetTxOutAssetTypes(vout, nIssues, nReissues, nTransfers, nOwners);

    if (nOwners > 0 || nReissues != 1 || nIssues > 0) {
        strError = "bad-txns-failed-reissue-asset-formatting-check";
        return false;
    }

    return true;
}

CAssetTransfer::CAssetTransfer(const std::string& strAssetName, const CAmount& nAmount)
{
    SetNull();
    this->strName = strAssetName;
    this->nAmount = nAmount;
}

bool CAssetTransfer::IsValid(std::string& strError) const
{
    // Don't use this function with any sort of consensus checks
    // All of these checks are run with ContextualCheckTransferAsset also

    strError = "";

    if (!IsAssetNameValid(std::string(strName))) {
        strError = "Invalid parameter: asset_name must only consist of valid characters and have a size between 3 and 30 characters. See help for more details.";
        return false;
    }

    // this function is only being called in createrawtranasction, so it is fine to have a contextual check here
    // if this gets called anywhere else, we will need to move this to a Contextual function
    if (nAmount <= 0) {
        strError = "Invalid parameter: asset amount can't be equal to or less than zero.";
        return false;
    }

    return true;
}

void CAssetTransfer::ConstructTransaction(CScript& script) const
{
    CDataStream ssTransfer(SER_NETWORK, PROTOCOL_VERSION);
    ssTransfer << *this;

    std::vector<unsigned char> vchMessage;
    vchMessage.push_back(YAC_Y); // y
    vchMessage.push_back(YAC_A); // a
    vchMessage.push_back(YAC_C); // c
    vchMessage.push_back(YAC_T); // t

    vchMessage.insert(vchMessage.end(), ssTransfer.begin(), ssTransfer.end());
    script << OP_YAC_ASSET << ToByteVector(vchMessage) << OP_DROP;
}

CReissueAsset::CReissueAsset(const std::string &strAssetName, const CAmount &nAmount, const int &nUnits, const int &nReissuable,
                             const std::string &strIPFSHash)
{
    SetNull();
    this->strName = strAssetName;
    this->strIPFSHash = strIPFSHash;
    this->nReissuable = int8_t(nReissuable);
    this->nAmount = nAmount;
    this->nUnits = nUnits;
}

void CReissueAsset::ConstructTransaction(CScript& script) const
{
    CDataStream ssReissue(SER_NETWORK, PROTOCOL_VERSION);
    ssReissue << *this;

    std::vector<unsigned char> vchMessage;
    vchMessage.push_back(YAC_Y); // y
    vchMessage.push_back(YAC_A); // a
    vchMessage.push_back(YAC_C); // c
    vchMessage.push_back(YAC_R); // r

    vchMessage.insert(vchMessage.end(), ssReissue.begin(), ssReissue.end());
    script << OP_YAC_ASSET << ToByteVector(vchMessage) << OP_DROP;
}

bool CReissueAsset::IsNull() const
{
    return strName == "" || nAmount < 0;
}

bool CAssetsCache::AddTransferAsset(const CAssetTransfer& transferAsset, const std::string& address, const COutPoint& out, const CTxOut& txOut)
{
    AddToAssetBalance(transferAsset.strName, address, transferAsset.nAmount);

    // Add to cache so we can save to database
    CAssetCacheNewTransfer newTransfer(transferAsset, address, out);

    if (setNewTransferAssetsToRemove.count(newTransfer))
        setNewTransferAssetsToRemove.erase(newTransfer);

    setNewTransferAssetsToAdd.insert(newTransfer);

    return true;
}

void CAssetsCache::AddToAssetBalance(const std::string& strName, const std::string& address, const CAmount& nAmount)
{
    if (fAssetIndex) {
        auto pair = std::make_pair(strName, address);
        // Add to map address -> amount map

        // Get the best amount
        if (!GetBestAssetAddressAmount(*this, strName, address))
            mapAssetsAddressAmount.insert(make_pair(pair, 0));

        // Add the new amount to the balance
        if (IsAssetNameAnOwner(strName))
            mapAssetsAddressAmount.at(pair) = OWNER_ASSET_AMOUNT;
        else
            mapAssetsAddressAmount.at(pair) += nAmount;
    }
}

bool CAssetsCache::TrySpendCoin(const COutPoint& out, const CTxOut& txOut)
{
    // Placeholder strings that will get set if you successfully get the transfer or asset from the script
    std::string address = "";
    std::string assetName = "";
    CAmount nAmount = -1;

    // Get the asset tx data
    int nType = -1;
    bool fIsOwner = false;
    if (txOut.scriptPubKey.IsAssetScript(nType, fIsOwner)) {

        // Get the New Asset or Transfer Asset from the scriptPubKey
        if (nType == TX_NEW_ASSET && !fIsOwner) {
            CNewAsset asset;
            if (AssetFromScript(txOut.scriptPubKey, asset, address)) {
                assetName = asset.strName;
                nAmount = asset.nAmount;
            }
        } else if (nType == TX_TRANSFER_ASSET) {
            CAssetTransfer transfer;
            if (TransferAssetFromScript(txOut.scriptPubKey, transfer, address)) {
                assetName = transfer.strName;
                nAmount = transfer.nAmount;
            }
        } else if (nType == TX_NEW_ASSET && fIsOwner) {
            if (!OwnerAssetFromScript(txOut.scriptPubKey, assetName, address))
                return error("%s : ERROR Failed to get owner asset from the OutPoint: %s", __func__,
                             out.ToString());
            nAmount = OWNER_ASSET_AMOUNT;
        } else if (nType == TX_REISSUE_ASSET) {
            CReissueAsset reissue;
            if (ReissueAssetFromScript(txOut.scriptPubKey, reissue, address)) {
                assetName = reissue.strName;
                nAmount = reissue.nAmount;
            }
        }
    } else {
        // If it isn't an asset tx return true, we only fail if an error occurs
        return true;
    }

    // If we got the address and the assetName, proceed to remove it from the database, and in memory objects
    if (address != "" && assetName != "") {
        if (fAssetIndex && nAmount > 0) {
            CAssetCacheSpendAsset spend(assetName, address, nAmount);
            if (GetBestAssetAddressAmount(*this, assetName, address)) {
                auto pair = make_pair(assetName, address);
                if (mapAssetsAddressAmount.count(pair))
                    mapAssetsAddressAmount.at(pair) -= nAmount;

                if (mapAssetsAddressAmount.at(pair) < 0)
                    mapAssetsAddressAmount.at(pair) = 0;

                // Update the cache so we can save to database
                vSpentAssets.push_back(spend);
            }
        }
    } else {
        return error("%s : ERROR Failed to get asset from the OutPoint: %s", __func__, out.ToString());
    }

    return true;
}

bool CAssetsCache::ContainsAsset(const CNewAsset& asset)
{
    return CheckIfAssetExists(asset.strName);
}

bool CAssetsCache::ContainsAsset(const std::string& assetName)
{
    return CheckIfAssetExists(assetName);
}

bool CAssetsCache::UndoAssetCoin(const Coin& coin, const COutPoint& out)
{
    std::string strAddress = "";
    std::string assetName = "";
    CAmount nAmount = 0;

    // Get the asset tx from the script
    int nType = -1;
    bool fIsOwner = false;
    if(coin.out.scriptPubKey.IsAssetScript(nType, fIsOwner)) {

        if (nType == TX_NEW_ASSET && !fIsOwner) {
            CNewAsset asset;
            if (!AssetFromScript(coin.out.scriptPubKey, asset, strAddress)) {
                return error("%s : Failed to get asset from script while trying to undo asset spend. OutPoint : %s",
                             __func__,
                             out.ToString());
            }
            assetName = asset.strName;

            nAmount = asset.nAmount;
        } else if (nType == TX_TRANSFER_ASSET) {
            CAssetTransfer transfer;
            if (!TransferAssetFromScript(coin.out.scriptPubKey, transfer, strAddress))
                return error(
                        "%s : Failed to get transfer asset from script while trying to undo asset spend. OutPoint : %s",
                        __func__,
                        out.ToString());

            assetName = transfer.strName;
            nAmount = transfer.nAmount;
        } else if (nType == TX_NEW_ASSET && fIsOwner) {
            std::string ownerName;
            if (!OwnerAssetFromScript(coin.out.scriptPubKey, ownerName, strAddress))
                return error(
                        "%s : Failed to get owner asset from script while trying to undo asset spend. OutPoint : %s",
                        __func__, out.ToString());
            assetName = ownerName;
            nAmount = OWNER_ASSET_AMOUNT;
        } else if (nType == TX_REISSUE_ASSET) {
            CReissueAsset reissue;
            if (!ReissueAssetFromScript(coin.out.scriptPubKey, reissue, strAddress))
                return error(
                        "%s : Failed to get reissue asset from script while trying to undo asset spend. OutPoint : %s",
                        __func__, out.ToString());
            assetName = reissue.strName;
            nAmount = reissue.nAmount;
        }
    }

    if (assetName == "" || strAddress == "" || nAmount == 0)
        return error("%s : AssetName, Address or nAmount is invalid., Asset Name: %s, Address: %s, Amount: %d", __func__, assetName, strAddress, nAmount);

    if (!AddBackSpentAsset(assetName, strAddress, nAmount, out))
        return error("%s : Failed to add back the spent asset. OutPoint : %s", __func__, out.ToString());

    return true;
}

//! Changes Memory Only
bool CAssetsCache::AddBackSpentAsset(const std::string& assetName, const std::string& address, const CAmount& nAmount, const COutPoint& out)
{
    if (fAssetIndex) {
        // Update the assets address balance
        auto pair = std::make_pair(assetName, address);

        // Get the map address amount from database if the map doesn't have it already
        if (!GetBestAssetAddressAmount(*this, assetName, address))
            mapAssetsAddressAmount.insert(std::make_pair(pair, 0));

        mapAssetsAddressAmount.at(pair) += nAmount;
    }

    // Add the undoAmount to the vector so we know what changes are dirty and what needs to be saved to database
    CAssetCacheUndoAssetAmount undoAmount(assetName, address, nAmount);
    vUndoAssetAmount.push_back(undoAmount);

    return true;
}

//! Changes Memory Only
bool CAssetsCache::UndoTransfer(const CAssetTransfer& transfer, const std::string& address, const COutPoint& outToRemove)
{
    if (fAssetIndex) {
        // Make sure we are in a valid state to undo the transfer of the asset
        if (!GetBestAssetAddressAmount(*this, transfer.strName, address))
            return error("%s : Failed to get the assets address balance from the database. Asset : %s Address : %s",
                         __func__, transfer.strName, address);

        auto pair = std::make_pair(transfer.strName, address);
        if (!mapAssetsAddressAmount.count(pair))
            return error(
                    "%s : Tried undoing a transfer and the map of address amount didn't have the asset address pair. Asset : %s Address : %s",
                    __func__, transfer.strName, address);

        if (mapAssetsAddressAmount.at(pair) < transfer.nAmount)
            return error(
                    "%s : Tried undoing a transfer and the map of address amount had less than the amount we are trying to undo. Asset : %s Address : %s",
                    __func__, transfer.strName, address);

        // Change the in memory balance of the asset at the address
        mapAssetsAddressAmount[pair] -= transfer.nAmount;
    }

    return true;
}

//! Changes Memory Only
bool CAssetsCache::RemoveNewAsset(const CNewAsset& asset, const std::string address)
{
    if (!CheckIfAssetExists(asset.strName))
        return error("%s : Tried removing an asset that didn't exist. Asset Name : %s", __func__, asset.strName);

    CAssetCacheNewAsset newAsset(asset, address, 0 , uint256());

    if (setNewAssetsToAdd.count(newAsset))
        setNewAssetsToAdd.erase(newAsset);

    setNewAssetsToRemove.insert(newAsset);

    if (fAssetIndex)
        mapAssetsAddressAmount[std::make_pair(asset.strName, address)] = 0;

    return true;
}

//! Changes Memory Only
bool CAssetsCache::AddNewAsset(const CNewAsset& asset, const std::string address, const int& nHeight, const uint256& blockHash)
{
    if(CheckIfAssetExists(asset.strName))
        return error("%s: Tried adding new asset, but it already existed in the set of assets: %s", __func__, asset.strName);

    CAssetCacheNewAsset newAsset(asset, address, nHeight, blockHash);

    if (setNewAssetsToRemove.count(newAsset))
        setNewAssetsToRemove.erase(newAsset);

    setNewAssetsToAdd.insert(newAsset);

    if (fAssetIndex) {
        // Insert the asset into the assests address amount map
        mapAssetsAddressAmount[std::make_pair(asset.strName, address)] = asset.nAmount;
    }

    return true;
}

//! Changes Memory Only
bool CAssetsCache::AddReissueAsset(const CReissueAsset& reissue, const std::string address, const COutPoint& out)
{
    auto pair = std::make_pair(reissue.strName, address);

    CNewAsset asset;
    int assetHeight;
    uint256 assetBlockHash;
    if (!GetAssetMetaDataIfExists(reissue.strName, asset, assetHeight, assetBlockHash))
        return error("%s: Failed to get the original asset that is getting reissued. Asset Name : %s",
                     __func__, reissue.strName);

    // Insert the reissue information into the reissue map
    if (!mapReissuedAssetData.count(reissue.strName)) {
        asset.nAmount += reissue.nAmount;
        asset.nReissuable = reissue.nReissuable;
        if (reissue.nUnits != -1)
            asset.units = reissue.nUnits;

        if (reissue.strIPFSHash != "") {
            asset.nHasIPFS = 1;
            asset.strIPFSHash = reissue.strIPFSHash;
        }
        mapReissuedAssetData.insert(make_pair(reissue.strName, asset));
    } else {
        mapReissuedAssetData.at(reissue.strName).nAmount += reissue.nAmount;
        mapReissuedAssetData.at(reissue.strName).nReissuable = reissue.nReissuable;
        if (reissue.nUnits != -1) {
            mapReissuedAssetData.at(reissue.strName).units = reissue.nUnits;
        }
        if (reissue.strIPFSHash != "") {
            mapReissuedAssetData.at(reissue.strName).nHasIPFS = 1;
            mapReissuedAssetData.at(reissue.strName).strIPFSHash = reissue.strIPFSHash;
        }
    }

    CAssetCacheReissueAsset reissueAsset(reissue, address, out, assetHeight, assetBlockHash);

    if (setNewReissueToRemove.count(reissueAsset))
        setNewReissueToRemove.erase(reissueAsset);

    setNewReissueToAdd.insert(reissueAsset);

    if (fAssetIndex) {
        // Add the reissued amount to the address amount map
        if (!GetBestAssetAddressAmount(*this, reissue.strName, address))
            mapAssetsAddressAmount.insert(make_pair(pair, 0));

        // Add the reissued amount to the amount in the map
        mapAssetsAddressAmount[pair] += reissue.nAmount;
    }

    return true;

}

//! Changes Memory Only
bool CAssetsCache::RemoveReissueAsset(const CReissueAsset& reissue, const std::string address, const COutPoint& out, const std::vector<std::pair<std::string, CBlockAssetUndo> >& vUndoIPFS)
{
    auto pair = std::make_pair(reissue.strName, address);

    CNewAsset assetData;
    int height;
    uint256 blockHash;
    if (!GetAssetMetaDataIfExists(reissue.strName, assetData, height, blockHash))
        return error("%s: Tried undoing reissue of an asset, but that asset didn't exist: %s", __func__, reissue.strName);

    // Change the asset data by undoing what was reissued
    assetData.nAmount -= reissue.nAmount;
    assetData.nReissuable = 1;

    // Find the ipfs hash in the undoblock data and restore the ipfs hash to its previous hash
    for (auto undoItem : vUndoIPFS) {
        if (undoItem.first == reissue.strName) {
            if (undoItem.second.fChangedIPFS)
                assetData.strIPFSHash = undoItem.second.strIPFS;
            if(undoItem.second.fChangedUnits)
                assetData.units = undoItem.second.nUnits;
            if (assetData.strIPFSHash == "")
                assetData.nHasIPFS = 0;
            break;
        }
    }

    mapReissuedAssetData[assetData.strName] = assetData;

    CAssetCacheReissueAsset reissueAsset(reissue, address, out, height, blockHash);

    if (setNewReissueToAdd.count(reissueAsset))
        setNewReissueToAdd.erase(reissueAsset);

    setNewReissueToRemove.insert(reissueAsset);

    if (fAssetIndex) {
        // Get the best amount form the database or dirty cache
        if (!GetBestAssetAddressAmount(*this, reissue.strName, address)) {
            if (reissueAsset.reissue.nAmount != 0)
                return error("%s : Trying to undo reissue of an asset but the assets amount isn't in the database",
                         __func__);
        }
        mapAssetsAddressAmount[pair] -= reissue.nAmount;

        if (mapAssetsAddressAmount[pair] < 0)
            return error("%s : Tried undoing reissue of an asset, but the assets amount went negative: %s", __func__,
                         reissue.strName);
    }

    return true;
}

//! Changes Memory Only
bool CAssetsCache::AddOwnerAsset(const std::string& assetsName, const std::string address)
{
    // Update the cache
    CAssetCacheNewOwner newOwner(assetsName, address);

    if (setNewOwnerAssetsToRemove.count(newOwner))
        setNewOwnerAssetsToRemove.erase(newOwner);

    setNewOwnerAssetsToAdd.insert(newOwner);

    if (fAssetIndex) {
        // Insert the asset into the assests address amount map
        mapAssetsAddressAmount[std::make_pair(assetsName, address)] = OWNER_ASSET_AMOUNT;
    }

    return true;
}

//! Changes Memory Only
bool CAssetsCache::RemoveOwnerAsset(const std::string& assetsName, const std::string address)
{
    // Update the cache
    CAssetCacheNewOwner newOwner(assetsName, address);
    if (setNewOwnerAssetsToAdd.count(newOwner))
        setNewOwnerAssetsToAdd.erase(newOwner);

    setNewOwnerAssetsToRemove.insert(newOwner);

    if (fAssetIndex) {
        auto pair = std::make_pair(assetsName, address);
        mapAssetsAddressAmount[pair] = 0;
    }

    return true;
}

//! Changes Memory Only
bool CAssetsCache::RemoveTransfer(const CAssetTransfer &transfer, const std::string &address, const COutPoint &out)
{
    if (!UndoTransfer(transfer, address, out))
        return error("%s : Failed to undo the transfer", __func__);

    CAssetCacheNewTransfer newTransfer(transfer, address, out);
    if (setNewTransferAssetsToAdd.count(newTransfer))
        setNewTransferAssetsToAdd.erase(newTransfer);

    setNewTransferAssetsToRemove.insert(newTransfer);

    return true;
}

bool CAssetsCache::DumpCacheToDatabase()
{
    try {
        bool dirty = false;
        std::string message;

        // Remove new assets from the database
        for (auto newAsset : setNewAssetsToRemove) {
            passetsCache->Erase(newAsset.asset.strName);
            if (!passetsdb->EraseAssetData(newAsset.asset.strName)) {
                dirty = true;
                message = "_Failed Erasing New Asset Data from database";
            }

            if (dirty) {
                return error("%s : %s", __func__, message);
            }

            if (fAssetIndex) {
                if (!passetsdb->EraseAssetAddressQuantity(newAsset.asset.strName, newAsset.address)) {
                    dirty = true;
                    message = "_Failed Erasing Address Balance from database";
                }

                if (!passetsdb->EraseAddressAssetQuantity(newAsset.address, newAsset.asset.strName)) {
                    dirty = true;
                    message = "_Failed Erasing New Asset Address Balance from AddressAsset database";
                }
            }

            if (dirty) {
                return error("%s : %s", __func__, message);
            }
        }

        // Add the new assets to the database
        for (auto newAsset : setNewAssetsToAdd) {
            passetsCache->Put(newAsset.asset.strName, CDatabasedAssetData(newAsset.asset, newAsset.blockHeight, newAsset.blockHash));
            if (!passetsdb->WriteAssetData(newAsset.asset, newAsset.blockHeight, newAsset.blockHash)) {
                dirty = true;
                message = "_Failed Writing New Asset Data to database";
            }

            if (dirty) {
                return error("%s : %s", __func__, message);
            }

            if (fAssetIndex) {
                if (!passetsdb->WriteAssetAddressQuantity(newAsset.asset.strName, newAsset.address,
                                                          newAsset.asset.nAmount)) {
                    dirty = true;
                    message = "_Failed Writing Address Balance to database";
                }

                if (!passetsdb->WriteAddressAssetQuantity(newAsset.address, newAsset.asset.strName,
                                                          newAsset.asset.nAmount)) {
                    dirty = true;
                    message = "_Failed Writing Address Balance to database";
                }
            }

            if (dirty) {
                return error("%s : %s", __func__, message);
            }
        }

        if (fAssetIndex) {
            // Remove the new owners from database
            for (auto ownerAsset : setNewOwnerAssetsToRemove) {
                if (!passetsdb->EraseAssetAddressQuantity(ownerAsset.assetName, ownerAsset.address)) {
                    dirty = true;
                    message = "_Failed Erasing Owner Address Balance from database";
                }

                if (!passetsdb->EraseAddressAssetQuantity(ownerAsset.address, ownerAsset.assetName)) {
                    dirty = true;
                    message = "_Failed Erasing New Owner Address Balance from AddressAsset database";
                }

                if (dirty) {
                    return error("%s : %s", __func__, message);
                }
            }

            // Add the new owners to database
            for (auto ownerAsset : setNewOwnerAssetsToAdd) {
                auto pair = std::make_pair(ownerAsset.assetName, ownerAsset.address);
                if (mapAssetsAddressAmount.count(pair) && mapAssetsAddressAmount.at(pair) > 0) {
                    if (!passetsdb->WriteAssetAddressQuantity(ownerAsset.assetName, ownerAsset.address,
                                                              mapAssetsAddressAmount.at(pair))) {
                        dirty = true;
                        message = "_Failed Writing Owner Address Balance to database";
                    }

                    if (!passetsdb->WriteAddressAssetQuantity(ownerAsset.address, ownerAsset.assetName,
                                                              mapAssetsAddressAmount.at(pair))) {
                        dirty = true;
                        message = "_Failed Writing Address Balance to database";
                    }

                    if (dirty) {
                        return error("%s : %s", __func__, message);
                    }
                }
            }

            // Undo the transfering by updating the balances in the database

            for (auto undoTransfer : setNewTransferAssetsToRemove) {
                auto pair = std::make_pair(undoTransfer.transfer.strName, undoTransfer.address);
                if (mapAssetsAddressAmount.count(pair)) {
                    if (mapAssetsAddressAmount.at(pair) == 0) {
                        if (!passetsdb->EraseAssetAddressQuantity(undoTransfer.transfer.strName,
                                                                  undoTransfer.address)) {
                            dirty = true;
                            message = "_Failed Erasing Address Quantity from database";
                        }

                        if (!passetsdb->EraseAddressAssetQuantity(undoTransfer.address,
                                                                  undoTransfer.transfer.strName)) {
                            dirty = true;
                            message = "_Failed Erasing UndoTransfer Address Balance from AddressAsset database";
                        }

                        if (dirty) {
                            return error("%s : %s", __func__, message);
                        }
                    } else {
                        if (!passetsdb->WriteAssetAddressQuantity(undoTransfer.transfer.strName,
                                                                  undoTransfer.address,
                                                                  mapAssetsAddressAmount.at(pair))) {
                            dirty = true;
                            message = "_Failed Writing updated Address Quantity to database when undoing transfers";
                        }

                        if (!passetsdb->WriteAddressAssetQuantity(undoTransfer.address,
                                                                  undoTransfer.transfer.strName,
                                                                  mapAssetsAddressAmount.at(pair))) {
                            dirty = true;
                            message = "_Failed Writing Address Balance to database";
                        }

                        if (dirty) {
                            return error("%s : %s", __func__, message);
                        }
                    }
                }
            }


            // Save the new transfers by updating the quantity in the database
            for (auto newTransfer : setNewTransferAssetsToAdd) {
                auto pair = std::make_pair(newTransfer.transfer.strName, newTransfer.address);
                // During init and reindex it disconnects and verifies blocks, can create a state where vNewTransfer will contain transfers that have already been spent. So if they aren't in the map, we can skip them.
                if (mapAssetsAddressAmount.count(pair)) {
                    if (!passetsdb->WriteAssetAddressQuantity(newTransfer.transfer.strName, newTransfer.address,
                                                              mapAssetsAddressAmount.at(pair))) {
                        dirty = true;
                        message = "_Failed Writing new address quantity to database";
                    }

                    if (!passetsdb->WriteAddressAssetQuantity(newTransfer.address, newTransfer.transfer.strName,
                                                              mapAssetsAddressAmount.at(pair))) {
                        dirty = true;
                        message = "_Failed Writing Address Balance to database";
                    }

                    if (dirty) {
                        return error("%s : %s", __func__, message);
                    }
                }
            }
        }

        for (auto newReissue : setNewReissueToAdd) {
            auto reissue_name = newReissue.reissue.strName;
            auto pair = make_pair(reissue_name, newReissue.address);
            if (mapReissuedAssetData.count(reissue_name)) {
                if(!passetsdb->WriteAssetData(mapReissuedAssetData.at(reissue_name), newReissue.blockHeight, newReissue.blockHash)) {
                    dirty = true;
                    message = "_Failed Writing reissue asset data to database";
                }

                if (dirty) {
                    return error("%s : %s", __func__, message);
                }

                passetsCache->Erase(reissue_name);

                if (fAssetIndex) {

                    if (mapAssetsAddressAmount.count(pair) && mapAssetsAddressAmount.at(pair) > 0) {
                        if (!passetsdb->WriteAssetAddressQuantity(pair.first, pair.second,
                                                                  mapAssetsAddressAmount.at(pair))) {
                            dirty = true;
                            message = "_Failed Writing reissue asset quantity to the address quantity database";
                        }

                        if (!passetsdb->WriteAddressAssetQuantity(pair.second, pair.first,
                                                                  mapAssetsAddressAmount.at(pair))) {
                            dirty = true;
                            message = "_Failed Writing Address Balance to database";
                        }

                        if (dirty) {
                            return error("%s, %s", __func__, message);
                        }
                    }
                }
            }
        }

        for (auto undoReissue : setNewReissueToRemove) {
            // In the case the the issue and reissue are both being removed
            // we can skip this call because the removal of the issue should remove all data pertaining the to asset
            // Fixes the issue where the reissue data will write over the removed asset meta data that was removed above
            CNewAsset asset(undoReissue.reissue.strName, 0);
            CAssetCacheNewAsset testNewAssetCache(asset, "", 0 , uint256());
            if (setNewAssetsToRemove.count(testNewAssetCache)) {
                continue;
            }

            auto reissue_name = undoReissue.reissue.strName;
            if (mapReissuedAssetData.count(reissue_name)) {
                if(!passetsdb->WriteAssetData(mapReissuedAssetData.at(reissue_name), undoReissue.blockHeight, undoReissue.blockHash)) {
                    dirty = true;
                    message = "_Failed Writing undo reissue asset data to database";
                }

                if (fAssetIndex) {
                    auto pair = make_pair(undoReissue.reissue.strName, undoReissue.address);
                    if (mapAssetsAddressAmount.count(pair)) {
                        if (mapAssetsAddressAmount.at(pair) == 0) {
                            if (!passetsdb->EraseAssetAddressQuantity(reissue_name, undoReissue.address)) {
                                dirty = true;
                                message = "_Failed Erasing Address Balance from database";
                            }

                            if (!passetsdb->EraseAddressAssetQuantity(undoReissue.address, reissue_name)) {
                                dirty = true;
                                message = "_Failed Erasing UndoReissue Balance from AddressAsset database";
                            }
                        } else {
                            if (!passetsdb->WriteAssetAddressQuantity(reissue_name, undoReissue.address,
                                                                      mapAssetsAddressAmount.at(pair))) {
                                dirty = true;
                                message = "_Failed Writing the undo of reissue of asset from database";
                            }

                            if (!passetsdb->WriteAddressAssetQuantity(undoReissue.address, reissue_name,
                                                                      mapAssetsAddressAmount.at(pair))) {
                                dirty = true;
                                message = "_Failed Writing Address Balance to database";
                            }
                        }
                    }
                }

                if (dirty) {
                    return error("%s : %s", __func__, message);
                }

                passetsCache->Erase(reissue_name);
            }
        }

        if (fAssetIndex) {
            // Undo the asset spends by updating there balance in the database
            for (auto undoSpend : vUndoAssetAmount) {
                auto pair = std::make_pair(undoSpend.assetName, undoSpend.address);
                if (mapAssetsAddressAmount.count(pair)) {
                    if (!passetsdb->WriteAssetAddressQuantity(undoSpend.assetName, undoSpend.address,
                                                              mapAssetsAddressAmount.at(pair))) {
                        dirty = true;
                        message = "_Failed Writing updated Address Quantity to database when undoing spends";
                    }

                    if (!passetsdb->WriteAddressAssetQuantity(undoSpend.address, undoSpend.assetName,
                                                              mapAssetsAddressAmount.at(pair))) {
                        dirty = true;
                        message = "_Failed Writing Address Balance to database";
                    }

                    if (dirty) {
                        return error("%s : %s", __func__, message);
                    }
                }
            }


            // Save the assets that have been spent by erasing the quantity in the database
            for (auto spentAsset : vSpentAssets) {
                auto pair = make_pair(spentAsset.assetName, spentAsset.address);
                if (mapAssetsAddressAmount.count(pair)) {
                    if (mapAssetsAddressAmount.at(pair) == 0) {
                        if (!passetsdb->EraseAssetAddressQuantity(spentAsset.assetName, spentAsset.address)) {
                            dirty = true;
                            message = "_Failed Erasing a Spent Asset, from database";
                        }

                        if (!passetsdb->EraseAddressAssetQuantity(spentAsset.address, spentAsset.assetName)) {
                            dirty = true;
                            message = "_Failed Erasing a Spent Asset from AddressAsset database";
                        }

                        if (dirty) {
                            return error("%s : %s", __func__, message);
                        }
                    } else {
                        if (!passetsdb->WriteAssetAddressQuantity(spentAsset.assetName, spentAsset.address,
                                                                  mapAssetsAddressAmount.at(pair))) {
                            dirty = true;
                            message = "_Failed Erasing a Spent Asset, from database";
                        }

                        if (!passetsdb->WriteAddressAssetQuantity(spentAsset.address, spentAsset.assetName,
                                                                  mapAssetsAddressAmount.at(pair))) {
                            dirty = true;
                            message = "_Failed Writing Address Balance to database";
                        }

                        if (dirty) {
                            return error("%s : %s", __func__, message);
                        }
                    }
                }
            }
        }

        ClearDirtyCache();

        return true;
    } catch (const std::runtime_error& e) {
        return error("%s : %s ", __func__, std::string("System error while flushing assets: ") + e.what());
    }
}

// This function will put all current cache data into the global passets cache.
//! Do not call this function on the passets pointer
bool CAssetsCache::Flush()
{

    if (!passets)
        return error("%s: Couldn't find passets pointer while trying to flush assets cache", __func__);

    try {
        for (auto &item : setNewAssetsToAdd) {
            if (passets->setNewAssetsToRemove.count(item))
                passets->setNewAssetsToRemove.erase(item);
            passets->setNewAssetsToAdd.insert(item);
        }

        for (auto &item : setNewAssetsToRemove) {
            if (passets->setNewAssetsToAdd.count(item))
                passets->setNewAssetsToAdd.erase(item);
            passets->setNewAssetsToRemove.insert(item);
        }

        for (auto &item : mapAssetsAddressAmount)
            passets->mapAssetsAddressAmount[item.first] = item.second;

        for (auto &item : mapReissuedAssetData)
            passets->mapReissuedAssetData[item.first] = item.second;

        for (auto &item : setNewOwnerAssetsToAdd) {
            if (passets->setNewOwnerAssetsToRemove.count(item))
                passets->setNewOwnerAssetsToRemove.erase(item);
            passets->setNewOwnerAssetsToAdd.insert(item);
        }

        for (auto &item : setNewOwnerAssetsToRemove) {
            if (passets->setNewOwnerAssetsToAdd.count(item))
                passets->setNewOwnerAssetsToAdd.erase(item);
            passets->setNewOwnerAssetsToRemove.insert(item);
        }

        for (auto &item : setNewReissueToAdd) {
            if (passets->setNewReissueToRemove.count(item))
                passets->setNewReissueToRemove.erase(item);
            passets->setNewReissueToAdd.insert(item);
        }

        for (auto &item : setNewReissueToRemove) {
            if (passets->setNewReissueToAdd.count(item))
                passets->setNewReissueToAdd.erase(item);
            passets->setNewReissueToRemove.insert(item);
        }

        for (auto &item : setNewTransferAssetsToAdd) {
            if (passets->setNewTransferAssetsToRemove.count(item))
                passets->setNewTransferAssetsToRemove.erase(item);
            passets->setNewTransferAssetsToAdd.insert(item);
        }

        for (auto &item : setNewTransferAssetsToRemove) {
            if (passets->setNewTransferAssetsToAdd.count(item))
                passets->setNewTransferAssetsToAdd.erase(item);
            passets->setNewTransferAssetsToRemove.insert(item);
        }

        for (auto &item : vSpentAssets) {
            passets->vSpentAssets.emplace_back(item);
        }

        for (auto &item : vUndoAssetAmount) {
            passets->vUndoAssetAmount.emplace_back(item);
        }

        return true;

    } catch (const std::runtime_error& e) {
        return error("%s : %s ", __func__, std::string("System error while flushing assets: ") + e.what());
    }
}

//! Get the amount of memory the cache is using
size_t CAssetsCache::DynamicMemoryUsage() const
{
    // TODO make sure this is accurate
    return memusage::DynamicUsage(mapAssetsAddressAmount) + memusage::DynamicUsage(mapReissuedAssetData);
}

//! Get an estimated size of the cache in bytes that will be needed inorder to save to database
size_t CAssetsCache::GetCacheSize() const
{
    // COutPoint: 32 bytes
    // CNewAsset: Max 80 bytes
    // CAssetTransfer: Asset Name, CAmount ( 40 bytes)
    // CReissueAsset: Max 80 bytes
    // CAmount: 8 bytes
    // Asset Name: Max 32 bytes
    // Address: 40 bytes
    // Block hash: 32 bytes
    // CTxOut: CAmount + CScript (105 + 8 = 113 bytes)

    size_t size = 0;

    size += (32 + 40 + 8) * vUndoAssetAmount.size(); // Asset Name, Address, CAmount

    size += (40 + 40 + 32) * setNewTransferAssetsToRemove.size(); // CAssetTrasnfer, Address, COutPoint
    size += (40 + 40 + 32) * setNewTransferAssetsToAdd.size(); // CAssetTrasnfer, Address, COutPoint

    size += 72 * setNewOwnerAssetsToAdd.size(); // Asset Name, Address
    size += 72 * setNewOwnerAssetsToRemove.size(); // Asset Name, Address

    size += (32 + 40 + 8) * vSpentAssets.size(); // Asset Name, Address, CAmount

    size += (80 + 40 + 32 + sizeof(int)) * setNewAssetsToAdd.size(); // CNewAsset, Address, Block hash, int
    size += (80 + 40 + 32 + sizeof(int)) * setNewAssetsToRemove.size(); // CNewAsset, Address, Block hash, int

    size += (80 + 40 + 32 + 32 + sizeof(int)) * setNewReissueToAdd.size(); // CReissueAsset, Address, COutPoint, Block hash, int
    size += (80 + 40 + 32 + 32 + sizeof(int)) * setNewReissueToRemove.size(); // CReissueAsset, Address, COutPoint, Block hash, int

    // TODO add the qualfier, and restricted sets into this calculation

    return size;
}

//! Get an estimated size of the cache in bytes that will be needed inorder to save to database
size_t CAssetsCache::GetCacheSizeV2() const
{
    // COutPoint: 32 bytes
    // CNewAsset: Max 80 bytes
    // CAssetTransfer: Asset Name, CAmount ( 40 bytes)
    // CReissueAsset: Max 80 bytes
    // CAmount: 8 bytes
    // Asset Name: Max 32 bytes
    // Address: 40 bytes
    // Block hash: 32 bytes
    // CTxOut: CAmount + CScript (105 + 8 = 113 bytes)

    size_t size = 0;
    size += memusage::DynamicUsage(vUndoAssetAmount);
    size += memusage::DynamicUsage(setNewTransferAssetsToRemove);
    size += memusage::DynamicUsage(setNewTransferAssetsToAdd);
    size += memusage::DynamicUsage(setNewOwnerAssetsToAdd);
    size += memusage::DynamicUsage(setNewOwnerAssetsToRemove);
    size += memusage::DynamicUsage(vSpentAssets);
    size += memusage::DynamicUsage(setNewAssetsToAdd);
    size += memusage::DynamicUsage(setNewAssetsToRemove);
    size += memusage::DynamicUsage(setNewReissueToAdd);
    size += memusage::DynamicUsage(setNewReissueToRemove);

    return size;
}

bool CheckIssueDataTx(const CTxOut& txOut)
{
    // Verify 'yacq' is in the transaction
    CScript scriptPubKey = txOut.scriptPubKey;

    int nStartingIndex = 0;
    return IsScriptNewAsset(scriptPubKey, nStartingIndex);
}

bool CheckReissueDataTx(const CTxOut& txOut)
{
    // Verify 'yacr' is in the transaction
    CScript scriptPubKey = txOut.scriptPubKey;

    return IsScriptReissueAsset(scriptPubKey);
}

bool CheckOwnerDataTx(const CTxOut& txOut)
{
    // Verify 'yacq' is in the transaction
    CScript scriptPubKey = txOut.scriptPubKey;

    return IsScriptOwnerAsset(scriptPubKey);
}

bool CheckTransferOwnerTx(const CTxOut& txOut)
{
    // Verify 'yacq' is in the transaction
    CScript scriptPubKey = txOut.scriptPubKey;

    return IsScriptTransferAsset(scriptPubKey);
}

bool IsScriptNewAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptNewAsset(scriptPubKey, index);
}

bool IsScriptNewAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner =false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex)) {
        return nType == TX_NEW_ASSET && !fIsOwner;
    }
    return false;
}

bool IsScriptNewUniqueAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptNewUniqueAsset(scriptPubKey, index);
}

bool IsScriptNewUniqueAsset(const CScript &scriptPubKey, int &nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (!scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return false;

    CNewAsset asset;
    std::string address;
    if (!AssetFromScript(scriptPubKey, asset, address))
        return false;

    AssetType assetType;
    if (!IsAssetNameValid(asset.strName, assetType))
        return false;

    return AssetType::UNIQUE == assetType;
}

bool IsScriptOwnerAsset(const CScript& scriptPubKey)
{

    int index = 0;
    return IsScriptOwnerAsset(scriptPubKey, index);
}

bool IsScriptOwnerAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner =false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex)) {
        return nType == TX_NEW_ASSET && fIsOwner;
    }

    return false;
}

bool IsScriptReissueAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptReissueAsset(scriptPubKey, index);
}

bool IsScriptReissueAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner =false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex)) {
        return nType == TX_REISSUE_ASSET;
    }

    return false;
}

bool IsScriptTransferAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptTransferAsset(scriptPubKey, index);
}

bool IsScriptTransferAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex)) {
        return nType == TX_TRANSFER_ASSET;
    }

    return false;
}

//! Returns a boolean on if the asset exists
bool CAssetsCache::CheckIfAssetExists(const std::string& name, bool fForceDuplicateCheck)
{
    // If we are reindexing, we don't know if an asset exists when accepting blocks
    if (fReindex) {
        return true;
    }

    // Create objects that will be used to check the dirty cache
    CNewAsset asset;
    asset.strName = name;
    CAssetCacheNewAsset cachedAsset(asset, "", 0, uint256());

    // Check the dirty caches first and see if it was recently added or removed
    if (setNewAssetsToRemove.count(cachedAsset)) {
        return false;
    }

    // Check the dirty caches first and see if it was recently added or removed
    if (passets->setNewAssetsToRemove.count(cachedAsset)) {
        return false;
    }

    if (setNewAssetsToAdd.count(cachedAsset)) {
        if (fForceDuplicateCheck) {
            return true;
        }
        else {
            printf("%s : Found asset %s in setNewAssetsToAdd but force duplicate check wasn't true\n", __func__, name);
        }
    }

    if (passets->setNewAssetsToAdd.count(cachedAsset)) {
        if (fForceDuplicateCheck) {
            return true;
        }
        else {
            printf("%s : Found asset %s in setNewAssetsToAdd but force duplicate check wasn't true\n", __func__, name);
        }
    }

    // Check the cache, if it doesn't exist in the cache. Try and read it from database
    if (passetsCache) {
        if (passetsCache->Exists(name)) {
            if (fForceDuplicateCheck) {
                return true;
            }
            else {
                printf("%s : Found asset %s in passetsCache but force duplicate check wasn't true\n", __func__, name);
            }
        } else {
            if (passetsdb) {
                CNewAsset readAsset;
                int nHeight;
                uint256 hash;
                if (passetsdb->ReadAssetData(name, readAsset, nHeight, hash)) {
                    passetsCache->Put(readAsset.strName, CDatabasedAssetData(readAsset, nHeight, hash));
                    if (fForceDuplicateCheck) {
                        return true;
                    }
                    else {
                        printf("%s : Found asset %s in passetsdb but force duplicate check wasn't true\n", __func__, name);
                    }
                }
            }
        }
    }
    return false;
}

bool CAssetsCache::GetAssetMetaDataIfExists(const std::string &name, CNewAsset &asset)
{
    int height;
    uint256 hash;
    return GetAssetMetaDataIfExists(name, asset, height, hash);
}

bool CAssetsCache::GetAssetMetaDataIfExists(const std::string &name, CNewAsset &asset, int& nHeight, uint256& blockHash)
{
    // Check the map that contains the reissued asset data. If it is in this map, it hasn't been saved to disk yet
    if (mapReissuedAssetData.count(name)) {
        asset = mapReissuedAssetData.at(name);
        return true;
    }

    // Check the map that contains the reissued asset data. If it is in this map, it hasn't been saved to disk yet
    if (passets->mapReissuedAssetData.count(name)) {
        asset = passets->mapReissuedAssetData.at(name);
        return true;
    }

    // Create objects that will be used to check the dirty cache
    CNewAsset tempAsset;
    tempAsset.strName = name;
    CAssetCacheNewAsset cachedAsset(tempAsset, "", 0, uint256());

    // Check the dirty caches first and see if it was recently added or removed
    if (setNewAssetsToRemove.count(cachedAsset)) {
        printf("%s : Found in new assets to Remove - Returning False\n", __func__);
        return false;
    }

    // Check the dirty caches first and see if it was recently added or removed
    if (passets->setNewAssetsToRemove.count(cachedAsset)) {
        printf("%s : Found in new assets to Remove - Returning False\n", __func__);
        return false;
    }

    auto setIterator = setNewAssetsToAdd.find(cachedAsset);
    if (setIterator != setNewAssetsToAdd.end()) {
        asset = setIterator->asset;
        nHeight = setIterator->blockHeight;
        blockHash = setIterator->blockHash;
        return true;
    }

    setIterator = passets->setNewAssetsToAdd.find(cachedAsset);
    if (setIterator != passets->setNewAssetsToAdd.end()) {
        asset = setIterator->asset;
        nHeight = setIterator->blockHeight;
        blockHash = setIterator->blockHash;
        return true;
    }

    // Check the cache, if it doesn't exist in the cache. Try and read it from database
    if (passetsCache) {
        if (passetsCache->Exists(name)) {
            CDatabasedAssetData data;
            data = passetsCache->Get(name);
            asset = data.asset;
            nHeight = data.nHeight;
            blockHash = data.blockHash;
            return true;
        }
    }

    if (passetsdb && passetsCache) {
        CNewAsset readAsset;
        int height;
        uint256 hash;
        if (passetsdb->ReadAssetData(name, readAsset, height, hash)) {
            asset = readAsset;
            nHeight = height;
            blockHash = hash;
            passetsCache->Put(readAsset.strName, CDatabasedAssetData(readAsset, height, hash));
            return true;
        }
    }

    printf("%s : Didn't find asset meta data anywhere. Returning False\n", __func__);
    return false;
}

bool GetAssetInfoFromScript(const CScript& scriptPubKey, std::string& strName, CAmount& nAmount)
{
    CAssetOutputEntry data;
    if(!GetAssetData(scriptPubKey, data))
        return false;

    strName = data.assetName;
    nAmount = data.nAmount;

    return true;
}

bool GetAssetInfoFromCoin(const Coin& coin, std::string& strName, CAmount& nAmount)
{
    return GetAssetInfoFromScript(coin.out.scriptPubKey, strName, nAmount);
}

bool GetAssetData(const CScript& script, CAssetOutputEntry& data)
{
    // Placeholder strings that will get set if you successfully get the transfer or asset from the script
    std::string address = "";
    std::string assetName = "";

    int nType = 0;
    bool fIsOwner = false;
    if (!script.IsAssetScript(nType, fIsOwner)) {
        return false;
    }

    txnouttype type = txnouttype(nType);

    // Get the New Asset or Transfer Asset from the scriptPubKey
    if (type == TX_NEW_ASSET && !fIsOwner) {
        CNewAsset asset;
        if (AssetFromScript(script, asset, address)) {
            data.type = TX_NEW_ASSET;
            data.nAmount = asset.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = asset.strName;
            return true;
        }
    } else if (type == TX_TRANSFER_ASSET) {
        CAssetTransfer transfer;
        if (TransferAssetFromScript(script, transfer, address)) {
            data.type = TX_TRANSFER_ASSET;
            data.nAmount = transfer.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = transfer.strName;
            return true;
        } else {
            printf("Failed to get transfer from script\n");
        }
    } else if (type == TX_NEW_ASSET && fIsOwner) {
        if (OwnerAssetFromScript(script, assetName, address)) {
            data.type = TX_NEW_ASSET;
            data.nAmount = OWNER_ASSET_AMOUNT;
            data.destination = DecodeDestination(address);
            data.assetName = assetName;
            return true;
        }
    } else if (type == TX_REISSUE_ASSET) {
        CReissueAsset reissue;
        if (ReissueAssetFromScript(script, reissue, address)) {
            data.type = TX_REISSUE_ASSET;
            data.nAmount = reissue.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = reissue.strName;
            return true;
        }
    }

    return false;
}

// REMOVE LATER
bool CheckIssueBurnTx(const CTxOut& txOut, const AssetType& type, const int numberIssued)
{
    if (type == AssetType::REISSUE || type == AssetType::VOTE || type == AssetType::OWNER || type == AssetType::INVALID)
        return false;

    CAmount lockAmount = 0;
    std::string lockAddress = "";

    // Get the lock address and amount for the type of asset
    lockAmount = GetLockAmount(type);
    lockAddress = GetLockAddress(type);

    // If issuing multiple (unique) assets need to burn for each
    lockAmount *= numberIssued;

    // Check if script satisfies the lock amount
    if (!(txOut.nValue == lockAmount))
        return false;

    // Extract the destination
    CTxDestination destination;
    if (!ExtractDestination(txOut.scriptPubKey, destination))
        return false;

    // Verify destination is valid
    if (!IsValidDestination(destination))
        return false;

    // Check destination address is the lock address
    auto strDestination = EncodeDestination(destination);
    if (!(strDestination == lockAddress))
        return false;

    return true;
}

bool CheckIssueBurnTx(const CTxOut& txOut, const AssetType& type)
{
    return CheckIssueBurnTx(txOut, type, 1);
}

bool CheckReissueBurnTx(const CTxOut& txOut)
{
    // Check the first transaction and verify that the correct YAC Amount
    if (txOut.nValue != GetReissueAssetLockAmount())
        return false;

    // Extract the destination
    CTxDestination destination;
    if (!ExtractDestination(txOut.scriptPubKey, destination))
        return false;

    // Verify destination is valid
    if (!IsValidDestination(destination))
        return false;

//    // Check destination address is the correct lock address
//    if (EncodeDestination(destination) != GetParams().ReissueAssetLockAddress())
//        return false;

    return true;
}

CAmount GetIssueAssetLockAmount()
{
    return feeLockAmount;
}

CAmount GetReissueAssetLockAmount()
{
    return GetIssueAssetLockAmount();
}

CAmount GetIssueSubAssetLockAmount()
{
    return GetIssueAssetLockAmount() / 2;
}

CAmount GetIssueUniqueAssetLockAmount()
{
    return GetIssueAssetLockAmount() / 4;
}

CAmount GetLockAmount(const int nType)
{
    return GetLockAmount((AssetType(nType)));
}

CAmount GetLockAmount(const AssetType type)
{
    switch (type) {
        case AssetType::ROOT:
            return GetIssueAssetLockAmount();
        case AssetType::SUB:
            return GetIssueSubAssetLockAmount();
        case AssetType::OWNER:
            return 0;
        case AssetType::UNIQUE:
            return GetIssueUniqueAssetLockAmount();
        case AssetType::VOTE:
            return 0;
        case AssetType::REISSUE:
            return GetReissueAssetLockAmount();
        default:
            return 0;
    }
}

std::string GetLockAddress(const int nType)
{
    return GetLockAddress((AssetType(nType)));
}

std::string GetLockAddress(const AssetType type)
{
    std::string burnAddr {"YCk26dUcaXu8vu6zG3E2PrbBeECAV8RNFp"};
    switch (type) {
        case AssetType::ROOT:
            return burnAddr;
        case AssetType::SUB:
            return burnAddr;
        case AssetType::OWNER:
            return "";
        case AssetType::UNIQUE:
            return burnAddr;
        case AssetType::VOTE:
            return "";
        case AssetType::REISSUE:
            return burnAddr;
        default:
            return "";
    }
}
// END OF REMOVE LATER

//! This will get the amount that an address for a certain asset contains from the database if they cache doesn't already have it
bool GetBestAssetAddressAmount(CAssetsCache& cache, const std::string& assetName, const std::string& address)
{
    if (fAssetIndex) {
        auto pair = make_pair(assetName, address);

        // If the caches map has the pair, return true because the map already contains the best dirty amount
        if (cache.mapAssetsAddressAmount.count(pair))
            return true;

        // If the caches map has the pair, return true because the map already contains the best dirty amount
        if (passets->mapAssetsAddressAmount.count(pair)) {
            cache.mapAssetsAddressAmount[pair] = passets->mapAssetsAddressAmount.at(pair);
            return true;
        }

        // If the database contains the assets address amount, insert it into the database and return true
        CAmount nDBAmount;
        if (passetsdb->ReadAssetAddressQuantity(pair.first, pair.second, nDBAmount)) {
            cache.mapAssetsAddressAmount.insert(make_pair(pair, nDBAmount));
            return true;
        }
    }

    // The amount wasn't found return false
    return false;
}

// 46 char base58 --> 34 char KAW compatible
std::string DecodeAssetData(std::string encoded)
{
    if (encoded.size() == 46) {
        std::vector<unsigned char> b;
        DecodeBase58(encoded, b);
        return std::string(b.begin(), b.end());
    }

    else if (encoded.size() == 64 && IsHex(encoded)) {
        std::vector<unsigned char> vec = ParseHex(encoded);
        return std::string(vec.begin(), vec.end());
    }

    return "";

};

std::string EncodeAssetData(std::string decoded)
{
    if (decoded.size() == 34) {
        return EncodeIPFS(decoded);
    }
    else if (decoded.size() == 32){
        return HexStr(decoded);
    }

    return "";
}

// 46 char base58 --> 34 char KAW compatible
std::string DecodeIPFS(std::string encoded)
{
    std::vector<unsigned char> b;
    DecodeBase58(encoded, b);
    return std::string(b.begin(), b.end());
};

// 34 char KAW compatible --> 46 char base58
std::string EncodeIPFS(std::string decoded){
    std::vector<char> charData(decoded.begin(), decoded.end());
    std::vector<unsigned char> unsignedCharData;
    for (char c : charData)
        unsignedCharData.push_back(static_cast<unsigned char>(c));
    return EncodeBase58(unsignedCharData);
};

void GetAllAdministrativeAssets(CWallet *pwallet, std::vector<std::string> &names, int nMinConf)
{
    if(!pwallet)
        return;

    GetAllMyAssets(pwallet, names, nMinConf, true, true);
}

void GetAllMyAssets(CWallet* pwallet, std::vector<std::string>& names, int nMinConf, bool fIncludeAdministrator, bool fOnlyAdministrator)
{
    if(!pwallet)
        return;

    std::map<std::string, std::vector<COutput> > mapAssets;
    pwallet->AvailableAssets(mapAssets, true, nullptr, 1, MAX_MONEY, MAX_MONEY, 0, nMinConf); // Set the mincof, set the rest to the defaults

    for (auto item : mapAssets) {
        bool isOwner = IsAssetNameAnOwner(item.first);

        if (isOwner) {
            if (fOnlyAdministrator || fIncludeAdministrator)
                names.emplace_back(item.first);
        } else {
            if (fOnlyAdministrator)
                continue;
            names.emplace_back(item.first);
        }
    }
}

//! sets _balances_ with the total quantity of each owned asset
bool GetAllMyAssetBalances(std::map<std::string, std::vector<COutput> >& outputs, std::map<std::string, CAmount>& amounts, const int confirmations, const std::string& prefix) {

    // Return false if no wallet was found to compute asset balances
    if (!vpwalletRegistered.size())
        return false;

    // Get the map of assetnames to outputs
    vpwalletRegistered[0]->AvailableAssets(outputs, true, nullptr, 1, MAX_MONEY, MAX_MONEY, 0, confirmations);

    // Loop through all pairs of Asset Name -> vector<COutput>
    for (const auto& pair : outputs) {
        if (prefix.empty() || pair.first.find(prefix) == 0) { // Check for prefix
            CAmount balance = 0;
            for (auto txout : pair.second) { // Compute balance of asset by summing all Available Outputs
                CAssetOutputEntry data;
                if (GetAssetData(txout.tx->vout[txout.i].scriptPubKey, data))
                    balance += data.nAmount;
            }
            amounts.insert(std::make_pair(pair.first, balance));
        }
    }

    return true;
}

bool GetMyAssetBalance(const std::string& name, CAmount& balance, const int& confirmations) {

    // Return false if no wallet was found to compute asset balances
    if (!vpwalletRegistered.size())
        return false;

    // Get the map of assetnames to outputs
    std::map<std::string, std::vector<COutput> > outputs;
    vpwalletRegistered[0]->AvailableAssets(outputs, true, nullptr, 1, MAX_MONEY, MAX_MONEY, 0, confirmations);

    // Loop through all pairs of Asset Name -> vector<COutput>
    if (outputs.count(name)) {
        auto& ref = outputs.at(name);
        for (const auto& txout : ref) {
            CAssetOutputEntry data;
            if (GetAssetData(txout.tx->vout[txout.i].scriptPubKey, data)) {
                balance += data.nAmount;
            }
        }
    }

    return true;
}

bool CreateAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const CNewAsset& asset, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired)
{
    std::vector<CNewAsset> assets;
    assets.push_back(asset);
    return CreateAssetTransaction(pwallet, coinControl, assets, address, error, wtxNew, reservekey, nFeeRequired);
}

bool CreateAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const std::vector<CNewAsset> assets, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired)
{
    std::string change_address = EncodeDestination(coinControl.destChange);

    auto currentActiveAssetCache = GetCurrentAssetCache();
    // Validate the assets data
    std::string strError;
    for (auto asset : assets) {
        if (!ContextualCheckNewAsset(currentActiveAssetCache, asset, strError)) {
            error = std::make_pair(RPC_INVALID_PARAMETER, strError);
            return false;
        }
    }

    if (!change_address.empty()) {
        CTxDestination destination = DecodeDestination(change_address);
        if (!IsValidDestination(destination)) {
            error = std::make_pair(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Raven address: ") + change_address);
            return false;
        }
    } else {
        // no coin control: send change to newly generated address
        CKeyID keyID;
        std::string strFailReason;
        if (!pwallet->CreateNewChangeAddress(reservekey, keyID, strFailReason)) {
            error = std::make_pair(RPC_WALLET_KEYPOOL_RAN_OUT, strFailReason);
            return false;
        }

        change_address = EncodeDestination(keyID);
        coinControl.destChange = DecodeDestination(change_address);
    }

    AssetType assetType;
    std::string parentName;
    for (auto asset : assets) {
        if (!IsAssetNameValid(asset.strName, assetType)) {
            error = std::make_pair(RPC_INVALID_PARAMETER, "Asset name not valid");
            return false;
        }
        if (assets.size() > 1 && assetType != AssetType::UNIQUE) {
            error = std::make_pair(RPC_INVALID_PARAMETER, "Only unique assets can be issued in bulk.");
            return false;
        }
        std::string parent = GetParentName(asset.strName);
        if (parentName.empty())
            parentName = parent;
        if (parentName != parent) {
            error = std::make_pair(RPC_INVALID_PARAMETER, "All assets must have the same parent.");
            return false;
        }
    }

    // Assign the correct lock amount and the correct lock address depending on the type of asset issuance that is happening
    // Currently, the lock address is same as the change address
    CAmount lockAmount = GetLockAmount(assetType) * assets.size();
    const CKeyID& keyID = boost::get<CKeyID>(coinControl.destChange);
    CScript feeLockScriptPubKey;
    feeLockScriptPubKey.SetCsvP2PKH(feeLockTime, keyID);

    CAmount curBalance = pwallet->GetBalance();

    // Check to make sure the wallet has the YAC required by the lockAmount
    if (curBalance < lockAmount) {
        error = std::make_pair(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
        return false;
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    // Create and send the transaction
    std::string strTxError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    bool fSubtractFeeFromAmount = false;

    CRecipient recipient = {feeLockScriptPubKey, lockAmount, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);

    // If the asset is a subasset or unique asset. We need to send the ownertoken change back to ourselfs
    // Currently, the address containing owner asset is same as the change address
    if (assetType == AssetType::SUB || assetType == AssetType::UNIQUE) {
        // Get the script for the destination address for the assets
        CScript scriptTransferOwnerAsset = GetScriptForDestination(DecodeDestination(change_address));

        CAssetTransfer assetTransfer(parentName + OWNER_TAG, OWNER_ASSET_AMOUNT);
        assetTransfer.ConstructTransaction(scriptTransferOwnerAsset);
        CRecipient rec = {scriptTransferOwnerAsset, 0, fSubtractFeeFromAmount};
        vecSend.push_back(rec);
    }

    // Get the owner outpoints if this is a subasset or unique asset
    if (assetType == AssetType::SUB || assetType == AssetType::UNIQUE) {
        // Verify that this wallet is the owner for the asset, and get the owner asset outpoint
        for (auto asset : assets) {
            if (!VerifyWalletHasAsset(parentName + OWNER_TAG, error)) {
                return false;
            }
        }
    }

    if (!pwallet->CreateTransactionWithAssets(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strTxError, coinControl, assets, DecodeDestination(address), assetType)) {
        if (!fSubtractFeeFromAmount && lockAmount + nFeeRequired > curBalance)
            strTxError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        error = std::make_pair(RPC_WALLET_ERROR, strTxError);
        return false;
    }
    return true;
}

bool CreateReissueAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const CReissueAsset& reissueAsset, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired)
{
    // Create transaction variables
    std::string strTxError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    bool fSubtractFeeFromAmount = false;

    // Create asset variables
    std::string asset_name = reissueAsset.strName;
    std::string change_address = EncodeDestination(coinControl.destChange);

    // Get the asset type
    AssetType asset_type = AssetType::INVALID;
    IsAssetNameValid(asset_name, asset_type);

    // Check that validitity of the address
    if (!IsValidDestinationString(address)) {
        error = std::make_pair(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Raven address: ") + address);
        return false;
    }

    // Build the change address
    if (!change_address.empty()) {
        CTxDestination destination = DecodeDestination(change_address);
        if (!IsValidDestination(destination)) {
            error = std::make_pair(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Raven address: ") + change_address);
            return false;
        }
    } else {
        CKeyID keyID;
        std::string strFailReason;
        if (!pwallet->CreateNewChangeAddress(reservekey, keyID, strFailReason)) {
            error = std::make_pair(RPC_WALLET_KEYPOOL_RAN_OUT, strFailReason);
            return false;
        }

        change_address = EncodeDestination(keyID);
        coinControl.destChange = DecodeDestination(change_address);
    }

    // Check the assets name
    if (!IsAssetNameValid(asset_name)) {
        error = std::make_pair(RPC_INVALID_PARAMS, std::string("Invalid asset name: ") + asset_name);
        return false;
    }

    // Check to make sure this isn't an owner token
    if (IsAssetNameAnOwner(asset_name)) {
        error = std::make_pair(RPC_INVALID_PARAMS, std::string("Owner Assets are not able to be reissued"));
        return false;
    }

    // passets and passetsCache need to be initialized
    auto currentActiveAssetCache = GetCurrentAssetCache();
    if (!currentActiveAssetCache) {
        error = std::make_pair(RPC_DATABASE_ERROR, std::string("passets isn't initialized"));
        return false;
    }

    // Fail if the asset cache isn't initialized
    if (!passetsCache) {
        error = std::make_pair(RPC_DATABASE_ERROR,
                               std::string("passetsCache isn't initialized"));
        return false;
    }

    // Check to make sure that the reissue asset data is valid
    std::string strError;
    if (!ContextualCheckReissueAsset(currentActiveAssetCache, reissueAsset, strError)) {
        error = std::make_pair(RPC_VERIFY_ERROR,
                               std::string("Failed to create reissue asset object. Error: ") + strError);
        return false;
    }

    // strip of the first character of the asset name, this is used for restricted assets only
    std::string stripped_asset_name = asset_name.substr(1, asset_name.size() - 1);

    // Verify that this wallet is the owner for the asset, and get the owner asset outpoint
    if (!VerifyWalletHasAsset(asset_name + OWNER_TAG, error)) {
        return false;
    }

    // Check the wallet balance
    CAmount curBalance = pwallet->GetBalance();

    // Get the current lock amount for issuing an asset
    CAmount lockAmount = GetReissueAssetLockAmount();

    // Check to make sure the wallet has the YAC required by the lockAmount
    if (curBalance < lockAmount) {
        error = std::make_pair(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
        return false;
    }

    // Get the script for the destination address for the assets
    CScript scriptTransferOwnerAsset = GetScriptForDestination(DecodeDestination(change_address));

    CAssetTransfer assetTransfer(asset_name + OWNER_TAG, OWNER_ASSET_AMOUNT);
    assetTransfer.ConstructTransaction(scriptTransferOwnerAsset);
    CRecipient recipient2 = {scriptTransferOwnerAsset, 0, fSubtractFeeFromAmount};
    vecSend.push_back(recipient2);

    // TODO: Locked coin
//    // Get the script for the lock address
//    CScript scriptPubKeyBurn = GetScriptForDestination(DecodeDestination(GetParams().ReissueAssetLockAddress()));
//    // Create and send the transaction
//    CRecipient recipient = {scriptPubKeyBurn, lockAmount, fSubtractFeeFromAmount};
//    vecSend.push_back(recipient);

    if (!pwallet->CreateTransactionWithReissueAsset(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strTxError, coinControl, reissueAsset, DecodeDestination(address))) {
        if (!fSubtractFeeFromAmount && lockAmount + nFeeRequired > curBalance)
            strTxError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        error = std::make_pair(RPC_WALLET_ERROR, strTxError);
        return false;
    }
    return true;
}


bool CreateTransferAssetTransaction(CWallet* pwallet, const CCoinControl& coinControl, const std::vector< std::pair<CAssetTransfer, std::string> >vTransfers, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired)
{
    // Initialize Values for transaction
    std::string strTxError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    bool fSubtractFeeFromAmount = false;

    // Check for a balance before processing transfers
    CAmount curBalance = pwallet->GetBalance();
    if (curBalance == 0) {
        error = std::make_pair(RPC_WALLET_INSUFFICIENT_FUNDS, std::string("This wallet doesn't contain any YAC, transfering an asset requires a network fee"));
        return false;
    }

    // Loop through all transfers and create scriptpubkeys for them
    for (auto transfer : vTransfers) {
        std::string address = transfer.second;
        std::string asset_name = transfer.first.strName;
        CAmount nAmount = transfer.first.nAmount;

        if (!IsValidDestinationString(address)) {
            error = std::make_pair(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Raven address: ") + address);
            return false;
        }
        auto currentActiveAssetCache = GetCurrentAssetCache();
        if (!currentActiveAssetCache) {
            error = std::make_pair(RPC_DATABASE_ERROR, std::string("passets isn't initialized"));
            return false;
        }

        if (!VerifyWalletHasAsset(asset_name, error)) // Sets error if it fails
            return false;

        // If it is an ownership transfer, make a quick check to make sure the amount is 1
        if (IsAssetNameAnOwner(asset_name)) {
            if (nAmount != OWNER_ASSET_AMOUNT) {
                error = std::make_pair(RPC_INVALID_PARAMS, std::string(
                        _("When transferring an 'Ownership Asset' the amount must always be 1. Please try again with the amount of 1")));
                return false;
            }
        }

        // Get the script for the lock address
        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(address));

        // Update the scriptPubKey with the transfer asset information
        CAssetTransfer assetTransfer(asset_name, nAmount);
        assetTransfer.ConstructTransaction(scriptPubKey);

        CRecipient recipient = {scriptPubKey, 0, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    // Create and send the transaction
    /*
     *  coinControl: contain RVN change address and asset change address
        vTransfers: contains receiver's address and asset transfer info
     */
    if (!pwallet->CreateTransactionWithTransferAsset(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strTxError, coinControl)) {
        if (!fSubtractFeeFromAmount && nFeeRequired > curBalance) {
            error = std::make_pair(RPC_WALLET_ERROR, strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired)));
            return false;
        }
        error = std::make_pair(RPC_TRANSACTION_ERROR, strTxError);
        return false;
    }
    return true;
}

bool SendAssetTransaction(CWallet* pwallet, CWalletTx& transaction, CReserveKey& reserveKey, std::pair<int, std::string>& error, std::string& txid)
{
    CValidationState state;
    if (!pwallet->CommitTransaction(transaction, reserveKey)) {
        error = std::make_pair(RPC_WALLET_ERROR, strprintf("Error: The transaction %s was rejected!", transaction.GetHash().GetHex().c_str()));
        return false;
    }

    txid = transaction.GetHash().GetHex();
    return true;
}

bool VerifyWalletHasAsset(const std::string& asset_name, std::pair<int, std::string>& pairError)
{
    CWallet* pwallet;
    if (vpwalletRegistered.size() > 0)
        pwallet = vpwalletRegistered[0];
    else {
        pairError = std::make_pair(RPC_WALLET_ERROR, strprintf("Wallet not found. Can't verify if it contains: %s", asset_name));
        return false;
    }

    std::vector<COutput> vCoins;
    std::map<std::string, std::vector<COutput> > mapAssetCoins;
    pwallet->AvailableAssets(mapAssetCoins);

    if (mapAssetCoins.count(asset_name))
        return true;

    pairError = std::make_pair(RPC_INVALID_REQUEST, strprintf("Wallet doesn't have asset: %s", asset_name));
    return false;
}

// Return true if the amount is valid with the units passed in
bool CheckAmountWithUnits(const CAmount& nAmount, const int8_t nUnits)
{
    return nAmount % int64_t(pow(10, (MAX_UNIT - nUnits))) == 0;
}

bool CheckEncoded(const std::string& hash, std::string& strError) {
    std::string encodedStr = EncodeAssetData(hash);
    if (encodedStr.substr(0, 2) == "Qm" && encodedStr.size() == 46) {
        return true;
    }

    strError = _("Invalid parameter: ipfs_hash is not valid, or txid hash is not the right length");

    return false;
}

void GetTxOutAssetTypes(const std::vector<CTxOut>& vout, int& issues, int& reissues, int& transfers, int& owners)
{
    for (auto out: vout) {
        int type;
        bool fIsOwner;
        if (out.scriptPubKey.IsAssetScript(type, fIsOwner)) {
            if (type == TX_NEW_ASSET && !fIsOwner)
                issues++;
            else if (type == TX_NEW_ASSET && fIsOwner)
                owners++;
            else if (type == TX_TRANSFER_ASSET)
                transfers++;
            else if (type == TX_REISSUE_ASSET)
                reissues++;
        }
    }
}

bool ParseAssetScript(CScript scriptPubKey, uint160 &hashBytes, std::string &assetName, CAmount &assetAmount) {
    int nType;
    bool fIsOwner;
    int _nStartingPoint;
    std::string _strAddress;
    bool isAsset = false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, _nStartingPoint)) {
        if (nType == TX_NEW_ASSET) {
            if (fIsOwner) {
                if (OwnerAssetFromScript(scriptPubKey, assetName, _strAddress)) {
                    assetAmount = OWNER_ASSET_AMOUNT;
                    isAsset = true;
                } else {
                    printf("%s : Couldn't get new owner asset from script: %s", __func__, HexStr(scriptPubKey));
                }
            } else {
                CNewAsset asset;
                if (AssetFromScript(scriptPubKey, asset, _strAddress)) {
                    assetName = asset.strName;
                    assetAmount = asset.nAmount;
                    isAsset = true;
                } else {
                    printf("%s : Couldn't get new asset from script: %s", __func__, HexStr(scriptPubKey));
                }
            }
        } else if (nType == TX_REISSUE_ASSET) {
            CReissueAsset asset;
            if (ReissueAssetFromScript(scriptPubKey, asset, _strAddress)) {
                assetName = asset.strName;
                assetAmount = asset.nAmount;
                isAsset = true;
            } else {
                printf("%s : Couldn't get reissue asset from script: %s", __func__, HexStr(scriptPubKey));
            }
        } else if (nType == TX_TRANSFER_ASSET) {
            CAssetTransfer asset;
            if (TransferAssetFromScript(scriptPubKey, asset, _strAddress)) {
                assetName = asset.strName;
                assetAmount = asset.nAmount;
                isAsset = true;
            } else {
                printf("%s : Couldn't get transfer asset from script: %s", __func__, HexStr(scriptPubKey));
            }
        } else {
            printf("%s : Unsupported asset type: %s", __func__, nType);
        }
    } else {
//        printf("%s : Found no asset in script: %s", __func__, HexStr(scriptPubKey));
    }
    if (isAsset) {
//        printf("%s : Found assets in script at address %s : %s (%s)", __func__, _strAddress, assetName, assetAmount);
        hashBytes = uint160(std::vector <unsigned char>(scriptPubKey.begin()+3, scriptPubKey.begin()+23));
        return true;
    }
    return false;
}

bool ContextualCheckTransferAsset(CAssetsCache* assetCache, const CAssetTransfer& transfer, const std::string& address, std::string& strError)
{
    strError = "";
    AssetType assetType;
    if (!IsAssetNameValid(transfer.strName, assetType)) {
        strError = "Invalid parameter: asset_name must only consist of valid characters and have a size between 3 and 30 characters. See help for more details.";
        return false;
    }

    if (transfer.nAmount <= 0) {
        strError = "Invalid parameter: asset amount can't be equal to or less than zero.";
        return false;
    }

    return true;
}

bool CheckNewAsset(const CNewAsset& asset, std::string& strError)
{
    strError = "";

    AssetType assetType;
    if (!IsAssetNameValid(std::string(asset.strName), assetType)) {
        strError = _("Invalid parameter: asset_name must only consist of valid characters and have a size between 3 and 30 characters. See help for more details.");
        return false;
    }

    if (assetType == AssetType::UNIQUE) {
        if (asset.units != UNIQUE_ASSET_UNITS) {
            strError = _("Invalid parameter: units must be ") + std::to_string(UNIQUE_ASSET_UNITS);
            return false;
        }
        if (asset.nAmount != UNIQUE_ASSET_AMOUNT) {
            strError = _("Invalid parameter: amount must be ") + std::to_string(UNIQUE_ASSET_AMOUNT);
            return false;
        }
        if (asset.nReissuable != 0) {
            strError = _("Invalid parameter: reissuable must be 0");
            return false;
        }
    }

    if (IsAssetNameAnOwner(std::string(asset.strName))) {
        strError = _("Invalid parameters: asset_name can't have a '!' at the end of it. See help for more details.");
        return false;
    }

    if (asset.nAmount <= 0) {
        strError = _("Invalid parameter: asset amount can't be equal to or less than zero.");
        return false;
    }

    if (asset.nAmount > MAX_MONEY) {
        strError = _("Invalid parameter: asset amount greater than max money: ") + std::to_string(MAX_MONEY / COIN);
        return false;
    }

    if (asset.units < 0 || asset.units > 8) {
        strError = _("Invalid parameter: units must be between 0-8.");
        return false;
    }

    if (!CheckAmountWithUnits(asset.nAmount, asset.units)) {
        strError = _("Invalid parameter: amount must be divisible by the smaller unit assigned to the asset");
        return false;
    }

    if (asset.nReissuable != 0 && asset.nReissuable != 1) {
        strError = _("Invalid parameter: reissuable must be 0 or 1");
        return false;
    }

    if (asset.nHasIPFS != 0 && asset.nHasIPFS != 1) {
        strError = _("Invalid parameter: has_ipfs must be 0 or 1.");
        return false;
    }

    return true;
}

bool ContextualCheckNewAsset(CAssetsCache* assetCache, const CNewAsset& asset, std::string& strError, bool fCheckMempool)
{
    if (!AreAssetsDeployed()) {
        strError = "bad-txns-new-asset-when-assets-is-not-active";
        return false;
    }

    if (!CheckNewAsset(asset, strError))
        return false;

    // Check our current cache to see if the asset has been created yet
    if (assetCache->CheckIfAssetExists(asset.strName, true)) {
        strError = std::string(_("Invalid parameter: asset_name '")) + asset.strName + std::string(_("' has already been used"));
        return false;
    }

    // Check the mempool
    if (fCheckMempool) {
        if (mempool.mapAssetToHash.count(asset.strName)) {
            strError = _("Asset with this name is already in the mempool");
            return false;
        }
    }

    // Check the ipfs hash as it changes when messaging goes active
    if (asset.nHasIPFS && asset.strIPFSHash.size() != 34) {
        strError = _("Invalid parameter: ipfs_hash must be 46 characters. Txid must be valid 64 character hash");
        return false;
    }

    if (asset.nHasIPFS) {
        if (!CheckEncoded(asset.strIPFSHash, strError))
            return false;
    }

    return true;
}

bool CheckReissueAsset(const CReissueAsset& asset, std::string& strError)
{
    strError = "";

    if (asset.nAmount < 0 || asset.nAmount >= MAX_MONEY) {
        strError = _("Unable to reissue asset: amount must be 0 or larger");
        return false;
    }

    if (asset.nUnits > MAX_UNIT || asset.nUnits < -1) {
        strError = _("Unable to reissue asset: unit must be between 8 and -1");
        return false;
    }

    if (asset.nReissuable != 0 && asset.nReissuable != 1) {
        strError = _("Unable to reissue asset: reissuable must be 0 or 1");
        return false;
    }

    AssetType type;
    IsAssetNameValid(asset.strName, type);

    return true;
}

bool ContextualCheckReissueAsset(CAssetsCache* assetCache, const CReissueAsset& reissue_asset, std::string& strError, const CTransaction& tx)
{
    // We are using this just to get the strAddress
    CReissueAsset reissue;
    std::string strAddress;
    if (!ReissueAssetFromTransaction(tx, reissue, strAddress)) {
        strError = "bad-txns-reissue-asset-contextual-check";
        return false;
    }

    // run non contextual checks
    if (!CheckReissueAsset(reissue_asset, strError))
        return false;

    // Check previous asset data with the reissuesd data
    CNewAsset prev_asset;
    if (!assetCache->GetAssetMetaDataIfExists(reissue_asset.strName, prev_asset)) {
        strError = _("Unable to reissue asset: asset_name '") + reissue_asset.strName + _("' doesn't exist in the database");
        return false;
    }

    if (!prev_asset.nReissuable) {
        // Check to make sure the asset can be reissued
        strError = _("Unable to reissue asset: reissuable is set to false");
        return false;
    }

    if (prev_asset.nAmount + reissue_asset.nAmount > MAX_MONEY) {
        strError = _("Unable to reissue asset: asset_name '") + reissue_asset.strName +
                   _("' the amount trying to reissue is to large");
        return false;
    }

    if (!CheckAmountWithUnits(reissue_asset.nAmount, prev_asset.units)) {
        strError = _("Unable to reissue asset: amount must be divisible by the smaller unit assigned to the asset");
        return false;
    }

    if (reissue_asset.nUnits < prev_asset.units && reissue_asset.nUnits != -1) {
        strError = _("Unable to reissue asset: unit must be larger than current unit selection");
        return false;
    }

    // Check the ipfs hash
    if (reissue_asset.strIPFSHash != "" && reissue_asset.strIPFSHash.size() != 34) {
        strError = _("Invalid parameter: ipfs_hash must be 34 bytes");
        return false;
    }

    if (reissue_asset.strIPFSHash != "") {
        if (!CheckEncoded(reissue_asset.strIPFSHash, strError))
            return false;
    }

    return true;
}

bool ContextualCheckReissueAsset(CAssetsCache* assetCache, const CReissueAsset& reissue_asset, std::string& strError)
{
    // run non contextual checks
    if (!CheckReissueAsset(reissue_asset, strError))
        return false;

    // Check previous asset data with the reissuesd data
    if (assetCache) {
        CNewAsset prev_asset;
        if (!assetCache->GetAssetMetaDataIfExists(reissue_asset.strName, prev_asset)) {
            strError = _("Unable to reissue asset: asset_name '") + reissue_asset.strName +
                       _("' doesn't exist in the database");
            return false;
        }

        if (!prev_asset.nReissuable) {
            // Check to make sure the asset can be reissued
            strError = _("Unable to reissue asset: reissuable is set to false");
            return false;
        }

        if (prev_asset.nAmount + reissue_asset.nAmount > MAX_MONEY) {
            strError = _("Unable to reissue asset: asset_name '") + reissue_asset.strName +
                       _("' the amount trying to reissue is to large");
            return false;
        }

        if (!CheckAmountWithUnits(reissue_asset.nAmount, prev_asset.units)) {
            strError = _("Unable to reissue asset: amount must be divisible by the smaller unit assigned to the asset");
            return false;
        }

        if (reissue_asset.nUnits < prev_asset.units && reissue_asset.nUnits != -1) {
            strError = _("Unable to reissue asset: unit must be larger than current unit selection");
            return false;
        }
    }

    // Check the ipfs hash
    if (reissue_asset.strIPFSHash != "" && reissue_asset.strIPFSHash.size() != 34) {
        strError = _("Invalid parameter: ipfs_hash must be 34 bytes");
        return false;
    }

    if (reissue_asset.strIPFSHash != "") {
        if (!CheckEncoded(reissue_asset.strIPFSHash, strError))
            return false;
    }

    return true;
}

bool ContextualCheckUniqueAssetTx(CAssetsCache* assetCache, std::string& strError, const CTransaction& tx)
{
    for (auto out : tx.vout)
    {
        if (IsScriptNewUniqueAsset(out.scriptPubKey))
        {
            CNewAsset asset;
            std::string strAddress;
            if (!AssetFromScript(out.scriptPubKey, asset, strAddress)) {
                strError = "bad-txns-issue-unique-serialization-failed";
                return false;
            }

            if (!ContextualCheckUniqueAsset(assetCache, asset, strError))
                return false;
        }
    }

    return true;
}

bool ContextualCheckUniqueAsset(CAssetsCache* assetCache, const CNewAsset& unique_asset, std::string& strError)
{
    if (!ContextualCheckNewAsset(assetCache, unique_asset, strError))
        return false;

    return true;
}

std::string GetUserErrorString(const ErrorReport& report)
{
    switch (report.type) {
        case ErrorReport::ErrorType::NotSetError: return _("Error not set");
        case ErrorReport::ErrorType::InvalidQualifierName: return _("Invalid Qualifier Name: ") + report.vecUserData[0];
        case ErrorReport::ErrorType::EmptyString: return _("Verifier string is empty");
        case ErrorReport::ErrorType::LengthToLarge: return _("Length is to large. Please use a smaller length");
        case ErrorReport::ErrorType::InvalidSubExpressionFormula: return _("Invalid expressions in verifier string: ") + report.vecUserData[0];
        case ErrorReport::ErrorType::InvalidSyntax: return _("Invalid syntax: ") + report.vecUserData[0];
        case ErrorReport::ErrorType::AssetDoesntExist: return _("Asset doesn't exist: ") + report.vecUserData[0];
        case ErrorReport::ErrorType::FailedToVerifyAgainstAddress: return _("This address doesn't contain the correct tags to pass the verifier string check: ") + report.vecUserData[0];
        case ErrorReport::ErrorType::EmptySubExpression: return _("The verifier string has two operators without a tag between them");
        case ErrorReport::ErrorType::UnknownOperator: return _("The symbol: '") + report.vecUserData[0] + _("' is not a valid character in the expression: ") + report.vecUserData[1];
        case ErrorReport::ErrorType::ParenthesisParity: return _("Every '(' must have a corresponding ')' in the expression: ") + report.vecUserData[0];
        case ErrorReport::ErrorType::VariableNotFound: return _("Variable is not allow in the expression: '") + report.vecUserData[0] + "'";;
        default:
            return _("Error not set");
    }
}
