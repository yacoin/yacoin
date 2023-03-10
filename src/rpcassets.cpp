// Copyright (c) 2017-2021 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "assets/assets.h"
#include "assets/assetdb.h"
#include "bitcoinrpc.h"
#include "coincontrol.h"
#include "init.h"
#include "script/script.h"
#include "txdb.h"
#include "wallet.h"

#include <boost/assign/list_of.hpp>
#include <map>

using namespace json_spirit;

using std::runtime_error;
using std::string;
using std::map;
using std::list;
using std::vector;
using std::set;
using std::pair;
using std::max;
using std::min;

std::string AssetActivationWarning()
{
    return AreAssetsDeployed() ? "" : "\nTHIS COMMAND IS NOT YET ACTIVE!\nhttps://github.com/RavenProject/rips/blob/master/rip-0002.mediawiki\n";
}

std::string AssetTypeToString(AssetType& assetType)
{
    switch (assetType)
    {
        case AssetType::ROOT:               return "ROOT";
        case AssetType::SUB:                return "SUB";
        case AssetType::UNIQUE:             return "UNIQUE";
        case AssetType::OWNER:              return "OWNER";
        case AssetType::VOTE:               return "VOTE";
        case AssetType::REISSUE:            return "REISSUE";
        case AssetType::INVALID:            return "INVALID";
        default:                            return "UNKNOWN";
    }
}

Value issue(const Array& params, bool fHelp)
{
    if (fHelp || !AreAssetsDeployed() || params.size() < 1 || params.size() > 8)
        throw runtime_error(
            "issue \"asset_name\" qty \"( to_address )\" \"( change_address )\" ( units ) ( reissuable ) ( has_ipfs ) \"( ipfs_hash )\"\n"
            + AssetActivationWarning() +
            "\nIssue an asset, subasset or unique asset.\n"
            "Asset name must not conflict with any existing asset.\n"
            "Unit as the number of decimals precision for the asset (0 for whole units (\"1\"), 8 for max precision (\"1.00000000\")\n"
            "Reissuable is true/false for whether additional units can be issued by the original issuer.\n"
            "If issuing a unique asset these values are required (and will be defaulted to): qty=1, units=0, reissuable=false.\n"

            "\nArguments:\n"
            "1. \"asset_name\"            (string, required) a unique name\n"
            "2. \"qty\"                   (numeric, optional, default=1) the number of units to be issued\n"
            "3. \"to_address\"            (string), optional, default=\"\"), address asset will be sent to, if it is empty, address will be generated for you\n"
            "4. \"change_address\"        (string), optional, default=\"\"), address the the rvn change will be sent to, if it is empty, change address will be generated for you\n"
            "5. \"units\"                 (integer, optional, default=0, min=0, max=8), the number of decimals precision for the asset (0 for whole units (\"1\"), 8 for max precision (\"1.00000000\")\n"
            "6. \"reissuable\"            (boolean, optional, default=true (false for unique assets)), whether future reissuance is allowed\n"
            "7. \"has_ipfs\"              (boolean, optional, default=false), whether ipfs hash is going to be added to the asset\n"
            "8. \"ipfs_hash\"             (string, optional but required if has_ipfs = 1), an ipfs hash or a txid hash once RIP5 is activated\n"

            "\nResult:\n"
            "\"txid\"                     (string) The transaction id\n"

            "\nExamples:\n"
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000")
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\"")
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" 4")
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" 2 true")
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" 8 false true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E")
            + HelpExampleCli("issue", "\"ASSET_NAME/SUB_ASSET\" 1000 \"myaddress\" \"changeaddress\" 2 true")
            + HelpExampleCli("issue", "\"ASSET_NAME#uniquetag\"")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Check asset name and infer assetType
    std::string assetName = params[0].get_str();
    AssetType assetType;
    std::string assetError = "";
    if (!IsAssetNameValid(assetName, assetType, assetError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset name: ") + assetName + std::string("\nError: ") + assetError);
    }

    // Check for unsupported asset types
    if (assetType == AssetType::VOTE || assetType == AssetType::REISSUE || assetType == AssetType::OWNER || assetType == AssetType::INVALID) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Unsupported asset type: ") + AssetTypeToString(assetType));
    }

    CAmount nAmount = COIN;
    if (params.size() > 1)
        nAmount = AmountFromValue(params[1]);

    std::string address = "";
    if (params.size() > 2)
        address = params[2].get_str();

    if (!address.empty()) {
        CTxDestination destination = DecodeDestination(address);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Raven address: ") + address);
        }
    } else {
        // Create a new address
        std::string strAccount;

        if (!pwalletMain->IsLocked()) {
            pwalletMain->TopUpKeyPool();
        }

        // Generate a new key that is added to wallet
        CPubKey newKey;
        if (!pwalletMain->GetKeyFromPool(newKey)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
        }
        CKeyID keyID = newKey.GetID();

        pwalletMain->SetAddressBookName(keyID, strAccount);

        address = EncodeDestination(keyID);
    }

    std::string change_address = "";
    if (params.size() > 3) {
        change_address = params[3].get_str();
        if (!change_address.empty()) {
            CTxDestination destination = DecodeDestination(change_address);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   std::string("Invalid Change Address: Invalid Raven address: ") + change_address);
            }
        }
    }

    int units = 0;
    if (params.size() > 4)
        units = params[4].get_int();

    bool reissuable = assetType != AssetType::UNIQUE;
    if (params.size() > 5)
        reissuable = params[5].get_bool();

    bool has_ipfs = false;
    if (params.size() > 6)
        has_ipfs = params[6].get_bool();

    // Check the ipfs
    std::string ipfs_hash = "";
    if (params.size() > 7 && has_ipfs) {
        ipfs_hash = params[7].get_str();
        if (ipfs_hash.length() != 46)
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid IPFS hash (must be 46 characters)"));
        if (ipfs_hash.substr(0,2) != "Qm")
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid IPFS hash (doesn't start with 'Qm')"));
    }

    // check for required unique asset params
    if (assetType == AssetType::UNIQUE && (nAmount != COIN || units != 0 || reissuable)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters for issuing a unique asset."));
    }

    CNewAsset asset(assetName, nAmount, units, reissuable ? 1 : 0, has_ipfs ? 1 : 0, DecodeAssetData(ipfs_hash));

    CReserveKey reservekey(pwalletMain);
    CWalletTx transaction;
    CAmount nRequiredFee;
    std::pair<int, std::string> error;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(change_address);

    // Create the Transaction
    if (!CreateAssetTransaction(pwalletMain, crtl, asset, address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwalletMain, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    return txid;
}

Value transfer(const Array& params, bool fHelp)
{
    if (fHelp || !AreAssetsDeployed() || params.size() < 3 || params.size() > 5)
        throw std::runtime_error(
                "transfer \"asset_name\" qty \"to_address\" \"change_address\" \"asset_change_address\"\n"
                + AssetActivationWarning() +
                "\nTransfers a quantity of an owned asset to a given address"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of asset\n"
                "2. \"qty\"                      (numeric, required) number of assets you want to send to the address\n"
                "3. \"to_address\"               (string, required) address to send the asset to\n"
                "4. \"change_address\"           (string, optional, default = \"\") the transactions RVN change will be sent to this address\n"
                "5. \"asset_change_address\"     (string, optional, default = \"\") the transactions Asset change will be sent to this address\n"

                "\nResult:\n"
                "txid"
                "[ \n"
                "txid\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("transfer", "\"ASSET_NAME\" 20 \"address\"")
                + HelpExampleCli("transfer", "\"ASSET_NAME\" 20 \"address\"")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    std::string asset_name = params[0].get_str();

    CAmount nAmount = AmountFromValue(params[1]);

    std::string to_address = params[2].get_str();
    CTxDestination to_dest = DecodeDestination(to_address);
    if (!IsValidDestination(to_dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Raven address: ") + to_address);
    }

    std::string rvn_change_address = "";
    if (params.size() > 3) {
        rvn_change_address = params[3].get_str();
    }

    std::string asset_change_address = "";
    if (params.size() > 4) {
        asset_change_address = params[4].get_str();
    }

    CTxDestination rvn_change_dest = DecodeDestination(rvn_change_address);
    if (!rvn_change_address.empty() && !IsValidDestination(rvn_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("RVN change address must be a valid address. Invalid address: ") + rvn_change_address);

    CTxDestination asset_change_dest = DecodeDestination(asset_change_address);
    if (!asset_change_address.empty() && !IsValidDestination(asset_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Asset change address must be a valid address. Invalid address: ") + asset_change_address);

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    CAssetTransfer transfer(asset_name, nAmount);

    vTransfers.emplace_back(std::make_pair(transfer, to_address));
    CReserveKey reservekey(pwalletMain);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;
    ctrl.destChange = rvn_change_dest;
    ctrl.assetDestChange = asset_change_dest;

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwalletMain, ctrl, vTransfers, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwalletMain, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    return txid;
}

Value transferfromaddress(const Array& params, bool fHelp)
{
    if (fHelp || !AreAssetsDeployed() || params.size() < 4 || params.size() > 6)
        throw std::runtime_error(
                "transferfromaddress \"asset_name\" \"from_address\" qty \"to_address\" \"rvn_change_address\" \"asset_change_address\"\n"
                + AssetActivationWarning() +
                "\nTransfer a quantity of an owned asset in a specific address to a given address"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of asset\n"
                "2. \"from_address\"             (string, required) address that the asset will be transferred from\n"
                "3. \"qty\"                      (numeric, required) number of assets you want to send to the address\n"
                "4. \"to_address\"               (string, required) address to send the asset to\n"
                "5. \"rvn_change_address\"       (string, optional, default = \"\") the transaction RVN change will be sent to this address\n"
                "6. \"asset_change_address\"     (string, optional, default = \"\") the transaction Asset change will be sent to this address\n"

                "\nResult:\n"
                "txid"
                "[ \n"
                "txid\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("transferfromaddress", "\"ASSET_NAME\" \"fromaddress\" 20 \"address\"")
                + HelpExampleRpc("transferfromaddress", "\"ASSET_NAME\" \"fromaddress\" 20 \"address\"")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    std::string asset_name = params[0].get_str();

    std::string from_address = params[1].get_str();

    // Check to make sure the given from address is valid
    CTxDestination dest = DecodeDestination(from_address);
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("From address must be valid addresses. Invalid address: ") + from_address);

    CAmount nAmount = AmountFromValue(params[2]);

    std::string address = params[3].get_str();

    std::string rvn_change_address = "";
    if (params.size() > 6) {
        rvn_change_address = params[6].get_str();
    }

    std::string asset_change_address = "";
    if (params.size() > 7) {
        asset_change_address = params[7].get_str();
    }

    CTxDestination rvn_change_dest = DecodeDestination(rvn_change_address);
    if (!rvn_change_address.empty() && !IsValidDestination(rvn_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("RVN change address must be a valid address. Invalid address: ") + rvn_change_address);

    CTxDestination asset_change_dest = DecodeDestination(asset_change_address);
    if (!asset_change_address.empty() && !IsValidDestination(asset_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Asset change address must be a valid address. Invalid address: ") + asset_change_address);


    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    vTransfers.emplace_back(std::make_pair(CAssetTransfer(asset_name, nAmount), address));
    CReserveKey reservekey(pwalletMain);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;
    std::map<std::string, std::vector<COutput> > mapAssetCoins;
    pwalletMain->AvailableAssets(mapAssetCoins);

    // Set the change addresses
    ctrl.destChange = rvn_change_dest;
    ctrl.assetDestChange = asset_change_dest;

    if (!mapAssetCoins.count(asset_name)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Wallet doesn't own the asset_name: " + asset_name));
    }

    // Add all the asset outpoints that match the given from addresses
    for (const auto& out : mapAssetCoins.at(asset_name)) {
        // Get the address that the coin resides in, because to send a valid message. You need to send it to the same address that it currently resides in.
        CTxDestination dest;
        ExtractDestination(out.tx->vout[out.i].scriptPubKey, dest);

        if (from_address == EncodeDestination(dest))
            ctrl.SelectAsset(COutPoint(out.tx->GetHash(), out.i));
    }

    std::vector<COutPoint> outs;
    ctrl.ListSelectedAssets(outs);
    if (!outs.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("No asset outpoints are selected from the given address, failed to create the transaction"));
    }

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwalletMain, ctrl, vTransfers, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwalletMain, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    return txid;
}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
