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
    return AreAssetsDeployed() ? "" : "\nTHIS COMMAND IS NOT YET ACTIVE!\n";
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

template <class Iter, class Incr>
void safe_advance(Iter& curr, const Iter& end, Incr n)
{
    size_t remaining(std::distance(curr, end));
    if (remaining < n)
    {
        n = remaining;
    }
    std::advance(curr, n);
};

Value issue(const Array& params, bool fHelp)
{
    if (fHelp || !AreAssetsDeployed() || params.size() < 1 || params.size() > 8)
        throw runtime_error(
            "issue \"asset_name\" qty \"( to_address )\" \"( change_address )\" ( units ) ( reissuable ) ( has_ipfs ) \"( ipfs_hash )\"\n"
            + AssetActivationWarning() +
            "\nIssue an asset, subasset or unique asset.\n"
            "Asset name must not conflict with any existing asset.\n"
            "Unit as the number of decimals precision for the asset (0 for whole units (\"1\"), 6 for max precision (\"1.000000\")\n"
            "Reissuable is true/false for whether additional units can be issued by the original issuer.\n"
            "If issuing a unique asset these values are required (and will be defaulted to): qty=1, units=0, reissuable=false.\n"

            "\nArguments:\n"
            "1. \"asset_name\"            (string, required) a unique name\n"
            "2. \"qty\"                   (numeric, optional, default=1) the number of units to be issued\n"
            "3. \"to_address\"            (string), optional, default=\"\"), address asset will be sent to, if it is empty, address will be generated for you\n"
            "4. \"change_address\"        (string), optional, default=\"\"), address the yac change will be sent to, if it is empty, change address will be generated for you\n"
            "5. \"units\"                 (integer, optional, default=0, min=0, max=6), the number of decimals precision for the asset (0 for whole units (\"1\"), 6 for max precision (\"1.000000\")\n"
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
            + HelpExampleCli("issue", "\"ASSET_NAME\" 1000 \"myaddress\" \"changeaddress\" 6 false true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E")
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
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Yacoin address: ") + address);
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
                                   std::string("Invalid Change Address: Invalid Yacoin address: ") + change_address);
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
                "4. \"change_address\"           (string, optional, default = \"\") the transactions YAC change will be sent to this address\n"
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
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Yacoin address: ") + to_address);
    }

    std::string yac_change_address = "";
    if (params.size() > 3) {
        yac_change_address = params[3].get_str();
    }

    std::string asset_change_address = "";
    if (params.size() > 4) {
        asset_change_address = params[4].get_str();
    }

    CTxDestination yac_change_dest = DecodeDestination(yac_change_address);
    if (!yac_change_address.empty() && !IsValidDestination(yac_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("YAC change address must be a valid address. Invalid address: ") + yac_change_address);

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
    ctrl.destChange = yac_change_dest;
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
                "transferfromaddress \"asset_name\" \"from_address\" qty \"to_address\" \"yac_change_address\" \"asset_change_address\"\n"
                + AssetActivationWarning() +
                "\nTransfer a quantity of an owned asset in a specific address to a given address"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of asset\n"
                "2. \"from_address\"             (string, required) address that the asset will be transferred from\n"
                "3. \"qty\"                      (numeric, required) number of assets you want to send to the address\n"
                "4. \"to_address\"               (string, required) address to send the asset to\n"
                "5. \"yac_change_address\"       (string, optional, default = \"\") the transaction YAC change will be sent to this address\n"
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

    std::string yac_change_address = "";
    if (params.size() > 6) {
        yac_change_address = params[6].get_str();
    }

    std::string asset_change_address = "";
    if (params.size() > 7) {
        asset_change_address = params[7].get_str();
    }

    CTxDestination yac_change_dest = DecodeDestination(yac_change_address);
    if (!yac_change_address.empty() && !IsValidDestination(yac_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("YAC change address must be a valid address. Invalid address: ") + yac_change_address);

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
    ctrl.destChange = yac_change_dest;
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

Value reissue(const Array& params, bool fHelp)
{
    if (fHelp || !AreAssetsDeployed() || params.size() > 7 || params.size() < 3)
        throw std::runtime_error(
                "reissue \"asset_name\" qty \"to_address\" \"change_address\" ( reissuable ) ( new_units) \"( new_ipfs )\" \n"
                + AssetActivationWarning() +
                "\nReissues a quantity of an asset to an owned address if you own the Owner Token"
                "\nCan change the reissuable flag during reissuance"
                "\nCan change the ipfs hash during reissuance"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of asset that is being reissued\n"
                "2. \"qty\"                      (numeric, required) number of assets to reissue\n"
                "3. \"to_address\"               (string, required) address to send the asset to\n"
                "4. \"change_address\"           (string, optional) address that the change of the transaction will be sent to\n"
                "5. \"reissuable\"               (boolean, optional, default=true), whether future reissuance is allowed\n"
                "6. \"new_units\"                (numeric, optional, default=-1), the new units that will be associated with the asset\n"
                "7. \"new_ipfs\"                 (string, optional, default=\"\"), whether to update the current ipfs hash or txid once RIP5 is active\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("reissue", "\"ASSET_NAME\" 20 \"address\"")
                + HelpExampleRpc("reissue", "\"ASSET_NAME\" 20 \"address\" \"change_address\" \"true\" 6 \"Qmd286K6pohQcTKYqnS1YhWrCiS4gz7Xi34sdwMe9USZ7u\"")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Get that paramaters
    std::string asset_name = params[0].get_str();
    CAmount nAmount = AmountFromValue(params[1]);
    std::string address = params[2].get_str();

    std::string changeAddress =  "";
    if (params.size() > 3)
        changeAddress = params[3].get_str();

    bool reissuable = true;
    if (params.size() > 4) {
        reissuable = params[4].get_bool();
    }

    int newUnits = -1;
    if (params.size() > 5) {
        newUnits = params[5].get_int();
    }

    std::string newipfs = "";
    if (params.size() > 6) {
        newipfs = params[6].get_str();
        if (newipfs.length() != 46)
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid IPFS hash (must be 46 characters)"));
        if (newipfs.substr(0,2) != "Qm")
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid IPFS hash (doesn't start with 'Qm')"));
        if (DecodeAssetData(newipfs).empty())
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid IPFS hash (contains invalid characters)"));
    }

    CReissueAsset reissueAsset(asset_name, nAmount, newUnits, reissuable, DecodeAssetData(newipfs));

    std::pair<int, std::string> error;
    CReserveKey reservekey(pwalletMain);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(changeAddress);

    // Create the Transaction
    if (!CreateReissueAssetTransaction(pwalletMain, crtl, reissueAsset, address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    std::string strError = "";
    if (!ContextualCheckReissueAsset(passets, reissueAsset, strError, transaction))
        throw JSONRPCError(RPC_INVALID_REQUEST, strError);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwalletMain, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    return txid;
}

Value listmyassets(const Array& params, bool fHelp)
{
    if (fHelp || !AreAssetsDeployed() || params.size() > 5)
        throw std::runtime_error(
                "listmyassets \"( asset )\" ( verbose ) ( count ) ( start ) (confs) \n"
                + AssetActivationWarning() +
                "\nReturns a list of all asset that are owned by this wallet\n"

                "\nArguments:\n"
                "1. \"asset\"                    (string, optional, default=\"*\") filters results -- must be an asset name or a partial asset name followed by '*' ('*' matches all trailing characters)\n"
                "2. \"verbose\"                  (boolean, optional, default=false) when false results only contain balances -- when true results include outpoints\n"
                "3. \"count\"                    (integer, optional, default=ALL) truncates results to include only the first _count_ assets found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ assets found (if negative it skips back from the end)\n"
                "5. \"confs\"                    (integet, optional, default=0) results are skipped if they don't have this number of confirmations\n"

                "\nResult (verbose=false):\n"
                "{\n"
                "  (asset_name): balance,\n"
                "  ...\n"
                "}\n"

                "\nResult (verbose=true):\n"
                "{\n"
                "  (asset_name):\n"
                "    {\n"
                "      \"balance\": balance,\n"
                "      \"outpoints\":\n"
                "        [\n"
                "          {\n"
                "            \"txid\": txid,\n"
                "            \"vout\": vout,\n"
                "            \"amount\": amount\n"
                "          }\n"
                "          {...}, {...}\n"
                "        ]\n"
                "    }\n"
                "}\n"
                "{...}, {...}\n"

                "\nExamples:\n"
                + HelpExampleRpc("listmyassets", "")
                + HelpExampleCli("listmyassets", "ASSET")
                + HelpExampleCli("listmyassets", "\"ASSET*\" true 10 20")
                  + HelpExampleCli("listmyassets", "\"ASSET*\" true 10 20 1")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    std::string filter = "*";
    if (params.size() > 0)
        filter = params[0].get_str();

    if (filter == "")
        filter = "*";

    bool verbose = false;
    if (params.size() > 1)
        verbose = params[1].get_bool();

    size_t count = INT_MAX;
    if (params.size() > 2) {
        if (params[2].get_int() < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be greater than 1.");
        count = params[2].get_int();
    }

    long start = 0;
    if (params.size() > 3) {
        start = params[3].get_int();
    }

    int confs = 0;
    if (params.size() > 4) {
        confs = params[4].get_int();
    }

    // retrieve balances
    std::map<std::string, CAmount> balances;
    std::map<std::string, std::vector<COutput> > outputs;
    if (filter == "*") {
        if (!GetAllMyAssetBalances(outputs, balances, confs))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset balances. For all assets");
    }
    else if (filter.back() == '*') {
        std::vector<std::string> assetNames;
        filter.pop_back();
        if (!GetAllMyAssetBalances(outputs, balances, confs, filter))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset balances. For all assets");
    }
    else {
        if (!IsAssetNameValid(filter))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset name.");
        if (!GetAllMyAssetBalances(outputs, balances, confs, filter))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset balances. For all assets");
    }

    // pagination setup
    auto bal = balances.begin();
    if (start >= 0)
        safe_advance(bal, balances.end(), (size_t)start);
    else
        safe_advance(bal, balances.end(), balances.size() + start);
    auto end = bal;
    safe_advance(end, balances.end(), count);

    // generate output
    Object result;
    if (verbose) {
        for (; bal != end && bal != balances.end(); bal++) {
            Object asset;
            asset.push_back(Pair("balance", AssetValueFromAmount(bal->second, bal->first)));

            Array outpoints;
            for (auto const& out : outputs.at(bal->first)) {
                Object tempOut;
                tempOut.push_back(Pair("txid", out.tx->GetHash().GetHex()));
                tempOut.push_back(Pair("vout", (int)out.i));

                //
                // get amount for this outpoint
                CAmount txAmount = 0;
                auto it = pwalletMain->mapWallet.find(out.tx->GetHash());
                if (it == pwalletMain->mapWallet.end()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
                }
                const CWalletTx* wtx = out.tx;
                CTxOut txOut = wtx->vout[out.i];
                std::string strAddress;
                if (CheckIssueDataTx(txOut)) {
                    CNewAsset asset;
                    if (!AssetFromScript(txOut.scriptPubKey, asset, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset from script.");
                    txAmount = asset.nAmount;
                }
                else if (CheckReissueDataTx(txOut)) {
                    CReissueAsset asset;
                    if (!ReissueAssetFromScript(txOut.scriptPubKey, asset, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset from script.");
                    txAmount = asset.nAmount;
                }
                else if (CheckTransferOwnerTx(txOut)) {
                    CAssetTransfer asset;
                    if (!TransferAssetFromScript(txOut.scriptPubKey, asset, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset from script.");
                    txAmount = asset.nAmount;
                }
                else if (CheckOwnerDataTx(txOut)) {
                    std::string assetName;
                    if (!OwnerAssetFromScript(txOut.scriptPubKey, assetName, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get asset from script.");
                    txAmount = OWNER_ASSET_AMOUNT;
                }
                tempOut.push_back(Pair("amount", AssetValueFromAmount(txAmount, bal->first)));
                //
                //

                outpoints.push_back(tempOut);
            }
            asset.push_back(Pair("outpoints", outpoints));
            result.push_back(Pair(bal->first, asset));
        }
    }
    else {
        for (; bal != end && bal != balances.end(); bal++) {
            result.push_back(Pair(bal->first, AssetValueFromAmount(bal->second, bal->first)));
        }
    }
    return result;
}

Value listassets(const Array& params, bool fHelp)
{
    if (fHelp || !AreAssetsDeployed() || params.size() > 4)
        throw std::runtime_error(
                "listassets \"( asset )\" ( verbose ) ( count ) ( start )\n"
                + AssetActivationWarning() +
                "\nReturns a list of all assets\n"
                "\nThis could be a slow/expensive operation as it reads from the database\n"

                "\nArguments:\n"
                "1. \"asset\"                    (string, optional, default=\"*\") filters results -- must be an asset name or a partial asset name followed by '*' ('*' matches all trailing characters)\n"
                "2. \"verbose\"                  (boolean, optional, default=false) when false result is just a list of asset names -- when true results are asset name mapped to metadata\n"
                "3. \"count\"                    (integer, optional, default=ALL) truncates results to include only the first _count_ assets found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ assets found (if negative it skips back from the end)\n"

                "\nResult (verbose=false):\n"
                "[\n"
                "  asset_name,\n"
                "  ...\n"
                "]\n"

                "\nResult (verbose=true):\n"
                "{\n"
                "  (asset_name):\n"
                "    {\n"
                "      amount: (number),\n"
                "      units: (number),\n"
                "      reissuable: (number),\n"
                "      has_ipfs: (number),\n"
                "      ipfs_hash: (hash) (only if has_ipfs = 1 and data is a ipfs hash)\n"
                "      ipfs_hash: (hash) (only if has_ipfs = 1 and data is a txid hash)\n"
                "    },\n"
                "  {...}, {...}\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleRpc("listassets", "")
                + HelpExampleCli("listassets", "ASSET")
                + HelpExampleCli("listassets", "\"ASSET*\" true 10 20")
        );

    if (!passetsdb)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "asset db unavailable.");

    std::string filter = "*";
    if (params.size() > 0)
        filter = params[0].get_str();

    if (filter == "")
        filter = "*";

    bool verbose = false;
    if (params.size() > 1)
        verbose = params[1].get_bool();

    size_t count = INT_MAX;
    if (params.size() > 2) {
        if (params[2].get_int() < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be greater than 1.");
        count = params[2].get_int();
    }

    long start = 0;
    if (params.size() > 3) {
        start = params[3].get_int();
    }

    std::vector<CDatabasedAssetData> assets;
    if (!passetsdb->AssetDir(assets, filter, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve asset directory.");

    Object resultObj;
    Array resultArr;

    for (auto data : assets) {
        CNewAsset asset = data.asset;
        if (verbose) {
            Object detail;
            detail.push_back(Pair("name", asset.strName));
            detail.push_back(Pair("amount", AssetValueFromAmount(asset.nAmount, asset.strName)));
            detail.push_back(Pair("units", asset.units));
            detail.push_back(Pair("reissuable", asset.nReissuable));
            detail.push_back(Pair("has_ipfs", asset.nHasIPFS));
            detail.push_back(Pair("block_height", data.nHeight));
            detail.push_back(Pair("blockhash", data.blockHash.GetHex()));
            if (asset.nHasIPFS) {
                if (asset.strIPFSHash.size() == 32) {
                    detail.push_back(Pair("txid_hash", EncodeAssetData(asset.strIPFSHash)));
                } else {
                    detail.push_back(Pair("ipfs_hash", EncodeAssetData(asset.strIPFSHash)));
                }
            }
            resultObj.push_back(Pair(asset.strName, detail));
        } else {
            resultArr.push_back(asset.strName);
        }
    }

    if (verbose)
    {
        return resultObj;
    }
    else
    {
        return resultArr;
    }
}

Value listaddressesbyasset(const Array& params, bool fHelp)
{
    if (!fAssetIndex) {
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";
    }

    if (fHelp || !AreAssetsDeployed() || params.size() > 4 || params.size() < 1)
        throw std::runtime_error(
                "listaddressesbyasset \"asset_name\" (onlytotal) (count) (start)\n"
                + AssetActivationWarning() +
                "\nReturns a list of all address that own the given asset (with balances)"
                "\nOr returns the total size of how many address own the given asset"

                "\nArguments:\n"
                "1. \"asset_name\"               (string, required) name of asset\n"
                "2. \"onlytotal\"                (boolean, optional, default=false) when false result is just a list of addresses with balances -- when true the result is just a single number representing the number of addresses\n"
                "3. \"count\"                    (integer, optional, default=50000, MAX=50000) truncates results to include only the first _count_ assets found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ assets found (if negative it skips back from the end)\n"

                "\nResult:\n"
                "[ "
                "  (address): balance,\n"
                "  ...\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listaddressesbyasset", "\"ASSET_NAME\" false 2 0")
                + HelpExampleCli("listaddressesbyasset", "\"ASSET_NAME\" true")
                + HelpExampleCli("listaddressesbyasset", "\"ASSET_NAME\"")
        );

    std::string asset_name = params[0].get_str();
    bool fOnlyTotal = false;
    if (params.size() > 1)
        fOnlyTotal = params[1].get_bool();

    size_t count = INT_MAX;
    if (params.size() > 2) {
        if (params[2].get_int() < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be greater than 1.");
        count = params[2].get_int();
    }

    long start = 0;
    if (params.size() > 3) {
        start = params[3].get_int();
    }

    if (!IsAssetNameValid(asset_name))
        return "_Not a valid asset name";

    std::vector<std::pair<std::string, CAmount> > vecAddressAmounts;
    int nTotalEntries = 0;
    if (!passetsdb->AssetAddressDir(vecAddressAmounts, nTotalEntries, fOnlyTotal, asset_name, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve address asset directory.");

    // If only the number of addresses is wanted return it
    if (fOnlyTotal) {
        return nTotalEntries;
    }

    Object result;
    for (auto& pair : vecAddressAmounts) {
        result.push_back(Pair(pair.first, AssetValueFromAmount(pair.second, asset_name)));
    }


    return result;
}

Value listassetbalancesbyaddress(const Array& params, bool fHelp)
{
    if (!fAssetIndex) {
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";
    }

    if (fHelp || !AreAssetsDeployed() || params.size() > 4 || params.size() < 1)
        throw std::runtime_error(
            "listassetbalancesbyaddress \"address\" (onlytotal) (count) (start)\n"
            + AssetActivationWarning() +
            "\nReturns a list of all asset balances for an address.\n"

            "\nArguments:\n"
            "1. \"address\"                  (string, required) a yacoin address\n"
            "2. \"onlytotal\"                (boolean, optional, default=false) when false result is just a list of assets balances -- when true the result is just a single number representing the number of assets\n"
            "3. \"count\"                    (integer, optional, default=50000, MAX=50000) truncates results to include only the first _count_ assets found\n"
            "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ assets found (if negative it skips back from the end)\n"

            "\nResult:\n"
            "{\n"
            "  (asset_name) : (quantity),\n"
            "  ...\n"
            "}\n"


            "\nExamples:\n"
            + HelpExampleCli("listassetbalancesbyaddress", "\"myaddress\" false 2 0")
            + HelpExampleCli("listassetbalancesbyaddress", "\"myaddress\" true")
            + HelpExampleCli("listassetbalancesbyaddress", "\"myaddress\"")
        );

    std::string address = params[0].get_str();
    CTxDestination destination = DecodeDestination(address);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Yacoin address: ") + address);
    }

    bool fOnlyTotal = false;
    if (params.size() > 1)
        fOnlyTotal = params[1].get_bool();

    size_t count = INT_MAX;
    if (params.size() > 2) {
        if (params[2].get_int() < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be greater than 1.");
        count = params[2].get_int();
    }

    long start = 0;
    if (params.size() > 3) {
        start = params[3].get_int();
    }

    if (!passetsdb)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "asset db unavailable.");

    std::vector<std::pair<std::string, CAmount> > vecAssetAmounts;
    int nTotalEntries = 0;
    if (!passetsdb->AddressDir(vecAssetAmounts, nTotalEntries, fOnlyTotal, address, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve address asset directory.");

    // If only the number of addresses is wanted return it
    if (fOnlyTotal) {
        return nTotalEntries;
    }

    Object result;
    for (auto& pair : vecAssetAmounts) {
        result.push_back(Pair(pair.first, AssetValueFromAmount(pair.second, pair.first)));
    }

    return result;
}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
