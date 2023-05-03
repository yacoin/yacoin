// Copyright (c) 2017-2021 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "tokens/tokens.h"
#include "tokens/tokendb.h"
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

std::string TokenActivationWarning()
{
    return AreTokensDeployed() ? "" : "\nTHIS COMMAND IS NOT YET ACTIVE!\n";
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
    if (fHelp || !AreTokensDeployed() || params.size() < 1 || params.size() > 8)
        throw runtime_error(
            "issue <token_name> [qty] [units] [reissuable] [has_ipfs] [ipfs_hash] [to_address] [change_address]\n"
            + TokenActivationWarning() +
            "\nIssue a YA-token, Sub-token or Unique-token.\n"
            "Token name must not conflict with any existing token.\n"
            "Unit as the number of decimals precision for the token (0 for whole units (\"1\"), 6 for max precision (\"1.000000\")\n"
            "Reissuable is true/false for whether additional units can be issued by the original issuer.\n"
            "If issuing a Unique-token these values are required (and will be defaulted to): qty=1, units=0, reissuable=false.\n"

            "\nArguments:\n"
            "1. \"token_name\"            (string, required) a unique name\n"
            "2. \"qty\"                   (numeric, optional, default=1) the number of units to be issued\n"
            "3. \"units\"                 (integer, optional, default=0, min=0, max=6), the number of decimals precision for the token (0 for whole units (\"1\"), 6 for max precision (\"1.000000\")\n"
            "4. \"reissuable\"            (boolean, optional, default=true (false for unique tokens)), whether future reissuance is allowed\n"
            "5. \"has_ipfs\"              (boolean, optional, default=false), whether ipfs hash is going to be added to the token\n"
            "6. \"ipfs_hash\"             (string, optional but required if has_ipfs = 1), an ipfs hash or a txid hash once RIP5 is activated\n"
            "7. \"to_address\"            (string), optional, default=\"\"), address token will be sent to, if it is empty, address will be generated for you\n"
            "8. \"change_address\"        (string), optional, default=\"\"), address the YAC change will be sent to, if it is empty, change address will be generated for you\n"

            "\nResult:\n"
            "\"txid\"                     (string) The transaction id\n"

            "\nExamples:\n"
            + HelpExampleCli("issue", "\"YATOKEN_NAME\" 1000")
            + HelpExampleCli("issue", "\"YATOKEN_NAME\" 1000 4")
            + HelpExampleCli("issue", "\"YATOKEN_NAME\" 1000 2 true")
            + HelpExampleCli("issue", "\"YATOKEN_NAME\" 1000 6 false true QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E \"myaddress\" \"changeaddress\"")
            + HelpExampleCli("issue", "\"YATOKEN_NAME/SUB_TOKEN\" 1000 2 true")
            + HelpExampleCli("issue", "\"YATOKEN_NAME#UNIQUE_TOKEN\"")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Check token name and infer tokenType
    std::string tokenName = capitalizeTokenName(params[0].get_str());

    ETokenType tokenType;
    std::string tokenError = "";
    if (!IsTokenNameValid(tokenName, tokenType, tokenError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid token name: ") + tokenName + std::string("\nError: ") + tokenError);
    }

    // Check for unsupported token types
    if (tokenType == ETokenType::VOTE || tokenType == ETokenType::REISSUE || tokenType == ETokenType::OWNER || tokenType == ETokenType::INVALID) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Unsupported token type: ") + ETokenTypeToString(tokenType));
    }

    // qty
    CAmount nAmount = COIN;
    if (params.size() > 1)
        nAmount = AmountFromValue(params[1]);

    // units
    int units = 0;
    if (params.size() > 2)
        units = params[2].get_int();

    // reissuable
    bool reissuable = tokenType != ETokenType::UNIQUE;
    if (params.size() > 3)
        reissuable = params[3].get_bool();

    // has_ipfs
    bool has_ipfs = false;
    if (params.size() > 4)
        has_ipfs = params[4].get_bool();

    // Check the ipfs
    CIDVersion cidVersion = CIDVersion::UNKNOWN;
    std::string ipfs_hash = "";
    std::string raw_multihash = "";
    if (params.size() > 5 && has_ipfs) {
        ipfs_hash = params[5].get_str();
        raw_multihash = DecodeTokenData(ipfs_hash, cidVersion);
        if (cidVersion == CIDVersion::CIDv0 && raw_multihash.empty())
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid CIDv0 IPFS hash (CIDv0 must be generated by hash algorithm sha2-256). Please check with https://cid.ipfs.tech/"));
        if (cidVersion == CIDVersion::CIDv1 && raw_multihash.empty())
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid CIDv1 IPFS hash (CIDv1 must have <version> = cidv1, <multicodec> = dag-pb, <multihash> generated "
                    "by hash algorithm sha2-256). Please check with https://cid.ipfs.tech/"));
        if (cidVersion == CIDVersion::UNKNOWN)
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid IPFS hash (CIDv0 must have 46 characters and start with 'Qm', CIDv1 must start with 'b')"));
    }

    // to_address
    std::string address = "";
    if (params.size() > 6)
        address = params[6].get_str();

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

    // change_address
    std::string change_address = "";
    if (params.size() > 7) {
        change_address = params[7].get_str();
        if (!change_address.empty()) {
            CTxDestination destination = DecodeDestination(change_address);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   std::string("Invalid Change Address: Invalid Yacoin address: ") + change_address);
            }
        }
    }

    // check for required unique token params
    if (tokenType == ETokenType::UNIQUE && (nAmount != COIN || units != 0 || reissuable)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameters for issuing a unique token."));
    }

    CNewToken token(tokenName, nAmount, units, reissuable ? 1 : 0, has_ipfs ? 1 : 0, raw_multihash);

    CReserveKey reservekey(pwalletMain);
    CWalletTx transaction;
    CAmount nRequiredFee;
    std::pair<int, std::string> error;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(change_address);

    // Create the Transaction
    if (!CreateTokenTransaction(pwalletMain, crtl, token, address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendTokenTransaction(pwalletMain, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    return txid;
}

Value transfer(const Array& params, bool fHelp)
{
    if (fHelp || !AreTokensDeployed() || params.size() < 3 || params.size() > 5)
        throw runtime_error(
                "transfer <token_name> [qty] <to_address> [change_address] [token_change_address]\n"
                + TokenActivationWarning() +
                "\nTransfers a quantity of an owned token to a given address"

                "\nArguments:\n"
                "1. \"token_name\"               (string, required) name of token\n"
                "2. \"qty\"                      (numeric, required) number of tokens you want to send to the address\n"
                "3. \"to_address\"               (string, required) address to send the token to\n"
                "4. \"change_address\"           (string, optional, default = \"\") the transactions YAC change will be sent to this address\n"
                "5. \"token_change_address\"     (string, optional, default = \"\") the transactions Token change will be sent to this address\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("transfer", "\"TOKEN_NAME\" 20 \"address\"")
                + HelpExampleCli("transfer", "\"TOKEN_NAME\" 20 \"address\"")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    std::string token_name = capitalizeTokenName(params[0].get_str());

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

    std::string token_change_address = "";
    if (params.size() > 4) {
        token_change_address = params[4].get_str();
    }

    CTxDestination yac_change_dest = DecodeDestination(yac_change_address);
    if (!yac_change_address.empty() && !IsValidDestination(yac_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("YAC change address must be a valid address. Invalid address: ") + yac_change_address);

    CTxDestination token_change_dest = DecodeDestination(token_change_address);
    if (!token_change_address.empty() && !IsValidDestination(token_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Token change address must be a valid address. Invalid address: ") + token_change_address);

    std::pair<int, std::string> error;
    std::vector< std::pair<CTokenTransfer, std::string> >vTransfers;

    CTokenTransfer transfer(token_name, nAmount);

    vTransfers.emplace_back(std::make_pair(transfer, to_address));
    CReserveKey reservekey(pwalletMain);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;
    ctrl.destChange = yac_change_dest;
    ctrl.tokenDestChange = token_change_dest;

    // Create the Transaction
    if (!CreateTransferTokenTransaction(pwalletMain, ctrl, vTransfers, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendTokenTransaction(pwalletMain, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    return txid;
}

Value transferfromaddress(const Array& params, bool fHelp)
{
    if (fHelp || !AreTokensDeployed() || params.size() < 4 || params.size() > 6)
        throw runtime_error(
                "transferfromaddress <token_name> <from_address> <qty> <to_address> [yac_change_address] [token_change_address]\n"
                + TokenActivationWarning() +
                "\nTransfer a quantity of an owned token in a specific address to a given address"

                "\nArguments:\n"
                "1. \"token_name\"               (string, required) name of token\n"
                "2. \"from_address\"             (string, required) address that the token will be transferred from\n"
                "3. \"qty\"                      (numeric, required) number of tokens you want to send to the address\n"
                "4. \"to_address\"               (string, required) address to send the token to\n"
                "5. \"yac_change_address\"       (string, optional, default = \"\") the transaction YAC change will be sent to this address\n"
                "6. \"token_change_address\"     (string, optional, default = \"\") the transaction Token change will be sent to this address\n"

                "\nResult:\n"
                "txid"
                "[ \n"
                "txid\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("transferfromaddress", "\"TOKEN_NAME\" \"fromaddress\" 20 \"address\"")
                + HelpExampleRpc("transferfromaddress", "\"TOKEN_NAME\" \"fromaddress\" 20 \"address\"")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    std::string token_name = capitalizeTokenName(params[0].get_str());

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

    std::string token_change_address = "";
    if (params.size() > 7) {
        token_change_address = params[7].get_str();
    }

    CTxDestination yac_change_dest = DecodeDestination(yac_change_address);
    if (!yac_change_address.empty() && !IsValidDestination(yac_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("YAC change address must be a valid address. Invalid address: ") + yac_change_address);

    CTxDestination token_change_dest = DecodeDestination(token_change_address);
    if (!token_change_address.empty() && !IsValidDestination(token_change_dest))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Token change address must be a valid address. Invalid address: ") + token_change_address);


    std::pair<int, std::string> error;
    std::vector< std::pair<CTokenTransfer, std::string> >vTransfers;

    vTransfers.emplace_back(std::make_pair(CTokenTransfer(token_name, nAmount), address));
    CReserveKey reservekey(pwalletMain);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;
    std::map<std::string, std::vector<COutput> > mapTokenCoins;
    pwalletMain->AvailableTokens(mapTokenCoins);

    // Set the change addresses
    ctrl.destChange = yac_change_dest;
    ctrl.tokenDestChange = token_change_dest;

    if (!mapTokenCoins.count(token_name)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Wallet doesn't own the token_name: " + token_name));
    }

    // Add all the token outpoints that match the given from addresses
    for (const auto& out : mapTokenCoins.at(token_name)) {
        // Get the address that the coin resides in, because to send a valid message. You need to send it to the same address that it currently resides in.
        CTxDestination dest;
        ExtractDestination(out.tx->vout[out.i].scriptPubKey, dest);

        if (from_address == EncodeDestination(dest))
            ctrl.SelectToken(COutPoint(out.tx->GetHash(), out.i));
    }

    std::vector<COutPoint> outs;
    ctrl.ListSelectedTokens(outs);
    if (!outs.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("No token outpoints are selected from the given address, failed to create the transaction"));
    }

    // Create the Transaction
    if (!CreateTransferTokenTransaction(pwalletMain, ctrl, vTransfers, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendTokenTransaction(pwalletMain, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    return txid;
}

Value reissue(const Array& params, bool fHelp)
{
    if (fHelp || !AreTokensDeployed() || params.size() > 7 || params.size() < 2)
        throw runtime_error(
                "reissue <token_name> <qty> [reissuable] [to_address] [change_address] [new_unit] [new_ipfs]\n"
                + TokenActivationWarning() +
                "\nReissues a quantity of an token to an owned address if you own the Owner Token"
                "\nCan change the reissuable flag during reissuance"
                "\nCan change the ipfs hash during reissuance"

                "\nArguments:\n"
                "1. \"token_name\"               (string, required) name of token that is being reissued\n"
                "2. \"qty\"                      (numeric, required) number of tokens to reissue\n"
                "3. \"reissuable\"               (boolean, optional, default=true), whether future reissuance is allowed\n"
                "4. \"to_address\"               (string, optional) address to send the token to\n"
                "5. \"change_address\"           (string, optional) address that the change of the transaction will be sent to\n"
                "6. \"new_units\"                (numeric, optional, default=-1), the new units that will be associated with the token\n"
                "7. \"new_ipfs\"                 (string, optional, default=\"\"), whether to update the current ipfs hash or txid once RIP5 is active\n"

                "\nResult:\n"
                "\"txid\"                     (string) The transaction id\n"

                "\nExamples:\n"
                + HelpExampleCli("reissue", "\"TOKEN_NAME\" 20")
                + HelpExampleRpc("reissue", "\"TOKEN_NAME\" 20 \"true\" \"address\" \"change_address\" 6 \"Qmd286K6pohQcTKYqnS1YhWrCiS4gz7Xi34sdwMe9USZ7u\"")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Get that paramaters
    std::string token_name = capitalizeTokenName(params[0].get_str());
    CAmount nAmount = AmountFromValue(params[1]);

    // reissueable
    bool reissuable = true;
    if (params.size() > 2) {
        reissuable = params[2].get_bool();
    }

    // to_address
    std::string address = "";
    if (params.size() > 3)
        address = params[3].get_str();

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

    // change_address
    std::string changeAddress =  "";
    if (params.size() > 4)
        changeAddress = params[4].get_str();

    // new_units
    int newUnits = -1;
    if (params.size() > 5) {
        newUnits = params[5].get_int();
    }

    // new_ipfs
    std::string newipfs = "";
    CIDVersion cidVersion = CIDVersion::UNKNOWN;
    std::string raw_multihash = "";
    if (params.size() > 6) {
        newipfs = params[6].get_str();
        raw_multihash = DecodeTokenData(newipfs, cidVersion);
        if (cidVersion == CIDVersion::CIDv0 && raw_multihash.empty())
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid CIDv0 IPFS hash (CIDv0 must be generated by hash algorithm sha2-256). Please check with https://cid.ipfs.tech/"));
        if (cidVersion == CIDVersion::CIDv1 && raw_multihash.empty())
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid CIDv1 IPFS hash (CIDv1 must have <version> = cidv1, <multicodec> = dag-pb, <multihash> generated "
                    "by hash algorithm sha2-256). Please check with https://cid.ipfs.tech/"));
        if (cidVersion == CIDVersion::UNKNOWN)
            throw JSONRPCError(RPC_INVALID_PARAMS, std::string("Invalid IPFS hash (CIDv0 must have 46 characters and start with 'Qm', CIDv1 must start with 'b')"));
    }

    CReissueToken reissueToken(token_name, nAmount, newUnits, reissuable, raw_multihash);

    std::pair<int, std::string> error;
    CReserveKey reservekey(pwalletMain);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl crtl;
    crtl.destChange = DecodeDestination(changeAddress);

    // Create the Transaction
    if (!CreateReissueTokenTransaction(pwalletMain, crtl, reissueToken, address, error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    std::string strError = "";
    if (!ContextualCheckReissueToken(ptokens, reissueToken, strError, transaction))
        throw JSONRPCError(RPC_INVALID_REQUEST, strError);

    // Send the Transaction to the network
    std::string txid;
    if (!SendTokenTransaction(pwalletMain, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    return txid;
}

Value listmytokens(const Array& params, bool fHelp)
{
    if (fHelp || !AreTokensDeployed() || params.size() > 5)
        throw runtime_error(
                "listmytokens [token] [verbose] [count] [start] (confs) \n"
                + TokenActivationWarning() +
                "\nReturns a list of all token that are owned by this wallet\n"

                "\nArguments:\n"
                "1. \"token\"                    (string, optional, default=\"*\") filters results -- must be an token name or a partial token name followed by '*' ('*' matches all trailing characters)\n"
                "2. \"verbose\"                  (boolean, optional, default=false) when false results only contain balances -- when true results include outpoints\n"
                "3. \"count\"                    (integer, optional, default=ALL) truncates results to include only the first _count_ tokens found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ tokens found (if negative it skips back from the end)\n"
                "5. \"confs\"                    (integet, optional, default=0) results are skipped if they don't have this number of confirmations\n"

                "\nResult (verbose=false):\n"
                "{\n"
                "  (token_name): balance,\n"
                "  ...\n"
                "}\n"

                "\nResult (verbose=true):\n"
                "{\n"
                "  (token_name):\n"
                "    {\n"
                "      \"balance\": balance,\n"
                "      \"outpoints\":\n"
                "        [\n"
                "          {\n"
                "            \"txid\": txid,\n"
                "            \"vout\": vout,\n"
                "            \"address\": \"address\",\n"
                "            \"account\": \"account\",\n"
                "            \"amount\": amount\n"
                "          }\n"
                "          {...}, {...}\n"
                "        ],\n"
                "      \"token_type\": token_type,\n"
                "    }\n"
                "}\n"
                "{...}, {...}\n"

                "\nExamples:\n"
                + HelpExampleRpc("listmytokens", "")
                + HelpExampleCli("listmytokens", "TOKEN")
                + HelpExampleCli("listmytokens", "\"TOKEN*\" true 10 20")
                  + HelpExampleCli("listmytokens", "\"TOKEN*\" true 10 20 1")
        );

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    std::string filter = "*";
    if (params.size() > 0)
        filter = params[0].get_str();

    if (filter == "")
        filter = "*";

    filter = capitalizeTokenName(filter);

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
        if (!GetAllMyTokenBalances(outputs, balances, confs))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get token balances. For all tokens");
    }
    else if (filter.back() == '*') {
        std::vector<std::string> tokenNames;
        filter.pop_back();
        if (!GetAllMyTokenBalances(outputs, balances, confs, filter))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get token balances. For all tokens");
    }
    else {
        if (!IsTokenNameValid(filter))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid token name.");
        if (!GetAllMyTokenBalances(outputs, balances, confs, filter))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get token balances. For all tokens");
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
            Object token;
            token.push_back(Pair("balance", TokenValueFromAmount(bal->second, bal->first)));

            Array outpoints;
            for (auto const& out : outputs.at(bal->first)) {
                Object tempOut;
                tempOut.push_back(Pair("txid", out.tx->GetHash().GetHex()));
                tempOut.push_back(Pair("vout", (int)out.i));

                // Get address
                CTxDestination address;
                if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
                {
                    tempOut.push_back(Pair("address", CBitcoinAddress(address).ToString()));
                    if (pwalletMain->mapAddressBook.count(address))
                        tempOut.push_back(Pair("account", pwalletMain->mapAddressBook[address]));
                }

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
                    CNewToken token;
                    if (!TokenFromScript(txOut.scriptPubKey, token, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get token from script.");
                    txAmount = token.nAmount;
                }
                else if (CheckReissueDataTx(txOut)) {
                    CReissueToken token;
                    if (!ReissueTokenFromScript(txOut.scriptPubKey, token, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get token from script.");
                    txAmount = token.nAmount;
                }
                else if (CheckTransferOwnerTx(txOut)) {
                    CTokenTransfer token;
                    if (!TransferTokenFromScript(txOut.scriptPubKey, token, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get token from script.");
                    txAmount = token.nAmount;
                }
                else if (CheckOwnerDataTx(txOut)) {
                    std::string tokenName;
                    if (!OwnerTokenFromScript(txOut.scriptPubKey, tokenName, strAddress))
                        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't get token from script.");
                    txAmount = OWNER_TOKEN_AMOUNT;
                }
                tempOut.push_back(Pair("amount", TokenValueFromAmount(txAmount, bal->first)));
                //
                //

                outpoints.push_back(tempOut);
            }
            token.push_back(Pair("outpoints", outpoints));

            ETokenType tokenType;
            std::string tokenError = "";
            if (!IsTokenNameValid(bal->first, tokenType, tokenError)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid token name: ") + bal->first + std::string("\nError: ") + tokenError);
            }
            token.push_back(Pair("token_type", ETokenTypeToString(tokenType)));
            result.push_back(Pair(bal->first, token));
        }
    }
    else {
        for (; bal != end && bal != balances.end(); bal++) {
            result.push_back(Pair(bal->first, TokenValueFromAmount(bal->second, bal->first)));
        }
    }
    return result;
}

Value listtokens(const Array& params, bool fHelp)
{
    if (fHelp || !AreTokensDeployed() || params.size() > 4)
        throw runtime_error(
                "listtokens [token] [verbose] [count] [start]\n"
                + TokenActivationWarning() +
                "\nReturns a list of all tokens in the blockchain\n"
                "\nThis could be a slow/expensive operation as it reads from the database\n"

                "\nArguments:\n"
                "1. \"token\"                    (string, optional, default=\"*\") filters results -- must be an token name or a partial token name followed by '*' ('*' matches all trailing characters)\n"
                "2. \"verbose\"                  (boolean, optional, default=false) when false result is just a list of token names -- when true results are token name mapped to metadata\n"
                "3. \"count\"                    (integer, optional, default=ALL) truncates results to include only the first _count_ tokens found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ tokens found (if negative it skips back from the end)\n"

                "\nResult (verbose=false):\n"
                "[\n"
                "  token_name,\n"
                "  ...\n"
                "]\n"

                "\nResult (verbose=true):\n"
                "{\n"
                "  (token_name):\n"
                "    {\n"
                "      name: (token_name),\n"
                "      token_type: (token_type),\n"
                "      amount: (number),\n"
                "      units: (number),\n"
                "      reissuable: (number),\n"
                "      has_ipfs: (number),\n"
                "      blockhash: (hash),\n"
                "      ipfs_hash: (hash) (only if has_ipfs = 1 and data is a txid hash)\n"
                "    },\n"
                "  {...}, {...}\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleRpc("listtokens", "")
                + HelpExampleCli("listtokens", "TOKEN")
                + HelpExampleCli("listtokens", "\"TOKEN*\" true 10 20")
        );

    if (!ptokensdb)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "token db unavailable.");

    std::string filter = "*";
    if (params.size() > 0)
        filter = params[0].get_str();

    if (filter == "")
        filter = "*";

    filter = capitalizeTokenName(filter);

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

    std::vector<CDatabasedTokenData> tokens;
    if (!ptokensdb->TokenDir(tokens, filter, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve token directory.");

    Object resultObj;
    Array resultArr;

    for (auto data : tokens) {
        CNewToken token = data.token;
        if (verbose) {
            Object detail;
            ETokenType tokenType;
            std::string tokenError = "";
            if (!IsTokenNameValid(token.strName, tokenType, tokenError)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid token name: ") + token.strName + std::string("\nError: ") + tokenError);
            }
            detail.push_back(Pair("name", token.strName));
            detail.push_back(Pair("token_type", ETokenTypeToString(tokenType)));
            detail.push_back(Pair("amount", TokenValueFromAmount(token.nAmount, token.strName)));
            detail.push_back(Pair("units", token.units));
            detail.push_back(Pair("reissuable", token.nReissuable));
            detail.push_back(Pair("has_ipfs", token.nHasIPFS));
            detail.push_back(Pair("block_height", data.nHeight));
            detail.push_back(Pair("blockhash", data.blockHash.GetHex()));
            if (token.nHasIPFS) {
                detail.push_back(Pair("ipfs_hash_cidv0", EncodeTokenData(token.strIPFSHash, CIDVersion::CIDv0)));
                detail.push_back(Pair("ipfs_hash_cidv1", EncodeTokenData(token.strIPFSHash, CIDVersion::CIDv1)));
            }
            resultObj.push_back(Pair(token.strName, detail));
        } else {
            resultArr.push_back(token.strName);
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

Value listaddressesbytoken(const Array& params, bool fHelp)
{
    if (!fTokenIndex) {
      return "_This rpc call is not functional unless -tokenindex is enabled "
             "in yacoin.conf. If you haven't enabled it before, in the first "
             "time you enable it, you need to enable -reindex-token option as "
             "well because yacoind need to build token index from the blk*.dat "
             "files on disk";
    }

    if (fHelp || !AreTokensDeployed() || params.size() > 4 || params.size() < 1)
        throw runtime_error(
                "listaddressesbytoken <token_name> [onlytotal] [count] [start]\n"
                + TokenActivationWarning() +
                "\nReturns a list of all address that own the given token (with balances)"
                "\nOr returns the total size of how many address own the given token"

                "\nArguments:\n"
                "1. \"token_name\"               (string, required) name of token\n"
                "2. \"onlytotal\"                (boolean, optional, default=false) when false result is just a list of addresses with balances -- when true the result is just a single number representing the number of addresses\n"
                "3. \"count\"                    (integer, optional, default=50000, MAX=50000) truncates results to include only the first _count_ tokens found\n"
                "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ tokens found (if negative it skips back from the end)\n"

                "\nResult:\n"
                "[ "
                "  (address): balance,\n"
                "  ...\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listaddressesbytoken", "\"TOKEN_NAME\" false 2 0")
                + HelpExampleCli("listaddressesbytoken", "\"TOKEN_NAME\" true")
                + HelpExampleCli("listaddressesbytoken", "\"TOKEN_NAME\"")
        );

    std::string token_name = capitalizeTokenName(params[0].get_str());
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

    if (!IsTokenNameValid(token_name))
        return "_Not a valid token name";

    std::vector<std::pair<std::string, CAmount> > vecAddressAmounts;
    int nTotalEntries = 0;
    if (!ptokensdb->TokenAddressDir(vecAddressAmounts, nTotalEntries, fOnlyTotal, token_name, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve address token directory.");

    // If only the number of addresses is wanted return it
    if (fOnlyTotal) {
        return nTotalEntries;
    }

    Object result;
    for (auto& pair : vecAddressAmounts) {
        result.push_back(Pair(pair.first, TokenValueFromAmount(pair.second, token_name)));
    }


    return result;
}

Value listtokenbalancesbyaddress(const Array& params, bool fHelp)
{
    if (!fTokenIndex) {
        return "_This rpc call is not functional unless -tokenindex is enabled "
               "in yacoin.conf. If you haven't enabled it before, in the first "
               "time you enable it, you need to enable -reindex-token option as "
               "well because yacoind need to build token index from the blk*.dat "
               "files on disk";
    }

    if (fHelp || !AreTokensDeployed() || params.size() > 4 || params.size() < 1)
        throw runtime_error(
            "listtokenbalancesbyaddress <address> [onlytotal] [count] [start]\n"
            + TokenActivationWarning() +
            "\nReturns a list of all token balances for an address.\n"

            "\nArguments:\n"
            "1. \"address\"                  (string, required) a yacoin address\n"
            "2. \"onlytotal\"                (boolean, optional, default=false) when false result is just a list of tokens balances -- when true the result is just a single number representing the number of tokens\n"
            "3. \"count\"                    (integer, optional, default=50000, MAX=50000) truncates results to include only the first _count_ tokens found\n"
            "4. \"start\"                    (integer, optional, default=0) results skip over the first _start_ tokens found (if negative it skips back from the end)\n"

            "\nResult:\n"
            "{\n"
            "  (token_name) : (quantity),\n"
            "  ...\n"
            "}\n"


            "\nExamples:\n"
            + HelpExampleCli("listtokenbalancesbyaddress", "\"myaddress\" false 2 0")
            + HelpExampleCli("listtokenbalancesbyaddress", "\"myaddress\" true")
            + HelpExampleCli("listtokenbalancesbyaddress", "\"myaddress\"")
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

    if (!ptokensdb)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "token db unavailable.");

    std::vector<std::pair<std::string, CAmount> > vecTokenAmounts;
    int nTotalEntries = 0;
    if (!ptokensdb->AddressDir(vecTokenAmounts, nTotalEntries, fOnlyTotal, address, count, start))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "couldn't retrieve address token directory.");

    // If only the number of addresses is wanted return it
    if (fOnlyTotal) {
        return nTotalEntries;
    }

    Object result;
    for (auto& pair : vecTokenAmounts) {
        result.push_back(Pair(pair.first, TokenValueFromAmount(pair.second, pair.first)));
    }

    return result;
}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
