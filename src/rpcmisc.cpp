// Copyright (c) 2017-2021 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "addressindex.h"
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

bool getAddressesFromParams(const Array& params, std::vector<std::pair<uint160, int> > &addresses)
{
    if (params[0].type() == str_type) {
        CBitcoinAddress address(params[0].get_str());
        uint160 hashBytes;
        int type = 0;
        if (!address.GetIndexKey(hashBytes, type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
        addresses.push_back(std::make_pair(hashBytes, type));
    } else if (params[0].type() == obj_type) {

        Array addressValues = find_value(params[0].get_obj(), "addresses").get_array();

        for (Value& input : addressValues)
        {
            CBitcoinAddress address(input.get_str());
            uint160 hashBytes;
            int type = 0;
            if (!address.GetIndexKey(hashBytes, type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            addresses.push_back(std::make_pair(hashBytes, type));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    return true;
}

bool getAddressFromIndex(const int &type, const uint160 &hash, std::string &address)
{
    if (type == 2) {
        address = CBitcoinAddress(CScriptID(hash)).ToString();
    } else if (type == 1) {
        address = CBitcoinAddress(CKeyID(hash)).ToString();
    } else {
        return false;
    }
    return true;
}

Value getaddressbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw std::runtime_error(
            "getaddressbalance\n"
            "\nReturns the balance for an address(es) (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses:\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "},\n"
            "\"includeAssets\" (boolean, optional, default false)  If true this will return an expanded result which includes asset balances\n"
            "\n"
            "\nResult:\n"
            "{\n"
            "  \"balance\"  (string) The current balance in satoshis\n"
            "  \"received\"  (string) The total number of satoshis received (including change)\n"
            "}\n"
            "OR\n"
            "[\n"
            "  {\n"
            "    \"assetName\"  (string) The asset associated with the balance (RVN for Ravencoin)\n"
            "    \"balance\"  (string) The current balance in satoshis\n"
            "    \"received\"  (string) The total number of satoshis received (including change)\n"
            "  },...\n"
            "\n]"
            "\nExamples:\n"
            + HelpExampleCli("getaddressbalance", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleCli("getaddressbalance", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}', true")
            + HelpExampleRpc("getaddressbalance", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
            + HelpExampleRpc("getaddressbalance", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}, true")
        );

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    bool includeAssets = false;
    if (params.size() > 1) {
        includeAssets = params[1].get_bool();
    }

    if (includeAssets) {
        if (!AreAssetsDeployed())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Assets aren't active.  includeAssets can't be true.");

        std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

        for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }

        //assetName -> (received, balance)
        std::map<std::string, std::pair<CAmount, CAmount>> balances;

        for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it = addressIndex.begin();
             it != addressIndex.end(); it++) {
            std::string assetName = it->first.asset;
            if (balances.count(assetName) == 0) {
                balances[assetName] = std::make_pair(0, 0);
            }
            if (it->second > 0) {
                balances[assetName].first += it->second;
            }
            balances[assetName].second += it->second;
        }

        Array result;

        for (std::map<std::string, std::pair<CAmount, CAmount>>::const_iterator it = balances.begin();
                it != balances.end(); it++) {
            Object balance;
            balance.push_back(Pair("assetName", it->first));
            balance.push_back(Pair("balance", it->second.second));
            balance.push_back(Pair("received", it->second.first));
            result.push_back(balance);
        }

        return result;

    } else {
        std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

        for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
            if (!GetAddressIndex((*it).first, (*it).second, YAC, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }

        CAmount balance = 0;
        CAmount received = 0;

        for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it = addressIndex.begin();
             it != addressIndex.end(); it++) {
            if (it->second > 0) {
                received += it->second;
            }
            balance += it->second;
        }

        Object result;
        result.push_back(Pair("balance", balance));
        result.push_back(Pair("received", received));

        return result;
    }

}

Value getaddressdeltas(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || params[0].type() != obj_type)
        throw std::runtime_error(
            "getaddressdeltas\n"
            "\nReturns all changes for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"start\" (number) The start block height\n"
            "  \"end\" (number) The end block height\n"
            "  \"chainInfo\" (boolean) Include chain info in results, only applies if start and end specified\n"
            "  \"assetName\"   (string, optional) Get deltas for a particular asset instead of RVN.\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"assetName\"  (string) The asset associated with the deltas (RVN for Ravencoin)\n"
            "    \"satoshis\"  (number) The difference of satoshis\n"
            "    \"txid\"  (string) The related txid\n"
            "    \"index\"  (number) The related input or output index\n"
            "    \"height\"  (number) The block height\n"
            "    \"address\"  (string) The base58check encoded address\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressdeltas", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressdeltas", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
            + HelpExampleCli("getaddressdeltas", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"],\"assetName\":\"MY_ASSET\"}'")
            + HelpExampleRpc("getaddressdeltas", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"],\"assetName\":\"MY_ASSET\"}")
        );


    Value startValue = find_value(params[0].get_obj(), "start");
    Value endValue = find_value(params[0].get_obj(), "end");

    Value chainInfo = find_value(params[0].get_obj(), "chainInfo");
    bool includeChainInfo = false;
    if (chainInfo.type() == bool_type) {
        includeChainInfo = chainInfo.get_bool();
    }

    std::string assetName = YAC;
    Value assetNameParam = find_value(params[0].get_obj(), "assetName");
    if (assetNameParam.type() == str_type) {
        if (!AreAssetsDeployed())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Assets aren't active.  assetName can't be specified.");
        assetName = assetNameParam.get_str();
    }

    int start = 0;
    int end = 0;

    if (startValue.type() == int_type && endValue.type() == int_type) {
        start = startValue.get_int();
        end = endValue.get_int();
        if (start <= 0 || end <= 0) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start and end is expected to be greater than zero");
        }
        if (end < start) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "End value is expected to be greater than start");
        }
    }

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex((*it).first, (*it).second, assetName, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, assetName, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    Array deltas;

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        Object delta;
        delta.push_back(Pair("assetName", it->first.asset));
        delta.push_back(Pair("satoshis", it->second));
        delta.push_back(Pair("txid", it->first.txhash.GetHex()));
        delta.push_back(Pair("index", (int)it->first.index));
        delta.push_back(Pair("blockindex", (int)it->first.txindex));
        delta.push_back(Pair("height", it->first.blockHeight));
        delta.push_back(Pair("address", address));
        deltas.push_back(delta);
    }

    Object result;

    if (includeChainInfo && start > 0 && end > 0) {
        if (start > chainActive.Height() || end > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start or end is outside chain range");
        }

        CBlockIndex* startIndex = chainActive[start];
        CBlockIndex* endIndex = chainActive[end];

        Object startInfo;
        Object endInfo;

        startInfo.push_back(Pair("hash", startIndex->GetBlockHash().GetHex()));
        startInfo.push_back(Pair("height", start));

        endInfo.push_back(Pair("hash", endIndex->GetBlockHash().GetHex()));
        endInfo.push_back(Pair("height", end));

        result.push_back(Pair("deltas", deltas));
        result.push_back(Pair("start", startInfo));
        result.push_back(Pair("end", endInfo));

        return result;
    } else {
        return deltas;
    }
}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
