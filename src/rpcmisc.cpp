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

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
