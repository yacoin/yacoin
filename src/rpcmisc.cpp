// Copyright (c) 2017-2021 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "addressindex.h"
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

bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a,
                std::pair<CAddressUnspentKey, CAddressUnspentValue> b) {
    return a.second.blockHeight < b.second.blockHeight;
}

Value getaddressbalance(const Array& params, bool fHelp)
{
    if (!fAddressIndex) {
      return "_This rpc call is not functional unless -addressindex is enabled "
             "in yacoin.conf. If you haven't enabled it before, in the first "
             "time you enable it, you need to enable -reindex-token option as "
             "well because yacoind need to build token index from the blk*.dat "
             "files on disk";
    }

    if (fHelp || params.size() > 2 || params[0].type() != obj_type)
        throw runtime_error(
            "getaddressbalance\n"
            "\nReturns the balance for an address(es) (requires -addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses:\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "},\n"
            "\"includeTokens\" (boolean, optional, default false)  If true this will return an expanded result which includes token balances\n"
            "\n"
            "\nResult:\n"
            "{\n"
            "  \"balance\"  (string) The current balance in satoshis\n"
            "  \"received\"  (string) The total number of satoshis received (including change)\n"
            "}\n"
            "OR\n"
            "[\n"
            "  {\n"
            "    \"tokenName\"  (string) The token associated with the balance (YAC for Yacoin)\n"
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

    bool includeTokens = false;
    if (params.size() > 1) {
        includeTokens = params[1].get_bool();
    }

    if (includeTokens) {
        if (!AreTokensDeployed())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Tokens aren't active.  includeTokens can't be true.");

        std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

        for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }

        //tokenName -> (received, balance)
        std::map<std::string, std::pair<CAmount, CAmount>> balances;

        for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it = addressIndex.begin();
             it != addressIndex.end(); it++) {
            std::string tokenName = it->first.token;
            if (balances.count(tokenName) == 0) {
                balances[tokenName] = std::make_pair(0, 0);
            }
            if (it->second > 0) {
                balances[tokenName].first += it->second;
            }
            balances[tokenName].second += it->second;
        }

        Array result;

        for (std::map<std::string, std::pair<CAmount, CAmount>>::const_iterator it = balances.begin();
                it != balances.end(); it++) {
            Object balance;
            balance.push_back(Pair("tokenName", it->first));
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
    if (!fAddressIndex) {
      return "_This rpc call is not functional unless -addressindex is enabled "
             "in yacoin.conf. If you haven't enabled it before, in the first "
             "time you enable it, you need to enable -reindex-token option as "
             "well because yacoind need to build token index from the blk*.dat "
             "files on disk";
    }

    if (fHelp || params.size() != 1 || params[0].type() != obj_type)
        throw runtime_error(
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
            "  \"tokenName\"   (string, optional) Get deltas for a particular token instead of YAC.\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"tokenName\"  (string) The token associated with the deltas (YAC for Yacoin)\n"
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
            + HelpExampleCli("getaddressdeltas", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"],\"tokenName\":\"MY_TOKEN\"}'")
            + HelpExampleRpc("getaddressdeltas", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"],\"tokenName\":\"MY_TOKEN\"}")
        );


    Value startValue = find_value(params[0].get_obj(), "start");
    Value endValue = find_value(params[0].get_obj(), "end");

    Value chainInfo = find_value(params[0].get_obj(), "chainInfo");
    bool includeChainInfo = false;
    if (chainInfo.type() == bool_type) {
        includeChainInfo = chainInfo.get_bool();
    }

    std::string tokenName = YAC;
    Value tokenNameParam = find_value(params[0].get_obj(), "tokenName");
    if (tokenNameParam.type() == str_type) {
        if (!AreTokensDeployed())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Tokens aren't active.  tokenName can't be specified.");
        tokenName = tokenNameParam.get_str();
    }
    tokenName = capitalizeTokenName(tokenName);

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
            if (!GetAddressIndex((*it).first, (*it).second, tokenName, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, tokenName, addressIndex)) {
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
        delta.push_back(Pair("tokenName", it->first.token));
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

Value getaddressutxos(const Array& params, bool fHelp)
{
    if (!fAddressIndex) {
      return "_This rpc call is not functional unless -addressindex is enabled "
             "in yacoin.conf. If you haven't enabled it before, in the first "
             "time you enable it, you need to enable -reindex-token option as "
             "well because yacoind need to build token index from the blk*.dat "
             "files on disk";
    }

    if (fHelp || params.size() != 1 || params[0].type() != obj_type)
        throw runtime_error(
            "getaddressutxos\n"
            "\nReturns all unspent outputs for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ],\n"
            "  \"chainInfo\",  (boolean, optional, default false) Include chain info with results\n"
            "  \"tokenName\"   (string, optional) Get UTXOs for a particular token instead of YAC ('*' for all tokens).\n"
            "}\n"
            "\nResult\n"
            "[\n"
            "  {\n"
            "    \"address\"  (string) The address base58check encoded\n"
            "    \"tokenName\" (string) The token associated with the UTXOs (YAC for Yacoin)\n"
            "    \"txid\"  (string) The output txid\n"
            "    \"height\"  (number) The block height\n"
            "    \"outputIndex\"  (number) The output index\n"
            "    \"script\"  (strin) The script hex encoded\n"
            "    \"satoshis\"  (number) The number of satoshis of the output\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressutxos", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressutxos", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
            + HelpExampleCli("getaddressutxos", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"],\"tokenName\":\"MY_TOKEN\"}'")
            + HelpExampleRpc("getaddressutxos", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"],\"tokenName\":\"MY_TOKEN\"}")
            );

    bool includeChainInfo = false;
    std::string tokenName = YAC;
    if (params[0].type() == obj_type) {
        Value chainInfo = find_value(params[0].get_obj(), "chainInfo");
        if (chainInfo.type() == bool_type) {
            includeChainInfo = chainInfo.get_bool();
        }
        Value tokenNameParam = find_value(params[0].get_obj(), "tokenName");
        if (tokenNameParam.type() == str_type) {
            if (!AreTokensDeployed())
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Tokens aren't active.  tokenName can't be specified.");
            tokenName = tokenNameParam.get_str();
        }
    }
    tokenName = capitalizeTokenName(tokenName);

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (tokenName == "*") {
            if (!GetAddressUnspent((*it).first, (*it).second, unspentOutputs)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressUnspent((*it).first, (*it).second, tokenName, unspentOutputs)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);

    Array utxos;

    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++) {
        Object output;
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        std::string tokenNameOut = "YAC";
        if (tokenName != "YAC") {
            CAmount _amount;
            if (!GetTokenInfoFromScript(it->second.script, tokenNameOut, _amount)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't decode token script");
            }
        }

        output.push_back(Pair("address", address));
        output.push_back(Pair("tokenName", tokenNameOut));
        output.push_back(Pair("txid", it->first.txhash.GetHex()));
        output.push_back(Pair("outputIndex", (int)it->first.index));
        output.push_back(Pair("script", HexStr(it->second.script.begin(), it->second.script.end())));
        output.push_back(Pair("satoshis", it->second.satoshis));
        output.push_back(Pair("height", it->second.blockHeight));
        utxos.push_back(output);
    }

    if (includeChainInfo) {
        Object result;
        result.push_back(Pair("utxos", utxos));
        result.push_back(Pair("hash", chainActive.Tip()->GetBlockHash().GetHex()));
        result.push_back(Pair("height", (int)chainActive.Height()));
        return result;
    } else {
        return utxos;
    }
}

Value getaddresstxids(const Array& params, bool fHelp)
{
    if (!fAddressIndex) {
      return "_This rpc call is not functional unless -addressindex is enabled "
             "in yacoin.conf. If you haven't enabled it before, in the first "
             "time you enable it, you need to enable -reindex-token option as "
             "well because yacoind need to build token index from the blk*.dat "
             "files on disk";
    }

    if (fHelp || params.size() > 2 || params[0].type() != obj_type)
        throw runtime_error(
            "getaddresstxids\n"
            "\nReturns the txids for an address(es) (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"start\" (number, optional) The start block height\n"
            "  \"end\" (number, optional) The end block height\n"
            "},\n"
            "\"includeTokens\" (boolean, optional, default false)  If true this will return an expanded result which includes token transactions\n"
            "\nResult:\n"
            "[\n"
            "  \"transactionid\"  (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddresstxids", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddresstxids", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
            + HelpExampleCli("getaddresstxids", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}', true")
            + HelpExampleRpc("getaddresstxids", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}, true")
        );

    std::vector<std::pair<uint160, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    int start = 0;
    int end = 0;
    if (params[0].type() == obj_type) {
        Value startValue = find_value(params[0].get_obj(), "start");
        Value endValue = find_value(params[0].get_obj(), "end");
        if (startValue.type() == int_type && endValue.type() == int_type) {
            start = startValue.get_int();
            end = endValue.get_int();
        }
    }

    bool includeTokens = false;
    if (params.size() > 1) {
        includeTokens = params[1].get_bool();
    }

    if (includeTokens)
        if (!AreTokensDeployed())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Tokens aren't active.  includeTokens can't be true.");

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (includeTokens) {
            if (start > 0 && end > 0) {
                if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
                }
            } else {
                if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
                }
            }
        } else {
            if (start > 0 && end > 0) {
                if (!GetAddressIndex((*it).first, (*it).second, YAC, addressIndex, start, end)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
                }
            } else {
                if (!GetAddressIndex((*it).first, (*it).second, YAC, addressIndex)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
                }
            }
        }
    }

    std::set<std::pair<int, std::string> > txids;
    Array result;

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        int height = it->first.blockHeight;
        std::string txid = it->first.txhash.GetHex();

        if (addresses.size() > 1) {
            txids.insert(std::make_pair(height, txid));
        } else {
            if (txids.insert(std::make_pair(height, txid)).second) {
                result.push_back(txid);
            }
        }
    }

    if (addresses.size() > 1) {
        for (std::set<std::pair<int, std::string> >::const_iterator it=txids.begin(); it!=txids.end(); it++) {
            result.push_back(it->second);
        }
    }

    return result;

}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
