// Copyright (c) 2017-2019 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util.h>
//#include <consensus/params.h>
//#include <script/ismine.h>
//#include <tinyformat.h>
#include "tokendb.h"
#include "tokens.h"
#include "main.h"
//#include "validation.h"

#include <boost/thread.hpp>
#include <memory>

static const char TOKEN_FLAG = 'A';
static const char TOKEN_ADDRESS_QUANTITY_FLAG = 'B';
static const char ADDRESS_TOKEN_QUANTITY_FLAG = 'C';
static const char MY_TOKEN_FLAG = 'M';
static const char BLOCK_TOKEN_UNDO_DATA = 'U';
static const char MEMPOOL_REISSUED_TX = 'Z';

static size_t MAX_DATABASE_RESULTS = 50000;

CTokensDB::CTokensDB(const char *pszMode) :
        CDBWrapper(TOKEN_DATA, pszMode) {
}

bool CTokensDB::WriteTokenData(const CNewToken &token, const int nHeight, const uint256& blockHash)
{
    CDatabasedTokenData data(token, nHeight, blockHash);
    return Write(std::make_pair(TOKEN_FLAG, token.strName), data);
}

bool CTokensDB::WriteTokenAddressQuantity(const std::string &tokenName, const std::string &address, const CAmount &quantity)
{
    return Write(std::make_pair(TOKEN_ADDRESS_QUANTITY_FLAG, std::make_pair(tokenName, address)), quantity);
}

bool CTokensDB::WriteAddressTokenQuantity(const std::string &address, const std::string &tokenName, const CAmount& quantity) {
    return Write(std::make_pair(ADDRESS_TOKEN_QUANTITY_FLAG, std::make_pair(address, tokenName)), quantity);
}

bool CTokensDB::ReadTokenData(const std::string& strName, CNewToken& token, int& nHeight, uint256& blockHash)
{

    CDatabasedTokenData data;
    bool ret =  Read(std::make_pair(TOKEN_FLAG, strName), data);

    if (ret) {
        token = data.token;
        nHeight = data.nHeight;
        blockHash = data.blockHash;
    }

    return ret;
}

bool CTokensDB::ReadTokenAddressQuantity(const std::string& tokenName, const std::string& address, CAmount& quantity)
{
    return Read(std::make_pair(TOKEN_ADDRESS_QUANTITY_FLAG, std::make_pair(tokenName, address)), quantity);
}

bool CTokensDB::ReadAddressTokenQuantity(const std::string &address, const std::string &tokenName, CAmount& quantity) {
    return Read(std::make_pair(ADDRESS_TOKEN_QUANTITY_FLAG, std::make_pair(address, tokenName)), quantity);
}

bool CTokensDB::EraseTokenData(const std::string& tokenName)
{
    return Erase(std::make_pair(TOKEN_FLAG, tokenName));
}

bool CTokensDB::EraseTokenAddressQuantity(const std::string &tokenName, const std::string &address) {
    return Erase(std::make_pair(TOKEN_ADDRESS_QUANTITY_FLAG, std::make_pair(tokenName, address)));
}

bool CTokensDB::EraseAddressTokenQuantity(const std::string &address, const std::string &tokenName) {
    return Erase(std::make_pair(ADDRESS_TOKEN_QUANTITY_FLAG, std::make_pair(address, tokenName)));
}

bool CTokensDB::WriteBlockUndoTokenData(const uint256& blockhash, const std::vector<std::pair<std::string, CBlockTokenUndo> >& tokenUndoData)
{
    return Write(std::make_pair(BLOCK_TOKEN_UNDO_DATA, blockhash), tokenUndoData);
}

bool CTokensDB::ReadBlockUndoTokenData(const uint256 &blockhash, std::vector<std::pair<std::string, CBlockTokenUndo> > &tokenUndoData)
{
    // If it exists, return the read value.
    if (Exists(std::make_pair(BLOCK_TOKEN_UNDO_DATA, blockhash)))
           return Read(std::make_pair(BLOCK_TOKEN_UNDO_DATA, blockhash), tokenUndoData);

    // If it doesn't exist, we just return true because we don't want to fail just because it didn't exist in the db
    return true;
}

bool CTokensDB::WriteReissuedMempoolState()
{
    return Write(MEMPOOL_REISSUED_TX, mapReissuedTokens);
}

bool CTokensDB::ReadReissuedMempoolState()
{
    mapReissuedTokens.clear();
    mapReissuedTx.clear();
    // If it exists, return the read value.
    bool rv = Read(MEMPOOL_REISSUED_TX, mapReissuedTokens);
    if (rv) {
        for (auto pair : mapReissuedTokens)
            mapReissuedTx.insert(std::make_pair(pair.second, pair.first));
    }
    return rv;
}

bool CTokensDB::LoadTokens()
{
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(TOKEN_FLAG, std::string()));

    // Load tokens
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, std::string> key;
        if (pcursor->GetKey(key) && key.first == TOKEN_FLAG) {
            CDatabasedTokenData data;
            if (pcursor->GetValue(data)) {
                ptokensCache->Put(data.token.strName, data);
                pcursor->Next();

                // Loaded enough from database to have in memory.
                // No need to load everything if it is just going to be removed from the cache
                if (ptokensCache->Size() == (ptokensCache->MaxSize() / 2))
                    break;
            } else {
                return error("%s: failed to read token", __func__);
            }
        } else {
            break;
        }
    }


    if (fTokenIndex) {
        std::unique_ptr<CDBIterator> pcursor3(NewIterator());
        pcursor3->Seek(std::make_pair(TOKEN_ADDRESS_QUANTITY_FLAG, std::make_pair(std::string(), std::string())));

        // Load mapTokenAddressAmount
        while (pcursor3->Valid()) {
            boost::this_thread::interruption_point();
            std::pair<char, std::pair<std::string, std::string> > key; // <Token Name, Address> -> Quantity
            if (pcursor3->GetKey(key) && key.first == TOKEN_ADDRESS_QUANTITY_FLAG) {
                CAmount value;
                if (pcursor3->GetValue(value)) {
                    ptokens->mapTokensAddressAmount.insert(
                            std::make_pair(std::make_pair(key.second.first, key.second.second), value));
                    if (ptokens->mapTokensAddressAmount.size() > MAX_CACHE_TOKENS_SIZE)
                        break;
                    pcursor3->Next();
                } else {
                    return error("%s: failed to read my address quantity from database", __func__);
                }
            } else {
                break;
            }
        }
    }

    return true;
}

bool CTokensDB::TokenDir(std::vector<CDatabasedTokenData>& tokens, const std::string filter, const size_t count, const long start)
{
    FlushTokenToDisk();

    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(std::make_pair(TOKEN_FLAG, std::string()));

    auto prefix = filter;
    bool wildcard = prefix.back() == '*';
    if (wildcard)
        prefix.pop_back();

    size_t skip = 0;
    if (start >= 0) {
        skip = start;
    }
    else {
        // compute table size for backwards offset
        long table_size = 0;
        while (pcursor->Valid()) {
            boost::this_thread::interruption_point();

            std::pair<char, std::string> key;
            if (pcursor->GetKey(key) && key.first == TOKEN_FLAG) {
                if (prefix == "" ||
                    (wildcard && key.second.find(prefix) == 0) ||
                    (!wildcard && key.second == prefix)) {
                    table_size += 1;
                }
            }
            pcursor->Next();
        }
        skip = table_size + start;
        pcursor->SeekToFirst();
    }


    size_t loaded = 0;
    size_t offset = 0;

    // Load tokens
    while (pcursor->Valid() && loaded < count) {
        boost::this_thread::interruption_point();

        std::pair<char, std::string> key;
        if (pcursor->GetKey(key) && key.first == TOKEN_FLAG) {
            if (prefix == "" ||
                    (wildcard && key.second.find(prefix) == 0) ||
                    (!wildcard && key.second == prefix)) {
                if (offset < skip) {
                    offset += 1;
                }
                else {
                    CDatabasedTokenData data;
                    if (pcursor->GetValue(data)) {
                        tokens.push_back(data);
                        loaded += 1;
                    } else {
                        return error("%s: failed to read token", __func__);
                    }
                }
            }
            pcursor->Next();
        } else {
            break;
        }
    }

    return true;
}

bool CTokensDB::AddressDir(std::vector<std::pair<std::string, CAmount> >& vecTokenAmount, int& totalEntries, const bool& fGetTotal, const std::string& address, const size_t count, const long start)
{
    FlushTokenToDisk();

    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(std::make_pair(ADDRESS_TOKEN_QUANTITY_FLAG, std::make_pair(address, std::string())));

    if (fGetTotal) {
        totalEntries = 0;
        while (pcursor->Valid()) {
            boost::this_thread::interruption_point();

            std::pair<char, std::pair<std::string, std::string> > key;
            if (pcursor->GetKey(key) && key.first == ADDRESS_TOKEN_QUANTITY_FLAG && key.second.first == address) {
                totalEntries++;
            }
            pcursor->Next();
        }
        return true;
    }

    size_t skip = 0;
    if (start >= 0) {
        skip = start;
    }
    else {
        // compute table size for backwards offset
        long table_size = 0;
        while (pcursor->Valid()) {
            boost::this_thread::interruption_point();

            std::pair<char, std::pair<std::string, std::string> > key;
            if (pcursor->GetKey(key) && key.first == ADDRESS_TOKEN_QUANTITY_FLAG && key.second.first == address) {
                table_size += 1;
            }
            pcursor->Next();
        }
        skip = table_size + start;
        pcursor->SeekToFirst();
    }


    size_t loaded = 0;
    size_t offset = 0;

    // Load tokens
    while (pcursor->Valid() && loaded < count && loaded < MAX_DATABASE_RESULTS) {
        boost::this_thread::interruption_point();

        std::pair<char, std::pair<std::string, std::string> > key;
        if (pcursor->GetKey(key) && key.first == ADDRESS_TOKEN_QUANTITY_FLAG && key.second.first == address) {
                if (offset < skip) {
                    offset += 1;
                }
                else {
                    CAmount amount;
                    if (pcursor->GetValue(amount)) {
                        vecTokenAmount.emplace_back(std::make_pair(key.second.second, amount));
                        loaded += 1;
                    } else {
                        return error("%s: failed to Address Token Quanity", __func__);
                    }
                }
            pcursor->Next();
        } else {
            break;
        }
    }

    return true;
}

// Can get to total count of addresses that belong to a certain token_name, or get you the list of all address that belong to a certain token_name
bool CTokensDB::TokenAddressDir(std::vector<std::pair<std::string, CAmount> >& vecAddressAmount, int& totalEntries, const bool& fGetTotal, const std::string& tokenName, const size_t count, const long start)
{
    FlushTokenToDisk();

    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(std::make_pair(TOKEN_ADDRESS_QUANTITY_FLAG, std::make_pair(tokenName, std::string())));

    if (fGetTotal) {
        totalEntries = 0;
        while (pcursor->Valid()) {
            boost::this_thread::interruption_point();

            std::pair<char, std::pair<std::string, std::string> > key;
            if (pcursor->GetKey(key) && key.first == TOKEN_ADDRESS_QUANTITY_FLAG && key.second.first == tokenName) {
                totalEntries += 1;
            }
            pcursor->Next();
        }
        return true;
    }

    size_t skip = 0;
    if (start >= 0) {
        skip = start;
    }
    else {
        // compute table size for backwards offset
        long table_size = 0;
        while (pcursor->Valid()) {
            boost::this_thread::interruption_point();

            std::pair<char, std::pair<std::string, std::string> > key;
            if (pcursor->GetKey(key) && key.first == TOKEN_ADDRESS_QUANTITY_FLAG && key.second.first == tokenName) {
                table_size += 1;
            }
            pcursor->Next();
        }
        skip = table_size + start;
        pcursor->SeekToFirst();
    }

    size_t loaded = 0;
    size_t offset = 0;

    // Load tokens
    while (pcursor->Valid() && loaded < count && loaded < MAX_DATABASE_RESULTS) {
        boost::this_thread::interruption_point();

        std::pair<char, std::pair<std::string, std::string> > key;
        if (pcursor->GetKey(key) && key.first == TOKEN_ADDRESS_QUANTITY_FLAG && key.second.first == tokenName) {
            if (offset < skip) {
                offset += 1;
            }
            else {
                CAmount amount;
                if (pcursor->GetValue(amount)) {
                    vecAddressAmount.emplace_back(std::make_pair(key.second.second, amount));
                    loaded += 1;
                } else {
                    return error("%s: failed to Token Address Quanity", __func__);
                }
            }
            pcursor->Next();
        } else {
            break;
        }
    }

    return true;
}

bool CTokensDB::TokenDir(std::vector<CDatabasedTokenData>& tokens)
{
    return CTokensDB::TokenDir(tokens, "*", MAX_SIZE, 0);
}
