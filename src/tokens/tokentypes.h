// Copyright (c) 2019 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_NEWTOKEN_H
#define YACOIN_NEWTOKEN_H

#include <string>
#include <sstream>
#include <list>
#include <unordered_map>
#include "amount.h"
#include "script/script.h"
#include "primitives/transaction.h"

#define MAX_UNIT 6
#define MIN_UNIT 0

class CTokensCache;

enum class ETokenType
{
    YATOKEN = 0,
    SUB = 1,
    UNIQUE = 2,
    OWNER = 3,
    VOTE = 4,
    REISSUE = 5,
    INVALID = 6
};

int IntFromETokenType(ETokenType type);
ETokenType ETokenTypeFromInt(int nType);
std::string ETokenTypeToString(ETokenType& tokenType);

const char IPFS_SHA2_256 = 0x12;
const char TXID_NOTIFIER = 0x54;
const char IPFS_SHA2_256_LEN = 0x20;

template <typename Stream, typename Operation>
bool ReadWriteTokenHash(Stream &s, Operation ser_action, std::string &strIPFSHash)
{
    // assuming 34-byte IPFS SHA2-256 decoded hash (0x12, 0x20, 32 more bytes)
    if (ser_action.ForRead())
    {
        strIPFSHash = "";
        if (!s.empty() and s.size() >= 33) {
            char _sha2_256;
            ::Unserialize(s, _sha2_256);
            std::basic_string<char> hash;
            ::Unserialize(s, hash);

            std::ostringstream os;

            // If it is an ipfs hash, we put the Q and the m 'Qm' at the front
            if (_sha2_256 == IPFS_SHA2_256)
                os << IPFS_SHA2_256 << IPFS_SHA2_256_LEN;

            os << hash.substr(0, 32); // Get the 32 bytes of data
            strIPFSHash = os.str();
            return true;
        }
    }
    else
    {
        if (strIPFSHash.length() == 34) {
            ::Serialize(s, IPFS_SHA2_256);
            ::Serialize(s, strIPFSHash.substr(2));
            return true;
        } else if (strIPFSHash.length() == 32) {
            ::Serialize(s, TXID_NOTIFIER);
            ::Serialize(s, strIPFSHash);
            return true;
        }
    }
    return false;
};

class CNewToken
{
public:
    std::string strName; // MAX 31 Bytes
    CAmount nAmount;     // 8 Bytes
    int8_t units;        // 1 Byte
    int8_t nReissuable;  // 1 Byte
    int8_t nHasIPFS;     // 1 Byte
    std::string strIPFSHash; // MAX 40 Bytes

    CNewToken()
    {
        SetNull();
    }

    CNewToken(const std::string& strName, const CAmount& nAmount, const int& units, const int& nReissuable, const int& nHasIPFS, const std::string& strIPFSHash);
    CNewToken(const std::string& strName, const CAmount& nAmount);

    CNewToken(const CNewToken& token);
    CNewToken& operator=(const CNewToken& token);

    void SetNull()
    {
        strName= "";
        nAmount = 0;
        units = int8_t(MAX_UNIT);
        nReissuable = int8_t(0);
        nHasIPFS = int8_t(0);
        strIPFSHash = "";
    }

    bool IsNull() const;
    std::string ToString();

    void ConstructTransaction(CScript& script) const;
    void ConstructOwnerTransaction(CScript& script) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(strName);
        READWRITE(nAmount);
        READWRITE(units);
        READWRITE(nReissuable);
        READWRITE(nHasIPFS);
        if (nHasIPFS == 1) {
            ReadWriteTokenHash(s, ser_action, strIPFSHash);
        }
    }
};

class TokenComparator
{
public:
    bool operator()(const CNewToken& s1, const CNewToken& s2) const
    {
        return s1.strName < s2.strName;
    }
};

class CDatabasedTokenData
{
public:
    CNewToken token;
    int nHeight;
    uint256 blockHash;

    CDatabasedTokenData(const CNewToken& token, const int& nHeight, const uint256& blockHash);
    CDatabasedTokenData();

    void SetNull()
    {
        token.SetNull();
        nHeight = -1;
        blockHash = uint256();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(token);
        READWRITE(nHeight);
        READWRITE(blockHash);
    }
};

class CTokenTransfer
{
public:
    std::string strName;
    CAmount nAmount;

    CTokenTransfer()
    {
        SetNull();
    }
    CTokenTransfer(const std::string& strTokenName, const CAmount& nAmount);

    void SetNull()
    {
        nAmount = 0;
        strName = "";
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(strName);
        READWRITE(nAmount);
    }
    bool IsValid(std::string& strError) const;
    void ConstructTransaction(CScript& script) const;
};

class CReissueToken
{
public:
    std::string strName;
    CAmount nAmount;
    int8_t nUnits;
    int8_t nReissuable;
    std::string strIPFSHash;

    CReissueToken()
    {
        SetNull();
    }

    void SetNull()
    {
        nAmount = 0;
        strName = "";
        nUnits = 0;
        nReissuable = 1;
        strIPFSHash = "";
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(strName);
        READWRITE(nAmount);
        READWRITE(nUnits);
        READWRITE(nReissuable);
        ReadWriteTokenHash(s, ser_action, strIPFSHash);
    }

    CReissueToken(const std::string& strTokenName, const CAmount& nAmount, const int& nUnits, const int& nReissuable, const std::string& strIPFSHash);
    void ConstructTransaction(CScript& script) const;
    bool IsNull() const;
};

/** THESE ARE ONLY TO BE USED WHEN ADDING THINGS TO THE CACHE DURING CONNECT AND DISCONNECT BLOCK */
struct CTokenCacheNewToken
{
    CNewToken token;
    std::string address;
    uint256 blockHash;
    int blockHeight;

    CTokenCacheNewToken(const CNewToken& token, const std::string& address, const int& blockHeight, const uint256& blockHash)
    {
        this->token = token;
        this->address = address;
        this->blockHash = blockHash;
        this->blockHeight = blockHeight;
    }

    bool operator<(const CTokenCacheNewToken& rhs) const
    {
        return token.strName < rhs.token.strName;
    }
};

struct CTokenCacheReissueToken
{
    CReissueToken reissue;
    std::string address;
    COutPoint out;
    uint256 blockHash;
    int blockHeight;


    CTokenCacheReissueToken(const CReissueToken& reissue, const std::string& address, const COutPoint& out, const int& blockHeight, const uint256& blockHash)
    {
        this->reissue = reissue;
        this->address = address;
        this->out = out;
        this->blockHash = blockHash;
        this->blockHeight = blockHeight;
    }

    bool operator<(const CTokenCacheReissueToken& rhs) const
    {
        return out < rhs.out;
    }

};

struct CTokenCacheNewTransfer
{
    CTokenTransfer transfer;
    std::string address;
    COutPoint out;

    CTokenCacheNewTransfer(const CTokenTransfer& transfer, const std::string& address, const COutPoint& out)
    {
        this->transfer = transfer;
        this->address = address;
        this->out = out;
    }

    bool operator<(const CTokenCacheNewTransfer& rhs ) const
    {
        return out < rhs.out;
    }
};

struct CTokenCacheNewOwner
{
    std::string tokenName;
    std::string address;

    CTokenCacheNewOwner(const std::string& tokenName, const std::string& address)
    {
        this->tokenName = tokenName;
        this->address = address;
    }

    bool operator<(const CTokenCacheNewOwner& rhs) const
    {

        return tokenName < rhs.tokenName;
    }
};

struct CTokenCacheUndoTokenAmount
{
    std::string tokenName;
    std::string address;
    CAmount nAmount;

    CTokenCacheUndoTokenAmount(const std::string& tokenName, const std::string& address, const CAmount& nAmount)
    {
        this->tokenName = tokenName;
        this->address = address;
        this->nAmount = nAmount;
    }
};

struct CTokenCacheSpendToken
{
    std::string tokenName;
    std::string address;
    CAmount nAmount;

    CTokenCacheSpendToken(const std::string& tokenName, const std::string& address, const CAmount& nAmount)
    {
        this->tokenName = tokenName;
        this->address = address;
        this->nAmount = nAmount;
    }
};

// Least Recently Used Cache
template<typename cache_key_t, typename cache_value_t>
class CLRUCache
{
public:
    typedef typename std::pair<cache_key_t, cache_value_t> key_value_pair_t;
    typedef typename std::list<key_value_pair_t>::iterator list_iterator_t;

    CLRUCache(size_t max_size) : maxSize(max_size)
    {
    }
    CLRUCache()
    {
        SetNull();
    }

    void Put(const cache_key_t& key, const cache_value_t& value)
    {
        auto it = cacheItemsMap.find(key);
        cacheItemsList.push_front(key_value_pair_t(key, value));
        if (it != cacheItemsMap.end())
        {
            cacheItemsList.erase(it->second);
            cacheItemsMap.erase(it);
        }
        cacheItemsMap[key] = cacheItemsList.begin();

        if (cacheItemsMap.size() > maxSize)
        {
            auto last = cacheItemsList.end();
            last--;
            cacheItemsMap.erase(last->first);
            cacheItemsList.pop_back();
        }
    }

    void Erase(const cache_key_t& key)
    {
        auto it = cacheItemsMap.find(key);
        if (it != cacheItemsMap.end())
        {
            cacheItemsList.erase(it->second);
            cacheItemsMap.erase(it);
        }
    }

    const cache_value_t& Get(const cache_key_t& key)
    {
        auto it = cacheItemsMap.find(key);
        if (it == cacheItemsMap.end())
        {
            throw std::range_error("There is no such key in cache");
        }
        else
        {
            cacheItemsList.splice(cacheItemsList.begin(), cacheItemsList, it->second);
            return it->second->second;
        }
    }

    bool Exists(const cache_key_t& key) const
    {
        return cacheItemsMap.find(key) != cacheItemsMap.end();
    }

    size_t Size() const
    {
        return cacheItemsMap.size();
    }


    void Clear()
    {
        cacheItemsMap.clear();
        cacheItemsList.clear();
    }

    void SetNull()
    {
        maxSize = 0;
        Clear();
    }

    size_t MaxSize() const
    {
        return maxSize;
    }


    void SetSize(const size_t size)
    {
        maxSize = size;
    }

   const std::unordered_map<cache_key_t, list_iterator_t>& GetItemsMap()
    {
        return cacheItemsMap;
    };

    const std::list<key_value_pair_t>& GetItemsList()
    {
        return cacheItemsList;
    };


    CLRUCache(const CLRUCache& cache)
    {
        this->cacheItemsList = cache.cacheItemsList;
        this->cacheItemsMap = cache.cacheItemsMap;
        this->maxSize = cache.maxSize;
    }

private:
    std::list<key_value_pair_t> cacheItemsList;
    std::unordered_map<cache_key_t, list_iterator_t> cacheItemsMap;
    size_t maxSize;
};

#endif //YACOIN_NEWTOKEN_H
