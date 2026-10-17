// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_TEST_TOKEN_TEST_UTIL_H
#define YACOIN_TEST_TOKEN_TEST_UTIL_H

#include "base58.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "txmempool.h"
#include "validation.h"

#include "test/test_bitcoin.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

/**
 * What init.cpp creates for tokens, for the guard's lifetime: an in-memory
 * token database and the LRU metadata cache, with the token index enabled.
 * The previous globals are restored, and the token maps cleared, when the
 * guard is destroyed, so no token state leaks into other suites. As a base or
 * member of a fixture this also holds when the fixture's constructor throws.
 */
struct TokenGlobalsGuard {
    CTokensDB* const prevTokensDb;
    CLRUCache<std::string, CDatabasedTokenData>* const prevTokensCache;
    const bool prevTokenIndex;
    std::unique_ptr<CTokensDB> tokensDb;
    std::unique_ptr<CLRUCache<std::string, CDatabasedTokenData> > tokensCache;

    TokenGlobalsGuard()
        : prevTokensDb(ptokensdb), prevTokensCache(ptokensCache), prevTokenIndex(fTokenIndex),
          tokensDb(new CTokensDB(1 << 20, true, true)),
          tokensCache(new CLRUCache<std::string, CDatabasedTokenData>(MAX_CACHE_TOKENS_SIZE))
    {
        ptokensdb = tokensDb.get();
        ptokensCache = tokensCache.get();
        fTokenIndex = true;
        ClearTokenGlobals();
    }

    ~TokenGlobalsGuard()
    {
        ClearTokenGlobals();
        ptokensdb = prevTokensDb;
        ptokensCache = prevTokensCache;
        fTokenIndex = prevTokenIndex;
    }

    TokenGlobalsGuard(const TokenGlobalsGuard&) = delete;
    TokenGlobalsGuard& operator=(const TokenGlobalsGuard&) = delete;

    static void ClearTokenGlobals()
    {
        mapReissuedTokens.clear();
        mapReissuedTx.clear();
        mempool.mapTokenToHash.clear();
        mempool.mapHashToToken.clear();
        if (ptokens) ptokens->ClearDirtyCache();
    }
};

/**
 * TestingSetup plus the token globals of TokenGlobalsGuard. TestingSetup
 * itself creates ptokens and activates genesis, so AreTokensDeployed() is true
 * (nTokenSupportBlockNumber is 0 in unit tests). The guard is destroyed before
 * TestingSetup.
 */
struct TokenTestingSetup : public TestingSetup, public TokenGlobalsGuard {
};

/** P2PKH script and mainnet address for a fixed test key id */
inline CScript TestTokenScriptBase(unsigned char n = 1)
{
    std::vector<unsigned char> vch(20, n);
    return GetScriptForDestination(CKeyID(uint160(vch)));
}

inline std::string TestTokenAddress(unsigned char n = 1)
{
    std::vector<unsigned char> vch(20, n);
    return EncodeDestination(CKeyID(uint160(vch)));
}

inline CScript NewTokenScript(const CNewToken& token, unsigned char n = 1)
{
    CScript script = TestTokenScriptBase(n);
    token.ConstructTransaction(script);
    return script;
}

inline CScript OwnerTokenScript(const CNewToken& token, unsigned char n = 1)
{
    CScript script = TestTokenScriptBase(n);
    token.ConstructOwnerTransaction(script);
    return script;
}

inline CScript TransferTokenScript(const CTokenTransfer& transfer, unsigned char n = 1)
{
    CScript script = TestTokenScriptBase(n);
    transfer.ConstructTransaction(script);
    return script;
}

inline CScript ReissueTokenScript(const CReissueToken& reissue, unsigned char n = 1)
{
    CScript script = TestTokenScriptBase(n);
    reissue.ConstructTransaction(script);
    return script;
}

/** YAC lock output as the wallet builds it (GetScriptForCsvP2PKH, tokens.cpp CreateTokenTransaction) */
inline CTxOut TokenLockOutput(ETokenType type, int nCount = 1, unsigned char n = 1)
{
    std::vector<unsigned char> vch(20, n);
    return CTxOut(GetLockAmount(type) * nCount, GetScriptForCsvP2PKH(GetLockDuration(type), CKeyID(uint160(vch))));
}

/** Issue tx as the wallet builds it: YAC lock, owner token, new token last */
inline CTransaction IssueTx(const CNewToken& token)
{
    ETokenType type;
    IsTokenNameValid(token.strName, type);
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x01"), 0)));
    mtx.vout.push_back(TokenLockOutput(type));
    mtx.vout.push_back(CTxOut(0, OwnerTokenScript(token)));
    mtx.vout.push_back(CTxOut(0, NewTokenScript(token)));
    return CTransaction(mtx);
}

/** Sub-token issue tx: YAC lock, parent owner token change, owner token, new token last */
inline CTransaction SubIssueTx(const CNewToken& token, const std::string& parent)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x04"), 0)));
    mtx.vout.push_back(TokenLockOutput(ETokenType::SUB));
    mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer(parent + OWNER_TAG, OWNER_TOKEN_AMOUNT))));
    mtx.vout.push_back(CTxOut(0, OwnerTokenScript(token)));
    mtx.vout.push_back(CTxOut(0, NewTokenScript(token)));
    return CTransaction(mtx);
}

/** Reissue tx: YAC lock, owner token change, reissue last */
inline CTransaction ReissueTx(const CReissueToken& reissue)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x02"), 0)));
    mtx.vout.push_back(TokenLockOutput(ETokenType::REISSUE));
    mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer(reissue.strName + OWNER_TAG, OWNER_TOKEN_AMOUNT))));
    mtx.vout.push_back(CTxOut(0, ReissueTokenScript(reissue)));
    return CTransaction(mtx);
}

/** Unique tokens tx: YAC lock for all of them, parent owner token change, the new tokens */
inline CTransaction UniqueTx(const std::string& parent, const std::vector<std::string>& tags)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn(COutPoint(uint256S("0x03"), 0)));
    mtx.vout.push_back(TokenLockOutput(ETokenType::UNIQUE, tags.size()));
    mtx.vout.push_back(CTxOut(0, TransferTokenScript(CTokenTransfer(parent + OWNER_TAG, OWNER_TOKEN_AMOUNT))));
    for (const std::string& tag : tags)
        mtx.vout.push_back(CTxOut(0, NewTokenScript(CNewToken(parent + "#" + tag, UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""))));
    return CTransaction(mtx);
}

/** IPFS hash used throughout the token tests, and its 34-byte decoded form */
static const std::string TEST_IPFS_CIDV0 = "QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo";

inline std::string TestIpfsHash()
{
    CIDVersion version;
    return DecodeTokenData(TEST_IPFS_CIDV0, version);
}

/** Token DB keys hold length-prefixed strings, so LevelDB orders names and addresses
 * by length first, then bytewise */
inline bool DbKeyLess(const std::string& a, const std::string& b)
{
    return a.size() != b.size() ? a.size() < b.size() : a < b;
}

/** "name=amount" for each entry of a token DB listing, for readable collection checks */
inline std::vector<std::string> TokenEntries(const std::vector<std::pair<std::string, CAmount> >& vec)
{
    std::vector<std::string> result;
    for (const auto& entry : vec)
        result.push_back(entry.first + "=" + std::to_string(entry.second));
    return result;
}

/** TokenEntries in the order the token DB lists them (DbKeyLess on the key) */
inline std::vector<std::string> TokenEntriesInDbOrder(std::vector<std::pair<std::string, CAmount> > vec)
{
    std::sort(vec.begin(), vec.end(), [](const std::pair<std::string, CAmount>& x, const std::pair<std::string, CAmount>& y) {
        return DbKeyLess(x.first, y.first);
    });
    return TokenEntries(vec);
}

/** TokenAddressDir without the total: "address=amount" of the holders of a token */
inline std::vector<std::string> TokenHolders(const std::string& name, size_t count, long start, bool fExpectOk = true)
{
    std::vector<std::pair<std::string, CAmount> > vec;
    int nTotal = -1;
    BOOST_CHECK_EQUAL(ptokensdb->TokenAddressDir(vec, nTotal, false, name, count, start), fExpectOk);
    BOOST_CHECK_EQUAL(nTotal, -1); // only written when asking for the total
    return TokenEntries(vec);
}

/** AddressDir without the total: "name=amount" of the tokens an address holds */
inline std::vector<std::string> TokenHoldings(const std::string& address, size_t count, long start, bool fExpectOk = true)
{
    std::vector<std::pair<std::string, CAmount> > vec;
    int nTotal = -1;
    BOOST_CHECK_EQUAL(ptokensdb->AddressDir(vec, nTotal, false, address, count, start), fExpectOk);
    BOOST_CHECK_EQUAL(nTotal, -1);
    return TokenEntries(vec);
}

/** Compare a vector<string> with a braced list, printing both on mismatch */
#define TOKEN_CHECK_LIST(got, ...) do { \
    const std::vector<std::string> want_ = __VA_ARGS__; \
    const std::vector<std::string> got_ = (got); \
    BOOST_CHECK_EQUAL_COLLECTIONS(got_.begin(), got_.end(), want_.begin(), want_.end()); \
} while (0)

#endif // YACOIN_TEST_TOKEN_TEST_UTIL_H
