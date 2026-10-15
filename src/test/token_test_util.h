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

#include <string>

/**
 * TestingSetup plus what init.cpp creates for tokens: an in-memory token
 * database and the LRU metadata cache, with the token index enabled.
 * TestingSetup itself creates ptokens and activates genesis, so
 * AreTokensDeployed() is true (nTokenSupportBlockNumber is 0 in unit tests).
 * Everything is restored or cleared on teardown so no token state leaks into
 * other suites.
 */
struct TokenTestingSetup : public TestingSetup {
    CTokensDB* prevTokensDb;
    CLRUCache<std::string, CDatabasedTokenData>* prevTokensCache;
    bool prevTokenIndex;

    TokenTestingSetup()
    {
        prevTokensDb = ptokensdb;
        prevTokensCache = ptokensCache;
        prevTokenIndex = fTokenIndex;
        ptokensdb = new CTokensDB(1 << 20, true, true);
        ptokensCache = new CLRUCache<std::string, CDatabasedTokenData>(MAX_CACHE_TOKENS_SIZE);
        fTokenIndex = true;
        ClearTokenGlobals();
    }

    ~TokenTestingSetup()
    {
        ClearTokenGlobals();
        delete ptokensdb;
        delete ptokensCache;
        ptokensdb = prevTokensDb;
        ptokensCache = prevTokensCache;
        fTokenIndex = prevTokenIndex;
    }

    static void ClearTokenGlobals()
    {
        mapReissuedTokens.clear();
        mapReissuedTx.clear();
        mempool.mapTokenToHash.clear();
        mempool.mapHashToToken.clear();
        if (ptokens) ptokens->ClearDirtyCache();
    }
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
inline std::vector<std::string> Entries(const std::vector<std::pair<std::string, CAmount> >& vec)
{
    std::vector<std::string> result;
    for (const auto& entry : vec)
        result.push_back(entry.first + "=" + std::to_string(entry.second));
    return result;
}

/** Compare a vector<string> with a braced list, printing both on mismatch */
#define CHECK_LIST(got, ...) do { \
    const std::vector<std::string> want_ = __VA_ARGS__; \
    const std::vector<std::string> got_ = (got); \
    BOOST_CHECK_EQUAL_COLLECTIONS(got_.begin(), got_.end(), want_.begin(), want_.end()); \
} while (0)

#endif // YACOIN_TEST_TOKEN_TEST_UTIL_H
