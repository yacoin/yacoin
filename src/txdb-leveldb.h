// Copyright (c) 2009-2012 The Bitcoin Developers.
// Authored by Google, Inc.
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LEVELDB_H
#define BITCOIN_LEVELDB_H
#ifdef USE_LEVELDB

#ifndef BITCOIN_MAIN_H
 #include "main.h"
#endif
#include "dbwrapper.h"

#include <string>

// Class that provides access to block index leveldb database
class CTxDB: public CDBWrapper
{
public:
    CTxDB(const char* pszMode="r+");
    ~CTxDB() {}

    bool ReadTxIndex(uint256 hash, CTxIndex& txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(uint256 hash);
    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool WriteBlockHash(const CDiskBlockIndex& blockindex);
    bool ReadBlockHash(const unsigned int nFile, const unsigned int nBlockPos, uint256& blockhash);
    bool ReadHashBestChain(uint256& hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);
    bool ReadBestInvalidTrust(CBigNum& bnBestInvalidTrust);
    bool WriteBestInvalidTrust(CBigNum bnBestInvalidTrust);
    bool ReadSyncCheckpoint(uint256& hashCheckpoint);
    bool WriteSyncCheckpoint(uint256 hashCheckpoint);
    bool ReadCheckpointPubKey(std::string& strPubKey);
    bool WriteCheckpointPubKey(const std::string& strPubKey);
    bool ReadModifierUpgradeTime(unsigned int& nUpgradeTime);
    bool WriteModifierUpgradeTime(const unsigned int& nUpgradeTime);
    bool LoadBlockIndex();
};

#endif
#endif // BITCOIN_DB_H
