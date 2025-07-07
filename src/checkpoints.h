// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CHECKPOINT_H
#define  BITCOIN_CHECKPOINT_H

#include <map>

#ifndef BITCOIN_UTIL_H
 #include "util.h"
#endif

#ifndef BITCOIN_NET_H
 #include "net.h"
#endif
#include "validation.h"

#define CHECKPOINT_MAX_SPAN (60 * 60) // max 1 hour before latest block

#ifdef WIN32
#undef STRICT_
#undef PERMISSIVE
#undef ADVISORY
#endif

class uint256;
class CBlockIndex;
class CSyncCheckpoint;

/** Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{
    /** Checkpointing mode */
    enum CPMode
    {
        // Scrict checkpoints policy, perform conflicts verification and resolve conflicts
        STRICT_ = 0,
        // Advisory checkpoints policy, perform conflicts verification but don't try to resolve them
        ADVISORY = 1,
        // Permissive checkpoints policy, don't perform any checking
        PERMISSIVE = 2
    };

    // Returns true if block passes checkpoint checks
    bool CheckHardened(int nHeight, const uint256& hash);

    // Return conservative estimate of total number of blocks, 0 if unknown
    int GetTotalBlocksEstimate();

    // Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
    CBlockIndex* GetLastCheckpoint(const BlockMap& mapBlockIndex);

    // Returns last checkpoint timestamp
    unsigned int GetLastCheckpointTime();

    extern uint256 hashSyncCheckpoint;
    extern CSyncCheckpoint checkpointMessage;
    extern uint256 hashInvalidCheckpoint;
    extern CCriticalSection cs_hashSyncCheckpoint;

    CBlockIndex* GetLastSyncCheckpoint();
    bool WriteSyncCheckpoint(const uint256& hashCheckpoint);
    uint256 AutoSelectSyncCheckpoint();
    bool CheckSync(const uint256& hashBlock, const CBlockIndex* pindexPrev);
    bool SetCheckpointPrivKey(std::string strPrivKey);
    bool IsMatureSyncCheckpoint();
}

// ppcoin: synchronized checkpoint
class CUnsignedSyncCheckpoint
{
public:
    int nVersion;
    uint256 hashCheckpoint;      // checkpoint block

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashCheckpoint);
    }

    void SetNull()
    {
        nVersion = 1;
        hashCheckpoint = 0;
    }

    std::string ToString() const
    {
        return strprintf(
                "CSyncCheckpoint(\n"
                "    nVersion       = %d\n"
                "    hashCheckpoint = %s\n"
                ")\n",
            nVersion,
            hashCheckpoint.ToString().c_str());
    }

    void print() const
    {
        LogPrintf("%s\n", ToString());
    }
};

class CSyncCheckpoint : public CUnsignedSyncCheckpoint
{
public:
    static const std::string strMasterPubKey;
    static std::string strMasterPrivKey;

    std::vector<unsigned char> vchMsg;
    std::vector<unsigned char> vchSig;

    CSyncCheckpoint()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchMsg);
        READWRITE(vchSig);
    }

    void SetNull()
    {
        CUnsignedSyncCheckpoint::SetNull();
        vchMsg.clear();
        vchSig.clear();
    }

    bool IsNull() const
    {
        return (hashCheckpoint == 0);
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool CheckSignature();
};

#endif
