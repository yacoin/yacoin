// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* TACA: NEW CODE START */
#ifndef BITCOIN_NET_PROCESSING_H
#define BITCOIN_NET_PROCESSING_H

#include "net.h"
#include "validationinterface.h"
#include <boost/array.hpp>

/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const unsigned int DEFAULT_MAX_ORPHAN_TRANSACTIONS = 100;
/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;
/** Expiration time for orphan transactions in seconds */
static const int64_t ORPHAN_TX_EXPIRE_TIME = 20 * 60;
/** Minimum time between orphan transactions expire time checks in seconds */
static const int64_t ORPHAN_TX_EXPIRE_INTERVAL = 5 * 60;
/** Default number of orphan+recently-replaced txn to keep around for block reconstruction */
static const unsigned int DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN = 100;
static const unsigned int DEFAULT_BANSCORE_THRESHOLD = 100;
/** Protect at least this many outbound peers from disconnection due to slow/
 * behind headers chain.
 */
static constexpr int32_t MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT = 4;
/** Timeout for (unprotected) outbound peers to sync to our chainwork, in seconds */
static constexpr int64_t CHAIN_SYNC_TIMEOUT = 20 * 60; // 20 minutes
/** How frequently to check for stale tips, in seconds */
static constexpr int64_t STALE_CHECK_INTERVAL = 10 * 60; // 10 minutes
/** How frequently to check for extra outbound peers and disconnect, in seconds */
static constexpr int64_t EXTRA_PEER_CHECK_INTERVAL = 45;
/** Minimum time an outbound-peer-eviction candidate must be connected for, in order to evict, in seconds */
static constexpr int64_t MINIMUM_CONNECT_TIME = 30;

extern const unsigned int nPoWTargetSpacing;
extern CCriticalSection cs_main;
extern boost::mutex mapHashmutex;
extern std::map<uint256, uint256> mapHash; // map of (SHA256-hash, chacha-hash)
extern int nHashCalcThreads;

class PeerLogicValidation : public CValidationInterface, public NetEventsInterface {
private:
    CConnman* const connman;

public:
    explicit PeerLogicValidation(CConnman* connman, CScheduler &scheduler);

    void BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected, const std::vector<CTransactionRef>& vtxConflicted) override;
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;
    void BlockChecked(const CBlock& block, const CValidationState& state) override;
    void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& pblock) override;


    void InitializeNode(CNode* pnode) override;
    void FinalizeNode(NodeId nodeid, bool& fUpdateConnectionTime) override;
    /** Process protocol messages received from a given node */
    bool ProcessMessages(CNode* pfrom, std::atomic<bool>& interrupt) override;
    /**
    * Send queued protocol messages to be sent to a give node.
    *
    * @param[in]   pto             The node which we are sending messages to.
    * @param[in]   interrupt       Interrupt condition for processing threads
    * @return                      True if there is more work to be done
    */
    bool SendMessages(CNode* pto, std::atomic<bool>& interrupt) override;

    void ConsiderEviction(CNode *pto, int64_t time_in_seconds);
    void CheckForStaleTipAndEvictPeers();
    void EvictExtraOutboundPeers(int64_t time_in_seconds);

private:
    int64_t m_stale_tip_check_time; //! Next time to check for stale tip
};

struct CNodeStateStats {
    int nMisbehavior;
    int nSyncHeight;
    int nCommonHeight;
    std::vector<int> vHeightInFlight;
};

class CBlockHeader;
/** Closure representing one block hash calculation
 *  Note that this stores pointer to the block*/
class CHashCalculation
{
private:
    CBlockHeader *pBlock;
    CNode* pNode;

public:
    CHashCalculation() {}
    CHashCalculation(CBlockHeader* pBlock, CNode* pNode) :
        pBlock(pBlock), pNode(pNode) { }

    bool operator()();
    void swap(CHashCalculation &check) {
        std::swap(pBlock, check.pBlock);
        std::swap(pNode, check.pNode);
    }
};

/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);
/** Increase a node's misbehavior score. */
void Misbehaving(NodeId nodeid, int howmuch);

// Run an instance of the hash calculation thread
void ThreadHashCalculation(void* parg);
// Stop the hash calculation threads
void ThreadHashCalculationQuit();

/* Wallet functions */
extern void Inventory(const uint256& hash);
void RelayTransaction(const CTransaction& tx, CConnman* connman);
/* TACA: NEW CODE END */

/** Thread types */
enum threadId
{
    THREAD_SOCKETHANDLER,
    THREAD_OPENCONNECTIONS,
    THREAD_MESSAGEHANDLER,
    THREAD_MINER,
    THREAD_RPCLISTENER,
    THREAD_UPNP,
    THREAD_DNSSEED,
    THREAD_ADDEDCONNECTIONS,
    THREAD_DUMPADDRESS,
    THREAD_RPCHANDLER,
    THREAD_MINTER,
    THREAD_SCRIPTCHECK,
    THREAD_HASHCALCULATION,

    THREAD_MAX
};

void StartNode(void *parg);
void StopNode();

extern boost::array<int, THREAD_MAX> vnThreadsRunning;

class CTransaction;
extern void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false, bool fConnect = true);

#endif // BITCOIN_NET_PROCESSING_H
