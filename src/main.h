// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include <algorithm>

#ifndef BITCOIN_TIMESTAMPS_H
 #include "timestamps.h"
#endif

#ifndef BITCOIN_BIGNUM_H
 #include "bignum.h"
#endif

#ifndef BITCOIN_SYNC_H
 #include "sync.h"
#endif

#ifndef BITCOIN_NET_H
 #include "net.h"
#endif

#ifndef H_BITCOIN_SCRIPT
 #include "script/script.h"
#endif

#ifndef SCRYPT_H
 #include "scrypt.h"
#endif

#include "primitives/transaction.h"
#include "primitives/block.h"
#include "addressindex.h"
#include "tokens/tokentypes.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "amount.h"
#include "policy/fees.h"
#include <list>
#include <map>
#include <boost/filesystem.hpp>
#include <txmempool.h>
#include <validation.h>
#include "consensus/consensus.h"

class CWallet;
class CBlock;
class CBlockIndex;
class CKeyItem;
class CReserveKey;
class COutPoint;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;
class CBlockIndexWorkComparator;

//
// GLOBAL VARIABLES USED FOR TOKEN MANAGEMENT SYSTEM
//
/** Global variable that point to the active tokens database (protected by cs_main) */
extern CTokensDB *ptokensdb;

/** Global variable that point to the active tokens (protected by cs_main) */
extern CTokensCache *ptokens;

/** Global variable that point to the tokens metadata LRU Cache (protected by cs_main) */
extern CLRUCache<std::string, CDatabasedTokenData> *ptokensCache;
extern bool fTokenIndex;
extern bool fAddressIndex;
//
// END OF GLOBAL VARIABLES USED FOR TOKEN MANAGEMENT SYSTEM
//

//
// FUNCTIONS USED FOR TOKEN MANAGEMENT SYSTEM
//
/** Flush all state, indexes and buffers to disk. */
bool FlushTokenToDisk();
bool AreTokensDeployed();
CTokensCache* GetCurrentTokenCache();
bool CheckTxTokens(
    const CTransaction& tx, CValidationState& state, MapPrevTx inputs,
    CTokensCache* tokenCache, bool fCheckMempool,
    std::vector<std::pair<std::string, uint256> >& vPairReissueTokens);
void UpdateTokenInfo(const CTransaction& tx, MapPrevTx& prevInputs, int nHeight, uint256 blockHash, CTokensCache* tokensCache, std::pair<std::string, CBlockTokenUndo>* undoTokenData);
void UpdateTokenInfoFromTxInputs(const COutPoint& out, const CTxOut& txOut, CTokensCache* tokensCache);
void UpdateTokenInfoFromTxOutputs(const CTransaction& tx, int nHeight, uint256 blockHash, CTokensCache* tokensCache, std::pair<std::string, CBlockTokenUndo>* undoTokenData);
bool GetAddressIndex(uint160 addressHash, int type, std::string tokenName,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                     int start = 0, int end = 0);
bool GetAddressIndex(uint160 addressHash, int type,
                     std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                     int start = 0, int end = 0);
bool GetAddressUnspent(uint160 addressHash, int type, std::string tokenName,
                       std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs);
bool GetAddressUnspent(uint160 addressHash, int type,
                       std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs);
/** Translation to a filesystem path */
boost::filesystem::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);
//
// END OF FUNCTIONS USED FOR TOKEN MANAGEMENT SYSTEM
//


//
// Global state
//
extern int 
    nStatisticsNumberOfBlocks2000,
    nStatisticsNumberOfBlocks1000,
    nStatisticsNumberOfBlocks200,
    nStatisticsNumberOfBlocks100,
    nStatisticsNumberOfBlocks;

static const unsigned int MAX_ORPHAN_TRANSACTIONS = 10000;
static const unsigned int MAX_INV_SZ = 50000;
/** Maxiumum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 21;

static const ::int64_t MAX_MINT_PROOF_OF_WORK = 100 * COIN;
static const ::int64_t MAX_MINT_PROOF_OF_STAKE = 1 * COIN;
static const ::int64_t MIN_TXOUT_AMOUNT = CENT/100;

// Maximum number of script-checking threads allowed
static const int MAX_SCRIPTCHECK_THREADS = 16;
/** Timeout in seconds during which a peer must stall block download progress before being disconnected. */
static const unsigned int BLOCK_STALLING_TIMEOUT = 2;
/** Number of headers sent in one getheaders result. We rely on the assumption that if a peer sends
 *  less than this number, we reached their tip. Changing this value is a protocol upgrade. */
static unsigned int MAX_HEADERS_RESULTS = 2000;
/** Number of blocks that can be requested at any given time from a single peer. */
extern int MAX_BLOCKS_IN_TRANSIT_PER_PEER;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
extern unsigned int BLOCK_DOWNLOAD_WINDOW; //32000
extern unsigned int FETCH_BLOCK_DOWNLOAD; //4000
// Trigger sending getblocks from other peers when header > block + HEADER_BLOCK_DIFFERENCES_TRIGGER_GETDATA
extern unsigned int HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS; //default = 10000
/** Headers download timeout expressed in microseconds
 *  Timeout = base + per_header * (expected number of headers) */
extern int64_t HEADERS_DOWNLOAD_TIMEOUT_BASE; // 10 minutes
extern int64_t BLOCK_DOWNLOAD_TIMEOUT_BASE; // 10 minutes
static const int64_t HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER = 1000; // 1ms/header
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    static const uint256 hashGenesisBlock("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5");
#else
    static const uint256 hashGenesisBlock("0x1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848");
#endif

extern const uint256 
    nPoWeasiestTargetLimitTestNet,
    hashGenesisBlockTestNet;
extern int 
    nConsecutiveStakeSwitchHeight;  // see timesamps.h = 420000;
// All pairs A->B, where A (or one if its ancestors) misses transactions, but B has transactions.
extern std::multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;
// Best header we've seen so far (used for getheaders queries' starting points).
extern CBlockIndex *pindexBestHeader;
const ::int64_t 
    nMaxClockDrift = nTwoHoursInSeconds;

inline ::int64_t PastDrift(::int64_t nTime)   
    { return nTime - nMaxClockDrift; } // up to 2 hours from the past
inline ::int64_t FutureDrift(::int64_t nTime) 
    { return nTime + nMaxClockDrift; } // up to 2 hours from the future

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern std::map<uint256, CBlockIndex*> mapBlockIndex;
extern boost::mutex mapHashmutex;
extern std::map<uint256, uint256> mapHash; // map of (SHA256-hash, chacha-hash)
extern std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;
extern unsigned int nNodeLifespan;
//extern unsigned int nStakeMinAge;
extern int nCoinbaseMaturity;
extern CBigNum bnBestChainTrust;
extern CBlockIndex *pindexBestInvalid;
extern uint256 hashBestChain;
extern ::uint64_t nLastBlockTx;
extern ::uint64_t nLastBlockSize;
extern ::uint32_t nLastCoinStakeSearchInterval;
extern const std::string strMessageMagic;
extern ::int64_t nTimeBestReceived;
extern CCriticalSection cs_vpwalletRegistered;
extern std::vector<CWallet*> vpwalletRegistered;
extern unsigned char pchMessageStart[4];
extern ::int64_t nBlockRewardPrev;
extern const ::int64_t nSimulatedMOneySupplyAtFork;
extern ::uint32_t nMinEase; // minimum ease corresponds to highest difficulty

// Settings
extern ::int64_t nTransactionFee;
extern ::int64_t nMinimumInputValue;
extern bool fUseFastIndex;
extern bool fReindexOnlyHeaderSync;
extern bool fReindexBlockIndex;
extern bool fReindexToken;
extern int nScriptCheckThreads;
extern int nHashCalcThreads;
extern const uint256 entropyStore[38];
extern bool fStoreBlockHashToDb;

// Minimum disk space required - used in CheckDiskSpace()
static const ::uint64_t nMinDiskSpace = 52428800;

// Median starting height of all connected peers.
extern int nMedianStartingHeight;

// Mempool
extern CTxMemPool mempool;

class CReserveKey;
class CTxDB;
class CTxIndex;
class CScriptCheck;
class CBlockLocator;
class CValidationState;
struct CNodeStateStats;

void RegisterWallet(CWallet* pwalletIn);
void CloseWallets();
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false, bool fConnect = true);
/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);
bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock, CDiskBlockPos *dbp = NULL);
bool CheckDiskSpace(::uint64_t nAdditionalBytes=0);

void UnloadBlockIndex();
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
CBlockIndex* FindBlockByHeight(int nHeight);
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);
/** Import blocks from an external file */
bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp = NULL);

// Run an instance of the script checking thread
void ThreadScriptCheck(void* parg);
// Stop the script checking threads
void ThreadScriptCheckQuit();
// Run an instance of the hash calculation thread
void ThreadHashCalculation(void* parg);
// Stop the hash calculation threads
void ThreadHashCalculationQuit();

bool CheckProofOfWork(uint256 hash, unsigned int nBits);
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake);
::int64_t GetProofOfStakeReward(::int64_t nCoinAge, unsigned int nBits, ::int64_t nTime, bool bCoinYearOnly=false);
::int64_t GetProofOfStakeReward(::int64_t nCoinAge);

unsigned int ComputeMinWork(unsigned int nBase, ::int64_t nTime);
unsigned int ComputeMinStake(unsigned int nBase, ::int64_t nTime, unsigned int nBlockTime);
int GetNumBlocksOfPeers();
std::string GetWarnings(std::string strFor);
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock);
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake);

void StakeMinter(CWallet *pwallet);
void ResendWalletTransactions();

bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType);
bool AbortNode(const std::string &msg);
/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);
/** Increase a node's misbehavior score. */
void Misbehaving(NodeId nodeid, int howmuch);

// yacoin: calculate Nfactor using timestamp
extern unsigned char GetNfactor(::int64_t nTimestamp, bool fYac1dot0BlockOrTx = false);

/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included in a block.
 * Consensus critical. Takes as input a list of heights at which tx's inputs (in order) confirmed.
 */
bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);

/**
 * Test whether the LockPoints height and time are still valid on the current chain
 */
bool TestLockPointValidity(const LockPoints* lp);

/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 *
 * Simulates calling SequenceLocks() with data from the tip of the current active chain.
 * Optionally stores in LockPoints the resulting height and time calculated and the hash
 * of the block needed for calculation or skips the calculation and uses the LockPoints
 * passed in for evaluation.
 * The LockPoints should not be considered valid if CheckSequenceLocks returns false.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp = nullptr, bool useExistingLockPoints = false);

/**
 * Get minimum confirmations to use coinbase
 */
int GetCoinbaseMaturity();

/**
 * Get an extra confirmations to add coinbase to balance
 */
int GetCoinbaseMaturityOffset();

//bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);

bool SetBestChain(CValidationState &state, CTxDB& txdb, CBlockIndex* pindexNew);
/** Find the best known block, and make it the tip of the block chain */
bool ActivateBestChain(CValidationState &state, CTxDB& txdb);

struct CNodeStateStats {
    int nMisbehavior;
    int nSyncHeight;
    int nCommonHeight;
    std::vector<int> vHeightInFlight;
};

/** Position on disk for a particular transaction. */
class CDiskTxPos
{
//public:   // if the data isn't private this isn't more than a plain old C struct
            // if private we can name the privates with no change to the code
private:
    ::uint32_t nFile;
    ::uint32_t nBlockPos;
    ::uint32_t nTxPos;
public:
    ::uint32_t Get_CDiskTxPos_nFile() const { return nFile; }
    ::uint32_t Get_CDiskTxPos_nBlockPos() const { return nBlockPos; }
    ::uint32_t Get_CDiskTxPos_nTxPos() const { return nTxPos; }
    // these 'getters' are most probably optimized compiles to the equivalent
    // return of the variable, no different than if they were public, just read only
    // this should/will be done for all these old fashioned classes with no privacy
    CDiskTxPos()
    {
        SetNull();
    }

    CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
    {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nTxPos);
    }

    void SetNull() { nFile = (unsigned int) -1; nBlockPos = 0; nTxPos = 0; }
    bool IsNull() const { return (nFile == (unsigned int) -1); }

    friend bool operator==(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return (a.nFile     == b.nFile &&
                a.nBlockPos == b.nBlockPos &&
                a.nTxPos    == b.nTxPos);
    }

    friend bool operator!=(const CDiskTxPos& a, const CDiskTxPos& b)
    {
        return !(a == b);
    }


    std::string ToString() const
    {
        if (IsNull())
            return "null";
        else
            return strprintf("(nFile=%u, nBlockPos=%u, nTxPos=%u)", nFile, nBlockPos, nTxPos);
    }

    void print() const
    {
        LogPrintf("%s\n", ToString());
    }
};

/** Closure representing one script verification
 *  Note that this stores references to the spending transaction */
class CScriptCheck
{
private:
    CScript scriptPubKey;
    const CTransaction *ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    int nHashType;

public:
    CScriptCheck() {}
    CScriptCheck(const CTransaction& txFromIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, int nHashTypeIn) :
        scriptPubKey(txFromIn.vout[txToIn.vin[nInIn].prevout.COutPointGet_n()].scriptPubKey),
        ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), nHashType(nHashTypeIn) { }

    bool operator()() const;

    void swap(CScriptCheck &check) {
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(nHashType, check.nHashType);
    }
};

/** Closure representing one block hash calculation
 *  Note that this stores pointer to the block*/
class CHashCalculation
{
private:
    CBlock *pBlock;
    CNode* pNode;

public:
    CHashCalculation() {}
    CHashCalculation(CBlock* pBlock, CNode* pNode) :
        pBlock(pBlock), pNode(pNode) { }

    bool operator()();
    void swap(CHashCalculation &check) {
        std::swap(pBlock, check.pBlock);
        std::swap(pNode, check.pNode);
    }
};


/** A transaction with a merkle branch linking it to the block chain. */
class CMerkleTx : public CTransaction
{
public:
    uint256 hashBlock;
    std::vector<uint256> vMerkleBranch;
    ::int32_t nIndex;

    // memory only
    mutable bool fMerkleVerified;


    CMerkleTx()
    {
        Init();
    }

    CMerkleTx(const CTransaction& txIn) : CTransaction(txIn)
    {
        Init();
    }

    void Init()
    {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
    }


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    }

    int SetMerkleBranch(const CBlock* pblock=NULL);
    int GetDepthInMainChain(CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(CTxDB& txdb);
    bool AcceptToMemoryPool();
};




/**  A txdb record that contains the disk location of a transaction and the
 * locations of transactions that spend its outputs.  vSpent is really only
 * used as a flag, but having the location is very helpful for debugging.
 */
class CTxIndex
{
public:
    CDiskTxPos pos;
    std::vector<CDiskTxPos> vSpent;

    CTxIndex()
    {
        SetNull();
    }

    CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs)
    {
        pos = posIn;
        vSpent.resize(nOutputs);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(_nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    }

    void SetNull()
    {
        pos.SetNull();
        vSpent.clear();
    }

    bool IsNull()
    {
        return pos.IsNull();
    }

    friend bool operator==(const CTxIndex& a, const CTxIndex& b)
    {
        return (a.pos    == b.pos &&
                a.vSpent == b.vSpent);
    }

    friend bool operator!=(const CTxIndex& a, const CTxIndex& b)
    {
        return !(a == b);
    }
    int GetDepthInMainChain() const;

};

#endif
