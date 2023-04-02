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
#include <list>
#include <map>

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

static const unsigned int MAX_GENESIS_BLOCK_SIZE = 1000000;
static const unsigned int MAX_ORPHAN_TRANSACTIONS = 10000;
static const unsigned int MAX_INV_SZ = 50000;
/** Maxiumum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 21;

static const ::int64_t MIN_TX_FEE = CENT;
static const ::int64_t MIN_RELAY_TX_FEE = MIN_TX_FEE;

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
    // hashGenesisBlock("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5");
    // hashGenesisBlock("0x00000f3f5eac1539c4e9216e17c74ff387ac1629884d2f97a3144dc32bf67bda");
    // hashGenesisBlock("0x0ea17bb85e10d8c6ded6783a4ce8f79e75d49b439ff41f55d274e6b15612fff9");
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    static const uint256 hashGenesisBlock("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5");
    static const int64_t INITIAL_MONEY_SUPPLY = 0;
#else
    static const uint256 hashGenesisBlock("0x1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848");
    static const int64_t INITIAL_MONEY_SUPPLY = 1E14;
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
extern unsigned int nTransactionsUpdated;
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

enum GetMaxSize_mode
{
    MAX_BLOCK_SIZE,
    MAX_BLOCK_SIZE_GEN,
    MAX_BLOCK_SIGOPS,
};

enum BlockStatus {
    // Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    // Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER       =    1,

    // All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    // are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    // Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
    // sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
    // parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
    BLOCK_VALID_TRANSACTIONS =    3,

    // Outputs do not overspend inputs, no double spends, coinbase output ok, immature coinbase spends, BIP30.
    // Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    // Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    // All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, // full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, // undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,
    BLOCK_FAILED_VALID       =   32, // stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, // descends from failed block
    BLOCK_FAILED_MASK = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
};

class CReserveKey;
class CTxDB;
class CTxIndex;
class CScriptCheck;
class CBlockLocator;
class CValidationState;
struct CNodeStateStats;

/** The currently-connected chain of blocks. */
/** An in-memory indexed chain of blocks. */
class CChain {
private:
    std::vector<CBlockIndex*> vChain;

public:
    /** Returns the index entry for the genesis block of this chain, or NULL if none. */
    CBlockIndex *Genesis() const {
        return vChain.size() > 0 ? vChain[0] : NULL;
    }

    /** Returns the index entry for the tip of this chain, or NULL if none. */
    CBlockIndex *Tip() const {
        return vChain.size() > 0 ? vChain[vChain.size() - 1] : NULL;
    }

    /** Returns the index entry at a particular height in this chain, or NULL if no such height exists. */
    CBlockIndex *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return NULL;
        return vChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain &a, const CChain &b) {
        return a.vChain.size() == b.vChain.size() &&
               a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const;

    /** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
    CBlockIndex *Next(const CBlockIndex *pindex) const;

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const {
        return vChain.size() - 1;
    }

    /** Set/initialize a chain with a given tip. Returns the forking point. */
    CBlockIndex *SetTip(CBlockIndex *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator GetLocator(const CBlockIndex *pindex = NULL) const;

    /** Find the last common block between this chain and a locator. */
    CBlockIndex *FindFork(const CBlockLocator &locator) const;

    /** Find the last common block between this chain and a block index entry. */
    CBlockIndex *FindFork(CBlockIndex *pindex) const;
};
/** The currently-connected chain of blocks. */
extern CChain chainActive;

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state);

void RegisterWallet(CWallet* pwalletIn);
void CloseWallets();
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false, bool fConnect = true);
/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals& nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals& nodeSignals);
bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock);
bool CheckDiskSpace(::uint64_t nAdditionalBytes=0);

void UnloadBlockIndex();
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
CBlockIndex* FindBlockByHeight(int nHeight);
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);
bool LoadExternalBlockFile(FILE* fileIn);

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
::int64_t GetProofOfWorkReward(unsigned int nBits=0, ::int64_t nFees=0, unsigned int nHeight=0);
::int64_t GetProofOfStakeReward(::int64_t nCoinAge, unsigned int nBits, ::int64_t nTime, bool bCoinYearOnly=false);

::int64_t GetProofOfStakeReward(::int64_t nCoinAge);
::uint64_t GetMaxSize(enum GetMaxSize_mode mode);

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
 * Check if transaction will be BIP 68 final in the next block to be created.
 */
bool CheckSequenceLocks(const CTransaction &tx, int flags);

/**
 * Get minimum confirmations to use coinbase
 */
int GetCoinbaseMaturity();

/**
 * Get an extra confirmations to add coinbase to balance
 */
int GetCoinbaseMaturityOffset();

/**
 * Check if the hardfork happens
 */
bool isHardforkHappened();

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

    IMPLEMENT_SERIALIZE
    ( 
        READWRITE(FLATDATA(*this)); 
    )
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
        printf("%s", ToString().c_str());
    }
};

/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
//public:
private:
    CTransaction* ptx;
    ::uint32_t n;
public:
    CTransaction* GetPtx() const { return ptx; }
    CInPoint() { SetNull(); }
    CInPoint(CTransaction* ptxIn, unsigned int nIn) { ptx = ptxIn; n = nIn; }
    void SetNull() { ptx = NULL; n = (unsigned int) -1; }
    bool IsNull() const { return (ptx == NULL && n == (unsigned int) -1); }
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


    IMPLEMENT_SERIALIZE
    (
        nSerSize += SerReadWrite(s, *(CTransaction*)this, nType, nVersion, ser_action);
        nVersion = this->nVersion;
        READWRITE(hashBlock);
        READWRITE(vMerkleBranch);
        READWRITE(nIndex);
    )


    int SetMerkleBranch(const CBlock* pblock=NULL);
    int GetDepthInMainChain(CBlockIndex* &pindexRet) const;
    int GetDepthInMainChain() const { CBlockIndex *pindexRet; return GetDepthInMainChain(pindexRet); }
    bool IsInMainChain() const { return GetDepthInMainChain() > 0; }
    int GetBlocksToMaturity() const;
    bool AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs=true);
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

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(pos);
        READWRITE(vSpent);
    )

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

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 *
 * What about the top index? What is its pnext? NULL?
 *
 */
class CBlockIndex
{
protected:
    std::string ToString() const
    {
        return strprintf(
                         "CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d "
                         "nHeight=%d, nMint=%s, nMoneySupply=%s, nFlags=(%s)(%d)(%s), "
                         "nStakeModifier=%016" PRIx64 ", nStakeModifierChecksum=%08x, "
                         "hashProofOfStake=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, "
                         "hashBlock=%s)",
                         pprev, pnext, nFile, nBlockPos, nHeight,
                         FormatMoney(nMint).c_str(), FormatMoney(nMoneySupply).c_str(),
                         GeneratedStakeModifier() ? "MOD" : "-", GetStakeEntropyBit(), IsProofOfStake()? "PoS" : "PoW",
                         nStakeModifier, nStakeModifierChecksum, 
                         hashProofOfStake.ToString().c_str(),
                         prevoutStake.ToString().c_str(), nStakeTime,
                         hashMerkleRoot.ToString().c_str(),
                         GetBlockHash().ToString().c_str()
                        );
    }

public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;
    // pointer to the index of some further predecessor of this block
    CBlockIndex* pskip;
    ::uint32_t nFile;
    ::uint32_t nBlockPos;
    CBigNum bnChainTrust; // ppcoin: trust score of block chain
    ::int32_t nHeight;

    ::int64_t nMint;
    ::int64_t nMoneySupply;

    ::uint32_t nFlags;  // ppcoin: block index flags
    enum  
    {
        BLOCK_PROOF_OF_STAKE = (1 << 0), // is proof-of-stake block
        BLOCK_STAKE_ENTROPY  = (1 << 1), // entropy bit for stake modifier
        BLOCK_STAKE_MODIFIER = (1 << 2), // regenerated stake modifier
    };

    ::uint64_t nStakeModifier; // hash modifier for proof-of-stake
    ::uint32_t nStakeModifierChecksum; // checksum of index; in-memeory only

    // proof-of-stake specific fields
    COutPoint prevoutStake;
    ::uint32_t nStakeTime;
    uint256 hashProofOfStake;

    // block header
    ::int32_t  nVersion;
    uint256  hashMerkleRoot;
    mutable ::int64_t nTime;
    ::uint32_t nBits;
    ::uint32_t nNonce;

    ::uint256 blockHash; // store hash to avoid calculating many times
    // Verification status of this block. See enum BlockStatus
    unsigned int nStatus;
    // (memory only) Sequencial id assigned to distinguish order in which blocks are received.
    uint32_t nSequenceId;
    // (memory only) This value will be set to true only if and only if transactions for this block and all its parents are available.
    bool validTx;

public:
    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        pskip = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
        bnChainTrust = CBigNum(0);
        nMint = 0;
        nMoneySupply = INITIAL_MONEY_SUPPLY;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        prevoutStake.SetNull();
        nStakeTime = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
        blockHash      = 0;
        nStatus = 0;
        nSequenceId = 0;
        validTx = false;
    }

    CBlockIndex(CBlockHeader &blockHeader) :
            CBlockIndex(0, 0, blockHeader) {

    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlockHeader& blockHeader)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        pskip = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;
        bnChainTrust = CBigNum(0);
        nMint = 0;
        nMoneySupply = INITIAL_MONEY_SUPPLY;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        nStatus = 0;
        nSequenceId = 0;
        validTx = false;
        if (blockHeader.IsProofOfStake())
        {
            SetProofOfStake();
        }
        prevoutStake.SetNull();
        nStakeTime = 0;

        nVersion       = blockHeader.nVersion;
        hashMerkleRoot = blockHeader.hashMerkleRoot;
        nTime          = blockHeader.nTime;
        nBits          = blockHeader.nBits;
        nNonce         = blockHeader.nNonce;
        blockHash      = blockHeader.blockHash;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader blockHeader;
        blockHeader.nVersion       = nVersion;
        if (pprev)
            blockHeader.hashPrevBlock = pprev->GetBlockHash();
        blockHeader.hashMerkleRoot = hashMerkleRoot;
        blockHeader.nTime          = nTime;
        blockHeader.nBits          = nBits;
        blockHeader.nNonce         = nNonce;
        return blockHeader;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    uint256 GetSHA256Hash() const
    {
        CBlockHeader blockHeader = GetBlockHeader();
        return blockHeader.GetSHA256Hash();
    }

    ::int64_t GetBlockTime() const
    {
        return (::int64_t)nTime;
    }

    CBigNum GetBlockTrust() const;

    bool IsInMainChain() const
    {
        return (pnext || this == chainActive.Tip());
    }

    bool CheckIndex() const
    {
        return true;
    }

    enum { nMedianTimeSpan=11 };

    ::int64_t GetMedianTimePast() const
    {
        ::int64_t pmedian[nMedianTimeSpan];
        ::int64_t* pbegin = &pmedian[nMedianTimeSpan];
        ::int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    ::int64_t GetMedianTime() const
    {
        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan/2; i++)
        {
            if (!pindex->pnext)
                return GetBlockTime();
            pindex = pindex->pnext;
        }
        return pindex->GetMedianTimePast();
    }

    /**
     * Returns true if there are nRequired or more blocks of minVersion or above
     * in the last nToCheck blocks, starting at pstart and going backwards.
     */
    static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart,
                                unsigned int nRequired, unsigned int nToCheck);


    bool IsProofOfWork() const
    {
        return !(nFlags & BLOCK_PROOF_OF_STAKE);
    }

    bool IsProofOfStake() const
    {
        return (nFlags & BLOCK_PROOF_OF_STAKE);
    }

    void SetProofOfStake()
    {
        nFlags |= BLOCK_PROOF_OF_STAKE;
    }

    unsigned int GetStakeEntropyBit() const
    {
        return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
    }

    bool SetStakeEntropyBit(unsigned int nEntropyBit)
    {
        if (nEntropyBit > 1)
            return false;
        nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
        return true;
    }

    bool GeneratedStakeModifier() const
    {
        return (nFlags & BLOCK_STAKE_MODIFIER) != 0;
    }

    void SetStakeModifier(::uint64_t nModifier, bool fGeneratedStakeModifier)
    {
        nStakeModifier = nModifier;
        if (fGeneratedStakeModifier)
            nFlags |= BLOCK_STAKE_MODIFIER;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }

    // Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }

    // Raise the validity level of this block index entry.
    // Returns true if the validity was changed.
    bool RaiseValidity(enum BlockStatus nUpTo)
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }
    // Build the skiplist pointer for this entry.
    void BuildSkip();

    // Efficiently find an ancestor of this block.
    CBlockIndex* GetAncestor(int height);
    const CBlockIndex* GetAncestor(int height) const;
};



/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;
    uint256 hashNext;

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nHeight);
        READWRITE(nMint);
        READWRITE(nMoneySupply);
        READWRITE(nFlags);
        READWRITE(nStakeModifier);
        if (IsProofOfStake())
        {
            READWRITE(prevoutStake);
            READWRITE(nStakeTime);
            READWRITE(hashProofOfStake);
        }
        else if (fRead)
        {
            const_cast<CDiskBlockIndex*>(this)->prevoutStake.SetNull();
            const_cast<CDiskBlockIndex*>(this)->nStakeTime = 0;
            const_cast<CDiskBlockIndex*>(this)->hashProofOfStake = 0;
        }

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        // nTime is extended to 64-bit since yacoin 1.0.0
        if (this->nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
            READWRITE(nTime);
        }
        else // 32-bit nTime
        {
            ::uint32_t time = (::uint32_t)nTime; // needed for GetSerializeSize, Serialize function
            READWRITE(time);
            nTime = time; // needed for Unserialize function
        }
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(blockHash);
        if (!fReindexOnlyHeaderSync)
        {
            READWRITE(nStatus);
        }
    )

    uint256 GetBlockHash() const
    {
        if (fUseFastIndex && (blockHash != 0))
            return blockHash;

        CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;

        const_cast<CDiskBlockIndex*>(this)->blockHash = block.GetHash();

        return blockHash;
    }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().c_str(),
            hashNext.ToString().c_str());
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

struct CBlockIndexWorkComparator
{
    bool operator()(CBlockIndex *pa, CBlockIndex *pb) {
        // First sort by most total work, ...
        if (pa->bnChainTrust > pb->bnChainTrust) return false;
        if (pa->bnChainTrust < pb->bnChainTrust) return true;

        // ... then by earliest time received, ...
        if (pa->nSequenceId < pb->nSequenceId) return false;
        if (pa->nSequenceId > pb->nSequenceId) return true;

        // Use pointer address as tie breaker (should only happen with blocks
        // loaded from disk, as those all have id 0).
        if (pa < pb) return false;
        if (pa > pb) return true;

        // Identical blocks.
        return false;
    }
};

/** Capture information about block/transaction validation */
class CValidationState {
private:
    enum mode_state {
        MODE_VALID,   // everything ok
        MODE_INVALID, // network rule violation (DoS value may be set)
        MODE_ERROR,   // run-time error
    } mode;
    int nDoS;
    std::string strRejectReason;
    unsigned char chRejectCode;
    bool corruptionPossible;
    uint256 failedTransaction;
public:
    CValidationState() : mode(MODE_VALID), nDoS(0), corruptionPossible(false) {}
    bool DoS(int level, bool ret = false,
             unsigned char chRejectCodeIn=0, std::string strRejectReasonIn="",
             bool corruptionIn=false) {
        chRejectCode = chRejectCodeIn;
        strRejectReason = strRejectReasonIn;
        corruptionPossible = corruptionIn;
        if (mode == MODE_ERROR)
            return ret;
        nDoS += level;
        mode = MODE_INVALID;
        return ret;
    }
    bool Invalid(bool ret = false,
                 unsigned char _chRejectCode=0, std::string _strRejectReason="") {
        return DoS(0, ret, _chRejectCode, _strRejectReason);
    }
    bool Error() {
        mode = MODE_ERROR;
        return false;
    }
    bool Abort(const std::string &msg) {
        AbortNode(msg);
        return Error();
    }
    bool IsValid() const {
        return mode == MODE_VALID;
    }
    bool IsInvalid() const {
        return mode == MODE_INVALID;
    }
    bool IsError() const {
        return mode == MODE_ERROR;
    }
    bool IsInvalid(int &nDoSOut) const {
        if (IsInvalid()) {
            nDoSOut = nDoS;
            return true;
        }
        return false;
    }
    bool CorruptionPossible() const {
        return corruptionPossible;
    }
    void SetFailedTransaction(const uint256& txhash) {
        failedTransaction = txhash;
    }
    uint256 GetFailedTransaction() {
        return failedTransaction;
    }
    bool IsTransactionError() const  {
        return failedTransaction != uint256();
    }
    unsigned char GetRejectCode() const { return chRejectCode; }
    std::string GetRejectReason() const { return strRejectReason; }
};

class CTxMemPool
{
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;
    std::map<std::string, uint256> mapTokenToHash;
    std::map<uint256, std::string> mapHashToToken;

    bool accept(CValidationState &state, CTxDB& txdb, CTransaction &tx,
                bool fCheckInputs, bool* pfMissingInputs);
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    void remove(const CTransaction& tx);
    void remove(const std::vector<CTransaction>& vtx);
    void remove(const std::vector<CTransaction>& vtx, ConnectedBlockTokenData& connectedBlockData);
    void removeUnchecked(const CTransaction& tx, const uint256& hash);
    void clear();
    void queryHashes(std::vector<uint256>& vtxid);

    size_t size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    bool exists(uint256 hash)
    {
        return (mapTx.count(hash) != 0);
    }

    CTransaction& lookup(uint256 hash)
    {
        return mapTx[hash];
    }
};

extern CTxMemPool mempool;

#endif
