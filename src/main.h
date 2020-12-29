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
 #include "script.h"
#endif

#ifndef SCRYPT_H
 #include "scrypt.h"
#endif

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

//
// Global state
//
#if defined(Yac1dot0)
       const ::uint32_t Nfactor_1dot0 = 17;
#endif
extern int 
    nStatisticsNumberOfBlocks2000,
    nStatisticsNumberOfBlocks1000,
    nStatisticsNumberOfBlocks200,
    nStatisticsNumberOfBlocks100,
    nStatisticsNumberOfBlocks;

static const unsigned int MAX_GENESIS_BLOCK_SIZE = 1000000;
static const unsigned int MAX_ORPHAN_TRANSACTIONS = 10000;
static const unsigned int MAX_INV_SZ = 50000;

static const ::int64_t MIN_TX_FEE = CENT;
static const ::int64_t MIN_RELAY_TX_FEE = MIN_TX_FEE;

static const ::int64_t MAX_MONEY = 2000000000 * COIN;
static const ::int64_t MAX_MINT_PROOF_OF_WORK = 100 * COIN;
static const ::int64_t MAX_MINT_PROOF_OF_STAKE = 1 * COIN;
static const ::int64_t MIN_TXOUT_AMOUNT = CENT/100;

static const unsigned char MAXIMUM_N_FACTOR = 25;  //30; since uint32_t fails on 07 Feb 2106 06:28:15 GMT
                                                   //    when stored as an uint32_t in a block
                                                   //    so there is no point going past Nf = 25

//static const unsigned char MAXIMUM_YAC1DOT0_N_FACTOR = 21;

static const unsigned char YAC20_N_FACTOR = 16;

// block version header
static const int
    VERSION_of_block_for_yac_05x_new = 7,
    VERSION_of_block_for_yac_049     = 6,
    VERSION_of_block_for_yac_044_old = 3,
    CURRENT_VERSION_of_block = VERSION_of_block_for_yac_049;

//static const int
//    CURRENT_VERSION_previous = VERSION_of_block_for_yac_044_old;

inline bool MoneyRange(::int64_t nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }
// Maximum number of script-checking threads allowed
static const int MAX_SCRIPTCHECK_THREADS = 16;

static const uint256 
    // hashGenesisBlock("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5");
    // hashGenesisBlock("0x00000f3f5eac1539c4e9216e17c74ff387ac1629884d2f97a3144dc32bf67bda");
    // hashGenesisBlock("0x0ea17bb85e10d8c6ded6783a4ce8f79e75d49b439ff41f55d274e6b15612fff9");
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    hashGenesisBlock("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5");
#else
    hashGenesisBlock("0x1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848");
#endif

extern const uint256 
    nPoWeasiestTargetLimitTestNet,
    hashGenesisBlockTestNet;
extern int 
    nConsecutiveStakeSwitchHeight;  // see timesamps.h = 420000;

const ::int64_t 
    nMaxClockDrift = nTwoHoursInSeconds;

inline ::int64_t PastDrift(::int64_t nTime)   
    { return nTime - nMaxClockDrift; } // up to 2 hours from the past
inline ::int64_t FutureDrift(::int64_t nTime) 
    { return nTime + nMaxClockDrift; } // up to 2 hours from the future

extern const ::int64_t 
    nChainStartTime,
    nChainStartTimeTestNet;
extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern std::map<uint256, CBlockIndex*> mapBlockIndex;
extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
extern CBlockIndex* pindexGenesisBlock;
extern unsigned int nNodeLifespan;
//extern unsigned int nStakeMinAge;
extern int nCoinbaseMaturity;
extern int nBestHeight;
extern CBigNum bnBestChainTrust;
extern CBigNum bnBestInvalidTrust;
extern uint256 hashBestChain;
extern CBlockIndex* pindexBest;
extern unsigned int nTransactionsUpdated;
extern ::uint64_t nLastBlockTx;
extern ::uint64_t nLastBlockSize;
extern ::uint32_t nLastCoinStakeSearchInterval;
extern const std::string strMessageMagic;
extern ::int64_t nTimeBestReceived;
extern CCriticalSection cs_setpwalletRegistered;
extern std::set<CWallet*> setpwalletRegistered;
extern unsigned char pchMessageStart[4];
extern std::map<uint256, CBlock*> mapOrphanBlocks;
extern ::int64_t nBlockRewardPrev;
extern const ::int64_t nSimulatedMOneySupplyAtFork;
extern ::uint32_t nMinEase; // minimum ease corresponds to highest difficulty

// Settings
extern ::int64_t nTransactionFee;
extern ::int64_t nMinimumInputValue;
extern bool fUseFastIndex;
extern int nScriptCheckThreads;
extern const uint256 entropyStore[38];

// Minimum disk space required - used in CheckDiskSpace()
static const ::uint64_t nMinDiskSpace = 52428800;

enum GetMaxSize_mode
{
    MAX_BLOCK_SIZE,
    MAX_BLOCK_SIZE_GEN,
    MAX_BLOCK_SIGOPS,
};

class CReserveKey;
class CTxDB;
class CTxIndex;
class CScriptCheck;

void RegisterWallet(CWallet* pwalletIn);
void UnregisterWallet(CWallet* pwalletIn);
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false, bool fConnect = true);
bool ProcessBlock(CNode* pfrom, CBlock* pblock);
bool CheckDiskSpace(::uint64_t nAdditionalBytes=0);
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);

void UnloadBlockIndex();
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
CBlockIndex* FindBlockByHeight(int nHeight);
void ProcessMessages(CNode* pfrom);
void SendMessages(CNode* pto, bool fSendTrickle);
bool LoadExternalBlockFile(FILE* fileIn);

// Run an instance of the script checking thread
void ThreadScriptCheck(void* parg);
// Stop the script checking threads
void ThreadScriptCheckQuit();

bool CheckProofOfWork(uint256 hash, unsigned int nBits);
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake);
::int64_t GetProofOfWorkReward(unsigned int nBits=0, ::int64_t nFees=0, bool fGetRewardOfBestHeightBlock=false);
::int64_t GetProofOfStakeReward(::int64_t nCoinAge, unsigned int nBits, ::int64_t nTime, bool bCoinYearOnly=false);

::int64_t GetProofOfStakeReward(::int64_t nCoinAge);
::uint64_t GetMaxSize(enum GetMaxSize_mode mode);

unsigned int ComputeMinWork(unsigned int nBase, ::int64_t nTime);
unsigned int ComputeMinStake(unsigned int nBase, ::int64_t nTime, unsigned int nBlockTime);
int GetNumBlocksOfPeers();
bool IsInitialBlockDownload();
std::string GetWarnings(std::string strFor);
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock);
uint256 WantedByOrphan(const CBlock* pblockOrphan);
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake);

void StakeMinter(CWallet *pwallet);
void ResendWalletTransactions();

bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType);

// yacoin: calculate Nfactor using timestamp
extern unsigned char GetNfactor(::int64_t nTimestamp, bool fYac1dot0BlockOrTx = false);

// yacoin2015: GetProofOfWorkMA, GetProofOfWorkSMA
unsigned int GetProofOfWorkMA(const CBlockIndex* pIndexLast);
unsigned int GetProofOfWorkSMA(const CBlockIndex* pIndexLast);

/**
 * Check if transaction is final per BIP 68 sequence numbers and can be included in a block.
 * Consensus critical. Takes as input a list of heights at which tx's inputs (in order) confirmed.
 */
bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);

/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 */
bool CheckSequenceLocks(const CTransaction &tx, int flags);



//bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);

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



/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
//public:
private:
    uint256 hash;
    ::uint32_t n;
public:
    uint256 COutPointGetHash() const { return hash; }
    ::uint32_t COutPointGet_n() const { return n; }
    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    IMPLEMENT_SERIALIZE
    ( 
        READWRITE(FLATDATA(*this)); 
    )
    void SetNull() { hash = 0; n = (unsigned int) -1; }
    bool IsNull() const { return (hash == 0 && n == (unsigned int) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const
    {
        return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10).c_str(), n);
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    ::uint32_t nSequence;

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 1 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 30);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x3fffffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 60s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 1 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 1 = 2^0, or equivalently shifting up by
     * 0 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 0;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=SEQUENCE_FINAL)
    {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=SEQUENCE_FINAL)
    {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    )

    bool IsFinal() const
    {
        return (nSequence == SEQUENCE_FINAL);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToStringShort() const
    {
        return strprintf(" %s %d", prevout.COutPointGetHash().ToString().c_str(), prevout.COutPointGet_n());
    }

    std::string ToString() const
    {
        std::string str;
        str += "CTxIn(";
        str += prevout.ToString();
        if (prevout.IsNull())
            str += strprintf(", coinbase %s", HexStr(scriptSig).c_str());
        else
            str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
        if (nSequence != SEQUENCE_FINAL)
            str += strprintf(", nSequence=%u", nSequence);
        str += ")";
        return str;
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};




/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    ::int64_t nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(::int64_t nValueIn, CScript scriptPubKeyIn)
    {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    )

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull()
    {
        return (nValue == -1);
    }

    void SetEmpty()
    {
        nValue = 0;
        scriptPubKey.clear();
    }

    bool IsEmpty() const
    {
        return (nValue == 0 && scriptPubKey.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToStringShort() const
    {
        return strprintf(" out %s %s", FormatMoney(nValue).c_str(), scriptPubKey.ToString(true).c_str());
    }

    std::string ToString() const
    {
        if (IsEmpty()) return "CTxOut(empty)";
        if (scriptPubKey.size() < 6)
            return "CTxOut(error)";
        return strprintf("CTxOut(nValue=%s, scriptPubKey=%s)", FormatMoney(nValue).c_str(), scriptPubKey.ToString().c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
};

typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    static const int 
        CURRENT_VERSION_of_Tx_for_yac_old = 1,      // this should be different for Yac1.0
        CURRENT_VERSION_of_Tx_for_yac_new = 2;

    static const int 
      //CURRENT_VERSION_of_Tx = CURRENT_VERSION_of_Tx_for_yac_old;
        CURRENT_VERSION_of_Tx = CURRENT_VERSION_of_Tx_for_yac_old;

    int nVersion;
    mutable ::int64_t nTime;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    ::uint32_t nLockTime;

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const { nDoS += nDoSIn; return fIn; }

    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        // nTime is extended to 64-bit since yacoin 1.0.0
        if (this->nVersion >= CURRENT_VERSION_of_Tx_for_yac_new) // 64-bit nTime
        {
			READWRITE(nTime);
        }
        else // 32-bit nTime
        {
			uint32_t time = (uint32_t)nTime; // needed for GetSerializeSize, Serialize function
			READWRITE(time);
			nTime = time; // needed for Unserialize function
        }
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    )

    void SetNull()
    {
        // TODO: Need update for mainet
        if (nBestHeight != -1 && pindexGenesisBlock && nBestHeight >= nMainnetNewLogicBlockNumber)
        {
            nVersion = CTransaction::CURRENT_VERSION_of_Tx_for_yac_new;
        }
        else
        {
            nVersion = CTransaction::CURRENT_VERSION_of_Tx;
        }
        nTime = GetAdjustedTime();
        vin.clear();
        vout.clear();
        nLockTime = 0;
        nDoS = 0;  // Denial-of-service prevention
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const
    {
        return SerializeHash(*this);
    }

    bool IsFinal(int nBlockHeight=0, ::int64_t nBlockTime=0) const
    {
        // Time based nLockTime implemented in 0.1.6
        if (nLockTime == 0)
            return true;
        if (nBlockHeight == 0)
            nBlockHeight = nBestHeight + 1;
        if (nBlockTime == 0)
            nBlockTime = GetAdjustedTime();
        if ((::int64_t)nLockTime < ((::int64_t)nLockTime < LOCKTIME_THRESHOLD ? (::int64_t)nBlockHeight : nBlockTime))
            return true;
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (!txin.IsFinal())
                return false;
        return true;
    }

    bool IsNewerThan(const CTransaction& old) const
    {
        if (vin.size() != old.vin.size())
            return false;
        for (unsigned int i = 0; i < vin.size(); i++)
            if (vin[i].prevout != old.vin[i].prevout)
                return false;

        bool fNewer = false;
        unsigned int nLowest = CTxIn::SEQUENCE_FINAL;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            if (vin[i].nSequence != old.vin[i].nSequence)
            {
                if (vin[i].nSequence <= nLowest)
                {
                    fNewer = false;
                    nLowest = vin[i].nSequence;
                }
                if (old.vin[i].nSequence < nLowest)
                {
                    fNewer = true;
                    nLowest = old.vin[i].nSequence;
                }
            }
        }
        return fNewer;
    }

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull() && vout.size() >= 1);
    }

    bool IsCoinStake() const
    {
        // ppcoin: the coin stake transaction is marked with the first output empty
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
    }

    /** Check for standard transaction types
        @return True if all outputs (scriptPubKeys) use only standard transaction forms
    */
    bool IsStandard044(std::string& strReason) const;
    bool oldIsStandard(std::string& strReason) const;
    bool IsStandard(std::string& strReason) const;
    //bool IsStandard() const
    //{
    //    std::string strReason;
    //    return IsStandard(strReason);
    //}

    /** Check for standard transaction types
        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return True if all inputs (scriptSigs) use only standard transaction forms
        @see CTransaction::FetchInputs
    */
    bool AreInputsStandard(const MapPrevTx& mapInputs) const;

    /** Count ECDSA signature operations the old-fashioned (pre-0.6) way
        @return number of sigops this transaction's outputs will produce when spent
        @see CTransaction::FetchInputs
    */
    unsigned int GetLegacySigOpCount() const;

    /** Count ECDSA signature operations in pay-to-script-hash inputs.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return maximum number of sigops required to validate this transaction's inputs
        @see CTransaction::FetchInputs
     */
    unsigned int GetP2SHSigOpCount(const MapPrevTx& mapInputs) const;

    /** Amount of bitcoins spent by this transaction.
        @return sum of all outputs (note: does not include fees)
     */
    ::int64_t GetValueOut() const
    {
        ::int64_t nValueOut = 0;
        BOOST_FOREACH(const CTxOut& txout, vout)
        {
            nValueOut += txout.nValue;
            if (!MoneyRange(txout.nValue) || !MoneyRange(nValueOut))
                throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
        }
        return nValueOut;
    }

    /** Amount of bitcoins coming in to this transaction
        Note that lightweight clients may not know anything besides the hash of previous transactions,
        so may not be able to calculate this.

        @param[in] mapInputs	Map of previous transactions that have outputs we're spending
        @return	Sum of value of all inputs (scriptSigs)
        @see CTransaction::FetchInputs
     */
    ::int64_t GetValueIn(const MapPrevTx& mapInputs) const;

    static bool AllowFree(double dPriority)
    {
        // Large (in bytes) low-priority (new, small-coin) transactions
        // need a fee.
        return dPriority > COIN * 144 / 250;
    }

    ::int64_t GetMinFee(unsigned int nBytes = 0) const;

    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL)
    {
      //CAutoFile filein = CAutoFile(OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);
        CAutoFile filein = CAutoFile(OpenBlockFile(pos.Get_CDiskTxPos_nFile(), 0, pfileRet ? "rb+" : "rb"), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error("CTransaction::ReadFromDisk() : OpenBlockFile failed");

        // Read transaction
      //if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
        if (fseek(filein, pos.Get_CDiskTxPos_nTxPos(), SEEK_SET) != 0)
            return error("CTransaction::ReadFromDisk() : fseek failed");

        try {
            filein >> *this;
        }
        catch (std::exception& e) 
        //catch (...) 
        {
            //(void)e;
            return error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
        }

        // Return file pointer
        if (pfileRet)
        {
          //if (fseek(filein, pos.nTxPos, SEEK_SET) != 0)
            if (fseek(filein, pos.Get_CDiskTxPos_nBlockPos(), SEEK_SET) != 0)
                return error("CTransaction::ReadFromDisk() : second fseek failed");
            *pfileRet = filein.release();
        }
        return true;
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.nTime     == b.nTime &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockTime == b.nLockTime);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }

    std::string ToStringShort() const
    {
        std::string str;
        str += strprintf("%s %s", GetHash().ToString().c_str(), IsCoinBase()? "base" : (IsCoinStake()? "stake" : "user"));
        return str;
    }

    std::string ToString() const
    {
        std::string str;
        str += IsCoinBase()? "Coinbase" : (IsCoinStake()? "Coinstake" : "CTransaction");
        str += strprintf(
            "(hash=%s, "
            "nTime=%ld, "
            "ver=%d, "
            "vin.size=%" PRIszu ", "
            "vout.size=%" PRIszu ", "
            "nLockTime=%d)"
            "\n",
            GetHash().ToString().substr(0,10).c_str(),
            nTime,
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime
                        );
        for (unsigned int i = 0; i < vin.size(); ++i)
            str += strprintf( "vin[ %u ] =", i ) + vin[i].ToString() + "\n";
        for (unsigned int i = 0; i < vout.size(); ++i)
            str += strprintf( "vout[ %u ]=", i ) + vout[i].ToString() + "\n";
        return str;
    }

    void print() const
    {
        printf("%s", ToString().c_str());
    }


    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet);
    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout);
    bool ReadFromDisk(COutPoint prevout);
    bool DisconnectInputs(CTxDB& txdb);

    /** Fetch from memory and/or disk. inputsRet keys are transaction hashes.

     @param[in] txdb	Transaction database
     @param[in] mapTestPool	List of pending changes to the transaction index database
     @param[in] fBlock	True if being called to add a new best-block to the chain
     @param[in] fMiner	True if being called by CreateNewBlock
     @param[out] inputsRet	Pointers to this transaction's inputs
     @param[out] fInvalid	returns true if transaction is invalid
     @return	Returns true if all inputs are in txdb or mapTestPool
     */
    bool FetchInputs(CTxDB& txdb, const std::map<uint256, CTxIndex>& mapTestPool,
                     bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid);

    /** Sanity check previous transactions, then, if all checks succeed,
        mark them as spent by this transaction.

        @param[in] inputs	Previous transactions (from FetchInputs)
        @param[out] mapTestPool	Keeps track of inputs that need to be updated on disk
        @param[in] posThisTx	Position of this transaction on disk
        @param[in] pindexBlock
        @param[in] fBlock	true if called from ConnectBlock
        @param[in] fMiner	true if called from CreateNewBlock
        @param[in] fScriptChecks	enable scripts validation?
        @param[in] flags	STRICT_FLAGS script validation flags
        @param[in] pvChecks	NULL If pvChecks is not NULL, script checks are pushed onto it instead of being performed inline.
        @return Returns true if all checks succeed
     */
    bool ConnectInputs(CTxDB& txdb, MapPrevTx inputs, std::map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock, 
                     bool fBlock, bool fMiner, bool fScriptChecks=true, 
                     unsigned int flags=STRICT_FLAGS, std::vector<CScriptCheck> *pvChecks = NULL);
    bool ClientConnectInputs();
    bool CheckTransaction() const;
    bool AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs=true, bool* pfMissingInputs=NULL);
    bool GetCoinAge(CTxDB& txdb, ::uint64_t& nCoinAge) const;  // ppcoin: get transaction coin age

protected:
    const CTxOut& GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const;
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


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 *
 * Blocks are appended to blk0001.dat files on disk.  Their location on disk
 * is indexed by CBlockIndex objects in memory.
 */
class CBlock
{
public:
    // Block header
    ::int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    mutable ::int64_t nTime;
    ::uint32_t nBits;
    ::uint32_t nNonce;

    // Store following info to avoid calculating hash many times
    mutable struct block_header previousBlockHeader;
    mutable uint256 blockHash;
    mutable uint256 blockYacoinHash;

    // network and disk
    std::vector<CTransaction> vtx;

    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    // Denial-of-service detection:
    mutable int nDoS;
    bool DoS(int nDoSIn, bool fIn) const { nDoS += nDoSIn; return fIn; }

    CBlock()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        // nTime is extended to 64-bit since yacoin 1.0.0
        if (this->nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
               READWRITE(nTime);
        }
        else // 32-bit nTime
        {
               uint32_t time = (uint32_t)nTime; // needed for GetSerializeSize, Serialize function
               READWRITE(time);
               nTime = time; // needed for Unserialize function
        }
        READWRITE(nBits);
        READWRITE(nNonce);

        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY)))
        {
            READWRITE(vtx);
            READWRITE(vchBlockSig);
        }
        else if (fRead)
        {
            const_cast<CBlock*>(this)->vtx.clear();
            const_cast<CBlock*>(this)->vchBlockSig.clear();
        }
    )

    void SetNull()
    {
        // TODO: Need update for mainnet
        if (nBestHeight != -1 && pindexGenesisBlock && nBestHeight >= nMainnetNewLogicBlockNumber)
        {
            nVersion = VERSION_of_block_for_yac_05x_new;
        }
        else
        {
            nVersion = CURRENT_VERSION_of_block;
        }
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vtx.clear();
        vchBlockSig.clear();
        vMerkleTree.clear();
        nDoS = 0;
        blockHash = 0;
        blockYacoinHash = 0;
        memset(UVOIDBEGIN(previousBlockHeader), 0, sizeof(struct block_header));
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // yacoin2015 update
    uint256 CalculateHash() const
    {
        uint256 
            thash;

        if (nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
            struct block_header block_data;
            block_data.version = nVersion;
            block_data.prev_block = hashPrevBlock;
            block_data.merkle_root = hashMerkleRoot;
            block_data.timestamp = nTime;
            block_data.bits = nBits;
            block_data.nonce = nNonce;
            scrypt_hash(CVOIDBEGIN(block_data), sizeof(struct block_header), UINTBEGIN(thash), MAXIMUM_YAC1DOT0_N_FACTOR);
        }
        else // 32-bit nTime
        {
            const ::uint64_t
                nSpanOf4  = 1368515488 - nChainStartTime,
                nSpanOf5  = 1368777632 - nChainStartTime,
                nSpanOf6  = 1369039776 - nChainStartTime,
                nSpanOf7  = 1369826208 - nChainStartTime,
                nSpanOf8  = 1370088352 - nChainStartTime,
                nSpanOf9  = 1372185504 - nChainStartTime,
                nSpanOf10 = 1373234080 - nChainStartTime,
                nSpanOf11 = 1376379808 - nChainStartTime,
                nSpanOf12 = 1380574112 - nChainStartTime,   // Mon, 30 Sep 2013 20:48:32 GMT
                nSpanOf13 = 1384768416 - nChainStartTime,   // Mon, 18 Nov 2013 09:53:36 GMT
                nSpanOf14 = 1401545632 - nChainStartTime,   // Sat, 31 May 2014 14:13:52 GMT
                nSpanOf15 = 1409934240 - nChainStartTime,   // Fri, 05 Sep 2014 16:24:00 GMT (Nf) 16
                nSpanOf16 = 1435100064 - nChainStartTime,   // Tue, 23 Jun 2015 22:54:24 GMT (Nf) 17
                nSpanOf17 = 1468654496 - nChainStartTime,   // Sat, 16 Jul 2016 07:34:56 GMT (Nf) 18
                nSpanOf18 = 1502208928 - nChainStartTime,   // Tue, 08 Aug 2017 16:15:28 GMT (Nf) 19
                nSpanOf19 = 1602872224 - nChainStartTime,   // Fri, 16 Oct 2020 18:17:04 GMT
                nSpanOf20 = 1636426656 - nChainStartTime,   // Tue, 09 Nov 2021 02:57:36 GMT
                nSpanOf21 = 1904862112 - nChainStartTime,   // Mon, 13 May 2030 00:21:52 GMT
                nSpanOf22 = 2173297568U - nChainStartTime,   // Sat, 13 Nov 2038 21:46:08 GMT
                nSpanOf23 = 2441733024U - nChainStartTime,   // Fri, 17 May 2047 19:10:24 GMT
                nSpanOf24 = 3247039392U - nChainStartTime,   // Tue, 22 Nov 2072 11:23:12 GMT
                nSpanOf25 = 3515474848U - nChainStartTime;   // Mon, 26 May 2081 08:47:28 GMT
                // uint_32 fails here                          Sun, 07 Feb 2106 06:28:15 GMT
              //nSpanOf26 = 5662958496 - nChainStartTime,   // Sat, 14 Jun 2149 12:01:36 GMT
              //nSpanOf27 = 6736700320 - nChainStartTime,   // Tue, 24 Jun 2183 01:38:40 GMT
              //nSpanOf28 = 9957925792 - nChainStartTime,   // Tue, 21 Jul 2285 18:29:52 GMT
              //nSpanOf29 = 14252893088 - nChainStartTime,  // Sat, 28 Aug 2421 00:58:08 GMT
              //nSpanOf30 = 18547860384 - nChainStartTime;  // Tue, 04 Oct 2557 07:26:24 GMT

            unsigned char
                nfactor;
            if( !fTestNet )
            {     // nChainStartTime = 1367991200 is start
    		    if      ( nTime < (nChainStartTime + nSpanOf4 ) ) nfactor = 4;
                else if ( nTime < (nChainStartTime + nSpanOf5 ) ) nfactor = 5;
                else if ( nTime < (nChainStartTime + nSpanOf6 ) ) nfactor = 6;
                else if ( nTime < (nChainStartTime + nSpanOf7 ) ) nfactor = 7;
                else if ( nTime < (nChainStartTime + nSpanOf8 ) ) nfactor = 8;
                else if ( nTime < (nChainStartTime + nSpanOf9 ) ) nfactor = 9;
                else if ( nTime < (nChainStartTime + nSpanOf10) ) nfactor = 10;
                else if ( nTime < (nChainStartTime + nSpanOf11) ) nfactor = 11;
                else if ( nTime < (nChainStartTime + nSpanOf12) ) nfactor = 12;
                else if ( nTime < (nChainStartTime + nSpanOf13) ) nfactor = 13;
                else if ( nTime < (nChainStartTime + nSpanOf14) ) nfactor = 14;
                else if ( nTime < (nChainStartTime + nSpanOf15) ) nfactor = 15;
                else if ( nTime < (nChainStartTime + nSpanOf16) ) nfactor = 16;
                else if ( nTime < (nChainStartTime + nSpanOf17) ) nfactor = 17;
                else if ( nTime < (nChainStartTime + nSpanOf18) ) nfactor = 18;
                else if ( nTime < (nChainStartTime + nSpanOf19) ) nfactor = 19;
                else if ( nTime < (nChainStartTime + nSpanOf20) ) nfactor = 20;
                else if ( nTime < (nChainStartTime + nSpanOf21) ) nfactor = 21;
                else if ( nTime < (nChainStartTime + nSpanOf22) ) nfactor = 22;
                else if ( nTime < (nChainStartTime + nSpanOf23) ) nfactor = 23;
                else if ( nTime < (nChainStartTime + nSpanOf24) ) nfactor = 24;
                else if ( nTime < (nChainStartTime + nSpanOf25) ) nfactor = 25;
              //  else if ( nTime < (nChainStartTime + nSpanOf26) ) nfactor = 26;
                // uint_32 fails here
              //  else if ( nTime < (nChainStartTime + nSpanOf27) ) nfactor = 27;
              //  else if ( nTime < (nChainStartTime + nSpanOf28) ) nfactor = 28;
              //  else if ( nTime < (nChainStartTime + nSpanOf29) ) nfactor = 29;
              //  else if ( nTime < (nChainStartTime + nSpanOf30) ) nfactor = 30;
                else
                    nfactor = MAXIMUM_N_FACTOR;
            }
            else    // is TestNet
            {
#if defined(Yac1dot0)
                nfactor = Nfactor_1dot0;
#else
                nfactor = 4;
#endif
            }

            if(
               nYac20BlockNumberTime &&
               nTime >= (uint32_t)nYac20BlockNumberTime
              )
            {
                nfactor = YAC20_N_FACTOR;
            }

            old_block_header oldBlock;
            oldBlock.version = nVersion;
            oldBlock.prev_block = hashPrevBlock;
            oldBlock.merkle_root = hashMerkleRoot;
            oldBlock.timestamp = nTime;
            oldBlock.bits = nBits;
            oldBlock.nonce = nNonce;
            scrypt_hash(CVOIDBEGIN(oldBlock), sizeof(old_block_header), UINTBEGIN(thash), nfactor);
        }
		return thash;
    }

    bool IsHeaderDifferent() const
    {
        if((nVersion == previousBlockHeader.version)
            && (hashPrevBlock == previousBlockHeader.prev_block)
            && (hashMerkleRoot == previousBlockHeader.merkle_root)
            && (nTime == previousBlockHeader.timestamp)
            && (nBits == previousBlockHeader.bits)
            && (nNonce == previousBlockHeader.nonce))
        {
            return false;
        }
        return true;
    }

    uint256 GetHash(int blockHeight = 0) const
    {
        if(blockHash == 0 || IsHeaderDifferent())
        {
            blockHash = CalculateHash();
            previousBlockHeader.version = nVersion;
            previousBlockHeader.prev_block = hashPrevBlock;
            previousBlockHeader.merkle_root = hashMerkleRoot;
            previousBlockHeader.timestamp = nTime;
            previousBlockHeader.bits = nBits;
            previousBlockHeader.nonce = nNonce;
        }
        return blockHash;
    }

    // yacoin2015
    uint256 CalculateYacoinHash() const
    {
        uint256 
            thash;
        unsigned char nfactor;
        if (nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
            nfactor = GetNfactor(nTime, true);
            struct block_header block_data;
            block_data.version = nVersion;
            block_data.prev_block = hashPrevBlock;
            block_data.merkle_root = hashMerkleRoot;
            block_data.timestamp = nTime;
            block_data.bits = nBits;
            block_data.nonce = nNonce;
            scrypt_hash(CVOIDBEGIN(block_data), sizeof(struct block_header), UINTBEGIN(thash), nfactor);
        }
        else // 32-bit nTime
        {
        	nfactor = GetNfactor(nTime, false);
            old_block_header oldBlock;
            oldBlock.version = nVersion;
            oldBlock.prev_block = hashPrevBlock;
            oldBlock.merkle_root = hashMerkleRoot;
            oldBlock.timestamp = nTime;
            oldBlock.bits = nBits;
            oldBlock.nonce = nNonce;
            scrypt_hash(CVOIDBEGIN(oldBlock), sizeof(old_block_header), UINTBEGIN(thash), nfactor);
        }

        return thash;
    }

    uint256 GetYacoinHash(int blockHeight = 0) const
    {
        if(blockYacoinHash == 0 || IsHeaderDifferent())
        {
            blockYacoinHash = CalculateYacoinHash();
            previousBlockHeader.version = nVersion;
            previousBlockHeader.prev_block = hashPrevBlock;
            previousBlockHeader.merkle_root = hashMerkleRoot;
            previousBlockHeader.timestamp = nTime;
            previousBlockHeader.bits = nBits;
            previousBlockHeader.nonce = nNonce;
        }
        return blockYacoinHash;
    }

    ::int64_t GetBlockTime() const
    {
        return (::int64_t)nTime;
    }

    void UpdateTime(const CBlockIndex* pindexPrev);

    // ppcoin: entropy bit for stake modifier if chosen by modifier
    unsigned int GetStakeEntropyBit(unsigned int nHeight) const
    {
        
            // Take last bit of block hash as entropy bit
            unsigned int nEntropyBit = ((GetHash().Get64()) & 1ULL);
            if (fDebug && GetBoolArg("-printstakemodifier"))
                printf(
                        "GetStakeEntropyBit: nTime=%ld \nhashBlock=%s\nnEntropyBit=%u\n",
                        nTime, 
                        GetHash().ToString().c_str(), 
                        nEntropyBit
                      );
   			return nEntropyBit;
 
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
        return (vtx.size() > 1 && vtx[1].IsCoinStake());
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    std::pair<COutPoint, unsigned int> GetProofOfStake() const
    {
        return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, (unsigned int)vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }

    // ppcoin: get max transaction timestamp
    ::int64_t GetMaxTransactionTime() const
    {
        ::int64_t maxTransactionTime = 0;
        BOOST_FOREACH(const CTransaction& tx, vtx)
            maxTransactionTime = std::max(maxTransactionTime, (::int64_t)tx.nTime);
        return maxTransactionTime;
    }

    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        BOOST_FOREACH(const CTransaction& tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = (int)vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = std::min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        std::vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = (int)vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = std::min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        BOOST_FOREACH(const uint256& otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }


    bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
    {
        // Open history file to append
        CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
        if (!fileout)
            return error("CBlock::WriteToDisk() : AppendBlockFile failed");

        // Write index header
        unsigned int nSize = fileout.GetSerializeSize(*this);
        fileout << FLATDATA(pchMessageStart) << nSize;

        // Write block
        long fileOutPos = ftell(fileout);
        if (fileOutPos < 0)
            return error("CBlock::WriteToDisk() : ftell failed");
        nBlockPosRet = fileOutPos;
        fileout << *this;

        // Flush stdio buffers and commit to disk before returning
        fflush(fileout);
        if (!IsInitialBlockDownload() || (nBestHeight+1) % 500 == 0)
            FileCommit(fileout);

        return true;
    }

    bool ReadFromDisk(
                      unsigned int nFile, 
                      unsigned int nBlockPos, 
                      bool fReadTransactions = true,
                      bool fCheckHeader = true
                     )
    {
        SetNull();

        // Open history file to read
        CAutoFile filein = CAutoFile(OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, CLIENT_VERSION);
        if (!filein)
            return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
        if (!fReadTransactions)
            filein.nType |= SER_BLOCKHEADERONLY;

        // Read block
        try {
            filein >> *this;
        }
        catch (std::exception &e) 
        //catch (...) 
        {
            //(void)e;
            return error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
        }

        // Check the header
        if (
            fReadTransactions && 
            IsProofOfWork() && 
            (
             fCheckHeader &&           
             !CheckProofOfWork(GetYacoinHash(), nBits)
            )
           )
            return error("CBlock::ReadFromDisk() : errors in block header");

        return true;
    }



    void print() const
    {
        printf("CBlock(\n"
                "hash=%s,\n"
                "ver=%d,\n"
                "hashPrevBlock=%s,\n"
                "hashMerkleRoot=%s,\n"
                "nTime=%ld, "
                "nBits=%08x, "
                "nNonce=%u, "
                "vtx=%" PRIszu ",\n"
                "vchBlockSig=%s\n"
                ")\n",
            GetHash().ToString().c_str(),
            nVersion,
            hashPrevBlock.ToString().c_str(),
            hashMerkleRoot.ToString().c_str(),
            nTime, 
            nBits, 
            nNonce,
            vtx.size(),
            HexStr(vchBlockSig.begin(), vchBlockSig.end()).c_str()
              );
        for (unsigned int i = 0; i < vtx.size(); ++i)
        {
            printf("  ");
            vtx[i].print();
        }
        printf("  vMerkleTree: ");
        for (unsigned int i = 0; i < vMerkleTree.size(); ++i)
            printf("%s ", vMerkleTree[i].ToString().substr(0,10).c_str());
        printf("\n");
    }


    bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck=false);
    bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true, bool fCheckHeader = true);
    bool SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew);
    bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
    bool CheckBlock(bool fCheckPOW=true, bool fCheckMerkleRoot=true, bool fCheckSig=true) const;
    bool AcceptBlock();
    bool GetCoinAge(::uint64_t& nCoinAge) const; // ppcoin: calculate total coin age spent in block
    bool SignBlock044(const CKeyStore& keystore);
    bool SignBlock(CWallet& keystore);
    bool CheckBlockSignature() const;

private:
    bool SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew);
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
//private:
//public:

//protected:
//public:

public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;
    ::uint32_t nFile;
    ::uint32_t nBlockPos;
    CBigNum bnChainTrust; // ppcoin: trust score of block chain
    ::int32_t nHeight;
    ::int32_t nPosBlockCount;	// yacoin2015
    ::int32_t nBitsMA;		// yacoin2015

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
public:
    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
        nPosBlockCount = 0;
        nBitsMA = 0;
        bnChainTrust = CBigNum(0);
        nMint = 0;
        nMoneySupply = 0;
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
    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;
        nPosBlockCount = 0;
        nBitsMA = 0;
        bnChainTrust = CBigNum(0);
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        if (block.IsProofOfStake())
        {
            SetProofOfStake();
            prevoutStake = block.vtx[1].vin[0].prevout;
            nStakeTime = block.vtx[1].nTime;
        }
        else
        {
            prevoutStake.SetNull();
            nStakeTime = 0;
        }

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
        blockHash      = block.blockHash;
    }

    CBlock GetBlockHeader() const
    {
        CBlock block;
        block.nVersion       = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->GetBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    ::int64_t GetBlockTime() const
    {
        return (::int64_t)nTime;
    }

    double GetPoWPoSRatio() const;

    ::int32_t GetSpacingThreshold() const;

    CBigNum GetBlockTrust() const;

    bool IsInMainChain() const
    {
        return (pnext || this == pindexBest);
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

    std::string ToString() const
    {
        return strprintf("CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d nHeight=%d, nMint=%s, nMoneySupply=%s, nFlags=(%s)(%d)(%s), nStakeModifier=%016" PRIx64 ", nStakeModifierChecksum=%08x, hashProofOfStake=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, hashBlock=%s)",
            pprev, pnext, nFile, nBlockPos, nHeight,
            FormatMoney(nMint).c_str(), FormatMoney(nMoneySupply).c_str(),
            GeneratedStakeModifier() ? "MOD" : "-", GetStakeEntropyBit(), IsProofOfStake()? "PoS" : "PoW",
            nStakeModifier, nStakeModifierChecksum, 
            hashProofOfStake.ToString().c_str(),
            prevoutStake.ToString().c_str(), nStakeTime,
            hashMerkleRoot.ToString().c_str(),
            GetBlockHash().ToString().c_str());
    }

    void print() const
    {
        printf("%s\n", ToString().c_str());
    }
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
            uint32_t time = (uint32_t)nTime; // needed for GetSerializeSize, Serialize function
            READWRITE(time);
            nTime = time; // needed for Unserialize function
        }
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(blockHash);
    )

    uint256 GetBlockHash() const
    {
        if (fUseFastIndex && (nTime < GetAdjustedTime() - 24 * 60 * 60) && blockHash != 0)
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








/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:

    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
            Set((*mi).second);
    }

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }

    void Set(const CBlockIndex* pindex)
    {
        vHave.clear();
        int nStep = 1;
        while (pindex)
        {
            vHave.push_back(pindex->GetBlockHash());

            // Exponentially larger steps back
            for (int i = 0; pindex && i < nStep; i++)
                pindex = pindex->pprev;
            if (vHave.size() > 10)
                nStep *= 2;
        }
        vHave.push_back((!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet));
    }

    int GetDistanceBack()
    {
        // Retrace how far back it was in the sender's branch
        int nDistance = 0;
        int nStep = 1;
        BOOST_FOREACH(const uint256& hash, vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return nDistance;
            }
            nDistance += nStep;
            if (nDistance > 10)
                nStep *= 2;
        }
        return nDistance;
    }

    CBlockIndex* GetBlockIndex()
    {
        // Find the first block the caller has in the main chain
        BOOST_FOREACH(const uint256& hash, vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return pindex;
            }
        }
        return pindexGenesisBlock;
    }

    uint256 GetBlockHash()
    {
        // Find the first block the caller has in the main chain
        BOOST_FOREACH(const uint256& hash, vHave)
        {
            std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end())
            {
                CBlockIndex* pindex = (*mi).second;
                if (pindex->IsInMainChain())
                    return hash;
            }
        }
        return (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet);
    }

    int GetHeight()
    {
        CBlockIndex* pindex = GetBlockIndex();
        if (!pindex)
            return 0;
        return pindex->nHeight;
    }
};








class CTxMemPool
{
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;

    bool accept(CTxDB& txdb, CTransaction &tx,
                bool fCheckInputs, bool* pfMissingInputs);
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    bool remove(CTransaction &tx);
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
