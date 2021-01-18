// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef _BITCOINALERT_H_
 #include "alert.h"
#endif

#ifndef BITCOIN_CHECKPOINT_H
 #include "checkpoints.h"
#endif

#ifndef BITCOIN_DB_H
 #include "db.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb.h"
#endif

#ifndef BITCOIN_INIT_H
 #include "init.h"
#endif

#ifndef CHECKQUEUE_H
 #include "checkqueue.h"
#endif

#ifndef PPCOIN_KERNEL_H
 #include "kernel.h"
#endif

#ifdef QT_GUI
 #include "explorer.h"
#endif

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/math/special_functions/round.hpp>

#ifndef BITCOIN_MAIN_H
 #include "main.h"
#endif

using namespace boost;

using std::set;
using std::string;
using std::vector;
using std::runtime_error;
using std::map;
using std::pair;
using std::make_pair;
using std::max;
using std::min;
using std::multimap;

const ::int64_t 
    nSimulatedMOneySupplyAtFork = 124460820773591,  //124,460,820.773591 YAC
    nChainStartTime = 1367991200,           // unix time???? ~ Wed May 08 2013 05:33:20
//    nChainStartTimeTestNet = 1464123328;    //Tue, 24 May 2016 20:55:28 GMT
//                                            // 1464373956  Fri, 27 May 2016 18:32:36 GMT
    nChainStartTimeTestNet = 1546300800;    // 1546116950 ~12/29/2018
                                            // 1546300800 1/1/2019 00:00:00 GMT
const uint256 
  //hashGenesisBlockTestNet("0xfe20c2c2fc02b36d2473e1f51dba1fb123d41ff42966e2a4edabb98fdd7107e6"),
    // change here           ^^^^^^^^^^^^^
  //hashGenesisBlockTestNet( "0x0000fb514c55539c42aed840fb46fedf49ce9c8a81f2ab29bd8e5b0e7134467f" ),
  //hashGenesisBlockTestNet( "0x000026ab43bff071f9c5432b754ab00c90f520a9569007e9205d1ee13cde973d" ),

//hashGenesisBlockTestNet( "0bd0495ffce47a76504f338692b70dfcd8fabc5176a49cc646f3f28478b132dc" ),

                            // version 0.5.0.03
//hashGenesisBlockTestNet( "056ce89e39622e2577f35117eef4118f5b4a35b98a16ebc218d31d55fd018c1b" ),
                            // version 0.5.0.04
//hashGenesisBlockTestNet( "0x049a99dd896cbaa9004c790d8b3855e714ede6328b0555c55d08b94fda187f1e" ),
//hashGenesisBlockTestNet( "0x0619394c5fc682ef90f64a256a48b428636246010cf898b59491465e47d3b49e" ),
  hashGenesisBlockTestNet( "0x1dc29b112550069ecb870e1be78c8d0c166e5f4e41433283e74dcf30b510c1f3" ),
    
                            // version 0.5.0.03
//hashGenesisMerkleRootTestNet( "0xf87fdba660d8d4cf099c09bc684968249311611ff18c92ddce3d44ccf8df0c28" ),
                            // version 0.5.0.04
//hashGenesisMerkleRootTestNet( "0x389003d67b17d9a38a9c83b9289225f5e5469b9f6a2d70fc7c97ee6e8f995f23" ),
                            // old 0.4.9
  hashGenesisMerkleRootTestNet( "0xd6ab993974b85898d45cfd850c8865fefa342450b4b38dca9eaafb515920baf7" ),
                            // new 0.5.5
  //hashGenesisMerkleRootMainNet( "0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f" );
//   hashGenesisMerkleRootMainNet( "0x97a5a4d34dc12eff03febfd7c906b31740ac3412c820950a431b25ee1b874cb6" );
//   hashGenesisMerkleRootMainNet( "0x5b1c7339ef15a2c8ad96b672e345a8cd316cc8ee019ea7edeef4f0cd1e8116eb");
  hashGenesisMerkleRootMainNet( "0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f");

const ::uint32_t 
    nTestNetGenesisNonce = 0x1F656; // = 128,598 decimal
/*
Read best chain
block.nNonce == 0001F66B
block.nNonce == 0001F66B (128619 dec) after 31 tries
block.GetHash() ==
0bd0495ffce47a76504f338692b70dfcd8fabc5176a49cc646f3f28478b132dc
block.nBits ==
0fffff0000000000000000000000000000000000000000000000000000000000
block.hashMerkleRoot ==
389003d67b17d9a38a9c83b9289225f5e5469b9f6a2d70fc7c97ee6e8f995f23
*/
//
const int
    nBigLinearTrailingAverageLength = 2100, // arbitrary but 35 hours
    nNewBigLinearTrailingAverageLength = 10 * nBigLinearTrailingAverageLength, // 21000 arbitrary but 350 hours!!
    nExponentialTrailingAverageLength = 8;  //arbitrary
int 
    nStatisticsNumberOfBlocks2000 = 2000,
    nStatisticsNumberOfBlocks1000 = 1000,
    nStatisticsNumberOfBlocks200 = 200,
    nStatisticsNumberOfBlocks100 = 100,
    nStatisticsNumberOfBlocks,  // = nBigLinearTrailingAverageLength,    
    nConsecutiveStakeSwitchHeight = 420000;  // see timesamps.h

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;
unsigned int nTransactionsUpdated = 0;

map<uint256, CBlockIndex*> mapBlockIndex;
set<pair<COutPoint, unsigned int> > setStakeSeen;

// are all of these undocumented numbers a function of Nfactor?  Cpu power? Other???
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
CBigNum bnProofOfWorkLimit(~uint256(0) >> 20);
#else
CBigNum bnProofOfWorkLimit(~uint256(0) >> 3);
#endif

CBigNum bnProofOfStakeLegacyLimit(~uint256(0) >> 24); 
CBigNum bnProofOfStakeLimit(~uint256(0) >> 27); 
CBigNum bnProofOfStakeHardLimit(~uint256(0) >> 30); // fix minimal proof of stake difficulty at 0.25

//  CBigNum bnProofOfWorkLimitTestNet(~uint256(0) >> 16);    
//                           IS IT A MAX OR A MIN? 
//                           IS IT AN EASE? 
//                           IS IT A DIFFICULTY??????
//                           can you say NFD

                                            // this is the number used by TestNet 0.5.0.x
const uint256 nPoWeasiestTargetLimitTestNet = ((~uint256( 0 )) >> 3 );
CBigNum bnProofOfWorkLimitTestNet( nPoWeasiestTargetLimitTestNet );

// YACOIN TODO
::int64_t nBlockRewardPrev = 0;
::uint32_t nMinEase = bnProofOfWorkLimit.GetCompact();
bool recalculateBlockReward = false;
bool recalculateMinEase = false;

static CBigNum bnProofOfStakeTestnetLimit(~uint256(0) >> 20);

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
static CBigNum bnInitialHashTarget(~uint256(0) >> 20);
#else
static CBigNum bnInitialHashTarget(~uint256(0) >> 8);
#endif

static CBigNum bnInitialHashTargetTestNet(~uint256(0) >> 8);    // test
//static CBigNum bnInitialHashTarget(~uint256(0) >> 16);

int
    nCoinbaseMaturityInBlocks = 500;

int 
    nCoinbaseMaturity = nCoinbaseMaturityInBlocks;  //500;
                                                    // @~1 blk/minute, ~8.33 hrs        

int
    nCoinbaseMaturityAfterHardfork = 6;

CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;

CBigNum bnBestChainTrust(0);
CBigNum bnBestInvalidTrust(0);

uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
::int64_t nTimeBestReceived = 0;
int nScriptCheckThreads = 0;

CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
set<pair<COutPoint, unsigned int> > setStakeSeenOrphan;
map<uint256, uint256> mapProofOfStake;

map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Yacoin Signed Message:\n";

// Settings
::int64_t nTransactionFee = MIN_TX_FEE;
::int64_t nMinimumInputValue = MIN_TX_FEE;

// Ping and address broadcast intervals
::int64_t nPingInterval = 30 * nSecondsPerMinute;  // I presume 30 minutes????

::int64_t nBroadcastInterval = nOneDayInSeconds;    // can be from 6 days in seconds down to 0!

::int64_t
    nLongAverageBP2000 = 0,
    nLongAverageBP1000 = 0,
    nLongAverageBP200 = 0,
    nLongAverageBP100 = 0,
    nLongAverageBP = 0;

extern enum Checkpoints::CPMode CheckpointsMode;

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets


void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.erase(pwalletIn);
    }
}

// check whether the passed transaction is from us
bool static IsFromMe(CTransaction& tx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}

// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx,wtx))
            return true;
    return false;
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fConnect)
{
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
                if (pwallet->IsFromMe(tx))
                    pwallet->DisableTransaction(tx);
        }
        return;
    }

    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
    // Preloaded coins cache invalidation
    fCoinsDataActual = false;
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void ResendWalletTransactions()
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions();
}







//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION_of_Tx);

    if (nSize > 5000)
    {
        printf("ignoring large orphan tx (size: %" PRIszu ", hash: %s)\n", nSize, hash.ToString().substr(0,10).c_str());
        return false;
    }

    mapOrphanTransactions[hash] = tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.COutPointGetHash()].insert(hash);

    printf("stored orphan tx %s (mapsz %" PRIszu ")\n", hash.ToString().substr(0,10).c_str(),
        mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CTransaction& tx = mapOrphanTransactions[hash];
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.COutPointGetHash()].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.COutPointGetHash()].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.COutPointGetHash());
    }
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

/**
 * Calculates the block height and previous block's time at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
static std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx,
        int flags, std::vector<int> *prevHeights, const CBlockIndex &block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++)
    {
        const CTxIn &txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            CBlockIndex *pbi = FindBlockByHeight(std::max(nCoinHeight - 1, 0));
            int64_t nCoinTime = pbi->GetBlockTime();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the time of the block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        }
        else
        {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

static bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetBlockTime();
    if (lockPair.first >= block.nHeight)
    {
        printf("EvaluateSequenceLocks, failed to use relative time-lock coins, current block height  = %d"
                ", the coin inputs can only be used in a block with height > %d\n", block.nHeight, lockPair.first);
        return false;
    }
    else if (lockPair.second >= nBlockTime)
    {
        printf("EvaluateSequenceLocks, failed to use relative time-lock coins, current block time  = %ld (%s)"
                ", the coin inputs can only be used after a block with block time > %ld (%s) is mined\n",
                nBlockTime, DateTimeStrFormat(nBlockTime).c_str(),
                lockPair.second, DateTimeStrFormat(lockPair.second).c_str());
        return false;
    }

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool CheckSequenceLocks(const CTransaction &tx, int flags)
{
    LOCK2(cs_main, mempool.cs);

    CBlockIndex index;
    index.pprev = pindexBest;
    // CheckSequenceLocks() uses pindexBest->nHeight+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than pindexBest->nHeight
    index.nHeight = pindexBest->nHeight + 1;

    std::vector<int> prevheights;
    prevheights.resize(tx.vin.size());
    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        COutPoint prevout = tx.vin[txinIndex].prevout;

        // Check from both mempool and db
        if (mempool.exists(prevout.COutPointGetHash()))
        {
            // Assume all mempool transaction confirm in the next block
            prevheights[txinIndex] = pindexBest->nHeight + 1;
        }
        else // Check from txdb
        {
            CTransaction txPrev;
            CTxIndex txindex;
            CTxDB txdb("r");
            if (!txPrev.ReadFromDisk(txdb, prevout, txindex))
            {
                // Can't find transaction index
                return error("CheckSequenceLocks : ReadFromDisk tx %s failed", prevout.COutPointGetHash().ToString().substr(0,10).c_str());
            }

            uint256 hashBlock = 0;
            CBlock block;
            if (!block.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos(), false))
            {
                return error("CheckSequenceLocks : ReadFromDisk block containing tx %s failed", prevout.COutPointGetHash().ToString().substr(0,10).c_str());
            }
            else
            {
                hashBlock = block.GetHash();
            }

            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
            if (mi != mapBlockIndex.end() && (*mi).second)
            {
                CBlockIndex* pindex = (*mi).second;
                prevheights[txinIndex] = pindex->nHeight;
            }
            else
            {
                return error("CheckSequenceLocks : mapBlockIndex doesn't contains block %s", hashBlock.ToString().substr(0,10).c_str());
            }
        }
    }

    std::pair<int, int64_t> lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
    return EvaluateSequenceLocks(index, lockPair);
}

int GetCoinbaseMaturity()
{
    if (nBestHeight != -1 && pindexGenesisBlock && nBestHeight >= nMainnetNewLogicBlockNumber)
    {
        return nCoinbaseMaturityAfterHardfork;
    }
    else
    {
        return nCoinbaseMaturity;
    }
}

int GetCoinbaseMaturityOffset()
{
    if (nBestHeight != -1 && pindexGenesisBlock && nBestHeight >= nMainnetNewLogicBlockNumber)
    {
        return 0;
    }
    else
    {
        return 20;
    }
}

bool isHardforkHappened()
{
    if (nBestHeight != -1 && pindexGenesisBlock && nBestHeight >= nMainnetNewLogicBlockNumber)
    {
        return true;
    }
    else
    {
        return false;
    }
}
//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet)
{
    SetNull();
    if (!txdb.ReadTxIndex(prevout.COutPointGetHash(), txindexRet))
        return false;
    if (!ReadFromDisk(txindexRet.pos))
        return false;
    if (prevout.COutPointGet_n() >= vout.size())
    {
        SetNull();
        return false;
    }
    return true;
}

bool CTransaction::ReadFromDisk(CTxDB& txdb, COutPoint prevout)
{
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::ReadFromDisk(COutPoint prevout)
{
    CTxDB txdb("r");
    CTxIndex txindex;
    return ReadFromDisk(txdb, prevout, txindex);
}

bool CTransaction::oldIsStandard(string& strReason) const
{
    // TODO: Temporary fix to avoid warning for yacoind 1.0.0. Because in yacoind 1.0.0, there are two times
    // block version is upgraded:
	// 1) At the time installing yacoind 1.0.0
	// 2) At the time happening hardfork
	// Need update this line at next yacoin version
    if (nVersion > CTransaction::CURRENT_VERSION_of_Tx_for_yac_new)
    {
        strReason = "version";
        return false;
    }

    unsigned int nDataOut = 0;
    txnouttype whichType;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)=1624
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
        if (txin.scriptSig.size() > 1650)
        {
            strReason = "scriptsig-size";
            return false;
        }
        if (!txin.scriptSig.IsPushOnly())
        {
            strReason = "scriptsig-not-pushonly";
            return false;
        }
        if (!txin.scriptSig.HasCanonicalPushes()) {
            strReason = "txin-scriptsig-not-canonicalpushes";
            return false;
        }
    }
    BOOST_FOREACH(const CTxOut& txout, vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            strReason = "scriptpubkey";
            return false;
        }
        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else {
            if (txout.nValue == 0) {
                strReason = "txout-value=0";
                return false;
            }
            if (!txout.scriptPubKey.HasCanonicalPushes()) {
                strReason = "txout-scriptsig-not-canonicalpushes";
                return false;
            }
        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        strReason = "multi-op-return";
        return false;
    }

    return true;
}

bool CTransaction::IsStandard044( string& strReason ) const
{
    // TODO: Temporary fix to avoid warning for yacoind 1.0.0. Because in yacoind 1.0.0, there are two times
    // block version is upgraded:
	// 1) At the time installing yacoind 1.0.0
	// 2) At the time happening hardfork
	// Need update this line at next yacoin version
    if (nVersion > CTransaction::CURRENT_VERSION_of_Tx_for_yac_new) // same as in 0.4.4!?
    {                                                   // if we test differently,
        strReason = "version(in 0.4.4)";                // then shouldn't 0.4.5 be 
        return false;                                   // different?
    }

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
        // pay-to-script-hash, which is 3 ~80-byte signatures, 3
        // ~65-byte public keys, plus a few script ops.
        if (txin.scriptSig.size() > 500)
        {
            return false;
        }
        if (!txin.scriptSig.IsPushOnly())
            return false;
    }
    txnouttype whichType;
    BOOST_FOREACH(const CTxOut& txout, vout) 
    {
      //if (!::IsStandard(txout.scriptPubKey))
        if (!::IsStandard(txout.scriptPubKey, whichType)) 
        {
            strReason = "scriptpubkey0.4.4";
            return false;
        }
        if (txout.nValue == 0)
            return false;
    }
    return true;
}

bool CTransaction::IsStandard(string& strReason) const
{
    bool
        fIsStandard = oldIsStandard( strReason );

    if( !fIsStandard )
    {
        fIsStandard = IsStandard044( strReason ); 
    }
    return fIsStandard;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(const MapPrevTx& mapInputs) const
{
    if (IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prev = GetOutputFor(vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, vin[i].scriptSig, *this, i, false, 0))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (!Solver(subscript, whichType2, vSolutions2))
                return false;
            if (whichType2 == TX_SCRIPTHASH)
                return false;

            int tmpExpected;
            tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0)
                return false;
            nArgsExpected += tmpExpected;
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

unsigned int
CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL)
        {
            // Load the block this tx is in
            CTxIndex txindex;
            if (!CTxDB("r").ReadTxIndex(GetHash(), txindex))
                return 0;
            if (!blockTmp.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos()))
                return 0;
            pblock = &blockTmp;
        }

        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == (int)pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}







bool CTransaction::CheckTransaction() const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty())
        return DoS(10, error("CTransaction::CheckTransaction() : vout empty"));
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > GetMaxSize(MAX_BLOCK_SIZE))
        return DoS(100, error("CTransaction::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    ::int64_t 
        nValueOut = 0;

    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut
            & txout = vout[i];

        if (txout.IsEmpty() && !IsCoinBase() && !IsCoinStake())
            return DoS(100, error("CTransaction::CheckTransaction() : txout empty for user transaction"));

        if (txout.nValue < 0)
            return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue is negative"));
        if (txout.nValue > MAX_MONEY)
            return DoS(100, error("CTransaction::CheckTransaction() : txout.nValue too high"));
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return DoS(100, error("CTransaction::CheckTransaction() : txout total out of range"));
    }

    // Check for duplicate inputs
    set<COutPoint> 
        vInOutPoints;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return false;
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
            return DoS(100, error("CTransaction::CheckTransaction() : coinbase script size is invalid"));
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return DoS(10, error("CTransaction::CheckTransaction() : prevout is null"));
    }

    return true;
}

::int64_t CTransaction::GetMinFee(unsigned int nBytes) const
{
    return (nBytes * MIN_TX_FEE) / 1000;
}


bool CTxMemPool::accept(CTxDB& txdb, CTransaction &tx, bool fCheckInputs,
                        bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (tx.nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old && isHardforkHappened())
        return error("CTxMemPool::accept() : Not accept transaction with old version");

    if (!tx.CheckTransaction())
        return error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("CTxMemPool::accept() : coinstake as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((::int64_t)tx.nLockTime > std::numeric_limits<int>::max())
        return error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    string strNonStd;
    if (!fTestNet && !tx.IsStandard(strNonStd))
        return error("CTxMemPool::accept() : nonstandard transaction (%s)", strNonStd.c_str());

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!tx.IsFinal())
        return error("CTxMemPool::accept() : non-final transaction");

    // Do we already have it?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash))
            return false;
    }
    if (fCheckInputs)
        if (txdb.ContainsTx(hash))
            return false;

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].GetPtx();
            if (ptxOld->IsFinal())
                return false;
            if (!tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].GetPtx() != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (!tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            if (fInvalid)
                return error("CTxMemPool::accept() : FetchInputs found invalid tx %s", hash.ToString().substr(0,10).c_str());
            if (pfMissingInputs)
                *pfMissingInputs = true;
            return false;
        }

        // Only accept BIP68 sequence locked transactions that can be mined in the next
        // block; we don't want our mempool filled up with transactions that can't
        // be mined yet.
        if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        {
            return error("CTxMemPool::accept() : non-BIP68-final transaction");
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(mapInputs) && !fTestNet)
            return error("CTxMemPool::accept() : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

        ::int64_t nFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        ::int64_t txMinFee = tx.GetMinFee(nSize);
        if (nFees < txMinFee)
            return error("CTxMemPool::accept() : not enough fees %s, %" PRId64 " < %" PRId64,
                         hash.ToString().c_str(),
                         nFees, txMinFee);

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (
            !tx.ConnectInputs(
                              txdb, 
                              mapInputs, 
                              mapUnused, 
                              CDiskTxPos(1,1,1), 
                              pindexBest, 
                              false, 
                              false, 
                              true, 
                              SIG_SWITCH_TIME < tx.nTime ? STRICT_FLAGS : SOFT_FLAGS
                             )
           )
        {
            return error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
        }
    }

    // Store transaction in memory
    {
        LOCK(cs);
        if (ptxOld)
        {
            printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());

    printf("CTxMemPool::accept() : accepted %s (poolsz %" PRIszu ")\n",
           hash.ToString().substr(0,10).c_str(),
           mapTx.size());
#ifdef QT_GUI
    {
        LOCK(cs);

    lastTxHash.storeLasthash( hash );
    //uiInterface.NotifyBlocksChanged();
    }
#endif

    return true;
}

bool CTransaction::AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs, bool* pfMissingInputs)
{
    return mempool.accept(txdb, *this, fCheckInputs, pfMissingInputs);
}

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTxMemPool::remove(CTransaction &tx)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);
            nTransactionsUpdated++;
        }
    }
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}




int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return pindexBest->nHeight - pindex->nHeight + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    return max(
                0, 
                fTestNet?
                (GetCoinbaseMaturity() +  0) - GetDepthInMainChain():   //<<<<<<<<<<< test
                (GetCoinbaseMaturity() + GetCoinbaseMaturityOffset()) - GetDepthInMainChain()    // why is this 20?
              );                                                    // what is this 20 from? For?
}


bool CMerkleTx::AcceptToMemoryPool(CTxDB& txdb, bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientConnectInputs())
            return false;
        return CTransaction::AcceptToMemoryPool(txdb, false);
    }
    else
    {
        return CTransaction::AcceptToMemoryPool(txdb, fCheckInputs);
    }
}

bool CMerkleTx::AcceptToMemoryPool()
{
    CTxDB txdb("r");
    return AcceptToMemoryPool(txdb);
}



bool CWalletTx::AcceptWalletTransaction(CTxDB& txdb, bool fCheckInputs)
{

    {
        LOCK(mempool.cs);
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && !txdb.ContainsTx(hash))
                    tx.AcceptToMemoryPool(txdb, fCheckInputs);
            }
        }
        return AcceptToMemoryPool(txdb, fCheckInputs);
    }
    return false;
}

bool CWalletTx::AcceptWalletTransaction()
{
    CTxDB txdb("r");
    return AcceptWalletTransaction(txdb);
}

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(pos.Get_CDiskTxPos_nFile(), pos.Get_CDiskTxPos_nBlockPos(), false))
        return 0;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + nBestHeight - pindex->nHeight;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    {
        LOCK(cs_main);
        {
            LOCK(mempool.cs);
            if (mempool.exists(hash))
            {
                tx = mempool.lookup(hash);
                return true;
            }
        }
        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos(), false))
                hashBlock = block.GetHash();
            return true;
        }
    }
    return false;
}








//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;
CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    // Check input parameter
    if (nHeight <= 0)
        return pindexGenesisBlock;
    if (nHeight >= pindexBest->nHeight)
        return pindexBest;

    if (nHeight < nBestHeight / 2)
        pblockindex = pindexGenesisBlock;
    else
        pblockindex = pindexBest;
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
        pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions, bool fCheckHeader)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions, fCheckHeader))
        return false;

    if (
        fCheckHeader &&
        (GetHash() != pindex->GetBlockHash())
       )
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    return pblockOrphan->hashPrevBlock;
}

// yacoin: increasing Nfactor gradually
const unsigned char minNfactor = 4;
const unsigned char maxNfactor = MAXIMUM_N_FACTOR;
                                        //30; since uint32_t fails on 07 Feb 2106 06:28:15 GMT
                                        //    when stored as an uint32_t in a block
                                        //    so there is no point going past Nf = 25
const unsigned char maxNfactorYc1dot0 = 21;

unsigned char GetNfactor(::int64_t nTimestamp, bool fYac1dot0BlockOrTx)
{
	if (fYac1dot0BlockOrTx)
	{
		return MAXIMUM_YAC1DOT0_N_FACTOR;
	}

    int
        nBitCount = 0;

    if (
        ( nTimestamp <= (fTestNet? nChainStartTimeTestNet: nChainStartTime) )
        || fTestNet
       )    //was just nTimestamp <= nChainStartTime)
#if defined(Yac1dot0)
            return Nfactor_1dot0;
#else
            return minNfactor;
#endif

    ::int64_t
        nAgeOfBlockOrTxInSeconds = nTimestamp - (fTestNet? nChainStartTimeTestNet: nChainStartTime);
        //nChainStartTime, nSavedAgeOfBlockOrTxInSeconds = nAgeOfBlockOrTxInSeconds;

    while ((nAgeOfBlockOrTxInSeconds >> 1) > 3)     // nAgeOfBlockOrTxInSeconds / 2 is 4 or more
    {
        nBitCount += 1;
        nAgeOfBlockOrTxInSeconds >>= 1;             // /2 again
    }
    nAgeOfBlockOrTxInSeconds &= 0x03;   //3;    // really a mask on the low 2 bits.  But why?

    int                             // is 3 max
        n = ( (nBitCount * 170) + (nAgeOfBlockOrTxInSeconds * 25) - 2320) / 100;

    if (n < 0)
        n = 0;
    if (n > 255)
      //printf("GetNfactor (%ld) - something wrong(n == %d)\n", nTimestamp, n);
        printf("GetNfactor (%"PRId64") - something wrong(n == %d)\n", nTimestamp, n); // for g++

    // so n is between 0 and 0xff
    unsigned char N = (unsigned char)n;
#ifdef _DEBUG
    if(
        false &&    // just a quick way to turn it off
        fDebug &&
        fPrintToConsole
      )
    {
        printf(
                "GetNfactor: %"PRI64d" -> %d %"PRId64" : %d / %d\n",
                nTimestamp - (fTestNet? nChainStartTimeTestNet: nChainStartTime), //nChainStartTime,   // 64 bit int
                nBitCount,
                nAgeOfBlockOrTxInSeconds,
                n,
                (unsigned int)min(
                                    max(
                                        N,
                                        minNfactor
                                       ),
                                    maxNfactor
                                 )
                );
    }
#endif
    return min(max(N, minNfactor), maxNfactor);
}


// yacoin2015: ProofOfWork target Weighted Moving Average
unsigned int GetProofOfWorkMA(const CBlockIndex* pIndexLast)
{
    CBigNum wma(0);    // Weighted Moving Average of PoW target
    unsigned int nCount = 0;

    if (
        fUseOld044Rules
       )
        return 0;

    if ( pIndexLast->IsProofOfStake() )
    {
        return ( pIndexLast->nBitsMA > 0 ) ? pIndexLast->nBitsMA : GetProofOfWorkSMA( pIndexLast );
    }
    else
    {
        CBigNum bn;

        const CBlockIndex* pindex = pIndexLast;
        const CBlockIndex* ppos = GetLastBlockIndex( pindex->pprev, true ); // last ProofOfStake block preceeding

        if ( ppos->IsProofOfStake() && ppos->nBitsMA > 0 )
        {
            int overstep = ( pindex->nHeight - ppos->nHeight ) - ppos->GetSpacingThreshold();

            // ignore overstepped blocks, they get punished with higher difficulty, but we exclude that from MA
            for ( int i = 0; i < overstep; i++ )
                pindex = pindex->pprev;
        }
        else    // ProofOfWork came after, last ProofOfStake block before YACOIN_NEW_LOGIC_SWITCH_TIME
        {
            return GetProofOfWorkSMA( pIndexLast );
        }


        while ( pindex->IsProofOfWork() )
        {
            wma += bn.SetCompact( pindex->nBits );
            nCount++;
            pindex = pindex->pprev;
        }

        bn.SetCompact( ppos->nBitsMA );
        bn = bn << 10;  // previous MA multiplication *1024
        wma = wma << 1;   // multiplication *2
        wma = ( wma + bn ) / ( 1024 + nCount*2 );   // new weighted MA, ~0.2% weight on last block (adj. 12~24h)

        return wma.GetCompact();
    }
}


// yacoin2015: ProofOfWork Simple Moving Average
unsigned int GetProofOfWorkSMA(const CBlockIndex* pIndexLast)
{
    CBigNum sma(0);    // Simple Moving Average
    unsigned int nCount = 0;

    const CBlockIndex* pindex = GetLastBlockIndex( pIndexLast, false ); // ProofOfWork

    while ( pindex && pindex->pprev && nCount < 14400 )    // ~10+ day window of PoW blocks
    {
        if ( pindex->IsProofOfWork() )
        {
            CBigNum bn;
            sma += bn.SetCompact( pindex->nBits );
            nCount++;
        }

        pindex = pindex->pprev;
    }

    if ( nCount == 0 )
        return 0;
    else
    {
        sma /= nCount;
        return sma.GetCompact();
    }
}


// select stake target limit according to hard-coded conditions
CBigNum inline GetProofOfStakeLimit(int nHeight, unsigned int nTime)
{
    if(fTestNet) // separate proof of stake target limit for testnet
        return bnProofOfStakeTestnetLimit;  //bnProofOfStakeLimit;
    if(nTime > TARGETS_SWITCH_TIME)
        return bnProofOfStakeLimit; 

    return bnProofOfStakeHardLimit; // YAC has always been 30 
}

// Before hardfork, miner's coin base reward based on nBits
// After hardfork, calculate coinbase reward based on nHeight. If not specify nHeight, always
// calculate coinbase reward based on pindexBest->nHeight + 1 (reward of next best block)
::int64_t GetProofOfWorkReward(unsigned int nBits, ::int64_t nFees, unsigned int nHeight)
{
#ifdef Yac1dot0
    // Get reward of a specific block height
    if (nHeight != 0 && nHeight >= nMainnetNewLogicBlockNumber)
    {
        ::int32_t startEpochBlockHeight = (nHeight / nEpochInterval) * nEpochInterval;
        const CBlockIndex* pindexMoneySupplyBlock = FindBlockByHeight(startEpochBlockHeight - 1);
        return (pindexMoneySupplyBlock->nMoneySupply * nInflation / nNumberOfBlocksPerYear);
    }

    if (pindexBest && (pindexBest->nHeight + 1) >= nMainnetNewLogicBlockNumber)
    {
        // Get reward of current mining block
        ::int64_t nBlockRewardExcludeFees;
        if (recalculateBlockReward) // Reorg through two or many epochs
        {
            recalculateBlockReward = false;
            bool reorgToHardforkBlock = false;
            if (pindexBest->nHeight / nEpochInterval == nMainnetNewLogicBlockNumber / nEpochInterval)
            {
                reorgToHardforkBlock = true;
            }
            ::int32_t startEpochBlockHeight = (pindexBest->nHeight / nEpochInterval) * nEpochInterval;
            ::int32_t moneySupplyBlockHeight =
                reorgToHardforkBlock ? nMainnetNewLogicBlockNumber - 1 : startEpochBlockHeight - 1;
            const CBlockIndex* pindexMoneySupplyBlock = FindBlockByHeight(moneySupplyBlockHeight);
            nBlockRewardExcludeFees = (::int64_t)(pindexMoneySupplyBlock->nMoneySupply * nInflation / nNumberOfBlocksPerYear);
            nBlockRewardPrev = nBlockRewardExcludeFees;
        }
        else // normal case
        {
            // Default: nEpochInterval = 21000 blocks, recalculated with each epoch
            if ((pindexBest->nHeight + 1) % nEpochInterval == 0 || (pindexBest->nHeight + 1) == nMainnetNewLogicBlockNumber)
            {
                // recalculated
                // PoW reward is 2%
                nBlockRewardExcludeFees = (::int64_t)(pindexBest->nMoneySupply * nInflation / nNumberOfBlocksPerYear);
                nBlockRewardPrev = nBlockRewardExcludeFees;
            }
            else
            {
                nBlockRewardExcludeFees = (::int64_t)nBlockRewardPrev;
                if (!nBlockRewardPrev)
                {
                    const CBlockIndex* pindexMoneySupplyBlock =
                        FindBlockByHeight(nMainnetNewLogicBlockNumber ? nMainnetNewLogicBlockNumber - 1 : 0);
                    nBlockRewardExcludeFees =
                        (::int64_t)(pindexMoneySupplyBlock->nMoneySupply * nInflation / nNumberOfBlocksPerYear);
                }
            }
        }
        return nBlockRewardExcludeFees;
    }
#endif
    CBigNum bnSubsidyLimit = MAX_MINT_PROOF_OF_WORK;

    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    CBigNum bnTargetLimit = bnProofOfWorkLimit;
    bnTargetLimit.SetCompact(bnTargetLimit.GetCompact());

    // NovaCoin: subsidy is cut in half every 64x multiply of PoW difficulty
    // A reasonably continuous curve is used to avoid shock to market
    // (nSubsidyLimit / nSubsidy) ** 6 == bnProofOfWorkLimit / bnTarget
    //
    // Human readable form:
    //
    // nSubsidy = 100 / (diff ^ 1/6)
    CBigNum bnLowerBound = CENT;
    CBigNum bnUpperBound = bnSubsidyLimit;
    while (bnLowerBound + CENT <= bnUpperBound)
    {
        CBigNum bnMidValue = (bnLowerBound + bnUpperBound) / 2;
        if (fDebug && GetBoolArg("-printcreation"))
            printf("GetProofOfWorkReward() : lower=%" PRId64 " upper=%" PRId64 " mid=%" PRId64 "\n", bnLowerBound.getuint64(), bnUpperBound.getuint64(), bnMidValue.getuint64());
        if (bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnTargetLimit > bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnSubsidyLimit * bnTarget)
            bnUpperBound = bnMidValue;
        else
            bnLowerBound = bnMidValue;
    }

    ::int64_t nSubsidy = bnUpperBound.getuint64();

    nSubsidy = (nSubsidy / CENT) * CENT;
    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfWorkReward() : create=%s nBits=0x%08x nSubsidy=%" PRId64 "\n", FormatMoney(nSubsidy).c_str(), nBits, nSubsidy);

    return min(nSubsidy, MAX_MINT_PROOF_OF_WORK) + nFees;
}

::uint64_t GetMaxSize(enum GetMaxSize_mode mode)
{
    ::uint64_t nMaxSize = 0;
    if (pindexGenesisBlock == NULL || (pindexBest->nHeight + 1) < nMainnetNewLogicBlockNumber)
    {
        nMaxSize = MAX_GENESIS_BLOCK_SIZE;
    }
    else
    {
        nMaxSize = (GetProofOfWorkReward() * 1000 / MIN_TX_FEE);
    }

    switch (mode)
    {
        case MAX_BLOCK_SIZE_GEN:
            nMaxSize /= 2;
            break;

        case MAX_BLOCK_SIGOPS:
            nMaxSize = max(nMaxSize, (::uint64_t)MAX_GENESIS_BLOCK_SIZE) / 50;
            break;

        case MAX_BLOCK_SIZE:
        default:
            break;
    }
    return nMaxSize;
}

// ppcoin: miner's coin stake is rewarded based on coin age spent (coin-days)
::int64_t GetProofOfStakeReward(::int64_t nCoinAge)
{
    static ::int64_t
        nRewardCoinYear = 5 * CENT;  // creation amount per coin-year

    ::int64_t 
        nSubsidy = nCoinAge * 33 / (365 * 33 + 8) * nRewardCoinYear;
    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeReward(): create=%s nCoinAge=%"PRId64"\n", FormatMoney(nSubsidy).c_str(), nCoinAge);
    return nSubsidy;
}
// miner's coin stake reward based on nBits and coin age spent (coin-days)
::int64_t GetProofOfStakeReward(::int64_t nCoinAge, unsigned int nBits, ::int64_t nTime, bool bCoinYearOnly)
{
    ::int64_t nRewardCoinYear, nSubsidy, nSubsidyLimit = 10 * COIN;

    if(
        fTestNet || 
        ((::uint64_t)nTime > (::uint64_t)STAKE_SWITCH_TIME)
        // is this the same as
        //(::uint64_t)nTime > (::uint64_t)STAKE_SWITCH_TIME
        // ?.  It seems not??
      )
    {
        // Stage 2 of emission process is PoS-based. It will be active on mainNet since 20 Jun 2013.

        CBigNum 
            bnRewardCoinYearLimit = MAX_MINT_PROOF_OF_STAKE; // Base stake mint rate, 100% year interest

        CBigNum 
            bnTarget;

        bnTarget.SetCompact(nBits);

        CBigNum 
            bnTargetLimit = GetProofOfStakeLimit(0, nTime);

        bnTargetLimit.SetCompact(bnTargetLimit.GetCompact());

        // NovaCoin: A reasonably continuous curve is used to avoid shock to market

        CBigNum 
            bnLowerBound = 1 * CENT, // Lower interest bound is 1% per year
            bnUpperBound = bnRewardCoinYearLimit, // Upper interest bound is 100% per year
            bnMidPart, bnRewardPart;

        while (bnLowerBound + CENT <= bnUpperBound)
        {
            CBigNum 
                bnMidValue = (bnLowerBound + bnUpperBound) / 2;

            if (fDebug && GetBoolArg("-printcreation"))
                printf("GetProofOfStakeReward() : lower=%" PRId64 " upper=%" PRId64 " mid=%" PRId64 "\n", bnLowerBound.getuint64(), bnUpperBound.getuint64(), bnMidValue.getuint64());

            if(
                !fTestNet && 
                nTime < STAKECURVE_SWITCH_TIME
              )
            {
                //
                // Until 20 Oct 2013: reward for coin-year is cut in half 
                // every 64x multiply of PoS difficulty
                //
                // (nRewardCoinYearLimit / nRewardCoinYear) ** 6 == bnProofOfStakeLimit / bnTarget
                //
                // Human readable form: nRewardCoinYear = 1 / (posdiff ^ 1/6)
                //

                bnMidPart = bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue * bnMidValue;
                bnRewardPart = bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit * 
                                bnRewardCoinYearLimit;
            }
            else
            {
                //
                // Since 20 Oct 2013: reward for coin-year is cut in half 
                // every 8x multiply of PoS difficulty
                //
                // (nRewardCoinYearLimit / nRewardCoinYear) ** 3 == bnProofOfStakeLimit / bnTarget
                //
                // Human readable form: nRewardCoinYear = 1 / (posdiff ^ 1/3)
                //

                bnMidPart = bnMidValue * bnMidValue * bnMidValue;
                bnRewardPart = bnRewardCoinYearLimit * bnRewardCoinYearLimit * bnRewardCoinYearLimit;
            }

            if (
                (bnMidPart * bnTargetLimit) > (bnRewardPart * bnTarget)
               )
                bnUpperBound = bnMidValue;
            else
                bnLowerBound = bnMidValue;
        }

        nRewardCoinYear = bnUpperBound.getuint64();
        nRewardCoinYear = min((nRewardCoinYear / CENT) * CENT, MAX_MINT_PROOF_OF_STAKE);
    }
    else
    {
        // Old creation amount per coin-year, 5% fixed stake mint rate
        nRewardCoinYear = 5 * CENT;
    }

    if(bCoinYearOnly)
        return nRewardCoinYear;

    nSubsidy = nCoinAge * nRewardCoinYear * 33 / (365 * 33 + 8);

    // Set reasonable reward limit for large inputs since 20 Oct 2013
    //
    // This will stimulate large holders to use smaller inputs, 
    // that's good for the network protection
    if(
        fTestNet || 
        (STAKECURVE_SWITCH_TIME < nTime)
        // is this the same as
        //(::uint64_t)STAKECURVE_SWITCH_TIME > (::uint64_t)nTime
        // ?.  It seems not??
      )
    {
        if (fDebug && GetBoolArg("-printcreation") && nSubsidyLimit < nSubsidy)
            printf("GetProofOfStakeReward(): %s is greater than %s, coinstake reward will be truncated\n", FormatMoney(nSubsidy).c_str(), FormatMoney(nSubsidyLimit).c_str());

        nSubsidy = min(nSubsidy, nSubsidyLimit);
    }

    if (fDebug && GetBoolArg("-printcreation"))
        printf("GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64 " nBits=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge, nBits);
    return nSubsidy;
}

static const ::int64_t nTargetTimespan = 7 * 24 * 60 * 60;  // one week
static const ::int64_t nTargetSpacingWorkMax = 12 * nStakeTargetSpacing; // 2-hour BS, 12 minutes!

// get proof of work blocks max spacing according to hard-coded conditions
::int64_t inline GetTargetSpacingWorkMax(int nHeight, unsigned int nTime)
{
    if(nTime > TARGETS_SWITCH_TIME)
        return 3 * nStakeTargetSpacing; // 30 minutes on mainNet since 20 Jul 2013 00:00:00

    if(fTestNet)
        return 3 * nStakeTargetSpacing; // 15 minutes on testNet

    return 12 * nStakeTargetSpacing; // 2 hours otherwise
}

//
// maximum nBits value could possible be required nTime after
//
unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, ::int64_t nTime)
{
    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
        // Maximum 200% adjustment per day...
        bnResult *= 2;
        nTime -= 24 * 60 * 60;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

//
// minimum amount of work that could possibly be required nTime after
// minimum proof-of-work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, ::int64_t nTime)
{
    return ComputeMaxBits(bnProofOfWorkLimit, nBase, nTime);
}

//
// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int ComputeMinStake(unsigned int nBase, ::int64_t nTime, unsigned int nBlockTime)
{
    return ComputeMaxBits(GetProofOfStakeLimit(0, nBlockTime), nBase, nTime);
}

// ppcoin: find last block index up to pindex
// Wouldn't this be a more correct comment?
// ppcoin: find last block index of type fProofOfStake up to and including pindex?
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (
           pindex &&                                    // there is a block
           pindex->pprev &&                             // there is a previous block 
           (pindex->IsProofOfStake() != fProofOfStake)  // the block is a !fProofOfStake
          )
        pindex = pindex->pprev;                         // go back
    return pindex;
}
const CBlockIndex* GetLastPoSBlockIndex( const CBlockIndex* pindex )
{
    return GetLastBlockIndex( pindex, true);
}
const CBlockIndex* GetLastPoWBlockIndex( const CBlockIndex* pindex )
{
    return GetLastBlockIndex( pindex, false);
}

//_____________________________________________________________________________
bool HaveWeSwitchedToNewLogicRules( bool &fUsingOld044Rules )
{
    bool
        fReturn = false;

    if (true == fUsingOld044Rules)         // should we switch to new rules
    {
        if(
           fTestNet &&    // may use new rules, ATM only in TestNet
           (
            fTestNetNewLogic &&
            (nMainnetNewLogicBlockNumber <= nBestHeight)
           )
          )
        {
            fUsingOld044Rules = false;
            fReturn = true;
            if (fDebug)
            {
#ifdef WIN32
                (void)printf(
                     "\n"
                     "fUseOld044Rules is "
                     "%s"
                     "\n"
                     "\n"
                     , fUsingOld044Rules? "true": "false"
                            );
#endif
            }
        }
    }
    return fReturn;
}
/*****************/
static unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, ::int64_t nFirstBlockTime)
{
    //if (params.fPowNoRetargeting)   // disguised testnet, again
    //    return pindexLast->nBits;

    const ::int64_t 
        nAverageBlockperiod = nStakeTargetSpacing;  // 1 minute in seconds

    ::int64_t 
        nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime,
        nNominalTimespan = nDifficultyInterval * nAverageBlockperiod;

    if (nActualTimespan < nNominalTimespan / 4)
        nActualTimespan = nNominalTimespan / 4;
    if (nActualTimespan > nNominalTimespan * 4)
        nActualTimespan = nNominalTimespan * 4;

    // Calculate to target 1 minute/block for the previous 'epoch's 21,000 blocks
    uint256 
        bnPrev = CBigNum().SetCompact(pindexLast->nBits).getuint256();

    CBigNum
        bnPrevTarget;
    bnPrevTarget.setuint256( bnPrev );

    bnPrevTarget *= nActualTimespan;
    bnPrevTarget /= nNominalTimespan;

    // Calculate maximum target of all blocks, it corresponds to 1/3 highest difficulty (or 3 minimum ease)
    uint256 bnMaximum = CBigNum().SetCompact(nMinEase).getuint256();
    CBigNum bnMaximumTarget;
    bnMaximumTarget.setuint256(bnMaximum);
    bnMaximumTarget *= 3;

    // Compare 1/3 highest difficulty with 0.4.9 min difficulty (genesis block difficulty), choose the higher
    if (bnMaximumTarget > bnProofOfWorkLimit)
    {
        bnMaximumTarget = bnProofOfWorkLimit;
    }

    // Choose higher difficulty (higher difficulty have smaller target)
    CBigNum bnNewTarget = min(bnPrevTarget, bnMaximumTarget);
    (void)printf(
                 "PoW new constant target %s\n"
                 ""
                 , CBigNum( bnNewTarget ).getuint256().ToString().substr(0,16).c_str()
                );

    // Update minimum ease for next target calculation
    ::uint32_t nNewEase = bnNewTarget.GetCompact();
    if (nMinEase > nNewEase)
    {
        nMinEase = nNewEase;
    }

    return nNewEase;
}
/*****************/
static unsigned int GetNextTargetRequired044(const CBlockIndex* pindexLast, bool fProofOfStake)
{
	// First three blocks will have following targets:
	// genesis (zeroth) block: bnEasiestTargetLimit
	// first block and second block: bnInitialHashTarget (~uint256(0) >> 8)
    CBigNum 
        bnEasiestTargetLimit = fProofOfStake? 
                            (fTestNet? 
                             bnProofOfStakeTestnetLimit: //bnProofOfStakeHardLimit: // <<<< test
                             bnProofOfStakeHardLimit
                            ): 
                            (fTestNet?
                             bnProofOfWorkLimitTestNet:
                             bnProofOfWorkLimit
                            );

    if (pindexLast == NULL)
    {
        return bnEasiestTargetLimit.GetCompact(); // genesis (zeroth) block
    }

    const CBlockIndex
        * pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);

    if (pindexPrev->pprev == NULL)
    {
        return bnInitialHashTarget.GetCompact(); // first block
    }

    const CBlockIndex
        * pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);

    if (pindexPrevPrev->pprev == NULL)
        return bnInitialHashTarget.GetCompact(); // second block

    // so there are more than 3 blocks
    ::int64_t
        nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    CBigNum 
        bnNewTarget;
    ::uint32_t
        nEase = pindexLast->nBits;
    CBigNum
        bnNew;
    uint256
        nTarget = CBigNum().SetCompact( nEase ).getuint256(),
        nRelativeTargetDelta = (nTarget >> 3);  // i.e. 1/8 of the current target

    // Yacoind version 1.0.0
    if ((pindexBest->nHeight + 1) >= nMainnetNewLogicBlockNumber)
    {
        // COMMENT THIS BLOCK CODE OUT , WE MAY USE IT IN CASE OF AN EMERGENCY HARDFORK
//        const ::int64_t
//            nAverageBlockperiod = nStakeTargetSpacing;  // 1 minute in seconds

        // Recalculate nMinEase if reorg through two or many epochs
        if (recalculateMinEase)
        {
            recalculateMinEase = false;
            ::int32_t currentEpochNumber = pindexBest->nHeight / nEpochInterval;
            ::int32_t firstEpochNumberSinceHardfork = nMainnetNewLogicBlockNumber / nEpochInterval;
            ::uint32_t tempMinEase = bnEasiestTargetLimit.GetCompact();
            for (int i = firstEpochNumberSinceHardfork; i < currentEpochNumber; i++)
            {
                CBlockIndex* pbi = FindBlockByHeight(i*nEpochInterval);
                if (tempMinEase > pbi->nBits)
                {
                    tempMinEase = pbi->nBits;
                }
            }
            nMinEase = tempMinEase;
        }

        // From block 3, the target is only recalculated every 21000 blocks
        int nBlocksToGo = (pindexLast->nHeight + 1) % nDifficultyInterval;
        // Only change once per difficulty adjustment interval, first at block 21000
        if (0 != nBlocksToGo) // the btc-ltc 2016 blocks
        {                     // don't change the target
            bnNewTarget.setuint256(nTarget);

            (void)printf("PoW constant target %s"
                         " (%d block"
                         "%s to go)"
                         "\n"
                         "",
                         nTarget.ToString().substr(0, 16).c_str(), (nDifficultyInterval - nBlocksToGo),
                         (1 != nBlocksToGo) ? "s" : "");
            return bnNewTarget.GetCompact();
        }
        else // actually do a DAA
        {
            // Hardfork happens
            if ((pindexLast->nHeight + 1) == nMainnetNewLogicBlockNumber)
            {
                return bnProofOfWorkLimit.GetCompact();
            }
            // Go back by what we want to be 14 days worth of blocks
            const CBlockIndex* pindexFirst = pindexLast;

            if (pindexLast->nHeight > nDifficultyInterval + 1)
            {
                for (int i = 0; pindexFirst && i < nDifficultyInterval; ++i)
                    pindexFirst = pindexFirst->pprev;
            }
            else // get block #0
            {
                CBlockIndex* pbi = FindBlockByHeight(0);
                CBlock block;

                block.ReadFromDisk(pbi);
                pindexFirst = pbi;
            }
            Yassert(pindexFirst);

            return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime());
        }

        // COMMENT THIS BLOCK CODE OUT , WE MAY USE IT IN CASE OF AN EMERGENCY HARDFORK
        // Before block 4032, the target is recalculated every block
        // since we are forking off of YAC, there exists > 1,806,727 blocks, as of 1/6/2019 10am EST
        // we can do a weighted (exponential) average of the last 9(arbitrary) block times
        // last is Block(height).GetBlockTime() which is .nTime (64 bit),
        // next is Block(height - 1).GetBlockTime(), etc.
        // so given as a parameter, pindexLast,
//        int
//            nNumberOfWeightedBlocks = min(
//                                            nExponentialTrailingAverageLength,
//                                            pindexLast->nHeight - 2  //skip block 0 & 1
//                                         );
//        const CBlockIndex
//            *pLastBI = pindexLast,
//            *pPreviousBI = pLastBI->pprev;
//        ::int64_t
//            nMultiplier,
//            nLatestDeltaT,
//            nDeltaT,
//            nWeighting = 0,
//            nSum2000 = 0,
//            nSum1000 = 0,
//            nSum200 = 0,
//            nSum100 = 0,
//            nSum = 0;
//
//        nStatisticsNumberOfBlocks = min( nBigLinearTrailingAverageLength, pindexLast->nHeight - 1 ),
//        nLatestDeltaT = pLastBI->GetBlockTime() - pPreviousBI->GetBlockTime();
//
//        nSum = pLastBI->GetBlockTime();
//        for( int count = nStatisticsNumberOfBlocks; count >= 1; --count )
//        {
//            pLastBI = pPreviousBI;  // just get previous block
//            pPreviousBI = pLastBI->pprev;
//            if( nStatisticsNumberOfBlocks2000 == (nStatisticsNumberOfBlocks - count) )
//            {
//                nSum2000 = nSum - pPreviousBI->GetBlockTime();
//                nLongAverageBP2000 = nSum2000 / nStatisticsNumberOfBlocks2000;
//            }
//            if( nStatisticsNumberOfBlocks1000 == (nStatisticsNumberOfBlocks - count) )
//            {
//                nSum1000 = nSum - pPreviousBI->GetBlockTime();
//                nLongAverageBP1000 = nSum1000 / nStatisticsNumberOfBlocks1000;
//            }
//            if( nStatisticsNumberOfBlocks200 == (nStatisticsNumberOfBlocks - count) )
//            {
//                nSum200 = nSum - pPreviousBI->GetBlockTime();
//                nLongAverageBP200 = nSum200 / nStatisticsNumberOfBlocks200;
//            }
//            if( nStatisticsNumberOfBlocks100 == (nStatisticsNumberOfBlocks - count) )
//            {
//                nSum100 = nSum - pPreviousBI->GetBlockTime();
//                nLongAverageBP100 = nSum100 / nStatisticsNumberOfBlocks100;
//            }
//        }
//        nSum -= pLastBI->GetBlockTime();
//        if ( 0 != nStatisticsNumberOfBlocks )
//            nLongAverageBP = nSum / nStatisticsNumberOfBlocks;   // integer /
//
//        // new fixed length DAA code ala ltc
//
//
//
//        pLastBI = pindexLast,
//        pPreviousBI = pLastBI->pprev;
//        nWeighting = 0,
//        nSum = 0;
//        for( int count = nNumberOfWeightedBlocks; count >= 1; --count )
//        {
//            nMultiplier = ((::int64_t)0x0001 << count);
//            nDeltaT = pLastBI->GetBlockTime() - pPreviousBI->GetBlockTime();
//            nSum += (nDeltaT * nMultiplier);
//            nWeighting += nMultiplier;
//
//            pLastBI = pPreviousBI;  // just get previous block
//            pPreviousBI = pLastBI->pprev;
//        }
//
//        ::int64_t
//            nEWA = 0;
//
//        if ( 0 != nWeighting )
//            nEWA = nSum / nWeighting;   // integer /
//        // should be near (?) average block period
//        (void)printf(
//                     "PoW last period %" PRId64 "sec, weighted average period %" PRId64 " sec\n"
//                     ""
//                     , nActualSpacing, nEWA
//                    );
//        (void)printf(
//                     "PoW old target %s\n"
//                     ""
//                     , nTarget.ToString().substr(0,16).c_str()
//                    );
//
//        // do we do a special case for no block in > future drift time?
//        if( nLatestDeltaT >= nMaxClockDrift/2 )   // in this case, 12/2 = 6 minutes
//        {
//            //nTarget <<= 1; // double target value
//        }
//        if(
//           (nLatestDeltaT >= (5 * nAverageBlockperiod / 4))
//           ||
//           (nLatestDeltaT <= (3 * nAverageBlockperiod / 4))
//          )
//        {       // latest period was still out of the normal range so adjust the ease
//            if( nEWA > (4 * nAverageBlockperiod) )      // too difficult
//            {
//                nTarget += (nRelativeTargetDelta << 1); // up the ease 1/4 of target value
//            }
//            if( nEWA > (2 * nAverageBlockperiod) )      // too difficult
//            {
//                nTarget += nRelativeTargetDelta;        // up the ease 1/8 of target value
//            }
//            if( nEWA > (3 * nAverageBlockperiod / 2) )  // too difficult
//            {
//                nTarget += nRelativeTargetDelta;        // up the ease 1/8 of target value
//            }
//            if( nEWA > (4 * nAverageBlockperiod / 3) )  // too difficult
//            {
//                nTarget += nRelativeTargetDelta;        // up the ease 1/8 of target value
//            }
//            if( nEWA > (5 * nAverageBlockperiod / 4) )  // too difficult
//            {
//                nTarget += nRelativeTargetDelta;        // up the ease 1/8 of target value
//            }
//            else // nLWA <= 3 * nAverageBlockperiod / 2 // i.e. perhaps too easy
//            {
//                if( nEWA <= (nAverageBlockperiod / 4) )     // too easy
//                {
//                    nTarget -= (nRelativeTargetDelta << 1); // decrease the ease 1/4 of target value
//                }
//                if( nEWA <= (nAverageBlockperiod / 2) )     // too easy
//                {
//                    nTarget -= nRelativeTargetDelta;        // decrease the ease 1/8 of target value
//                }
//                if( nEWA <= (3 * nAverageBlockperiod / 4) ) // too easy
//                {
//                    nTarget -= nRelativeTargetDelta;        // decrease the ease by 1/8 of target value
//                }
//            }
//        }
//        else
//        {       // latest period was within range so leave the ease as is
//        }
//    //#ifdef DEBUG
//        (void)printf(
//                     "PoW new target %s\n"
//                     ""
//                     , nTarget.ToString().substr(0,16).c_str()
//                    );
//    //#endif
//        //uint256 nTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
//        bnNewTarget.setuint256( nTarget );
    }
    else
    {
        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        //
        // I don't understand how this code is an exponential weighting?
        //
        bnNewTarget.SetCompact(pindexPrev->nBits);

        ::int64_t
            nTargetSpacing = fProofOfStake?
                             nStakeTargetSpacing :
                             min(                       // what is this PoW value?
                                nTargetSpacingWorkMax,  //12 minutes
                                (::int64_t) nStakeTargetSpacing *
                                            (1 + pindexLast->nHeight - pindexPrev->nHeight)
                                );

        ::int64_t
            nInterval = nTargetTimespan / nTargetSpacing;   // this is the one week / nTargetSpacing

        bnNewTarget *= (((nInterval - 1) * nTargetSpacing) + nActualSpacing + nActualSpacing);
        bnNewTarget /=  ((nInterval + 1) * nTargetSpacing);
    }

    if (bnNewTarget > bnEasiestTargetLimit)
        bnNewTarget = bnEasiestTargetLimit;

    return bnNewTarget.GetCompact();
}
//_____________________________________________________________________________
// yacoin2015 upgrade: penalize ignoring ProofOfStake blocks with high difficulty.
// requires adjusted PoW-PoS ratio (GetSpacingThreshold), PoW target moving average (nBitsMA)
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    if( fUseOld044Rules )
    {
        return GetNextTargetRequired044( pindexLast, fProofOfStake );
    }
    CBigNum 
        bnTargetLimit = fProofOfStake ? 
                        bnProofOfStakeHardLimit: 
                        bnProofOfWorkLimit; // PoS(~uint256(0) >> 30), PoW(~uint256(0) >> 20)

    bool fCheckPreviousPoWBlockOverstep(false); // flag, used for check and ignore overstepped PoW block difficulty

    if (
        !fProofOfStake && 
        !fUseOld044Rules     //((pindexLast->nTime >= YACOIN_NEW_LOGIC_SWITCH_TIME) || fTestNet)
       )
    {
        if ( pindexLast->IsProofOfWork() )  // PoW after PoW
        {
            CBigNum bnOverstepNew;

            const CBlockIndex
                * ppos = GetLastBlockIndex( pindexLast->pprev, true ); // get last PoS block preceeding

            if( ppos )  // we are NOT on genesis block
            {
                int 
                    overstep = ( pindexLast->nHeight - ppos->nHeight ) - ppos->GetSpacingThreshold();    // distanceToPoS - AdjPowPosRatio

                if ( overstep == 0 && ppos->nBitsMA > 0 )    // if true, we generate target for next (1st) overstepped block
                {
                    bnOverstepNew.SetCompact( ppos->nBitsMA );
                    const CBlockIndex* pindex = pindexLast;

                    while ( pindex->IsProofOfWork() )
                    {
                        CBigNum powTarget;
                        powTarget.SetCompact( pindex->nBits );

                        // if any recent PoW block target is lower than MA, we use that one to maximize difficulty
                        if ( powTarget < bnOverstepNew )
                            bnOverstepNew = powTarget;

                        pindex = pindex->pprev;
                    }

                    bnOverstepNew = bnOverstepNew >> 1; // cut that target in half, consequently double difficulty
                    return bnOverstepNew.GetCompact();  // now it should take twice the time ...
                }
                else if ( overstep > 0 )
                {
                    bnOverstepNew.SetCompact( pindexLast->nBits );
                    bnOverstepNew = bnOverstepNew >> 1; // for each overstepped block, make difficulty double
                    return bnOverstepNew.GetCompact();  // good luck ignoring PoS blocks for long ...
                }
                else {} // we let old rules down below do the work
            }
            else  // we are on genesis block, so what to do???, let 0.4.4 run????
            {
            }
        }
        else    // PoW after PoS
            fCheckPreviousPoWBlockOverstep = true;
    }

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);

    if (pindexPrev->pprev == NULL)
        return bnProofOfWorkLimit.GetCompact(); // first block: CBigNum(~uint256(0) >> 20)


    int nPoSBlocksBetween = pindexLast->nHeight - pindexPrev->nHeight;  // calc now, pindexPrev might later point elsewhere

    if ( fCheckPreviousPoWBlockOverstep )  // if calculating target for PoW after PoS block, adjustment is needed when previous PoW in overstep
    {
        const CBlockIndex* ppos = GetLastBlockIndex( pindexPrev->pprev, true ); // get last PoS block preceeding last PoW block

        if ( ppos->nBitsMA > 0 )
        {
            int overstep = ( pindexPrev->nHeight - ppos->nHeight ) - ppos->GetSpacingThreshold();

            // overstepped blocks are expected to be produced with delay but next difficulty (after PoS block) shouldn't be too high because of that.
            // if overstepped, we point pindexPrev to last non-overstepped PoW block and use it's nTime and nBits to derive bnNew
            for ( int i = 0; i < overstep; i++ )
                pindexPrev = pindexPrev->pprev;
        }
    }


    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);

    if (pindexPrevPrev->pprev == NULL)
        return bnProofOfWorkLimit.GetCompact(); // second block: CBigNum(~uint256(0) >> 20)

    ::int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);

    ::int64_t nTargetSpacing = fProofOfStake ? nStakeTargetSpacing : min(nTargetSpacingWorkMax, (::int64_t) nStakeTargetSpacing * (1 + nPoSBlocksBetween));
    ::int64_t nInterval = nTargetTimespan / nTargetSpacing;

    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    printf("CheckProofOfWork: nBits: %d\n",nBits);
    // Check range
    if (
        (bnTarget <= 0 )
        || 
        (bnTarget > ( fTestNet? bnProofOfWorkLimitTestNet: bnProofOfWorkLimit) )
       )
        return error("CheckProofOfWork() : nBits below minimum work");
    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash > target nBits");

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload()
{
    bool
        fIsIBD = true;      // presume still downloading blocks

    if (
        pindexBest == NULL || 
        (nBestHeight < Checkpoints::GetTotalBlocksEstimate())
       )
        return fIsIBD;

    fIsIBD = false;         // presume downloading blocks is done
    if( 
        (0 == nBestHeight) 
      )
        return fIsIBD;

    ::int64_t
        nTimeOfBestBlockInSeconds = pindexBest->GetBlockTime(),
        nCurrentTime = GetTime();

    const ::int64_t 
        nOnedayAgoInSeconds = nCurrentTime - nOneDayInSeconds,
        nTwoHoursAgoInSeconds = nCurrentTime - nTwoHoursInSeconds,
        n12MinutesAgo = nCurrentTime - (12 * nSecondsPerMinute);

    bool 
        fIsBestBlockYoungEnough = (nTimeOfBestBlockInSeconds >= nOnedayAgoInSeconds)? true: false;

    if( fIsBestBlockYoungEnough )   // being young enough means "caught up"
    {                               // i.e. done with the "initial block download"
        fIsBestBlockYoungEnough =   // it's within a day of now, so is it within 12 minutes
            (nTimeOfBestBlockInSeconds >= n12MinutesAgo)? 
            true: 
            false;
    }

    if( !fIsBestBlockYoungEnough )  // i.e. we think IBD is still happening
    {                               // maybe it isn't, so let's try some trickery!
        const ::int64_t
            nTenSeconds = 10;
        static ::int64_t
            nLastUpdate;
        static CBlockIndex
            * pindexLastBest;
        if (pindexBest != pindexLastBest)   // we just got a new block
        {                           // first time through, we set the values
            pindexLastBest = pindexBest;
            nLastUpdate = GetTime();
        }
        //else  // nLastUpdate gets older & older
        fIsBestBlockYoungEnough =
              !(
                ((GetTime() - nLastUpdate) < nTenSeconds) && // < 10 seconds between calls?
                (pindexBest->GetBlockTime() < (GetTime() - nOneDayInSeconds)) // block is > 1 day old
               );                                   // we take this to mean still IBD, I think???
    }
    //else  // fIsBestBlockYoungEnough is true, meaning done with IBD
    return !fIsBestBlockYoungEnough;
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->bnChainTrust > bnBestInvalidTrust)
    {
        bnBestInvalidTrust = pindexNew->bnChainTrust;
        CTxDB().WriteBestInvalidTrust(bnBestInvalidTrust);
#ifdef QT_GUI
        //uiInterface.NotifyBlocksChanged();
#endif
    }

    CBigNum bnBestInvalidBlockTrust = pindexNew->bnChainTrust - pindexNew->pprev->bnChainTrust;
    CBigNum bnBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->bnChainTrust - pindexBest->pprev->bnChainTrust) : pindexBest->bnChainTrust;

    printf("InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      (pindexNew->bnChainTrust).ToString().c_str(), bnBestInvalidBlockTrust.getuint64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    printf("InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
      (pindexBest->bnChainTrust).ToString().c_str(),
      bnBestBlockTrust.getuint64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
}


void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}











bool CTransaction::DisconnectInputs(CTxDB& txdb)
{
    // Relinquish previous transactions' spent pointers
    if (!IsCoinBase())
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
        {
            COutPoint prevout = txin.prevout;

            // Get prev txindex from disk
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(prevout.COutPointGetHash(), txindex))
                return error("DisconnectInputs() : ReadTxIndex failed");

            if (prevout.COutPointGet_n() >= txindex.vSpent.size())
                return error("DisconnectInputs() : prevout.n out of range");

            // Mark outpoint as not spent
            txindex.vSpent[prevout.COutPointGet_n()].SetNull();

            // Write back
            if (!txdb.UpdateTxIndex(prevout.COutPointGetHash(), txindex))
                return error("DisconnectInputs() : UpdateTxIndex failed");
        }
    }

    // Remove transaction from index
    // This can fail if a duplicate of this transaction was in a chain that got
    // reorganized away. This is only possible if this transaction was completely
    // spent, so erasing it would be a no-op anyway.
    txdb.EraseTxIndex(*this);

    return true;
}


bool CTransaction::FetchInputs(CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool,
                               bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid)
{
    // FetchInputs can return false either because we just haven't seen some inputs
    // (in which case the transaction should be stored as an orphan)
    // or because the transaction is malformed (in which case the transaction should
    // be dropped).  If tx is definitely invalid, fInvalid will be set to true.
    fInvalid = false;

    if (IsCoinBase())
        return true; // Coinbase transactions have no inputs to fetch.

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        COutPoint prevout = vin[i].prevout;
        if (inputsRet.count(prevout.COutPointGetHash()))
            continue; // Got it already

        // Read txindex
        CTxIndex& txindex = inputsRet[prevout.COutPointGetHash()].first;
        bool fFound = true;
        if ((fBlock || fMiner) && mapTestPool.count(prevout.COutPointGetHash()))
        {
            // Get txindex from current proposed changes
            txindex = mapTestPool.find(prevout.COutPointGetHash())->second;
        }
        else
        {
            // Read txindex from txdb
            fFound = txdb.ReadTxIndex(prevout.COutPointGetHash(), txindex);
        }
        if (!fFound && (fBlock || fMiner))
            return fMiner ? false : error("FetchInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.COutPointGetHash().ToString().substr(0,10).c_str());

        // Read txPrev
        CTransaction& txPrev = inputsRet[prevout.COutPointGetHash()].second;
        if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
        {
            // Get prev tx from single transactions in memory
            {
                LOCK(mempool.cs);
                if (!mempool.exists(prevout.COutPointGetHash()))
                    return error("FetchInputs() : %s mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.COutPointGetHash().ToString().substr(0,10).c_str());
                txPrev = mempool.lookup(prevout.COutPointGetHash());
            }
            if (!fFound)
                txindex.vSpent.resize(txPrev.vout.size());
        }
        else
        {
            // Get prev tx from disk
            if (!txPrev.ReadFromDisk(txindex.pos))
                return error("FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.COutPointGetHash().ToString().substr(0,10).c_str());
        }
    }

    // Make sure all prevout.n indexes are valid:
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const COutPoint prevout = vin[i].prevout;
        Yassert(inputsRet.count(prevout.COutPointGetHash()) != 0);
        const CTxIndex& txindex = inputsRet[prevout.COutPointGetHash()].first;
        const CTransaction& txPrev = inputsRet[prevout.COutPointGetHash()].second;
        if (prevout.COutPointGet_n() >= txPrev.vout.size() || prevout.COutPointGet_n() >= txindex.vSpent.size())
        {
            // Revisit this if/when transaction replacement is implemented and allows
            // adding inputs:
            fInvalid = true;
            return DoS(100, error("FetchInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.COutPointGet_n(), txPrev.vout.size(), txindex.vSpent.size(), prevout.COutPointGetHash().ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
        }
    }

    return true;
}

const CTxOut& CTransaction::GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const
{
    MapPrevTx::const_iterator mi = inputs.find(input.prevout.COutPointGetHash());
    if (mi == inputs.end())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.hash not found");

    const CTransaction& txPrev = (mi->second).second;
    if (input.prevout.COutPointGet_n() >= txPrev.vout.size())
        throw std::runtime_error("CTransaction::GetOutputFor() : prevout.n out of range");

    return txPrev.vout[input.prevout.COutPointGet_n()];
}

::int64_t CTransaction::GetValueIn(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    ::int64_t nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        nResult += GetOutputFor(vin[i], inputs).nValue;
    }
    return nResult;

}

unsigned int CTransaction::GetP2SHSigOpCount(const MapPrevTx& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    }
    return nSigOps;
}

bool CScriptCheck::operator()() const 
{
    const CScript 
        &scriptSig = ptxTo->vin[nIn].scriptSig;
    if (!VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, nHashType))
        return error("CScriptCheck() : %s VerifySignature failed", 
                     ptxTo->GetHash().ToString().substr(0,10).c_str()
                    );
    return true;
}

bool VerifySignature(
                     const CTransaction& txFrom, 
                     const CTransaction& txTo, 
                     unsigned int nIn, 
                     unsigned int flags, 
                     int nHashType
                    )
{
    return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();
}

bool CTransaction::ConnectInputs(
                                 CTxDB& txdb, 
                                 MapPrevTx inputs, 
                                 map<uint256, CTxIndex>& mapTestPool, 
                                 const CDiskTxPos& posThisTx,
                                 const CBlockIndex* pindexBlock, 
                                 bool fBlock, 
                                 bool fMiner, 
                                 bool fScriptChecks, 
                                 unsigned int flags, std::vector<CScriptCheck> *pvChecks
                                )
{
    // Take over previous transactions' spent pointers
    // fBlock is true when this is called from AcceptBlock when a new best-block is added to the blockchain
    // fMiner is true when called from the internal bitcoin miner
    // ... both are false when called from CTransaction::AcceptToMemoryPool

    if (!IsCoinBase())
    {
        ::int64_t 
            nValueIn = 0;
        ::int64_t 
            nFees = 0;
        for (unsigned int i = 0; i < vin.size(); ++i)
        {
            COutPoint 
                prevout = vin[i].prevout;
            Yassert(inputs.count(prevout.COutPointGetHash()) > 0);
            CTxIndex
                & txindex = inputs[prevout.COutPointGetHash()].first;
            CTransaction
                & txPrev = inputs[prevout.COutPointGetHash()].second;

            if (
                prevout.COutPointGet_n() >= txPrev.vout.size() || 
                prevout.COutPointGet_n() >= txindex.vSpent.size()
               )    // what exactly is this a test of??????????????
                return DoS(
                            100, 
                            error(
                                  "ConnectInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", 
                                  GetHash().ToString().substr(0,10).c_str(), 
                                  prevout.COutPointGet_n(), txPrev.vout.size(), 
                                  txindex.vSpent.size(), 
                                  prevout.COutPointGetHash().ToString().substr(0,10).c_str(), 
                                  txPrev.ToString().c_str()
                                 )
                          );

            // If prev is coinbase or coinstake, check that it's matured
            if (txPrev.IsCoinBase() || txPrev.IsCoinStake())
            {
                // Fix off-by-one error in coinbase maturity check after hardfork
                int coinbaseMaturityOffset = 0;
                if (nBestHeight != -1 && pindexGenesisBlock && nBestHeight >= nMainnetNewLogicBlockNumber)
                {
                    coinbaseMaturityOffset = 1;
                }

                for (
                     const CBlockIndex
                        * pindex = pindexBlock;
                     pindex && ((pindexBlock->nHeight - pindex->nHeight + coinbaseMaturityOffset) < GetCoinbaseMaturity());
                     pindex = pindex->pprev
                    )
                    if (
                        (pindex->nBlockPos == txindex.pos.Get_CDiskTxPos_nBlockPos()) && 
                        (pindex->nFile == txindex.pos.Get_CDiskTxPos_nFile())
                       )    // what does this test actually test for??
                        return error(
                                     "ConnectInputs() : tried to spend %s at depth %d", 
                                     txPrev.IsCoinBase()? "coinbase": "coinstake", 
                                     pindexBlock->nHeight - pindex->nHeight + coinbaseMaturityOffset
                                    );
            }

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime)
                return DoS(100, error("ConnectInputs() : transaction timestamp earlier than input transaction"));

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.COutPointGet_n()].nValue;
            if (!MoneyRange(txPrev.vout[prevout.COutPointGet_n()].nValue) || !MoneyRange(nValueIn))
                return DoS(100, error("ConnectInputs() : txin values out of range"));

        }

        if (pvChecks)
            pvChecks->reserve(vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.
        for (unsigned int i = 0; i < vin.size(); ++i)
        {
            COutPoint 
                prevout = vin[i].prevout;
            Yassert(inputs.count(prevout.COutPointGetHash()) > 0);
            CTxIndex
                & txindex = inputs[prevout.COutPointGetHash()].first;
            CTransaction
                & txPrev = inputs[prevout.COutPointGetHash()].second;

            // Check for conflicts (double-spend)
            // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
            // for an attacker to attempt to split the network.
            if (!txindex.vSpent[prevout.COutPointGet_n()].IsNull())
                return fMiner ? false : error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.COutPointGet_n()].ToString().c_str());

            // Skip ECDSA signature verification when connecting blocks (fBlock=true)
            // before the last blockchain checkpoint. This is safe because block merkle hashes are
            // still computed and checked, and any change will be caught at the next checkpoint.
            if (fScriptChecks)
            {
                // Verify signature
                CScriptCheck check(txPrev, *this, i, flags, 0);
                if (pvChecks)
                {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                }
                else if (!check())
                {
                    if (flags & STRICT_FLAGS)
                    {
                        // Don't trigger DoS code in case of STRICT_FLAGS caused failure.
                        CScriptCheck check(txPrev, *this, i, flags & ~STRICT_FLAGS, 0);
                        if (check())
                            return error("ConnectInputs() : %s strict VerifySignature failed", GetHash().ToString().substr(0,10).c_str());
                    }
                    return DoS(100,error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                }
            }

            // Mark outpoints as spent
            txindex.vSpent[prevout.COutPointGet_n()] = posThisTx;

            // Write back
            if (fBlock || fMiner)
            {
                mapTestPool[prevout.COutPointGetHash()] = txindex;
            }
        }

        if (IsCoinStake())
        {
            // ppcoin: coin stake tx earns reward instead of paying fee
            ::uint64_t 
                nCoinAge;
            if (!GetCoinAge(txdb, nCoinAge))
                return error(
                            "ConnectInputs() : %s unable to get coin age for coinstake", 
                            GetHash().ToString().substr(0,10).c_str()
                            );

            unsigned int 
                nTxSize = (nTime > VALIDATION_SWITCH_TIME || fTestNet) ? 
                          GetSerializeSize(SER_NETWORK, PROTOCOL_VERSION) : 0;

            ::int64_t 
                nReward = GetValueOut() - nValueIn;
            ::int64_t 
                nCalculatedReward = GetProofOfStakeReward(
                                                            nCoinAge, 
                                                            pindexBlock->nBits, 
                                                            nTime
                                                         ) - 
                                    GetMinFee(nTxSize) +
                                    CENT;

            if (nReward > nCalculatedReward)
                return DoS(100, error("ConnectInputs() : coinstake pays too much(actual=%" PRId64 " vs calculated=%" PRId64 ")", nReward, nCalculatedReward));
        }
        else
        {
            if (nValueIn < GetValueOut())
                return DoS(100, error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));

            // Tally transaction fees
            ::int64_t nTxFee = nValueIn - GetValueOut();
            if (nTxFee < 0)
                return DoS(100, error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));

            nFees += nTxFee;
            if (!MoneyRange(nFees))
                return DoS(100, error("ConnectInputs() : nFees out of range"));
        }
    }

    return true;
}


bool CTransaction::ClientConnectInputs()
{
    if (IsCoinBase())
        return false;

    // Take over previous transactions' spent pointers
    {
        LOCK(mempool.cs);
        ::int64_t nValueIn = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            // Get prev tx from single transactions in memory
            COutPoint prevout = vin[i].prevout;
            if (!mempool.exists(prevout.COutPointGetHash()))
                return false;
            CTransaction& txPrev = mempool.lookup(prevout.COutPointGetHash());

            if (prevout.COutPointGet_n() >= txPrev.vout.size())
                return false;

            // Verify signature
            if (!VerifySignature(txPrev, *this, i, SCRIPT_VERIFY_NOCACHE | SCRIPT_VERIFY_P2SH, 0))
                return error("ClientConnectInputs() : VerifySignature failed");

            ///// this is redundant with the mempool.mapNextTx stuff,
            ///// not sure which I want to get rid of
            ///// this has to go away now that posNext is gone
            // // Check for conflicts
            // if (!txPrev.vout[prevout.n].posNext.IsNull())
            //     return error("ConnectInputs() : prev tx already used");
            //
            // // Flag outpoints as used
            // txPrev.vout[prevout.n].posNext = posThisTx;

            nValueIn += txPrev.vout[prevout.COutPointGet_n()].nValue;

            if (!MoneyRange(txPrev.vout[prevout.COutPointGet_n()].nValue) || !MoneyRange(nValueIn))
                return error("ClientConnectInputs() : txin values out of range");
        }
        if (GetValueOut() > nValueIn)
            return false;
    }

    return true;
}




bool CBlock::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("DisconnectBlock() : WriteBlockIndex failed");
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, false, false);

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck(void*) 
{
    ++vnThreadsRunning[THREAD_SCRIPTCHECK];
    RenameThread("yacoin-scriptch");
    scriptcheckqueue.Thread();
    --vnThreadsRunning[THREAD_SCRIPTCHECK];
}

void ThreadScriptCheckQuit() 
{
    scriptcheckqueue.Quit();
}

bool CBlock::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck)
{
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock(!fJustCheck, !fJustCheck, false))
        return false;

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes in their
    // initial block download.
    bool fEnforceBIP30 = true;
    bool fScriptChecks = pindex->nHeight >= Checkpoints::GetTotalBlocksEstimate();

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck)
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    else
        nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    ::int64_t nFees = 0;
    ::int64_t nValueIn = 0;
    ::int64_t nValueOut = 0;
    unsigned int nSigOps = 0;
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();

        if (fEnforceBIP30) {
            CTxIndex txindexOld;
            if (txdb.ReadTxIndex(hashTx, txindexOld)) {
                BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
                    if (pos.IsNull())
                        return false;
            }
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > GetMaxSize(MAX_BLOCK_SIGOPS))
            return DoS(100, error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        MapPrevTx mapInputs;
        if (tx.IsCoinBase())
            nValueOut += tx.GetValueOut();
        else
        {
            bool fInvalid;
            if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
                return false;

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            std::vector<int> prevheights;
            prevheights.resize(tx.vin.size());
            int nLockTimeFlags = 0;
            for (unsigned int i = 0; i < tx.vin.size(); ++i)
            {
                COutPoint
                    prevout = tx.vin[i].prevout;
                CTransaction tx;
                uint256 hashBlock = 0;
                if (GetTransaction(prevout.COutPointGetHash(), tx, hashBlock))
                {
                    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
                    if (mi != mapBlockIndex.end() && (*mi).second)
                    {
                        CBlockIndex* pTmpIndex = (*mi).second;
                        prevheights[i] = pTmpIndex->nHeight;
                    }
                    else
                    {
                        prevheights[i] = pindex->nHeight;
                    }
                }
                else
                {
                    prevheights[i] = pindex->nHeight;
                }
            }
            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex))
            {
                return DoS(100, error("ConnectBlock(): contains a non-BIP68-final transaction", __func__));
            }

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nSigOps > GetMaxSize(MAX_BLOCK_SIGOPS))
                return DoS(100, error("ConnectBlock() : too many sigops"));

            ::int64_t nTxValueIn = tx.GetValueIn(mapInputs);
            ::int64_t nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            if (!tx.IsCoinStake())
                nFees += nTxValueIn - nTxValueOut;

            std::vector<CScriptCheck> vChecks;
            if (!tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false, fScriptChecks, SCRIPT_VERIFY_NOCACHE | SCRIPT_VERIFY_P2SH, nScriptCheckThreads ? &vChecks : NULL))
                return false;
            control.Add(vChecks);
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }
//_____________________ this is new code here
    if (!control.Wait())
    {
        (void)printf( "\nDoS ban of whom?\n\n" );   //maybe all nodes?
        return DoS(100, false);     // a direct ban
    }

    if (IsProofOfWork())
    {
        ::int64_t nBlockReward = GetProofOfWorkReward(nBits, nFees);

        // Check coinbase reward
        if (vtx[0].GetValueOut() > nBlockReward)
            return error(
                        "CheckBlock () : coinbase reward exceeded "
                        "(actual=%" PRId64 " vs calculated=%" PRId64 ")",
                        vtx[0].GetValueOut(),
                        nBlockReward
                        );
    }
//_____________________ 

    // track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    if (!txdb.WriteBlockIndex(CDiskBlockIndex(pindex)))
        return error("Connect() : WriteBlockIndex for pindex failed");

    // fees are not collected by proof-of-stake miners
    // fees are destroyed to compensate the entire network
    if (fDebug && IsProofOfStake() && GetBoolArg("-printcreation"))
        printf("ConnectBlock() : destroy=%s nFees=%" PRId64 "\n", FormatMoney(nFees).c_str(), nFees);

    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock() : UpdateTxIndex failed");
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("ConnectBlock() : WriteBlockIndex failed");
    }

    // Watch for transactions paying to me
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, true);


    return true;
}

bool static Reorganize(CTxDB& txdb, CBlockIndex* pindexNew)
{
    printf("REORGANIZE\n");

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
        Sleep( nOneMillisecond );
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    printf("REORGANIZE: Disconnect %" PRIszu " blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
    printf("REORGANIZE: Connect %" PRIszu " blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, pindex))
            return error("Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
                vResurrect.push_back(tx);
        Sleep( nOneMillisecond );
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for connect failed");
        if (!block.ConnectBlock(txdb, pindex))
        {
            // Invalid block
            return error("Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
        Sleep( nOneMillisecond );
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return error("Reorganize() : TxnCommit failed");

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect)
        tx.AcceptToMemoryPool(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete)
        mempool.remove(tx);

    printf("REORGANIZE: done\n");

    return true;
}


// Called from inside SetBestChain: attaches a block to the new best chain being built
bool CBlock::SetBestChainInner(CTxDB& txdb, CBlockIndex *pindexNew) //<<<<<<<<<
{
    uint256 hash = GetHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, pindexNew) || !txdb.WriteHashBestChain(hash))
    {
        txdb.TxnAbort();
        InvalidChainFound(pindexNew);
        return false;
    }
    if (!txdb.TxnCommit())
        return error("SetBestChain () : TxnCommit failed");

    // Add to current best branch
    pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    BOOST_FOREACH(CTransaction& tx, vtx)
        mempool.remove(tx);

    return true;
}

bool CBlock::SetBestChain(CTxDB& txdb, CBlockIndex* pindexNew)
{
    uint256 hash = GetHash();

    if (!txdb.TxnBegin())
        return error("SetBestChain () : TxnBegin failed");

    if (
        (pindexGenesisBlock == NULL) && 
        (hash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
       )
    {
        txdb.WriteHashBestChain(hash);
        if (!txdb.TxnCommit())
            return error("SetBestChain () : TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == hashBestChain)
    {
        if (!SetBestChainInner(txdb, pindexNew))
            return error("SetBestChain () : SetBestChainInner failed");
    }
    else
    {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex*> vpindexSecondary;

        // Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (
                pindexIntermediate->pprev && 
                pindexIntermediate->pprev->bnChainTrust > pindexBest->bnChainTrust
              )
        {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->pprev;
        }

        if (!vpindexSecondary.empty())
            printf("Postponing %" PRIszu " reconnects\n", vpindexSecondary.size());

        // Switch to new best branch
        if (!Reorganize(txdb, pindexIntermediate))
        {
            txdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return error("SetBestChain () : Reorganize failed");
        }

        // Connect further blocks
        BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vpindexSecondary)
        {
            CBlock block;
            if (!block.ReadFromDisk(pindex))
            {
                printf("SetBestChain () : ReadFromDisk failed\n");
                break;
            }
            if (!txdb.TxnBegin()) {
                printf("SetBestChain () : TxnBegin 2 failed\n");
                break;
            }
            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (!block.SetBestChainInner(txdb, pindex))
                break;
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    bool 
        fIsInitialDownload = IsInitialBlockDownload();

    if (!fIsInitialDownload)
    {
        const CBlockLocator locator(pindexNew);

        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = hash;
    pblockindexFBBHLast = NULL;
    pindexBest = pindexNew;
    // Reorg through two or many epochs
    if ((abs(nBestHeight - pindexBest->nHeight) >= 2) &&
        (abs((::int32_t)(nBestHeight / nEpochInterval) - (::int32_t)(pindexBest->nHeight / nEpochInterval)) >= 1))
    {
        recalculateBlockReward = true;
        recalculateMinEase = true;
    }
    // Update minimum ease for next target calculation
    if ((pindexBest->nHeight >= nMainnetNewLogicBlockNumber)
        && (nMinEase > pindexBest->nBits))
    {
        nMinEase = pindexBest->nBits;
    }
    nBestHeight = pindexBest->nHeight;

    // good place to test for new logic
    (void)HaveWeSwitchedToNewLogicRules( fUseOld044Rules );

    bnBestChainTrust = pindexNew->bnChainTrust;
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;

    CBigNum bnBestBlockTrust = 
        (pindexBest->nHeight != 0)? 
        (pindexBest->bnChainTrust - pindexBest->pprev->bnChainTrust):
        pindexBest->bnChainTrust;

    printf(
            "SetBestChain: new best=%s height=%d trust=%s\nblocktrust=%" PRId64 "  date=%s\n",
            hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
            bnBestChainTrust.ToString().c_str(),
            bnBestBlockTrust.getuint64(),
            DateTimeStrFormat("%x %H:%M:%S", 
            pindexBest->GetBlockTime()).c_str()
          );
#ifdef QT_GUI
    //uiInterface.NotifyBlocksChanged();
#endif

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexBest;
        for (int i = 0; i < 100 && pindex != NULL; ++i)
        {
            // TODO: Temporary fix to avoid warning for yacoind 1.0.0. Because in yacoind 1.0.0, there are two times
            // block version is upgraded:
        	// 1) At the time installing yacoind 1.0.0
        	// 2) At the time happening hardfork
        	// Need update this line at next yacoin version
            if (pindex->nVersion > VERSION_of_block_for_yac_05x_new)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            printf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CURRENT_VERSION_of_block);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are 
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CTxDB& txdb, ::uint64_t& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue;  // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos(), false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        ::int64_t nValueIn = txPrev.vout[txin.prevout.COutPointGet_n()].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;

        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%" PRId64 " nTimeDiff=%ld bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(::uint64_t& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        ::uint64_t nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("block coin age total nCoinDays=%" PRId64 "\n", nCoinAge);
    return true;
}

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    pindexNew->phashBlock = &hash;

    map<uint256, CBlockIndex*>::iterator 
        miPrev = mapBlockIndex.find(hashPrevBlock); // this bothers me when mapBlockIndex == NULL!?

    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->nPosBlockCount = pindexNew->pprev->nPosBlockCount + 
                                    ( pindexNew->IsProofOfStake() ? 1 : 0 );
        pindexNew->nBitsMA = pindexNew->IsProofOfStake()? 
                             GetProofOfWorkMA(pindexNew->pprev): 0;
    }

    // ppcoin: compute chain trust score
    pindexNew->bnChainTrust = (pindexNew->pprev ? 
                                pindexNew->pprev->bnChainTrust : 
                                CBigNum(0)
                              ) + 
                              pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->nHeight)))
        return error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    // ppcoin: record proof-of-stake hash value
    if (pindexNew->IsProofOfStake())
    {
        if (!mapProofOfStake.count(hash))
            return error("AddToBlockIndex() : hashProofOfStake not found in map");
        pindexNew->hashProofOfStake = mapProofOfStake[hash];
    }

    if (!pindexBest || (pindexBest->nHeight + 1) < nMainnetNewLogicBlockNumber)
    {
        // ppcoin: compute stake modifier
        ::uint64_t nStakeModifier = 0;
        bool fGeneratedStakeModifier = false;
        if (!ComputeNextStakeModifier(pindexNew, nStakeModifier, fGeneratedStakeModifier))
            return error("AddToBlockIndex() : ComputeNextStakeModifier() failed");
        pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);

        pindexNew->nStakeModifierChecksum = GetStakeModifierChecksum(pindexNew);
        if (!CheckStakeModifierCheckpoints(pindexNew->nHeight, pindexNew->nStakeModifierChecksum))
            return error("AddToBlockIndex() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindexNew->nHeight, nStakeModifier);
    }

    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
        setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
    pindexNew->phashBlock = &((*mi).first);

    // Write to disk block index
    CTxDB txdb;
    if (!txdb.TxnBegin())
        return false;
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (!txdb.TxnCommit())
        return false;

    // New best
    if (
        (pindexNew->bnChainTrust > bnBestChainTrust)
        || fTestNet     //<<<<<<<<<<<<<<<<<<<<<<<<<<
       )
        if (!SetBestChain(txdb, pindexNew))
            return false;

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

#ifdef QT_GUI
    static ::int8_t counter = 0;
    if( 
       ((++counter & 0x0F) == 0) ||     // every 16 blocks, why?
       !IsInitialBlockDownload()
      ) // repaint every 16 blocks if not in initial block download
    {
        //uiInterface.NotifyBlocksChanged();
    }
    else
    {
    //uiInterface.NotifyBlocksChanged();
    }
#endif
    return true;
}




bool CBlock::CheckBlock(bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    set<uint256> 
        uniqueTx; // tx hashes
    unsigned int 
        nSigOps = 0; // total sigops

    // Size limits
    if (vtx.empty() || vtx.size() > GetMaxSize(MAX_BLOCK_SIZE) || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > GetMaxSize(MAX_BLOCK_SIZE))
        return DoS(100, error("CheckBlock () : size limits failed"));

    bool fProofOfStake = IsProofOfStake();

    // First transaction must be coinbase, the rest must not be
    if (!vtx[0].IsCoinBase())
        return DoS(100, error("CheckBlock () : first tx is not coinbase"));

    if (!vtx[0].CheckTransaction())
        return DoS(vtx[0].nDoS, error("CheckBlock () : CheckTransaction failed on coinbase"));

    uniqueTx.insert(vtx[0].GetHash());
    nSigOps += vtx[0].GetLegacySigOpCount();

    if (fProofOfStake)
    {
        // Proof-of-STake related checkings. Note that we know here that 1st transactions is coinstake. We don't need 
        //   check the type of 1st transaction because it's performed earlier by IsProofOfStake()

        // nNonce must be zero for proof-of-stake blocks
        if (nNonce != 0)
            return DoS(100, error("CheckBlock () : non-zero nonce in proof-of-stake block"));

        // Coinbase output should be empty if proof-of-stake block
        if (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty())
            return DoS(100, error("CheckBlock () : coinbase output not empty for proof-of-stake block"));

        // Check coinstake timestamp
        if (GetBlockTime() != (::int64_t)vtx[1].nTime)
            return DoS(50, error("CheckBlock () : coinstake timestamp violation nTimeBlock=%" PRId64 " nTimeTx=%ld", GetBlockTime(), vtx[1].nTime));

        // Check timestamp  06/04/2018 missing test in this 0.4.5-0.48 code.  Thanks Joe! ;>
        if (GetBlockTime() > FutureDrift(GetAdjustedTime()))
            return error("CheckBlock () : block timestamp too far in the future");

        // NovaCoin: check proof-of-stake block signature
        if (fCheckSig && !CheckBlockSignature())
        {
            printf( "\n" );
            printf(
                "bad PoS block signature, in block:"
                "\n"
                  );
            print();
            printf( "\n" );

            return DoS(100, error("CheckBlock () : bad proof-of-stake block signature"));
        }

        if (!vtx[1].CheckTransaction())
            return DoS(vtx[1].nDoS, error("CheckBlock () : CheckTransaction failed on coinstake"));

        uniqueTx.insert(vtx[1].GetHash());
        nSigOps += vtx[1].GetLegacySigOpCount();
    }
    else    // is PoW block
    {       // nNonce must be greater than zero for proof-of-work blocks, WHY????
        if (
            (!fUseOld044Rules) && 
            (nNonce == 0)
           )
            return DoS(50, error("CheckBlock () : zero nonce in proof-of-work block"));

        // Check proof of work matches claimed amount
        if (fCheckPOW && !CheckProofOfWork(GetYacoinHash(), nBits))
            return DoS(50, error("CheckBlock () : proof of work failed"));

        // Check timestamp
        if (GetBlockTime() > FutureDrift(GetAdjustedTime())){
            printf("Block timestamp in future: blocktime %d futuredrift %d",GetBlockTime(),FutureDrift(GetAdjustedTime()));
            return error("CheckBlock () : block timestamp too far in the future");
        }

        // Check coinbase timestamp
        if (GetBlockTime() < PastDrift((::int64_t)vtx[0].nTime))
            return DoS(50, error("CheckBlock () : coinbase timestamp is too late"));
    }

    // Iterate all transactions starting from second for proof-of-stake block 
    //    or first for proof-of-work block
    for (unsigned int i = (fProofOfStake ? 2 : 1); i < vtx.size(); ++i)
    {
        const CTransaction& tx = vtx[i];

        // Reject coinbase transactions at non-zero index
        if (tx.IsCoinBase())
            return DoS(100, error("CheckBlock () : coinbase at wrong index"));

        // Reject coinstake transactions at index != 1
        if (tx.IsCoinStake())
            return DoS(100, error("CheckBlock () : coinstake at wrong index"));

        // Check transaction timestamp
        if (GetBlockTime() < (::int64_t)tx.nTime)
            return DoS(50, error("CheckBlock () : block timestamp earlier than transaction timestamp"));

        // Check transaction consistency
        if (!tx.CheckTransaction())
            return DoS(tx.nDoS, error("CheckBlock () : CheckTransaction failed"));

        // Add transaction hash into list of unique transaction IDs
        uniqueTx.insert(tx.GetHash());

        // Calculate sigops count
        nSigOps += tx.GetLegacySigOpCount();
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    if (uniqueTx.size() != vtx.size())
        return DoS(100, error("CheckBlock () : duplicate transaction"));

    // Reject block if validation would consume too much resources.
    if (nSigOps > GetMaxSize(MAX_BLOCK_SIGOPS))
        return DoS(100, error("CheckBlock () : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
        return DoS(100, error("CheckBlock () : hashMerkleRoot mismatch"));

    return true;
}

bool CBlock::AcceptBlock()
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock () : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return DoS(10, error("AcceptBlock () : prev block not found"));
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight+1;

    // Since hardfork block, new blocks don't accept transactions with version 1 anymore
    if (nHeight >= nMainnetNewLogicBlockNumber)
    {
        bool fProofOfStake = IsProofOfStake();

        if (vtx[0].nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old)
            return DoS(vtx[0].nDoS, error("AcceptBlock () : Not accept coinbase transaction with version 1"));

        if(fProofOfStake && vtx[1].nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old)
            return DoS(vtx[1].nDoS, error("AcceptBlock () : Not accept coinstake transaction with version 1"));

        // Iterate all transactions starting from second for proof-of-stake block
        //    or first for proof-of-work block
        for (unsigned int i = (fProofOfStake ? 2 : 1); i < vtx.size(); ++i)
        {
            if (vtx[i].nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old)
                return DoS(vtx[i].nDoS, error("AcceptBlock () : Not accept transaction with version 1"));
        }
    }

    // Check proof-of-work or proof-of-stake
    if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake()))
        return DoS(100, error("AcceptBlock () : incorrect %s", IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    ::int64_t 
        nMedianTimePast = pindexPrev->GetMedianTimePast();
//    int 
//      //nMaxOffset = 12 * nSecondsPerHour; // 12 hours
//        nMaxOffset = 7 * nSecondsPerDay; // One week (test)

//    if (fTestNet)   // || pindexPrev->nTime < 1450569600)
//        nMaxOffset = 7 * 7 * nSecondsPerDay; // 7 weeks on testNet

// Check timestamp against prev
    if (
        GetBlockTime() <= pindexPrev->GetMedianTimePast()
        ||
        FutureDrift(GetBlockTime()) < pindexPrev->GetBlockTime()
       )
        return error("AcceptBlock () : block's timestamp is too early");
/******* removed since it does't exist in <=0.4.4 code.  Thanks again, Joe ;>
    if (
        (pindexPrev->nHeight > 1) && 
        ( (nMedianTimePast + nMaxOffset) < GetBlockTime() )
       )
        return error("AcceptBlock () : block's timestamp is too far in the future");
*******/
    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock () : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock () : rejected by hardened checkpoint lock-in at %d", nHeight));

    bool cpSatisfies = Checkpoints::CheckSync(hash, pindexPrev);

    // Check that the block satisfies synchronized checkpoint
    if (
        (CheckpointsMode == Checkpoints::STRICT_) &&
/**************
    // using STRICT instead of STRICT_ collides with windef.h
    // and strangely cause gcc to fail when WIN32 is true & QT_GUI
    // but not WIN32 gcc compiling the daemon???
    // so I changed to STRICT_ which doesn't collide!
    // if we don't then this if would have to look like
    if (
        (CheckpointsMode == 
#ifdef WIN32 && QT_GUI
         0
#else
         Checkpoints::STRICT
#endif
        ) && 
***************/
        !cpSatisfies
       )
        return error("AcceptBlock () : rejected by synchronized checkpoint");

    if (
        (CheckpointsMode == Checkpoints::ADVISORY) && 
        !cpSatisfies
       )
        strMiscWarning = _("WARNING: syncronized checkpoint violation detected, but skipped!");

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (
        ( (!fUseOld044Rules) && ( vtx[0].vin[0].scriptSig.size() < expect.size() ) )
        ||
        !std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin())
       )
        return DoS(100, error("AcceptBlock () : block height mismatch in coinbase"));

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock () : out of disk space");
    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock () : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos))
        return error("AcceptBlock () : AddToBlockIndex failed");

    // here would be a good place to check for new logic

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {{
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (
                nBestHeight > (
                (pnode->nStartingHeight != -1) ? 
                pnode->nStartingHeight - 2000 : 
                nBlockEstimate )
               )                            // does 2000 blocks define IBD? 24 hours + a little
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
    }}

    // ppcoin: check pending sync-checkpoint
    Checkpoints::AcceptPendingSyncCheckpoint();

    return true;
}

// yacoin2015: ProofOfWork/ProofOfStake block ratio
double CBlockIndex::GetPoWPoSRatio() const
{
    Yassert ( nPosBlockCount > 0 );
    return (double)( nHeight - nPosBlockCount ) / (double) nPosBlockCount;
}

// yacoin2015: ProofOfWork block spacing threshold
::int32_t CBlockIndex::GetSpacingThreshold() const
{
    // always force lower spacing to encourage ProofOfStake block inclusion

    ::int32_t 
        spacing =  (0 < nPosBlockCount)?
                   (::int32_t)( boost::math::round( GetPoWPoSRatio() - 0.75 ) ):
                   0;
    return std::max( spacing, 1 );
}

// yacoin2015 GetBlockTrust upgrade
CBigNum CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    if (bnTarget <= 0)
        return CBigNum(0);

    // is (nTime >= YACOIN_NEW_LOGIC_SWITCH_TIME) actually true for blocks before 12/13/2015
    if (
        (0 < nPosBlockCount) 
        &&
        ( 
         (
          fTestNet 
          && 
          pprev 
         ) 
         ||
         !fUseOld044Rules         //(nTime >= YACOIN_NEW_LOGIC_SWITCH_TIME)
        )
       )
    {
        ::int32_t iratio =  (::int32_t)boost::math::round( GetPoWPoSRatio() );

        if ( IsProofOfStake() )
        {
            if ( iratio < 2 )
            // switch to ppcoin trust model occurs when real PoW:PoS ratio drops below 1.5
            {
                if ( (nHeight - GetLastBlockIndex(pprev,false)->nHeight) > 10 )
                {
                    // after 10 sequential PoS blocks, we drop trust so PoW block (with trust doubled) can get in
                    bnTarget.SetCompact( nBitsMA );
                }
                else // real proof-of-stake difficulty
                  return (CBigNum(1)<<256) / (bnTarget+1);
            }
            else // but until ratio drops enough, we derive ProofOfStake block trust from ProofOfWork target MA
            {
                if ( pprev->IsProofOfWork() )
                {
                    bnTarget.SetCompact( nBitsMA );
                    bnTarget = ( bnTarget >> 1 ) + ( bnTarget >> 4 ); // target MA/2 + target MA/16 -> ~1.78x MA trust
                }
                else if ( iratio < 5 && pprev->IsProofOfStake() && pprev->pprev->IsProofOfWork() )
                // Under limited conditions we award trust also to second subsequent ProofOfStake block.
                // This happens when iratio is 3 or 4 and there is less than average PoS blocks in recent history.
                // It also remains in force when round(PoW:PoS) ratio equals 2, so that PoS blocks can prevail one day.
                {
                    ::int32_t recentPoSBlockCount = 0;

                    if ( iratio > 2 )
                    {
                        const CBlockIndex* pindex = pprev->pprev;
                        for ( int i=0; i < ( iratio*iratio + iratio - 2); i++ )
                        {
                            pindex = pindex->pprev;
                            if ( pindex->IsProofOfStake() )
                                recentPoSBlockCount++;
                        }
                    }

                    if ( iratio == 2 || recentPoSBlockCount < iratio )
                    // now we need to beat double trust of ProofOfWork block
                    {
                        bnTarget.SetCompact( nBitsMA );
                        bnTarget = ( bnTarget >> 2 ) + ( bnTarget >> 3 ); // target MA/4 + target MA/8 -> ~2.67x MA trust
                    }
                }
                else
                  // no trust for 3,4,5... subsequent ProofOfStake block
                  // (not until iratio < 2 and ppcoin trust model takes over)
                  return CBigNum(0);
            }
        }
        else // ProofOfWork block
        {
            if ( pprev->IsProofOfStake() )
                bnTarget = bnTarget >> 1; // double trust for PoW after PoS block

            else // IsProofOfWork() && pprev->IsProofOfWork()
            {
                const CBlockIndex* ppos = GetLastBlockIndex( pprev->pprev, true ); // last ProofOfStake block preceding
                if ( ppos->nBitsMA > 0 ) // this check is needed in case PoS block came before YACOIN_NEW_LOGIC_SWITCH_TIME

                {
                    int overstep = ( this->nHeight - ppos->nHeight ) - ppos->GetSpacingThreshold();
                    if ( overstep > 0 )
                    {
                        // block difficulty already high for overstepped block due GetNextTargetRequired,
                        // we don't want to use that low nBits, rather use PoW target moving average from nBitsMA
                        bnTarget.SetCompact( ppos->nBitsMA );
                        // cut trust in half (by doubling target) with each overstepped block:
                        bnTarget = bnTarget << min( overstep, bnProofOfWorkLimit.bitSize() - bnTarget.bitSize() );
                    }
                }
            }
        }
        if( 0 == bnTarget )
        {
            bnTarget = 1;
        }
        return bnProofOfWorkLimit / bnTarget;
    }


    // saironiq: new trust rules (since CONSECUTIVE_STAKE_SWITCH_TIME on mainnet and always on testnet)
    if (
        fTestNet
        ||
        (GetBlockTime() >= CONSECUTIVE_STAKE_SWITCH_TIME)
       ) 
    {
        // first block trust - for future compatibility (i.e., forks :P)
        if (pprev == NULL)
            return CBigNum(1);

        // PoS after PoS? no trust for ya!
        // (no need to explicitly disallow consecutive PoS
        // blocks now as they won't get any trust anyway)
        if (IsProofOfStake() && pprev->IsProofOfStake())
            return CBigNum(0);

        // PoS after PoW? trust = prev_trust + 1!
        if (IsProofOfStake() && pprev->IsProofOfWork())
            return pprev->GetBlockTrust() + 1;  //<<<<<<<<<<<<< does this mean this is recursive??????
                                                // sure looks thatway!  Is this the intent?
        // PoW trust calculation
        if (IsProofOfWork()) 
        {
            // set trust to the amount of work done in this block
            CBigNum bnTrust = bnProofOfWorkLimit / bnTarget;

            // double the trust if previous block was PoS
            // (to prevent orphaning of PoS)
            if (pprev->IsProofOfStake())
                bnTrust *= 2;

            return bnTrust;
        }
        // what the hell?!
        return CBigNum(0);
    }
    return (IsProofOfStake()? (CBigNum(1)<<256) / (bnTarget+1) : CBigNum(1));
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
        return error("ProcessBlock () : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().substr(0,20).c_str());
    if (mapOrphanBlocks.count(hash))
        return error("ProcessBlock () : already have block (orphan) %s", hash.ToString().substr(0,20).c_str());

    // ppcoin: check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (
        pblock->IsProofOfStake() && 
        setStakeSeen.count(pblock->GetProofOfStake()) && 
        !mapOrphanBlocksByPrev.count(hash) && 
        !Checkpoints::WantedByPendingSyncCheckpoint(hash)
       )
        return error("ProcessBlock () : duplicate proof-of-stake (%s, %d) for block %s", 
                     pblock->GetProofOfStake().first.ToString().c_str(), 
                     pblock->GetProofOfStake().second, 
                     hash.ToString().c_str()
                    );

    // Preliminary checks
    if (
        !pblock->CheckBlock(
                            true, 
                            true, 
                            (pblock->nTime > Checkpoints::GetLastCheckpointTime())
                           )
       )
        return error("ProcessBlock () : CheckBlock FAILED");

    // ppcoin: verify hash target and signature of coinstake tx
    if (pblock->IsProofOfStake())
    {
        uint256 hashProofOfStake = 0, targetProofOfStake = 0;
        if (!CheckProofOfStake(pblock->vtx[1], pblock->nBits, hashProofOfStake, targetProofOfStake))
        {
            printf("WARNING: ProcessBlock (): "
                   "check proof-of-stake failed for block %s (%s)\n", 
                    hash.ToString().c_str()
                    , DateTimeStrFormat( " %Y-%m-%d %H:%M:%S",
                                        pblock->nTime
                                       ).c_str()
                  );
            return false; // do not error here as we expect this during initial block download
        }
        if (!mapProofOfStake.count(hash)) // add to mapProofOfStake
            mapProofOfStake.insert(make_pair(hash, hashProofOfStake));
    }

    CBlockIndex
        * pcheckpoint = Checkpoints::GetLastSyncCheckpoint();

    if (
        pcheckpoint && 
        pblock->hashPrevBlock != hashBestChain && 
        !Checkpoints::WantedByPendingSyncCheckpoint(hash)
       )
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        ::int64_t 
            deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;

        CBigNum 
            bnNewBlock;

        bnNewBlock.SetCompact(pblock->nBits);

        CBigNum 
            bnRequired;

        if(
           fUseOld044Rules
           //(pblock->nTime < YACOIN_NEW_LOGIC_SWITCH_TIME) 
           //&& !fTestNet // new rules on Testnet
           //|| fTestNet  // old rules on TestNet
          )
        {
            bnRequired.SetCompact(
                                  ComputeMinWork(GetLastBlockIndex(pcheckpoint, false)->nBits, 
                                                 deltaTime
                                                )
                                 );
        }
        else
        {
            if (pblock->IsProofOfStake()) // <<<<<<<<<<<<<<<<<<<<<<<< this part is different
                bnRequired.SetCompact(
                                      ComputeMinStake(
                                                      GetLastBlockIndex(pcheckpoint, true)->nBits, 
                                                      deltaTime, 
                                                      pblock->nTime                                                 
                                                     )
                                     );
            else
                bnRequired.SetCompact(
                                      ComputeMinWork(GetLastBlockIndex(pcheckpoint, false)->nBits, 
                                                     deltaTime
                                                    )
                                     );
        }
        if (bnNewBlock > bnRequired)
        {
            if (pfrom)
                (void)pfrom->Misbehaving(100);
            return error("ProcessBlock () : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    // ppcoin: ask for pending sync-checkpoint if any
    if (!IsInitialBlockDownload())
        Checkpoints::AskForPendingSyncCheckpoint(pfrom);

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,20).c_str());
        CBlock* pblock2 = new CBlock(*pblock);
        // ppcoin: check proof-of-stake
        if (pblock2->IsProofOfStake())
        {
            // Limited duplicity on stake: prevents block flood attack
            // Duplicate stake allowed only when there is orphan child block
            if (setStakeSeenOrphan.count(pblock2->GetProofOfStake()) && 
                !mapOrphanBlocksByPrev.count(hash) && 
                !Checkpoints::WantedByPendingSyncCheckpoint(hash)
               )
                return error("ProcessBlock () : duplicate proof-of-stake (%s, %d) for orphan block %s", pblock2->GetProofOfStake().first.ToString().c_str(), pblock2->GetProofOfStake().second, hash.ToString().c_str());
            else
                setStakeSeenOrphan.insert(pblock2->GetProofOfStake());
        }
        mapOrphanBlocks.insert(make_pair(hash, pblock2));
        mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            if (!IsInitialBlockDownload())
                pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));
        }
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock())
        return error("ProcessBlock () : AcceptBlock FAILED");

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> 
        vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); ++i)
    {
        uint256 
            hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock
                * pblockOrphan = (*mi).second;
            Sleep( nOneMillisecond );  // let's try this arbitrary value? 
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("ProcessBlock: ACCEPTED %s BLOCK\n", pblock->IsProofOfStake()?"POS":"POW");

    // ppcoin: if responsible for sync-checkpoint send it
    if (pfrom && !CSyncCheckpoint::strMasterPrivKey.empty())
        Checkpoints::SendSyncCheckpoint(Checkpoints::AutoSelectSyncCheckpoint());
#ifdef QT_GUI
    //uiInterface.NotifyBlocksChanged();
#endif

    return true;
}

//_____________________________________________________________________________
// ppcoin: sign block
bool CBlock::SignBlock044(const CKeyStore& keystore)
//bool SignBlock044(const CKeyStore& keystore)
{
    vector<valtype> vSolutions;
    txnouttype whichType;

    if(!IsProofOfStake())
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                continue;

            if (whichType == TX_PUBKEY)
            {
                // Sign
                valtype& vchPubKey = vSolutions[0];
                CKey key;

                if (!keystore.GetKey(Hash160(vchPubKey), key))
                    continue;
                if (key.GetPubKey() != vchPubKey)
                    continue;
                if(
                    !key.Sign(
                                GetYacoinHash(),    //<<<<<<<<<<<<<<< test
                                //GetHash(), 
                                vchBlockSig
                             )
                  )
                    continue;
                return true;
            }
        }
    }
    else
    {
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            // Sign
            valtype& vchPubKey = vSolutions[0];
            CKey key;

            if (!keystore.GetKey(Hash160(vchPubKey), key))
                return false;
            if (key.GetPubKey() != vchPubKey)
                return false;

            return key.Sign(GetHash(), vchBlockSig);
        }
    }

    printf("Sign failed\n");
    return false;
}

//_____________________________________________________________________________
// novacoin: attempt to generate suitable proof-of-stake
bool CBlock::SignBlock(CWallet& wallet)
{
    // if we are doing 0.4.4 blocks, let's check using 0.4.4 code
    if( 
       !IsProofOfStake()    // i.e PoW then immaterial what version!
       ||
       (VERSION_of_block_for_yac_05x_new == nVersion)
       ||
       (VERSION_of_block_for_yac_05x_new == nVersion)
       ||
       (VERSION_of_block_for_yac_044_old == nVersion)
      )
    {
        bool
            fOldVersion = SignBlock044( wallet );
        return fOldVersion;
    }
    // if we are trying to sign
    //    something except proof-of-stake block template
    if (
        !vtx[0].vout[0].IsEmpty()
       )
        return false;

    // if we are trying to sign
    //    a complete proof-of-stake block
    if (IsProofOfStake())   // seems like no signature on a PoS???
        return true;
    // does this mean that here we are PoW?
    static ::uint32_t nLastCoinStakeSearchTime = GetAdjustedTime(); // startup timestamp

    CKey key;
    CTransaction txCoinStake;
    ::uint32_t nSearchTime = txCoinStake.nTime; // search to current time

    if (nSearchTime > nLastCoinStakeSearchTime)
    {
        if (
            wallet.CreateCoinStake(
                                   wallet, 
                                   nBits, 
                                   nSearchTime - nLastCoinStakeSearchTime, 
                                   txCoinStake, 
                                   key
                                  )
           )
        {
            if (
                txCoinStake.nTime >= max(
                                         pindexBest->GetMedianTimePast() + 1, 
                                         PastDrift( pindexBest->GetBlockTime() )
                                        )
               )
            {
                // make sure coinstake would meet timestamp protocol
                //    as it would be the same as the block timestamp
                vtx[0].nTime = nTime = txCoinStake.nTime;
                nTime = max(pindexBest->GetMedianTimePast()+1, GetMaxTransactionTime());
                nTime = max(GetBlockTime(), PastDrift(pindexBest->GetBlockTime()));

                // we have to make sure that we have no future timestamps in
                //    our transactions set
                for (
                     vector<CTransaction>::iterator it = vtx.begin(); 
                     it != vtx.end();
                    )
                {
                    if (it->nTime > nTime) 
                    { 
                        it = vtx.erase(it); 
                    } 
                    else 
                    { 
                        ++it; 
                    }
                }
                vtx.insert(vtx.begin() + 1, txCoinStake);
                hashMerkleRoot = BuildMerkleTree();

                // append a signature to our block
                return key.Sign(GetHash(), vchBlockSig);
            }
        }
        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
        nLastCoinStakeSearchTime = nSearchTime;
    }

    return false;
}

// ppcoin: check block signature
bool CBlock::CheckBlockSignature() const
{
    if (GetHash() == hashGenesisBlock)  // from 0.4.4 code
        return vchBlockSig.empty();

    vector<valtype> 
        vSolutions;

    txnouttype 
        whichType;

    if (IsProofOfWork())
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                return false;

            if (whichType == TX_PUBKEY)
            {
                // Verify
                valtype& vchPubKey = vSolutions[0];
                CKey key;
                if (!key.SetPubKey(vchPubKey))
                    continue;
                if (vchBlockSig.empty())
                    continue;
                if(!key.Verify(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    else  // is PoS
    {
        // so we are only concerned with PoS blocks!
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            valtype
                & vchPubKey = vSolutions[0];

            CKey 
                key;

            if (!key.SetPubKey(vchPubKey))
                return false;
            if (vchBlockSig.empty())
                return false;

            bool
                fVerifyOK = key.Verify(GetHash(), vchBlockSig);

            if( false == fVerifyOK )
                return false;       // so I can trap it
            else
            {   // just to see if it ever is true? It is!!!
                return true;
            }
        }
    }
    return false;
}

bool CheckDiskSpace(::uint64_t nAdditionalBytes)
{
    ::uint64_t nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low!");
        strMiscWarning = strMessage;
        printf("*** %s\n", strMessage.c_str());
        uiInterface.ThreadSafeMessageBox(strMessage, "Yacoin", CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        StartShutdown();
        return false;
    }
    return true;
}

static filesystem::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);
    return GetDataDir() / strBlockFn;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1) || (nFile == (unsigned int) -1))
        return NULL;
    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    while (true)
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

void UnloadBlockIndex()
{
    mapBlockIndex.clear();
    setStakeSeen.clear();
    pindexGenesisBlock = NULL;
    nBestHeight = 0;
    bnBestChainTrust = CBigNum(0);
    bnBestInvalidTrust = CBigNum(0);
    hashBestChain = 0;
    pindexBest = NULL;
}

bool LoadBlockIndex(bool fAllowNew)
{   // by default fUseOld044Rules are false, i.e new rules are true
    if (
        !fTestNet ||    // may use new rules, ATM only in TestNet
        (
         (GetTime() < (::int64_t)YACOIN_NEW_LOGIC_SWITCH_TIME)   // before the new PoW/PoS rules date-time
         &&
         !fTestNetNewLogic      // (0 == nMainnetNewLogicBlockNumber )  // if fTestNetNewLogic is true, we
        )                                                               // will use it in TestNet
       )
        fUseOld044Rules = true;
    // the implied else is that
    // new rules if TestNet AND 


    if (fTestNet)
    {
        pchMessageStart[0] = 0xcd;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0xc0;
        pchMessageStart[3] = 0xef;

        bnProofOfWorkLimit = bnProofOfWorkLimitTestNet; // 16 bits PoW target limit for testnet
        bnInitialHashTarget = bnInitialHashTargetTestNet;
        nStakeMinAge = 2 * nSecondsPerHour;             // 2 hours (to what?)
        nModifierInterval =  10 * nSecondsperMinute;    // 10 minutes, for what?
        nCoinbaseMaturity = 6; // test maturity is 6 blocks + nCoinbaseMaturity(20) = 26
        nStakeTargetSpacing = 1 * nSecondsperMinute;    // 1 minute average block period target
        nConsecutiveStakeSwitchHeight = 4200;           // 4200 blocks until what?
    }

    //
    // Load block index
    //
    CTxDB txdb("cr+");
    if (!txdb.LoadBlockIndex()) // true is no error,whether it does anything or not!
        return false;           // this is then the error return

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())  // there is no mapBlockIndex, so (re)create genesis block
    {
        if (!fAllowNew)
            return false;

        // Genesis block

        // MainNet:

        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, 
        //        nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), 
        //          coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e
        
        //TODO
        
        // TestNet:

        //CBlock(hash=0000c763e402f2436da9ed36c7286f62c3f6e5dbafce9ff289bd43d7459327eb, 
        //       ver=1, 
        //       hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, 
        //       hashMerkleRoot=4cb33b3b6a861dcbc685d3e614a9cafb945738d6833f182855679f2fad02057b, 
        //       nTime=1360105017, nBits=1f00ffff, nNonce=46534, vtx=1, vchBlockSig=)
        //  Coinbase(
        //       hash=4cb33b3b6a, nTime=1360105017, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //    CTxIn(COutPoint(0000000000, 4294967295), 
        //          coinbase 04ffff001d020f274468747470733a2f2f626974636f696e74616c6b2e6f72672f696e6465782e7068703f746f7069633d3133343137392e6d736731353032313936236d736731353032313936)
        //    CTxOut(empty)
        //  vMerkleTree: 4cb33b3b6a

        const char* 
            pszTimestamp = "https://bitcointalk.org/index.php?topic=196196";
        CTransaction 
            txNew;

        txNew.nTime = (::uint32_t)( fTestNet? nChainStartTimeTestNet: nChainStartTime );
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = 
            CScript()           // what is being constructed here?????
            << (!fTestNet?  486604799:      // is this a time? 1985?
                            1464032600)  // how about a more current time????  If it is a time???????
            << CScriptNum(9999)    // what is this??
            << vector<unsigned char>((const unsigned char*)pszTimestamp, 
                                     (const unsigned char*)pszTimestamp + strlen(pszTimestamp)
                                    );
      //txNew.vout[0].scriptPubKey = CScript() << ParseHex("04a5814813115273a109cff99907ba4a05d951873dae7acb6c973d0c9e7c88911a3dbc9aa600deac241b91707e7b4ffb30ad91c8e56e695a1ddf318592988afe0a") << OP_CHECKSIG;
        txNew.vout[0].SetEmpty();

        //Yassert( NULL != pwalletMain );
        //CReserveKey 
        //    reservekey(pwalletMain);

        //txNew.vout[0].nValue = nSimulatedMOneySupplyAtFork; //estimate 1/25/2019 7:00PM EST
        //txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

#ifdef Yac1dot0
        txNew.print();
#endif
        CBlock 
            block;

        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;  // was 1; which is strange?
        block.nTime    = (::uint32_t)( fTestNet?
                                       nChainStartTimeTestNet + 20: 
                                       nChainStartTime + 20 
                                      );   // why + 20??
        block.nBits    = bnProofOfWorkLimit.GetCompact();
        block.nNonce   = !fTestNet ? 
                            127357 :        // main net genesis block nonce
							nTestNetGenesisNonce;
                                            //0x1F653; //for 0.5.0.04 TestNet
                                            //0x1F652; //for 0.5.0.03 TestNet
                                            //0x1f650;  13D93;    //67103;

        CBigNum 
            bnTarget;

        bnTarget.SetCompact( block.nBits );

        uint256
            the_target = bnTarget.getuint256();
    
        uint256
            the_hash = block.GetHash();
////////////////////////////////////
// This little section of code allows any node to create a genesis block
// Is this too much?  Will this causes forks from block 0?
// Or should only one node create a single block 0, and all others must 
// use that one block 0?
// if all block 0s created from this code are identical, then there should 
// be no problem!
        ::uint32_t
            nCount = 0;
		while( the_hash > the_target )
		{
			++(block.nNonce);
            ++nCount;
            the_hash = block.GetHash();
            printf(
                    "block.nNonce == %08X"
                    "\r", 
                    block.nNonce
                  );		
		}
        printf(
                "\n" 
                "block.nNonce == %08X (%u dec) after %u tries"
                "\n", 
                block.nNonce,
                block.nNonce,
                nCount
              );		
////////////////////////////////////

        // debug print
        printf("block.GetHash() ==\n%s\n", the_hash.ToString().c_str());
        printf("block.nBits ==\n%s\n", the_target.ToString().c_str());
        printf("block.hashMerkleRoot ==\n%s\n", block.hashMerkleRoot.ToString().c_str());

        Yassert(block.hashMerkleRoot == uint256(
                            fTestNet?
                            hashGenesisMerkleRootTestNet:
                            hashGenesisMerkleRootMainNet
                                               )
              );
        block.SignBlock(*pwalletMain);
        block.print();
        Yassert(block.GetHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet));
        Yassert(block.CheckBlock());
        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        if (!block.AddToBlockIndex(nFile, nBlockPos))
            return error("LoadBlockIndex() : genesis block not accepted");

        // initialize synchronized checkpoint
        if (!Checkpoints::WriteSyncCheckpoint((!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)))
            return error("LoadBlockIndex() : failed to init sync checkpoint");

        // upgrade time set to zero if txdb initialized
        {
            if (!txdb.WriteModifierUpgradeTime(0))
                return error("LoadBlockIndex() : failed to init upgrade info");
            printf(" Upgrade Info: ModifierUpgradeTime txdb initialization\n");
        }
    }

    {
        CTxDB txdb("r+");
        string strPubKey = "";
        if (!txdb.ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::strMasterPubKey)
        {
            // write checkpoint master key to db
            txdb.TxnBegin();
            if (!txdb.WriteCheckpointPubKey(CSyncCheckpoint::strMasterPubKey))
                return error("LoadBlockIndex() : failed to write new checkpoint master key to db");
            if (!txdb.TxnCommit())
                return error("LoadBlockIndex() : failed to commit new checkpoint master key to db");
            if ((!fTestNet) && !Checkpoints::ResetSyncCheckpoint())
                return error("LoadBlockIndex() : failed to reset sync-checkpoint");
        }

        // upgrade time set to zero if blocktreedb initialized
        if (txdb.ReadModifierUpgradeTime(nModifierUpgradeTime))
        {
            if (nModifierUpgradeTime)
                printf(" Upgrade Info: blocktreedb upgrade detected at timestamp %d\n", nModifierUpgradeTime);
            else
                printf(" Upgrade Info: no blocktreedb upgrade detected.\n");
        }
        else
        {
            nModifierUpgradeTime = GetTime();
            printf(" Upgrade Info: upgrading blocktreedb at timestamp %u\n", nModifierUpgradeTime);
            if (!txdb.WriteModifierUpgradeTime(nModifierUpgradeTime))
                return error("LoadBlockIndex() : failed to write upgrade info");
        }

#ifndef USE_LEVELDB
        txdb.Close();
#endif
    }

    return true;
}



void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %" PRIszu "",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().c_str(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            FormatMoney(pindex->nMint).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn)
{
    ::int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(cs_main);
        try 
        {
            CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);
            unsigned int nPos = 0;
            while (
                  //(nPos != (unsigned int)-1) && 
                    (nPos != UINT_MAX) && 
                    blkdat.good() && 
                    !fRequestShutdown
                  )
            {
              //unsigned char pchData[65536];   // is there anything special about this #??
                unsigned char pchData[ (int)1 << 16 ];   
                do 
                {
                    (void)fseek(blkdat, nPos, SEEK_SET);    // who cares if it fails!  What silly code!!
                    int 
                        nRead = fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8)
                    {
                        nPos = UINT_MAX;
                        break;
                    }
                    void
                        * nFind = memchr(
                                         pchData, 
                                         pchMessageStart[ 0 ], 
                                         nRead + 1 - sizeof( pchMessageStart )
                                        );
                    if (nFind)
                    {
                        if (memcmp(nFind, pchMessageStart, sizeof(pchMessageStart))==0)
                        {
                            nPos += ((unsigned char*)nFind - pchData) + sizeof(pchMessageStart);
                            break;
                        }
                        nPos += ((unsigned char*)nFind - pchData) + 1;
                    }
                    else
                        nPos += sizeof(pchData) - sizeof(pchMessageStart) + 1;
                } 
                while(!fRequestShutdown);
                if (nPos == UINT_MAX)
                    break;
                (void)fseek(blkdat, nPos, SEEK_SET);  // again, what seek error!
                unsigned int nSize;
                blkdat >> nSize;
                if (
                    (nSize > 0) && (nSize <= GetMaxSize(MAX_BLOCK_SIZE))
                   )
                {
                    CBlock block;
                    blkdat >> block;
                    if (ProcessBlock(NULL,&block))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (std::exception &e) 
        {
            printf("%s() : Deserialize or I/O error caught during load\n",
                   BOOST_CURRENT_FUNCTION);
        }
    }
    printf("Loaded %i blocks from external file in %" PRId64 "ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // if detected unmet upgrade requirement enter safe mode
    // Note: Modifier upgrade requires blockchain redownload if past protocol switch
    if (IsFixedModifierInterval(nModifierUpgradeTime + 60*60*24)) // 1 day margin
    {
        nPriority = 5000;
        strStatusBar = strRPC = "WARNING: Blockchain redownload required approaching or past v.0.4.5 upgrade deadline.";
    }

    // if detected invalid checkpoint enter safe mode
    if (Checkpoints::hashInvalidCheckpoint != 0)
    {
        nPriority = 3000;
        strStatusBar = strRPC = _("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000)
                    strRPC = strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    Yassert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(CTxDB& txdb, const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
        bool txInMap = false;
            {
            LOCK(mempool.cs);
            txInMap = (mempool.exists(inv.hash));
            }
        return txInMap ||
               mapOrphanTransactions.count(inv.hash) ||
               txdb.ContainsTx(inv.hash);
        }

    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
               mapOrphanBlocks.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xd9, 0xe6, 0xe7, 0xe5 };

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    RandAddSeedPerfmon();
    if (fDebug)
        printf("received: %s (%" PRIszu " bytes)\n", strCommand.c_str(), vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

/******************
    if (strCommand == "version")
    else if (strCommand == "verack")
    else if (strCommand == "addr")
    else if (strCommand == "inv")
    else if (strCommand == "getdata")
    else if (strCommand == "getblocks")
    else if (strCommand == "checkpoint")
    else if (strCommand == "getheaders")
    else if (strCommand == "tx")
    else if (strCommand == "block")
    else if (strCommand == "getaddr")
    else if (strCommand == "mempool")
    else if (strCommand == "checkorder")
    else if (strCommand == "reply")
    else if (strCommand == "ping")
    else if (strCommand == "alert")
    else
    {
        // Ignore unknown commands for extensibility
    }
******************/ 
    string arrayOfAllowedMessages[] = {
                                        "addr"
                                      , "alert"
                                      , "block"
                                      , "checkorder"
                                      , "checkpoint"
                                      , "verack"
                                      , "getaddr"
                                      , "getblocks"
                                      , "getdata"
                                      , "getheaders"
                                      , "inv"
                                      , "mempool"
                                      , "ping"
                                      , "reply"
                                      , "tx"
                                      };
    // int nSize = sizeof( arrayOfAllowedMessages ) / sizeof( arrayOfAllowedMessages[ 0 ]);
    // for( int index = 0; index < nSize; ++index )
    // {
    //      if( "addr" == arrayOfAllowedMessages[ index ] )
    //      {
    //          
    //      }
    // }

    // rx'ed a version response
    if (strCommand == "version")
    {
        // a general form might be
        // bool fReturnFromProcessMessage( string strCommand, bool & return_value )
        // if( fReturnFromProcessMessage( string strCommand, bool & return_value ) )
        //      return return value;
        // a particular form might be
        // if( fReturnFrom_version_Message( bool & return_value ) )
        //      return return value;

        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            (void)pfrom->Misbehaving(1);
            return false;
        }

        ::int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        ::uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PROTO_VERSION)
        {
            // Since February 20, 2012, the protocol is initiated at version 209,
            // and earlier versions are no longer supported
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty())
            vRecv >> pfrom->strSubVer;
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        if (pfrom->nVersion < MIN_PEER_BUGGY_VERSION)   // i.e. 60005 and lower disconnected.
        {
            printf("partner %s using a buggy client %d, disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return true;
        }
        // else this node is version 60006 or higher

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable())
            addrSeenByPeer = addrMe;

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || 
                pfrom->nVersion >= CADDR_TIME_VERSION || 
                addrman.size() < 1000
               )
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } 
        else 
        {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Ask the first connected node for block updates
        static int 
            nAskedForBlocks = 0;

        if (
            !pfrom->fClient && 
            !pfrom->fOneShot &&
          //(pfrom->nStartingHeight > (nBestHeight - 144)) &&   // this is probably Bitcoin???, so
            (pfrom->nStartingHeight > (nBestHeight - (int)nOnedayOfAverageBlocks)) 
            // this is unneccessary since nodeis known to be >= 60006, see l. 3605
            //&&
            //(
            // (pnode->nVersion < NOBLKS_VERSION_START) || // why <60002 || >= 60005
            // (pnode->nVersion >= NOBLKS_VERSION_END)    // why are 60002, 3, 4 taboo?
            //) 
            &&
            (
             (nAskedForBlocks < 1) || (vNodes.size() <= 1)
            )
           )
        {
            ++nAskedForBlocks;
            pfrom->PushGetBlocks(pindexBest, uint256(0));   // why the 0 hash, I wonder?
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        // Relay sync-checkpoint
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (!Checkpoints::checkpointMessage.IsNull())
                Checkpoints::checkpointMessage.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", 
                pfrom->nVersion, 
                pfrom->nStartingHeight, 
                addrMe.ToString().c_str(), 
                addrFrom.ToString().c_str(), 
                pfrom->addr.ToString().c_str()
              );

        cPeerBlockCounts.input(pfrom->nStartingHeight);

        // ppcoin: ask for pending sync-checkpoint if any
        if (!IsInitialBlockDownload())
            Checkpoints::AskForPendingSyncCheckpoint(pfrom);
    }

    // rx'ed something from pfrom other than version

    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        printf("Misbehaving received version = 0\n");
        (void)pfrom->Misbehaving(1);      // tell me what the 1 means? Or intends?? If anything???
        return false;
    }

    //_________________________________________________________________________
    // rx'ed a ver(sion)ack

    else if (strCommand == "verack")
    {
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }


    //_________________________________________________________________________
    // rx'ed a node addr(esses) response

    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (
            (pfrom->nVersion < CADDR_TIME_VERSION) && 
            (addrman.size() > 1000)
           )
            return true;    // meaning what?
        if (vAddr.size() > 1000)
        {
            (void)pfrom->Misbehaving(20);
            return error("message addr size() = %" PRIszu " too big!?", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> 
            vAddrOk;

        ::int64_t 
            nNow = GetAdjustedTime();
        ::int64_t 
            nSince = nNow - 10 * 60;

        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            if (fShutdown)
                return true;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);

            bool 
                fReachable = IsReachable(addr);

            if (
                (addr.nTime > nSince) && 
                !pfrom->fGetAddr && 
                (vAddr.size() <= 10) && 
                addr.IsRoutable()
               )
            {
                // Relay to a limited number of other nodes
                {{
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 
                        hashSalt;

                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    
                    ::uint64_t 
                        hashAddr = addr.GetHash();

                    uint256 
                        hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));

                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    
                    multimap<uint256, CNode*> 
                        mapMix;

                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;

                        unsigned int 
                            nPointer;

                        memcpy(&nPointer, &pnode, sizeof(nPointer));

                        uint256 
                            hashKey = hashRand ^ nPointer;

                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int 
                        nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)

                    for (
                        multimap<uint256, CNode*>::iterator mi = mapMix.begin(); 
                        (mi != mapMix.end()) && (nRelayNodes-- > 0); 
                        ++mi
                        )
                    {
                        ((*mi).second)->PushAddress(addr);
                    }
                }}
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60); // what is the intent here?
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)                // what is the logic here?
            pfrom->fDisconnect = true;
    }
    //_________________________________________________________________________


    // rx'ed an inv(entory) of Tx's or Blocks

    else if (strCommand == "inv")
    {
        vector<CInv> 
            vInv;

        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            (void)pfrom->Misbehaving(20);
            return error("message inv size() = %" PRIszu " too big!", vInv.size());
        }

        // find last block in inv vector
        unsigned int 
            nLastBlock = (unsigned int)(-1);
        for (unsigned int nInv = 0; nInv < vInv.size(); ++nInv) 
        {
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK) 
            {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }
        CTxDB 
            txdb("r");

        for (unsigned int nInv = 0; nInv < vInv.size(); ++nInv)
        {
            const CInv 
                &inv = vInv[nInv];

            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool 
                fAlreadyHave = AlreadyHave(txdb, inv);

            if (fDebug)
                printf(
                        "  got inventory: %s  %s\n", 
                        inv.ToString().c_str(), 
                        fAlreadyHave ? "have" : "new"
                      );

            if (!fAlreadyHave)      // that is, it's new to us
                pfrom->AskFor(inv);
            else    // we already have these Txs or blocks in our inventory
            {
                if (                                    // what is this test in aid of, I wonder?
                    (inv.type == MSG_BLOCK) &&          // it's a block we have
                    mapOrphanBlocks.count(inv.hash)     // & it's an orphan
                   ) 
                {                                       // and what does this intend?
                    pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
                } 
                else        // it's a Tx or it's not an orphan block
                {
                    if (nInv == nLastBlock) 
                    {
                        // In case we are on a very long side-chain, it is possible that we already have
                        // the last block in an inv bundle sent in response to getblocks. Try to detect
                        // this situation and push another getblocks to continue.
                        pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
                        if (fDebug)
                            printf("force request: %s\n", inv.ToString().c_str());
                    }
                }
            }
            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }

    //_________________________________________________________________________
    // rx'ed a getdata request 

    else if (strCommand == "getdata")
    {
        vector<CInv> 
            vInv;
        vRecv >> vInv;      // how does this allocate into a vector?
        if (vInv.size() > MAX_INV_SZ)
        {
            (void)pfrom->Misbehaving(20);     // OK, what's the magic 20 about? units? intent??
            return error("message getdata size() = %" PRIszu " too big!", vInv.size());
        }

        if (fDebugNet || (vInv.size() != 1))    // what if it is 1?
            printf("rx'd a getdata request (%" PRIszu " invsz) from %s\n", 
                    vInv.size()
                    , pfrom->addr.ToString().c_str()
                  );

        BOOST_FOREACH(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            if (fDebugNet || (vInv.size() == 1))
                printf("rx'd a getdata request for: %s from %s\n", 
                        inv.ToString().c_str()
                        , pfrom->addr.ToString().c_str()
                      );
            // there are only 2 types" a block or a transaction being requested as inventory
            if (inv.type == MSG_BLOCK)      // I persume this means the node requested a block
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator 
                    mi = mapBlockIndex.find(inv.hash);

                if (mi != mapBlockIndex.end())  // means we found it
                {
                    CBlock 
                        block;

                    block.ReadFromDisk((*mi).second);
                    pfrom->PushMessage("block", block);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    // what does that mean, exactly?
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // ppcoin: send latest proof-of-work block to allow the
                        // download node to accept as orphan (proof-of-stake 
                        // block might be rejected by stake connection check)
                        vector<CInv> 
                            vInv;

                        vInv.push_back(CInv(MSG_BLOCK, 
                                            GetLastBlockIndex(pindexBest, false)->GetBlockHash()
                                           )
                                      );
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
                Sleep( nOneMillisecond );   // just to test if RPC can run?
            }
            else if (inv.IsKnownType()) // it must be a transaction
            {
                // Send stream from relay memory
                bool 
                    pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator 
                        mi = mapRelay.find(inv);

                    if (mi != mapRelay.end())   // we found it
                    {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (
                    !pushed &&                  // not from relay memory
                    (inv.type == MSG_TX)        // by analogy, I presume a Tx is requested?
                   ) // inventory is not here
                {
                    LOCK(mempool.cs);
                    if (mempool.exists(inv.hash)) 
                    {
                        CTransaction 
                            tx = mempool.lookup(inv.hash);

                        CDataStream 
                            ss(SER_NETWORK, PROTOCOL_VERSION);

                        ss.reserve(1000);           // is this related to anything else?
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                    }
                }
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }

    //_________________________________________________________________________
    // rx'ed a getblocks request for blocks

    else if (strCommand == "getblocks")
    {
        CBlockLocator 
            locator;
        uint256 
            hashStop;

        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex
            * pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;  // how does this do "the rest"?

        int 
            nLimit = 500;

        printf("getblocks request for %d to %s limit %d from %s\n", 
               (pindex ? pindex->nHeight : -1), 
               hashStop.ToString().substr(0,20).c_str(), 
               nLimit
               , pfrom->addr.ToString().c_str()
              );
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks request stopping at %d %s\n", 
                       pindex->nHeight, 
                       pindex->GetBlockHash().ToString().substr(0,20).c_str()
                      );
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if (
                    (hashStop != hashBestChain) && 
                    ((pindex->GetBlockTime() + nStakeMinAge) > pindexBest->GetBlockTime())
                   )
                    pfrom->PushInventory(CInv(MSG_BLOCK, hashBestChain));
                break;
            }
            pfrom->PushInventory(
                                CInv(
                                    MSG_BLOCK, 
                                    pindex->GetBlockHash()
                                    )
                                );
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s\n", 
                        pindex->nHeight, 
                        pindex->GetBlockHash().ToString().substr(0,20).c_str()
                      );
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }

    //_________________________________________________________________________
    // rx'ed a checkpoint relay request?

    else if (strCommand == "checkpoint")
    {
        CSyncCheckpoint checkpoint;
        vRecv >> checkpoint;

        if (checkpoint.ProcessSyncCheckpoint(pfrom))
        {
            // Relay
            pfrom->hashCheckpointKnown = checkpoint.hashCheckpoint;
            {{
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                    checkpoint.RelayTo(pnode);
            }}
        }
    }

    //_________________________________________________________________________
    // rx'ed a getheaders request

    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000;
        printf("getheaders request %d to %s from %s\n", 
                (pindex ? pindex->nHeight : -1), 
                hashStop.ToString().substr(0,20).c_str()
                , pfrom->addr.ToString().c_str()
              );
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }

    //_________________________________________________________________________
    // rx'ed a Tx

    else if (strCommand == "tx")
    {
        vector<uint256> 
            vWorkQueue;

        vector<uint256> 
            vEraseQueue;

        CDataStream vMsg(vRecv);
        CTxDB txdb("r");
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool 
            fMissingInputs = false;
        if (tx.AcceptToMemoryPool(txdb, true, &fMissingInputs))
        {
            SyncWithWallets(tx, NULL, true);
            RelayTransaction(tx, inv.hash);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); ++i)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {   //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< this part is different???????????????????
                    const uint256
                        & orphanTxHash = *mi;

                    CTransaction
                        & orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool 
                        fMissingInputs2 = false;

                    if (orphanTx.AcceptToMemoryPool(txdb, true, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                        SyncWithWallets(tx, NULL, true);
                        RelayTransaction(orphanTx, orphanTxHash);
                        mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanTxHash));
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid orphan
                        vEraseQueue.push_back(orphanTxHash);
                        printf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        if (tx.nDoS) 
            (void)pfrom->Misbehaving(tx.nDoS);
    }

    //_________________________________________________________________________
    // rx'ed a block

    else if (strCommand == "block")
    {
        CBlock 
            block;

        vRecv >> block;
        uint256 hashBlock = block.GetHash();

        printf(
            "received block %s (%s) from %s\n", 
              //hashBlock.ToString().substr(0,20).c_str()
                hashBlock.ToString().substr(0,16).c_str()
                , DateTimeStrFormat( "%Y-%m-%d %H:%M:%S", block.GetBlockTime() ).c_str()
                , pfrom->addr.ToString().c_str()
              );
        // block.print();
        CInv 
            inv(MSG_BLOCK, hashBlock);

        pfrom->AddInventoryKnown(inv);

        Sleep( nOneMillisecond );  // let's try this arbitrary value? 
        if (ProcessBlock(pfrom, &block))
        {
            mapAlreadyAskedFor.erase(inv);
        }
        //if( !IsInitialBlockDownload() )        {}
        if (block.nDoS) 
        {
            (void)pfrom->Misbehaving(block.nDoS);
        }
    }

    //_________________________________________________________________________
    // rx'ed a getaddr(esses) request

    else if (strCommand == "getaddr")
    {   //<<<<<<<<<<<<<<<<<<<<<<<<<< this is different
        // Don't return addresses older than nCutOff timestamp
        ::int64_t 
            nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);

        pfrom->vAddrToSend.clear();
        
        vector<CAddress> 
            vAddr = addrman.GetAddr();

        BOOST_FOREACH(const CAddress &addr, vAddr)
            if(addr.nTime > nCutOff)
                pfrom->PushAddress(addr);
    }

    //_________________________________________________________________________
    // rx'ed a mempool request UTXO

    else if (strCommand == "mempool")
    {
        std::vector<uint256> 
            vtxid;

        mempool.queryHashes(vtxid);
        
        vector<CInv> 
            vInv;

        for (unsigned int i = 0; i < vtxid.size(); ++i) 
        {
            CInv 
                inv(MSG_TX, vtxid[i]);

            vInv.push_back(inv);
            if (i == (MAX_INV_SZ - 1))
                    break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }

    //_________________________________________________________________________
    // rx'ed a checkorder?

    else if (strCommand == "checkorder")
    {
        static map<CService, CPubKey> 
            mapReuseKey;

        uint256 hashReply;
        vRecv >> hashReply;

        if (!GetBoolArg("-allowreceivebyip"))
        {
            pfrom->PushMessage("reply", hashReply, (int)2, string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr))
            pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }

    //_________________________________________________________________________
    // rx'ed a reply?

    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        {
            LOCK(pfrom->cs_mapRequests);
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }

    //_________________________________________________________________________
    // rx'ed a ping request

    else if (strCommand == "ping")
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            ::uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }

    //_________________________________________________________________________
    // rx'ed an alert

    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {{
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }}
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                (void)pfrom->Misbehaving(10);
            }
        }
    }

    // rx'ed all other unknown commands

    //_________________________________________________________________________
    else
    {
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (
            strCommand == "version" || 
            strCommand == "addr" || 
            strCommand == "inv" || 
                //    strCommand == "block" ||    //TEST<<<<<<<<<<<<<<
            strCommand == "getdata" || 
            strCommand == "ping"
           )                                    // why these only?
            AddressCurrentlyConnected(pfrom->addr); // what does this accomplish?

    return true;
}

void ProcessMessages(CNode* pfrom)
{
    CDataStream& 
        vRecv = pfrom->vRecv;

    if (vRecv.empty())
        return;
    //if (fDebug)
    //    printf("ProcessMessages(%u bytes)\n", vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //

    while (true)
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->vSend.size() >= SendBufferSize())
            break;

        // Scan for message start
        CDataStream::iterator 
            pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));

        int 
            nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());

        if (vRecv.end() - pstart < nHeaderSize)
        {
            if ((int)vRecv.size() > nHeaderSize)
            {
                printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if (pstart - vRecv.begin() > 0)
            printf("\n\nPROCESSMESSAGE SKIPPED %" PRIpdd " BYTES\n\n", pstart - vRecv.begin());
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        vector<char> 
            vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);

        CMessageHeader 
            hdr;

        vRecv >> hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int 
            nMessageSize = hdr.nMessageSize;

        if (nMessageSize > MAX_SIZE)
        {
            printf("ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE\n", 
                    strCommand.c_str(), 
                    nMessageSize
                  );
            continue;
        }
        if (nMessageSize > vRecv.size())
        {
            // Rewind and wait for rest of message
            vRecv.insert(
                        vRecv.begin(), 
                        vHeaderSave.begin(), 
                        vHeaderSave.end()
                        );
            break;
        }

        // Checksum
        uint256 
            hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);

        unsigned int 
            nChecksum = 0;

        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Copy message to its own buffer
        CDataStream 
            vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);

        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try
        {
            {{
                LOCK(cs_main);
                fRet = ProcessMessage(pfrom, strCommand, vMsg);
            }}
            if (fShutdown)
                return;
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                printf(
                        "ProcessMessages(%s, %u bytes) : "
                        "Exception '%s' caught, normally caused by "
                        "a message being shorter than its stated length"
                        "\n", 
                        strCommand.c_str(), 
                        nMessageSize, 
                        e.what()
                      );
            }
            else 
            {
                if (strstr(e.what(), "size too large"))
                {
                    // Allow exceptions from over-long size
                    printf(
                            "ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", 
                            strCommand.c_str(), 
                            nMessageSize, 
                            e.what()
                          );
                }
                else
                {
                    PrintExceptionContinue(&e, "ProcessMessages()");
                }
            }
        }
        catch (std::exception& e) 
        {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } 
        catch (...) 
        {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
    }

    vRecv.Compact();
    return;
}


void SendMessages(CNode* pto, bool fSendTrickle)
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain) 
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return;

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (
            pto->nLastSend && 
            ((GetTime() - pto->nLastSend) > nPingInterval) && 
            pto->vSend.empty()
           ) 
        {
            ::uint64_t 
                nonce = 0;

            if (pto->nVersion > BIP0031_VERSION)
                pto->PushMessage("ping", nonce);
            else
                pto->PushMessage("ping");
        }

/*****************
        // Start block sync
        if (pto->fStartSync) 
        {
            pto->fStartSync = false;
            pto->PushGetBlocks(pindexBest, uint256(0));  // what is the 0 here represent, if anything?
        }
*****************/
        // Resend wallet transactions that haven't gotten in a block yet
        ResendWalletTransactions();

        // Address refresh broadcast
        static ::int64_t 
            nLastRebroadcast;   // remember, statics are initialized to 0
        if (
            !IsInitialBlockDownload() && 
            ((GetTime() - nLastRebroadcast) > nBroadcastInterval)
           )
        {
            {{
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }}
            nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)       // why? What does 1000 mean?
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }


        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 
                        hashSalt;

                    if (hashSalt == 0)
                        hashSalt = GetRandHash();

                    uint256 
                        hashRand = inv.hash ^ hashSalt;

                    hashRand = Hash(BEGIN(hashRand), END(hashRand));

                    bool 
                        fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx 
                            wtx;

                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        //
        // Message: getdata
        //
        vector<CInv> 
            vGetData;

        ::int64_t 
            nNow = GetTime() * 1000000;   //??? time now * 1,000,000 what is this about???

        CTxDB 
            txdb("r");

        while (
                !pto->mapAskFor.empty() && 
                ((*pto->mapAskFor.begin()).first <= nNow)
              )
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(txdb, inv))
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
                mapAlreadyAskedFor[inv] = nNow;
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

    }
    return;
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() 
    {
        if (fDebug)
        {
#ifdef _MSC_VER
            (void)printf( "~CMainCleanup() destructor...\n" );
#endif
        }
#ifdef _MSC_VER
            unsigned int
                nCount = 0,
    #ifdef _DEBUG
                nUpdatePeriod = 100,
    #else
                nUpdatePeriod = 3000, //10000,   // pure guess for a decent update period ~1 second
    #endif
                nEstimate;

            unsigned __int64
                nSize = (unsigned __int64)mapBlockIndex.size();
#endif
            // block headers
            std::map<uint256, CBlockIndex*>::iterator 
                it1 = mapBlockIndex.begin();

            for (; it1 != mapBlockIndex.end(); ++it1)
            {
                delete (*it1).second;
                if (fDebug)
                {
    #ifdef _MSC_VER
                    ++nCount;
                    nEstimate = (unsigned int)( ( 100 * nCount ) / nSize );
                    if( 0 == (nCount % nUpdatePeriod) )
                    {
                        (void)printf( "~CMainCleanup() progess ~%-u%%" 
                                      "\r",
                                      nEstimate
                                    );
                    }
    #endif
                }
            }
            mapBlockIndex.clear();
            if (fDebug)
            {
    #ifdef _MSC_VER
                (void)printf( "~CMainCleanup() progess ~100%%" 
                              "\r"
                            );
    #endif
            }

            // orphan blocks
            std::map<uint256, CBlock*>::iterator 
                it2 = mapOrphanBlocks.begin();

            for (; it2 != mapOrphanBlocks.end(); ++it2)
                delete (*it2).second;
            mapOrphanBlocks.clear();

            // orphan transactions
            mapOrphanTransactions.clear();
        if (fDebug)
        {
#ifdef _MSC_VER
            (void)printf( "\ndone\n" );
#endif
        }
    }
} instance_of_cmaincleanup;
//_____________________________________________________________________________

void releaseModeAssertionfailure( 
                                 const char* pFileName, 
                                 const int nL, 
                                 const std::string strFunctionName,
                                 const char * booleanExpression 
                                )
{   //Assertion failed: (fAssertBoolean), file l:\backups\senadjyac045.2\yacoin\src\init.cpp, line 1368
    (void)printf( 
                 "\n"
                 "Release mode\n"
                 "Assertion failed: (%s), file %s, line %d,\n"
                 "function %s()"
                 "\n"
                 "\n"
                 ""
                 , booleanExpression
                 , pFileName                //__FILE__
                 , nL                       //__LINE__
                 , strFunctionName.c_str()  // __FUNCTION__
                );
    StartShutdown();    // maybe there are other ways??
}
//_____________________________________________________________________________
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
