// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include <boost/assign/list_of.hpp>

#ifndef PPCOIN_KERNEL_H
 #include "kernel.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb.h"
#endif

using std::min;
using std::vector;
using std::pair;
using std::map;
using std::make_pair;
using std::string;

// Note: user must upgrade before the protocol switch deadline, otherwise it's required to
//   re-download the blockchain. The timestamp of upgrade is recorded in the blockchain 
//   database.
unsigned int nModifierUpgradeTime = 0;

typedef std::map<int, unsigned int> MapModifierCheckpoints;

// Hard checkpoints of stake modifiers to ensure they are deterministic
static std::map<int, unsigned int> mapStakeModifierCheckpoints =
    boost::assign::map_list_of
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    ( 0, 0x0e00670bu )    
#else
    ( 0, 0xfd11f4e7  )
#endif
    ( 15000, 0x085e9cafu )
    ( 30000, 0x3f123e2cu )
    ( 45000, 0x3e2ecf4fu )
    ( 60000, 0x1e8458eau )
    ( 75000, 0xd72d1395u )
    ( 90000, 0x7dce92ffu )
    (105000, 0x57cc71e0u )
    (120000, 0x4442fccbu )
    (135000, 0x4cea240fu )
    (150000, 0xd06bea80u )
    (165000, 0x697caae6u )
    (180000, 0x5d6f2627u )
    (195000, 0x054b2756u )
    (214998, 0xcbb62f73u )
    (236895, 0x05ee6bd6u )
    (259405, 0xb31abd61u )
    (281002, 0x95174906u )
    (303953, 0x4ba15dbcu )
    (388314, 0x97f8e820u )
    (420000, 0x9b6c9d80u )
    (465000, 0x1b1a219cu )
    (487658, 0xe7d5a3bcu )
    (550177, 0x8a1e3994u )
    (612177, 0x949c4dc0u )
	(712177, 0xad692cc0u )
    ;

// Hard checkpoints of stake modifiers to ensure they are deterministic (testNet)
static std::map<int, unsigned int> mapStakeModifierCheckpointsTestNet =
    boost::assign::map_list_of
        ( 0, 0x0e00670bu )
    ;

// Whether the given block is subject to new modifier protocol
bool IsFixedModifierInterval(unsigned int nTimeBlock)
{
    return (nTimeBlock >= (fTestNet? nModifierTestSwitchTime : nModifierSwitchTime));
}

// Get time weight
int64_t GetWeight(int64_t nIntervalBeginning, int64_t nIntervalEnd)
{
    // Kernel hash weight starts from 0 at the 30-day min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    //
    // Maximum TimeWeight is 90 days.

    return min(nIntervalEnd - nIntervalBeginning - nStakeMinAge, (int64_t)nStakeMaxAge);
}

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// Get selection interval section (in seconds)
static int64_t GetStakeModifierSelectionIntervalSection(int nSection)
{
    Yassert (nSection >= 0 && nSection < 64);
    return (                                        // what is the purpose of this calculation?
            nModifierInterval * 63 /                // what is the range of inputs??? etc. 
            (
             63 + (
                   (63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1)
                  )
            )
           );
}

// Get stake modifier selection interval (in seconds)
static int64_t GetStakeModifierSelectionInterval()
{
    int64_t 
        nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; ++nSection)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection);
    return nSelectionInterval;
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(vector<pair< int64_t, uint256> >& vSortedByTimestamp, map<uint256, const CBlockIndex*>& mapSelectedBlocks,
    int64_t nSelectionIntervalStop, uint64_t nStakeModifierPrev, const CBlockIndex** pindexSelected)
{
    bool fSelected = false;
    uint256 hashBest = 0;
    *pindexSelected = (const CBlockIndex*) 0;
    BOOST_FOREACH(const PAIRTYPE(int64_t, uint256)& item, vSortedByTimestamp)
    {
        if (!mapBlockIndex.count(item.second))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString().c_str());
        const CBlockIndex* pindex = mapBlockIndex[item.second];
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        uint256 hashProof = pindex->IsProofOfStake()? pindex->hashProofOfStake : pindex->GetBlockHash();
        CDataStream ss(SER_GETHASH, 0);
        ss << hashProof << nStakeModifierPrev;
        uint256 hashSelection = Hash(ss.begin(), ss.end());
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
        if (fSelected && hashSelection < hashBest)
        {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
        else if (!fSelected)
        {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
    }
    if (fDebug && GetBoolArg("-printstakemodifier"))
        printf("SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString().c_str());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every 
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexCurrent, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier)
{
    if (pindexBest && (pindexBest->nHeight + 1) >= nMainnetNewLogicBlockNumber)
    {
        return true;
    }

    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    const CBlockIndex* pindexPrev = pindexCurrent->pprev;
    if (!pindexPrev)
    {
        fGeneratedStakeModifier = true;
        return true;  // genesis block's modifier is 0
    }

    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64_t nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return error("ComputeNextStakeModifier: unable to get last modifier");
    if (fDebug)
    {
        printf("ComputeNextStakeModifier: prev modifier=0x%016" PRIx64 " time=%s epoch=%u\n", nStakeModifier, DateTimeStrFormat(nModifierTime).c_str(), (unsigned int)nModifierTime);
    }
    if (nModifierTime / nModifierInterval >= pindexPrev->GetBlockTime() / nModifierInterval)
    {
        if (fDebug)
        {
            printf("ComputeNextStakeModifier: no new interval keep current modifier: pindexPrev nHeight=%d nTime=%u\n", pindexPrev->nHeight, (unsigned int)pindexPrev->GetBlockTime());
        }
        return true;
    }
    if (nModifierTime / nModifierInterval >= pindexCurrent->GetBlockTime() / nModifierInterval)
    {
        // fixed interval protocol requires current block timestamp also be in a different modifier interval
        if (IsFixedModifierInterval(pindexCurrent->nTime))
        {
            if (fDebug)
            {
                printf("ComputeNextStakeModifier: no new interval keep current modifier: pindexCurrent nHeight=%d nTime=%u\n", pindexCurrent->nHeight, (unsigned int)pindexCurrent->GetBlockTime());
            }
            return true;
        }
        else
        {
            if (fDebug)
            {
                printf("ComputeNextStakeModifier: old modifier at block %s not meeting fixed modifier interval: pindexCurrent nHeight=%d nTime=%u\n", pindexCurrent->GetBlockHash().ToString().c_str(), pindexCurrent->nHeight, (unsigned int)pindexCurrent->GetBlockTime());
            }
        }
    }

    // Sort candidate blocks by timestamp
    vector<pair< int64_t, uint256> > vSortedByTimestamp;
    vSortedByTimestamp.reserve(64 * nModifierInterval / nStakeTargetSpacing);
    int64_t nSelectionInterval = GetStakeModifierSelectionInterval();
    int64_t nSelectionIntervalStart = (pindexPrev->GetBlockTime() / nModifierInterval) * nModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart)
    {
        vSortedByTimestamp.push_back(make_pair(pindex->GetBlockTime(), pindex->GetBlockHash()));
        pindex = pindex->pprev;
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;
    reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end());

    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64_t nStakeModifierNew = 0;
    int64_t nSelectionIntervalStop = nSelectionIntervalStart;
    map<uint256, const CBlockIndex*> mapSelectedBlocks;
    for (int nRound=0; nRound<min(64, (int)vSortedByTimestamp.size()); nRound++)
    {
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound);
        // select a block from the candidates of current round
        if (!SelectBlockFromCandidates(vSortedByTimestamp, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return error("ComputeNextStakeModifier: unable to select block at round %d", nRound);
        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64_t)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(make_pair(pindex->GetBlockHash(), pindex));
        if (fDebug && GetBoolArg("-printstakemodifier"))
            printf("ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d\n", nRound, DateTimeStrFormat(nSelectionIntervalStop).c_str(), pindex->nHeight, pindex->GetStakeEntropyBit());
    }

    // Print selection map for visualization of the selected blocks
    if (fDebug && GetBoolArg("-printstakemodifier"))
    {
        string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate)
        {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        BOOST_FOREACH(const PAIRTYPE(uint256, const CBlockIndex*)& item, mapSelectedBlocks)
        {
            // 'S' indicates selected proof-of-stake blocks
            // 'W' indicates selected proof-of-work blocks
            strSelectionMap.replace(item.second->nHeight - nHeightFirstCandidate, 1, item.second->IsProofOfStake()? "S" : "W");
        }
        printf("ComputeNextStakeModifier: selection height [%d, %d] map %s\n", nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap.c_str());
    }
    if (fDebug)
    {
        printf("ComputeNextStakeModifier: new modifier=0x%016" PRIx64 " time=%s\n", nStakeModifierNew, DateTimeStrFormat(pindexPrev->GetBlockTime()).c_str());
    }

    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
static bool GetKernelStakeModifier(
                                   uint256 hashBlockFrom, 
                                   uint64_t& nStakeModifier, 
                                   int& nStakeModifierHeight, 
                                   int64_t& nStakeModifierTime, 
                                   bool fPrintProofOfStake
                                  )
{
    nStakeModifier = 0;
    if (!mapBlockIndex.count(hashBlockFrom))
        return error("GetKernelStakeModifier() : block not indexed");

    const CBlockIndex
        * pindexFrom = mapBlockIndex[hashBlockFrom];

    nStakeModifierHeight = pindexFrom->nHeight;
    nStakeModifierTime = pindexFrom->GetBlockTime();
    
    int64_t 
        nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval();

    const CBlockIndex
        * pindex = pindexFrom;
    // loop to find the stake modifier later by a selection interval
    while (nStakeModifierTime < pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval)
    {
        if (!pindex->pnext)
        {   // reached best block; may happen if node is behind on block chain
            if (
                fPrintProofOfStake || 
                ((pindex->GetBlockTime() + nStakeMinAge - nStakeModifierSelectionInterval) > GetAdjustedTime())
               )
                return error("GetKernelStakeModifier() : reached best block %s at height %d from block %s",
                    pindex->GetBlockHash().ToString().c_str(), pindex->nHeight, hashBlockFrom.ToString().c_str());
            else
                return false;
        }
        pindex = pindex->pnext;
        if (pindex->GeneratedStakeModifier())
        {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return true;
}

bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64_t& nStakeModifier)
{
    int nStakeModifierHeight;
    int64_t nStakeModifierTime;

    return GetKernelStakeModifier(
                                    hashBlockFrom, 
                                    nStakeModifier, 
                                    nStakeModifierHeight, 
                                    nStakeModifierTime, 
                                    false
                                 );
}

// yacoin2015: nfactor for stake hash
// doc/GetStakeNfactor.html
uint8_t GetStakeNfactor (uint64_t nTime, uint64_t nCoinDayWeight)
{
	// coin day weight factor, used for ProofOfStake kernel hash
	// human friendly notation: nCoinDayWeight / ( ( nTime - 268435456 ) / 131072 - 8192 );
	uint64_t cdwfactor = nCoinDayWeight / ( ( ( nTime - ( 1<<28 ) ) >> 17 ) - ( 1<<13 ) ) ;
	uint8_t nfactor = GetNfactor(nTime, nBestHeight + 1 >= nMainnetNewLogicBlockNumber? true : false);

	if ( cdwfactor > (uint64_t)( nfactor - 4 ) )
		return 4;

	if ( cdwfactor < 2 )
		return 0;

	return nfactor + 1 - (uint8_t)cdwfactor;
}

// yacoin2015
uint256 GetProofOfStakeHash( 
                            uint64_t nStakeModifier, 
                            uint32_t nTimeBlockFrom, 
                            uint32_t nTxPrevOffset, 
                            uint32_t nTxPrevTime, 
                            uint32_t nPrevoutn, 
                            uint32_t nTimeTx, 
                            uint64_t nCoinDayWeight 
                           )
{
    uint256 thash;

    if (
        !fUseOld044Rules
    //(nTimeTx >= YACOIN_NEW_LOGIC_SWITCH_TIME) 
    //    || fTestNet   // to do testnet always the new way
    //    && !fTestNet  // to do testnet the old way
       )
    {
        // scrypt-jane used for hashProofOfStake from now on
        // valid stakeNfactor depends on transaction time and kernel Coin Day Weight
        // and ranges from 4 to ProofOfWork Nfactor-1
        uint8_t 
            stakeNfactor = GetStakeNfactor( (uint64_t)nTimeTx, nCoinDayWeight );

        if ( stakeNfactor < 4 )
            return error("GetProofOfStakeHash() : min coin day weight violation");

        struct stakeHashStruct
        {
            uint64_t nStakeModifier;
            uint32_t nTimeBlockFrom;
            uint32_t nTxPrevOffset;
            uint32_t nTxPrevTime;
            uint32_t nPrevoutn;
            uint32_t nTimeTx;
        }
          stakehashdata;

        stakehashdata.nStakeModifier = nStakeModifier;
        stakehashdata.nTimeBlockFrom = nTimeBlockFrom;
        stakehashdata.nTxPrevOffset = nTxPrevOffset;
        stakehashdata.nTxPrevTime = nTxPrevTime;
        stakehashdata.nPrevoutn = nPrevoutn;
        stakehashdata.nTimeTx = nTimeTx;

        scrypt_hash(
                    CVOIDBEGIN( stakehashdata.nStakeModifier ), 
                    sizeof( stakehashdata ), 
                    UINTBEGIN( thash ), 
                    stakeNfactor
                   );
    }
    else    // the old 0.4.4 way
    {
        CDataStream 
            ss(SER_GETHASH, 0);

        ss << nStakeModifier;
        ss << nTimeBlockFrom << nTxPrevOffset << nTxPrevTime << nPrevoutn << nTimeTx;
        thash = Hash(ss.begin(), ss.end());
    }
    return thash;
}

//_____________________________________________________________________________
bool CheckStakeKernelHash(
                          unsigned int nBits, 
                          const CBlock& blockFrom, 
                          unsigned int nTxPrevOffset, 
                          const CTransaction& txPrev, 
                          const COutPoint& prevout, 
                          unsigned int nTimeTx, 
                          uint256& hashProofOfStake, 
                          bool fPrintProofOfStake, 
                          PosMiningStuff *miningStuff
                         )
{
    if (nTimeTx < txPrev.nTime)  // Transaction timestamp violation
        return error("CheckStakeKernelHash () : nTime violation");

    unsigned int 
        nTimeBlockFrom = blockFrom.GetBlockTime();

    if (nTimeBlockFrom + nStakeMinAge > nTimeTx) // Min age requirement
        return error("CheckStakeKernelHash () : min age violation");

    CBigNum 
        bnTargetPerCoinDay;

    bnTargetPerCoinDay.SetCompact(nBits);

    ::int64_t 
        nValueIn = txPrev.vout[prevout.COutPointGet_n()].nValue;

    // v0.3 protocol kernel hash weight starts from 0 at the 30-day min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    ::int64_t 
        nTimeWeight = min((::int64_t)nTimeTx - txPrev.nTime, (::int64_t)nStakeMaxAge) - nStakeMinAge;

    CBigNum 
        bnCoinDayWeight = CBigNum(nValueIn) * nTimeWeight / COIN / (24 * 60 * 60);  // what is this
                                                                                    // meant to do???
    // Calculate hash
    CDataStream 
        ss(SER_GETHASH, 0);

    ::uint64_t 
        nStakeModifier = 0;

    int 
        nStakeModifierHeight = 0;

    ::int64_t 
        nStakeModifierTime = 0;

    if (miningStuff) 
    {
        nStakeModifier = miningStuff->nStakeModifier;
        nStakeModifierHeight = miningStuff->nStakeModifierHeight;
        nStakeModifierTime = miningStuff->nStakeModifierTime;
    }
    else 
    {
        if (
            !GetKernelStakeModifier(
                                    blockFrom.GetHash(), 
                                    nStakeModifier, 
                                    nStakeModifierHeight, 
                                    nStakeModifierTime, 
                                    fPrintProofOfStake
                                   )
           )
            return false;
    }
   
    ss << nStakeModifier;

    ss << nTimeBlockFrom << nTxPrevOffset << txPrev.nTime << prevout.COutPointGet_n() << nTimeTx;
    hashProofOfStake = Hash(ss.begin(), ss.end());
    if (fPrintProofOfStake)
    {
        printf(
                "CheckStakeKernelHash () : using modifier 0x%016" PRIx64 " "
                "at height=%d "
                "timestamp=%s "
                "for block from height=%d "
                "timestamp=%s"
                "\n"
                "",
            nStakeModifier, 
            nStakeModifierHeight,
            DateTimeStrFormat(nStakeModifierTime).c_str(),
            mapBlockIndex[blockFrom.GetHash()]->nHeight,
            DateTimeStrFormat(blockFrom.GetBlockTime()).c_str()
              );
        printf(
            "CheckStakeKernelHash () : "     //check protocol=%s "
            "modifier=0x%016" PRIx64 " "
            "nTimeBlockFrom=%u "
            "nTxPrevOffset=%u "
            "nTimeTxPrev=%u "
            "nPrevout=%u "
            "nTimeTx=%u "
            "hashProof=%s"
            "\n",
            "0.3",
            nStakeModifier,
            nTimeBlockFrom, 
            nTxPrevOffset, 
            txPrev.nTime, 
            prevout.COutPointGet_n(), 
            nTimeTx,
            hashProofOfStake.ToString().c_str());
    }

    // Now check if proof-of-stake hash meets target protocol
    if (
        (CBigNum(hashProofOfStake) > (bnCoinDayWeight * bnTargetPerCoinDay))
       )
        return false;
    if (fDebug && !fPrintProofOfStake)
    {
        printf(
            "CheckStakeKernelHash () : using modifier 0x%016" PRIx64 " "
            "at height=%d "
            "timestamp=%s "
            "for block from height=%d "
            "timestamp=%s"
            "\n",
            nStakeModifier, 
            nStakeModifierHeight, 
            DateTimeStrFormat(nStakeModifierTime).c_str(),
            mapBlockIndex[blockFrom.GetHash()]->nHeight,
            DateTimeStrFormat(blockFrom.GetBlockTime()).c_str());
        printf(
            "CheckStakeKernelHash () : pass protocol=%s "
            "modifier=0x%016" PRIx64 " "
            "nTimeBlockFrom=%u "
            "nTxPrevOffset=%u "
            "nTimeTxPrev=%u "
            "nPrevout=%u "
            "nTimeTx=%u "
            "hashProof=%s"
            "\n",
            "0.3",
            nStakeModifier,
            nTimeBlockFrom, 
            nTxPrevOffset, 
            txPrev.nTime, 
            prevout.COutPointGet_n(), 
            nTimeTx,
            hashProofOfStake.ToString().c_str());
    }
    return true;
}
//_____________________________________________________________________________
// ppcoin kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(
//          nStakeModifier + 
//          txPrev.block.nTime + 
//          txPrev.offset + 
//          txPrev.nTime + 
//          txPrev.vout.n + 
//          nTime
//         ) < (bnTarget * nCoinDayWeight)
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier: scrambles computation to make it very difficult to precompute
//                  future proof-of-stake at the time of the coin's confirmation
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of 
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(
                          uint32_t nBits, 
                          const CBlock& blockFrom, 
                          uint32_t nTxPrevOffset, 
                          const CTransaction& txPrev, 
                          const COutPoint& prevout, 
                          uint32_t nTimeTx, 
                          uint256& hashProofOfStake, 
                          uint256& targetProofOfStake, 
                          bool fPrintProofOfStake
                         )
{
    if (nTimeTx < txPrev.nTime)  // Transaction timestamp violation
        return error("CheckStakeKernelHash () : nTime violation");

    uint32_t nTimeBlockFrom = blockFrom.GetBlockTime();
    if (nTimeBlockFrom + nStakeMinAge > nTimeTx) // Min age requirement
        return error("CheckStakeKernelHash () : min age violation");

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64_t nValueIn = txPrev.vout[prevout.COutPointGet_n()].nValue;

    uint256 hashBlockFrom = blockFrom.GetHash();

    CBigNum 
        bnCoinDayWeight = CBigNum(nValueIn) * GetWeight(
                                                        (int64_t)txPrev.nTime, 
                                                        (int64_t)nTimeTx
                                                       ) / COIN / (24 * 60 * 60);
    targetProofOfStake = (bnCoinDayWeight * bnTargetPerCoinDay).getuint256();

    // Calculate hash

    uint64_t nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;

    if (!GetKernelStakeModifier(
                                hashBlockFrom, 
                                nStakeModifier, 
                                nStakeModifierHeight, 
                                nStakeModifierTime, 
                                fPrintProofOfStake
                               )
       )
        return false;

    // yacoin2015: scrypt-jane hash for stake kernel
    hashProofOfStake = GetProofOfStakeHash( 
                                           nStakeModifier, 
                                           nTimeBlockFrom, 
                                           nTxPrevOffset, 
                                           txPrev.nTime, 
                                           prevout.COutPointGet_n(), 
                                           nTimeTx, 
                                           bnCoinDayWeight.getuint64() 
                                          );

    if (fPrintProofOfStake)
    {
        printf("CheckStakeKernelHash () : using modifier 0x%016" PRIx64 " at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
            nStakeModifier, nStakeModifierHeight,
            DateTimeStrFormat(nStakeModifierTime).c_str(),
            mapBlockIndex[hashBlockFrom]->nHeight,
            DateTimeStrFormat(blockFrom.GetBlockTime()).c_str());
        printf("CheckStakeKernelHash () : check modifier=0x%016" PRIx64 " nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            nStakeModifier,
            nTimeBlockFrom, nTxPrevOffset, txPrev.nTime, prevout.COutPointGet_n(), nTimeTx,
            hashProofOfStake.ToString().c_str());
    }

    // Now check if proof-of-stake hash meets target protocol
    if (
        (CBigNum(hashProofOfStake) > (bnCoinDayWeight * bnTargetPerCoinDay))
       )
        return false;
    if (fDebug && !fPrintProofOfStake)
    {
        printf(
            "CheckStakeKernelHash () : using modifier 0x%016" PRIx64 " "
            "at height=%d "
            "timestamp=%s "
            "for block from height=%d "
            "timestamp=%s"
            "\n",
            nStakeModifier, 
            nStakeModifierHeight, 
            DateTimeStrFormat(nStakeModifierTime).c_str(),
            mapBlockIndex[hashBlockFrom]->nHeight,
            DateTimeStrFormat(blockFrom.GetBlockTime()).c_str()
              );
        printf(
            "CheckStakeKernelHash () : pass modifier=0x%016" PRIx64 " "
            "nTimeBlockFrom=%u "
            "nTxPrevOffset=%u "
            "nTimeTxPrev=%u "
            "nPrevout=%u "
            "nTimeTx=%u "
            "hashProof=%s"
            "\n",
            nStakeModifier,
            nTimeBlockFrom, 
            nTxPrevOffset, 
            txPrev.nTime, 
            prevout.COutPointGet_n(), 
            nTimeTx,
            hashProofOfStake.ToString().c_str()
              );
    }
    return true;
}

// Scan given coins set for kernel solution
bool ScanForStakeKernelHash(MetaMap &mapMeta, uint32_t nBits, uint32_t nTime, uint32_t nSearchInterval, CoinsSet::value_type &kernelcoin, uint32_t &nTimeTx, uint32_t &nBlockTime, uint64_t &nKernelsTried, uint64_t &nCoinDaysTried)
{
    uint256 hashProofOfStake = 0;

    // (txid, vout.n) => ((txindex, (tx, vout.n)), (block, modifier))
    for(MetaMap::const_iterator meta_item = mapMeta.begin(); meta_item != mapMeta.end(); meta_item++)
    {
        if (!fCoinsDataActual)
            break;

        CTxIndex txindex = (*meta_item).second.first.first;
        CBlock block = (*meta_item).second.second.first;
        uint64_t nStakeModifier = (*meta_item).second.second.second;

        // Get coin
        CoinsSet::value_type pcoin = meta_item->second.first.second;

        static unsigned int nMaxStakeSearchInterval = 60;

        // only count coins meeting min age requirement
        if (nStakeMinAge + block.nTime > nTime - nMaxStakeSearchInterval)
            continue;

        // Transaction offset inside block
        uint32_t nTxOffset = txindex.pos.Get_CDiskTxPos_nTxPos() - txindex.pos.Get_CDiskTxPos_nBlockPos();

        // Current timestamp scanning interval
        unsigned int nCurrentSearchInterval = min(nSearchInterval, nMaxStakeSearchInterval);

        nBlockTime = block.nTime;
        CBigNum bnTargetPerCoinDay;
        bnTargetPerCoinDay.SetCompact(nBits);
        int64_t nValueIn = pcoin.first->vout[pcoin.second].nValue;

        // Search backward in time from the given timestamp 
        // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
        // Stopping search in case of shutting down or cache invalidation
        for (unsigned int n=0; n<nCurrentSearchInterval && fCoinsDataActual && !fShutdown; n++)
        {
            nTimeTx = nTime - n;
            CBigNum 
                bnCoinDayWeight = CBigNum(nValueIn) * GetWeight(
                                                                (int64_t)pcoin.first->nTime, 
                                                                (int64_t)nTimeTx
                                                               ) / COIN / (24 * 60 * 60);
            CBigNum 
                bnTargetProofOfStake = bnCoinDayWeight * bnTargetPerCoinDay;

            // yacoin2015: scrypt-jane hash for stake kernel
            hashProofOfStake = GetProofOfStakeHash( 
                                                   nStakeModifier, 
                                                   nBlockTime, 
                                                   nTxOffset, 
                                                   pcoin.first->nTime, 
                                                   pcoin.second, 
                                                   nTimeTx, 
                                                   bnCoinDayWeight.getuint64() 
                                                  );

            // Update statistics
            nKernelsTried += 1;
            nCoinDaysTried += bnCoinDayWeight.getuint64();

            if (bnTargetProofOfStake >= CBigNum(hashProofOfStake))
            {
                if (fDebug)
                    printf("nStakeModifier=0x%016" PRIx64 ", nBlockTime=%u nTxOffset=%u nTxPrevTime=%u nVout=%u nTimeTx=%u hashProofOfStake=%s Success=true\n",
                        nStakeModifier, nBlockTime, nTxOffset, pcoin.first->nTime, pcoin.second, nTimeTx, hashProofOfStake.GetHex().c_str());

                kernelcoin = pcoin;
                return true;
            }

            if (fDebug)
                printf("nStakeModifier=0x%016" PRIx64 ", nBlockTime=%u nTxOffset=%u nTxPrevTime=%u nTxNumber=%u nTimeTx=%u hashProofOfStake=%s Success=false\n",
                    nStakeModifier, nBlockTime, nTxOffset, pcoin.first->nTime, pcoin.second, nTimeTx, hashProofOfStake.GetHex().c_str());
        }
    }

    return false;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake, uint256& targetProofOfStake)
{
    if (!tx.IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s", tx.GetHash().ToString().c_str());

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];

    // First try finding the previous transaction in database
    CTxDB txdb("r");
    CTransaction txPrev;
    CTxIndex txindex;
    if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
        return tx.DoS(1, error("CheckProofOfStake() : INFO: read txPrev failed"));  // previous transaction not in main chain, may occur during initial download

#ifndef USE_LEVELDB
    txdb.Close();
#endif

    // Verify signature
    if (!VerifySignature(txPrev, tx, 0, MANDATORY_SCRIPT_VERIFY_FLAGS, 0))
        return tx.DoS(100, error("CheckProofOfStake() : VerifySignature failed on coinstake %s", tx.GetHash().ToString().c_str()));

    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(txindex.pos.Get_CDiskTxPos_nFile(), txindex.pos.Get_CDiskTxPos_nBlockPos(), false))
        return fDebug? error("CheckProofOfStake() : read block failed") : false; // unable to read block of previous transaction

    if (
        !CheckStakeKernelHash(
                              nBits, 
                              block, 
                              txindex.pos.Get_CDiskTxPos_nTxPos() - txindex.pos.Get_CDiskTxPos_nBlockPos(), 
                              txPrev, 
                              txin.prevout, 
                              tx.nTime, 
                              hashProofOfStake, 
                              targetProofOfStake, 
                              fDebug
                             )
       )
        return tx.DoS(1, error("CheckProofOfStake() : INFO: check kernel failed on coinstake %s, hashProof=%s", tx.GetHash().ToString().c_str(), hashProofOfStake.ToString().c_str())); // may occur during initial download or if behind on block chain sync

    return true;
}

// Get stake modifier checksum
uint32_t GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    if( 0 < pindex->nHeight )
    {
        Yassert( pindex->pprev );
    }
    if( 0 == pindex->nHeight )
    {
        Yassert( pindex->GetBlockHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet) );
    }
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << pindex->hashProofOfStake << pindex->nStakeModifier;
    uint256 hashChecksum = Hash(ss.begin(), ss.end());
    hashChecksum >>= (256 - 32);
    return hashChecksum.Get64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, uint32_t nStakeModifierChecksum)
{
    if (pindexBest && (pindexBest->nHeight + 1) >= nMainnetNewLogicBlockNumber)
    {
        return true;
    }

    MapModifierCheckpoints& checkpoints = (fTestNet ? mapStakeModifierCheckpointsTestNet : mapStakeModifierCheckpoints);

    if (checkpoints.count(nHeight))
        return nStakeModifierChecksum == checkpoints[nHeight];

    return true;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
