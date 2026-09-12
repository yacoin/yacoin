// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "pow.h"

#include "arith_uint256.h"
#include "bignum.h"
#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "timestamps.h"
#include "uint256.h"
#include "validation.h"

#include <algorithm>

// POS params
CBigNum bnProofOfStakeHardLimit(~uint256(0) >> 30); // fix minimal proof of stake difficulty at 0.25
const unsigned int nStakeTargetSpacing = 1 * nSecondsperMinute; // 1 * 60; // 1-minute stake spacing

// Target params
static const ::int64_t nTargetSpacingWorkMax = 12 * nStakeTargetSpacing; // 2-hour BS, 12 minutes!
static const ::int64_t nTargetTimespan = 7 * 24 * 60 * 60;  // one week

/* POW FUNCTIONS */
// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, ::int64_t nFirstBlockTime, const Consensus::Params& params)
{
    // Recalculate nMinEase corresponding to highest difficulty
    CBlockIndex* tmpBlockIndex = chainActive.Tip();
    ::uint32_t nMinEase = params.powLimit.GetCompact();
    uint256 powTarget = params.powLimit.getuint256();

    while (tmpBlockIndex != nullptr && tmpBlockIndex->nHeight >= nMainnetNewLogicBlockNumber)
    {
        if (nMinEase > tmpBlockIndex->nBits)
        {
            nMinEase = tmpBlockIndex->nBits;
        }

        tmpBlockIndex = tmpBlockIndex->pprev;
    }

    // When headers sync before block download (especially in IBD), chainActive may be unreliable for highest difficulty calculation; use the block index instead
    if (pindexLast->phashBlock != nullptr)
    {
        BlockMap::iterator mi = mapBlockIndex.find(*pindexLast->phashBlock);
        tmpBlockIndex = (*mi).second;
    }
    while (tmpBlockIndex != nullptr && tmpBlockIndex->nHeight >= nMainnetNewLogicBlockNumber)
    {
        if (nMinEase > tmpBlockIndex->nBits)
        {
            nMinEase = tmpBlockIndex->nBits;
        }

        tmpBlockIndex = tmpBlockIndex->pprev;
    }

    ::int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    ::int64_t nNominalTimespan = nDifficultyInterval * params.nPowTargetSpacing;
    if (nActualTimespan < nNominalTimespan / 4)
        nActualTimespan = nNominalTimespan / 4;
    if (nActualTimespan > nNominalTimespan * 4)
        nActualTimespan = nNominalTimespan * 4;

    // Retarget: Calculate to target 1 minute/block for the previous 'epoch's 21,000 blocks
    uint256  bnPrev = CBigNum().SetCompact(pindexLast->nBits).getuint256();
    CBigNum bnPrevTarget;
    bnPrevTarget.setuint256( bnPrev );
    bnPrevTarget *= nActualTimespan;
    bnPrevTarget /= nNominalTimespan;

    // Calculate maximum target of all blocks, it corresponds to 1/3 highest difficulty (or 3 minimum ease)
    uint256 bnMaximum = CBigNum().SetCompact(nMinEase).getuint256();
    CBigNum bnMaximumTarget;
    bnMaximumTarget.setuint256(bnMaximum);
    bnMaximumTarget *= 3;
    // Compare 1/3 highest difficulty with 0.4.9 min difficulty (genesis block difficulty), choose the higher
    if (bnMaximumTarget > params.powLimit)
    {
        bnMaximumTarget = params.powLimit;
    }

    // Choose higher difficulty (higher difficulty have smaller target)
    CBigNum bnNewTarget = std::min(bnPrevTarget, bnMaximumTarget);
    LogPrintf(
                 "PoW new constant target %s\n"
                 ""
                 , CBigNum( bnNewTarget ).getuint256().ToString().substr(0,16)
                );

    return bnNewTarget.GetCompact();
}

// TODO: Refactor GetNextTargetRequired044
static unsigned int GetNextTargetRequired044(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    // First three blocks will have following targets:
    // genesis (zeroth) block: bnEasiestTargetLimit
    // first block and second block: Params().GetConsensus().initialHashTarget (~uint256(0) >> 8)
    CBigNum bnEasiestTargetLimit = fProofOfStake? bnProofOfStakeHardLimit : Params().GetConsensus().powLimit;

    if (pindexLast == NULL)
    {
        return bnEasiestTargetLimit.GetCompact(); // genesis (zeroth) block
    }

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);

    if (pindexPrev->pprev == NULL)
    {
        return Params().GetConsensus().initialHashTarget.GetCompact(); // first block
    }

    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);

    if (pindexPrevPrev->pprev == NULL)
        return Params().GetConsensus().initialHashTarget.GetCompact(); // second block

    // so there are more than 3 blocks
    ::int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();

    CBigNum bnNewTarget;
    ::uint32_t nEase = pindexLast->nBits;
    CBigNum bnNew;
    uint256 nTarget = CBigNum().SetCompact(nEase).getuint256();
    uint256 nRelativeTargetDelta = (nTarget >> 3);  // i.e. 1/8 of the current target

    // Since Heliospolis hardfork block 1890000, the target is only recalculated every 21000 blocks
    if ((pindexLast->nHeight + 1) >= nMainnetNewLogicBlockNumber)
    {
        // Since Heliospolis hardfork block 1890000, the target is only recalculated every 21000 blocks
        int nBlocksToGo = (pindexLast->nHeight + 1) % nDifficultyInterval;
        // Only change once per difficulty adjustment interval (every 21000 blocks)
        if (0 != nBlocksToGo)
        {
            bnNewTarget.setuint256(nTarget);

            LogPrintf("PoW constant target %s (%d block %s to go)\n",
                      nTarget.ToString().substr(0, 16),
                      (nDifficultyInterval - nBlocksToGo),
                      (1 != nBlocksToGo) ? "s" : "");
            return bnNewTarget.GetCompact();
        }
        else // actually do a DAA
        {
            const Consensus::Params& consensusParams = Params().GetConsensus();
            // Hardfork happens
            if ((pindexLast->nHeight + 1) == nMainnetNewLogicBlockNumber)
            {
                return consensusParams.powLimit.GetCompact();
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
                CBlockIndex* pbi = chainActive.Genesis();
                CBlock block;
                ReadBlockFromDisk(block, pbi, consensusParams);
                pindexFirst = pbi;
            }
            Yassert(pindexFirst);

            return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), consensusParams);
        }
    }
    else
    {
        // Old logic before Heliospolis hardfork block 1890000
        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        bnNewTarget.SetCompact(pindexPrev->nBits);

        ::int64_t nTargetSpacing = fProofOfStake
                ? nStakeTargetSpacing
                : std::min(nTargetSpacingWorkMax, (::int64_t)nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));

        ::int64_t nInterval = nTargetTimespan / nTargetSpacing;   // this is the one week / nTargetSpacing

        bnNewTarget *= (((nInterval - 1) * nTargetSpacing) + nActualSpacing + nActualSpacing);
        bnNewTarget /=  ((nInterval + 1) * nTargetSpacing);

        if (bnNewTarget > bnEasiestTargetLimit)
            bnNewTarget = bnEasiestTargetLimit;
        return bnNewTarget.GetCompact();
    }
}
//_____________________________________________________________________________
// yacoin2015 upgrade: penalize ignoring ProofOfStake blocks with high difficulty.
// requires adjusted PoW-PoS ratio (GetSpacingThreshold), PoW target moving average (nBitsMA)
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
    return GetNextTargetRequired044( pindexLast, fProofOfStake );
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if ((bnTarget <= 0) || (bnTarget > (params.powLimit)))
      return error("CheckProofOfWork() : nBits below minimum work");
    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash > target nBits");

    return true;
}
/* POW FUNCTIONS */

/* POS FUNCTIONS */
// select stake target limit according to hard-coded conditions
CBigNum inline GetProofOfStakeLimit(int nHeight, unsigned int nTime)
{
    return bnProofOfStakeHardLimit; // YAC has always been 30
}

// miner's coin stake reward based on nBits and coin age spent (coin-days)
::int64_t GetProofOfStakeReward(::int64_t nCoinAge, unsigned int nBits, ::int64_t nTime)
{
    ::int64_t nRewardCoinYear, nSubsidy, nSubsidyLimit = 10 * COIN;

    // Old creation amount per coin-year, 5% fixed stake mint rate
    nRewardCoinYear = 5 * CENT;
    nSubsidy = nCoinAge * nRewardCoinYear * 33 / (365 * 33 + 8);

    if (fDebug && gArgs.GetBoolArg("-printcreation"))
      LogPrintf("GetProofOfStakeReward(): create=%s nCoinAge=%" PRId64
                " nBits=%d\n",
                FormatMoney(nSubsidy), nCoinAge, nBits);
    return nSubsidy;
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
    return ComputeMaxBits(Params().GetConsensus().powLimit, nBase, nTime);
}

//
// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int ComputeMinStake(unsigned int nBase, ::int64_t nTime, unsigned int nBlockTime)
{
    return ComputeMaxBits(GetProofOfStakeLimit(0, nBlockTime), nBase, nTime);
}
/* POS FUNCTIONS */
