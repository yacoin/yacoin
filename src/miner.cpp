// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
    #include <memory>
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb.h"
#endif

#ifndef PPCOIN_KERNEL_H
 #include "kernel.h"
#endif

#ifndef BITCOIN_INIT_H
 #include "init.h"
#endif

#ifndef YACOIN_RANDOM_NONCE_H
 #include "random_nonce.h"
#endif

using std::vector;
using std::set;
using std::list;
using std::map;
using std::auto_ptr;
using std::max;
using std::string;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

extern unsigned int nMinerSleep;

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; ++i)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; ++i)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; ++i)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().substr(0,10).c_str(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};


uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
uint32_t nLastCoinStakeSearchInterval = 0;
 
// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

//_____________________________________________________________________________

class CdoTempoaryMockTime
{
private:
    CdoTempoaryMockTime( const CdoTempoaryMockTime & );
    CdoTempoaryMockTime &operator = ( const CdoTempoaryMockTime & );

public:
    CdoTempoaryMockTime()
    {
        if(
            false 
            //((pindexBest->nTime < YACOIN_NEW_LOGIC_SWITCH_TIME) && !fTestNet )
          )
        {
            SetMockTime( (int64_t)(pindexBest->nTime + nOneMinuteInSeconds) );
        }
    }

    ~CdoTempoaryMockTime()
    {
        if(
            false 
            //((pindexBest->nTime < YACOIN_NEW_LOGIC_SWITCH_TIME) && !fTestNet )
          )
        {
            SetMockTime( 0 );   // restores time to now
        }
    }    
};
//_____________________________________________________________________________

// CreateNewBlock: create new block (without proof-of-work/proof-of-stake)
CBlock* CreateNewBlock(CWallet* pwallet, bool fProofOfStake)
{
    // Create new block
    auto_ptr<CBlock> pblock(new CBlock());
    if (!pblock.get())
        return NULL;

    CdoTempoaryMockTime
        junk;   // just need to instantiate it so the ctors & dtors can do their work

    if( fUseOld044Rules )
    {
      //pblock->nVersion = CBlock::VERSION_of_block_for_yac_044_old;
        pblock->nVersion = CBlock::CURRENT_VERSION_of_block;
        // here we can fiddle with time to try to make block generation easier
    }
    // Create coinbase tx
    CTransaction 
        txNew;         // this uses real time

    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);

    CReserveKey 
        reservekey(pwallet);

    if (fProofOfStake)
    {
        txNew.vout[0].SetEmpty();
    }
    txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Largest block you're willing to create:
    unsigned int 
        nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);

    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int 
        nBlockPrioritySize = GetArg("-blockprioritysize", 27000);

    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int 
        nBlockMinSize = GetArg("-blockminsize", 0);

    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64_t 
        nMinTxFee = MIN_TX_FEE;

    if (mapArgs.count("-mintxfee"))
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);

    CBlockIndex
        * pindexPrev = pindexBest;
/*********************/
    // ppcoin: if coinstake available add coinstake tx
    static int64_t 
        nLastCoinStakeSearchTime = GetAdjustedTime();  // only initialized at startup
    //CBlockIndex* pindexPrev = pindexBest;

    if (fProofOfStake)  // attempt to find a coinstake
    {
        pblock->nBits = GetNextTargetRequired(pindexPrev, true);

        CTransaction 
            txCoinStake;    // uses real time

        int64_t 
            nSearchTime = (int64_t)txCoinStake.nTime; // search to current time

        if (
            (nSearchTime > nLastCoinStakeSearchTime)
           )  
        {
            CKey 
                key;

            bool
                fCreatedCoinStake;
            if(
                fUseOld044Rules
              )
            {
                fCreatedCoinStake = pwallet->CreateCoinStake(
                                                             *pwallet, 
                                                             pblock->nBits,
                                                             nSearchTime-nLastCoinStakeSearchTime, 
                                                             txCoinStake
                                                            );
            }
            else    // new rules are in play
            {
                fCreatedCoinStake = pwallet->CreateCoinStake(
                                                            *pwallet, 
                                                             pblock->nBits,
                                                             nSearchTime-nLastCoinStakeSearchTime, 
                                                             txCoinStake,
                                                             key
                                                            );
            }
            if( fCreatedCoinStake )
            {
                if (
                    txCoinStake.nTime >= max(
                                             pindexPrev->GetMedianTimePast()+1, 
                                             pindexPrev->GetBlockTime() - nMaxClockDrift
                                            )
                   )
                {   // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    pblock->vtx[0].vout[0].SetEmpty();
                    pblock->vtx[0].nTime = txCoinStake.nTime;
                    pblock->vtx.push_back(txCoinStake);
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
    }
/**********************/

    pblock->nBits = GetNextTargetRequired(pindexPrev, fProofOfStake);

    if(
        fUseOld044Rules
      )
    {   // Collect memory pool transactions into the block
        ::int64_t 
            nFees = 0;
        {
            LOCK2(cs_main, mempool.cs);
            CBlockIndex
                * pindexPrev = pindexBest;
            CTxDB 
                txdb("r");

            // Priority order to process transactions
            list<COrphan> 
                vOrphan; // list memory doesn't move
            map<uint256, vector<COrphan*> > mapDependers;

            // This vector will be sorted into a priority queue:
            vector<TxPriority> 
                vecPriority;
            vecPriority.reserve(mempool.mapTx.size());
            for (
                 map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); 
                 mi != mempool.mapTx.end(); 
                 ++mi
                )
            {
                CTransaction& 
                    tx = (*mi).second;
                if (tx.IsCoinBase() || tx.IsCoinStake() || !tx.IsFinal())
                    continue;

                COrphan
                    * porphan = NULL;
                double 
                    dPriority = 0;
                ::int64_t 
                    nTotalIn = 0;
                bool 
                    fMissingInputs = false;
                BOOST_FOREACH(const CTxIn& txin, tx.vin)
                {   // Read prev transaction
                    CTransaction 
                        txPrev;
                    CTxIndex 
                        txindex;
                    if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
                    {   // This should never happen; all transactions in the memory
                        // pool should connect to either transactions in the chain
                        // or other transactions in the memory pool.
                        if (!mempool.mapTx.count(txin.prevout.COutPointGetHash()))
                        {
                            printf("ERROR: mempool transaction missing input\n");
                            if (fDebug) 
                            {
                                //Yassert("mempool transaction missing input" == 0);
                            }
                            fMissingInputs = true;
                            if (porphan)
                                vOrphan.pop_back();
                            break;
                        }

                        // Has to wait for dependencies
                        if (!porphan)
                        {
                            // Use list for automatic deletion
                            vOrphan.push_back(COrphan(&tx));
                            porphan = &vOrphan.back();
                        }
                        mapDependers[txin.prevout.COutPointGetHash()].push_back(porphan);
                        porphan->setDependsOn.insert(txin.prevout.COutPointGetHash());
                        nTotalIn += mempool.mapTx[txin.prevout.COutPointGetHash()].vout[txin.prevout.COutPointGet_n()].nValue;
                        continue;
                    }
                    ::int64_t 
                        nValueIn = txPrev.vout[txin.prevout.COutPointGet_n()].nValue;
                    nTotalIn += nValueIn;

                    int 
                        nConf = txindex.GetDepthInMainChain();
                    dPriority += (double)nValueIn * nConf;
                }
                if (fMissingInputs) 
                    continue;

                // Priority is sum(valuein * age) / txsize
                unsigned int 
                    nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
                dPriority /= nTxSize;

                // This is a more accurate fee-per-kilobyte than is used by the client code, because the
                // client code rounds up the size to the nearest 1K. That's good, because it gives an
                // incentive to create smaller transactions.
                double 
                    dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

                if (porphan)
                {
                    porphan->dPriority = dPriority;
                    porphan->dFeePerKb = dFeePerKb;
                }
                else
                    vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
            }

            // Collect transactions into block
            map<uint256, CTxIndex> 
                mapTestPool;
            ::uint64_t 
                nBlockSize = 1000;
            ::uint64_t 
                nBlockTx = 0;
            int 
                nBlockSigOps = 100;
            bool 
                fSortedByFee = (nBlockPrioritySize <= 0);   // is usually 27,000

            TxPriorityCompare 
                comparer(fSortedByFee);
            std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

            while (!vecPriority.empty())
            {
                // Take highest priority transaction off the priority queue:
                double 
                    dPriority = vecPriority.front().get<0>();
                double 
                    dFeePerKb = vecPriority.front().get<1>();
                CTransaction
                    & tx = *(vecPriority.front().get<2>());

                std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
                vecPriority.pop_back();

                // Size limits
                unsigned int 
                    nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
                if ((nBlockSize + nTxSize) >= nBlockMaxSize)
                    continue;

                // Legacy limits on sigOps:
                unsigned int 
                    nTxSigOps = tx.GetLegacySigOpCount();
                if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                    continue;

                // Timestamp limit
                if (
                    (tx.nTime > GetAdjustedTime()) || 
                    (pblock->IsProofOfStake() && (tx.nTime > pblock->vtx[1].nTime))
                   )
                    continue;

                // ppcoin: simplify transaction fee - allow free = false
                ::int64_t 
                    nMinFee = tx.GetMinFee(nBlockSize, false, GMF_BLOCK);

                // Skip free transactions if we're past the minimum block size:
                if (
                    fSortedByFee && 
                    (dFeePerKb < nMinTxFee) && 
                    ((nBlockSize + nTxSize) >= nBlockMinSize)
                   )
                    continue;

                // Prioritize by fee once past the priority size or we run out of high-priority
                // transactions:
                if (
                    !fSortedByFee &&
                    (
                     ((nBlockSize + nTxSize) >= nBlockPrioritySize) || 
                     (dPriority < (COIN * 144 / 250))
                    )
                   )
                {
                    fSortedByFee = true;
                    comparer = TxPriorityCompare(fSortedByFee);
                    std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
                }

                // Connecting shouldn't fail due to dependency on other memory pool transactions
                // because we're already processing them in order of dependency
                map<uint256, CTxIndex> 
                    mapTestPoolTmp(mapTestPool);
                MapPrevTx 
                    mapInputs;
                bool 
                    fInvalid;
                if (!tx.FetchInputs(txdb, mapTestPoolTmp, false, true, mapInputs, fInvalid))
                    continue;

                ::int64_t 
                    nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
                if (nTxFees < nMinFee)
                    continue;

                nTxSigOps += tx.GetP2SHSigOpCount(mapInputs);
                if ((nBlockSigOps + nTxSigOps) >= MAX_BLOCK_SIGOPS)
                    continue;

                if (!tx.ConnectInputs(txdb, mapInputs, mapTestPoolTmp, CDiskTxPos(1,1,1), pindexPrev, false, true))
                    continue;
                mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), tx.vout.size());
                swap(mapTestPool, mapTestPoolTmp);

                // Added
                pblock->vtx.push_back(tx);
                nBlockSize += nTxSize;
                ++nBlockTx;
                nBlockSigOps += nTxSigOps;
                nFees += nTxFees;

                if (fDebug && GetBoolArg("-printpriority"))
                {
                    printf("priority %.1f feeperkb %.1f txid %s\n",
                           dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
                }

                // Add transactions that depend on this one to the priority queue
                uint256 
                    hash = tx.GetHash();
                if (mapDependers.count(hash))
                {
                    BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                    {
                        if (!porphan->setDependsOn.empty())
                        {
                            porphan->setDependsOn.erase(hash);
                            if (porphan->setDependsOn.empty())
                            {
                                vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                                std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                            }
                        }
                    }
                }
            }

            nLastBlockTx = nBlockTx;
            nLastBlockSize = nBlockSize;

            if (fDebug && GetBoolArg("-printpriority"))
                printf("CreateNewBlock (): total size %" PRI64u "\n", nBlockSize);

            if (pblock->IsProofOfWork())
                pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pblock->nBits);

            // Fill in header
            pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
            if (pblock->IsProofOfStake())   // nTime, this is overwritten immediately???!!!
                pblock->nTime      = pblock->vtx[1].nTime; //same as coinstake timestamp
            pblock->nTime          = max(                                   
                                        pindexPrev->GetMedianTimePast() + 1,
                                        pblock->GetMaxTransactionTime()     
                                        );                                  
            pblock->nTime          = max(
                                         pblock->GetBlockTime(),    // lo & behold this is nTime!?
                                         pindexPrev->GetBlockTime() - nMaxClockDrift
                                        );
            if (pblock->IsProofOfWork())
                pblock->UpdateTime(pindexPrev);
            pblock->nNonce         = 0;
        }
        return pblock.release();
    }
    // Collect memory pool transactions into the block
    int64_t 
        nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex
            * pindexPrev = pindexBest;
        CTxDB 
            txdb("r");

        // Priority order to process transactions
        list<COrphan> 
            vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > 
            mapDependers;

        // This vector will be sorted into a priority queue:
        vector<TxPriority> 
            vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (
             map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); 
             mi != mempool.mapTx.end(); 
             ++mi
            )
        {
            CTransaction
                & tx = (*mi).second;
            if (tx.IsCoinBase() || tx.IsCoinStake() || !tx.IsFinal())
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64_t nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                CTransaction txPrev;
                CTxIndex txindex;
                if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.COutPointGetHash()))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        //if (fDebug) 
                        //    Yassert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.COutPointGetHash()].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.COutPointGetHash());
                    nTotalIn += mempool.mapTx[txin.prevout.COutPointGetHash()].vout[txin.prevout.COutPointGet_n()].nValue;
                    continue;
                }
                int64_t nValueIn = txPrev.vout[txin.prevout.COutPointGet_n()].nValue;
                nTotalIn += nValueIn;

                int nConf = txindex.GetDepthInMainChain();
                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
        }

        // Collect transactions into block
        map<uint256, CTxIndex> mapTestPool;
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = tx.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Timestamp limit
            if (tx.nTime > GetAdjustedTime() || (fProofOfStake && tx.nTime > pblock->vtx[0].nTime))
                continue;

            // Simplify transaction fee - allow free = false
            int64_t nMinFee = tx.GetMinFee(nBlockSize, true, GMF_BLOCK, nTxSize);

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < nMinTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (
                !fSortedByFee &&
                (
                 ((nBlockSize + nTxSize) >= nBlockPrioritySize) || 
                 (dPriority < (COIN * 144 / 250))
                )               // what is this double < some int64 / mean?
               )
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            // Connecting shouldn't fail due to dependency on other memory pool transactions
            // because we're already processing them in order of dependency
            map<uint256, CTxIndex> mapTestPoolTmp(mapTestPool);
            MapPrevTx mapInputs;
            bool fInvalid;
            if (!tx.FetchInputs(txdb, mapTestPoolTmp, false, true, mapInputs, fInvalid))
                continue;

            int64_t nTxFees = tx.GetValueIn(mapInputs)-tx.GetValueOut();
            if (nTxFees < nMinFee)
                continue;

            nTxSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            if (!tx.ConnectInputs(txdb, mapInputs, mapTestPoolTmp, CDiskTxPos(1,1,1), pindexPrev, false, true, true, MANDATORY_SCRIPT_VERIFY_FLAGS))
                continue;
            mapTestPoolTmp[tx.GetHash()] = CTxIndex(CDiskTxPos(1,1,1), tx.vout.size());
            swap(mapTestPool, mapTestPoolTmp);

            // Added
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fDebug && GetBoolArg("-printpriority"))
            {
                printf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
            }

            // Add transactions that depend on this one to the priority queue
            uint256 hash = tx.GetHash();
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        if (!fProofOfStake)
        {
            pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pblock->nBits, nFees);

            if (fDebug)
                printf("PoW CreateNewBlock (): reward %" PRIu64 "\n", pblock->vtx[0].vout[0].nValue);
        }

        if (fDebug && GetBoolArg("-printpriority"))
            printf("CreateNewBlock (): total size %" PRIu64 "\n", nBlockSize);

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        if (!fProofOfStake)
        {
            pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime = max(pblock->GetBlockTime(), PastDrift(pindexPrev->GetBlockTime()));
            pblock->UpdateTime(pindexPrev);
        }
        pblock->nNonce = 0;
    }

    return pblock.release();
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 
        hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;

    unsigned int 
        nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2

    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    Yassert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);
    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (uint32_t i = 0; i < sizeof(tmp)/sizeof(uint32_t); ++i)
  //for (unsigned int i = 0; i < sizeof(tmp)/4; ++i)    // this is only true
    {                                                   // if an unsigned int 
                                                        // is 32 bits!!?? What 
                                                        // if it is 64 bits???????
        ((uint32_t *)&tmp)[i] = ByteReverse(((uint32_t *)&tmp)[i]);
    }
    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hashBlock = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if(!pblock->IsProofOfWork())
        return error("CheckWork () : %s is not a proof-of-work block", hashBlock.GetHex().c_str());

    if (hashBlock > hashTarget)
        return error("CheckWork () : proof-of-work not meeting target");

    //// debug print
    printf(
            "CheckWork () : new proof-of-work block found  \n"
            "hash: %s  \n"
            "target: %s\n", 
            hashBlock.GetHex().c_str(), 
            hashTarget.GetHex().c_str()
          );
    pblock->print();
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("CheckWork () : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[hashBlock] = 0;
        }

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return error("CheckWork () : ProcessBlock, block not accepted");
    }

    return true;
}

bool CheckStake(CBlock* pblock, CWallet& wallet)
{
    uint256 
        proofHash = 0, 
        hashTarget = 0;
    uint256 
        hashBlock = pblock->GetHash();

    if(!pblock->IsProofOfStake())
    {
#ifdef NDEBUG
        return false;
#endif
        if ( fTestNet )
            return false;
        return error("CheckStake() : %s is not a proof-of-stake block", 
                     hashBlock.GetHex().c_str()
                    );
    }

    // verify hash target and signature of coinstake tx
    if (!CheckProofOfStake(pblock->vtx[1], pblock->nBits, proofHash, hashTarget))
        return error("CheckStake() : proof-of-stake checking failed");

    //// debug print
    printf(
            "CheckStake() : new proof-of-stake block found  \n"
            "hash: %s \nproofhash: %s  \ntarget: %s\n", 
            hashBlock.GetHex().c_str(), 
            proofHash.GetHex().c_str(), 
            hashTarget.GetHex().c_str()
          );
    pblock->print();
    printf("out %s\n", FormatMoney(pblock->vtx[1].GetValueOut()).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("CheckStake() : generated block is stale");

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[hashBlock] = 0;
        }

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return error("CheckStake() : ProcessBlock, block not accepted");
    }

    return true;
}

void StakeMinter(CWallet *pwallet)
{
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread("yacoin-PoS-minter");

    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    while (true)
    {
        if (fShutdown)
            return;

        while (pwallet->IsLocked())
        {
            Sleep(1000);
            if (fShutdown)
                return;
        }

        while (
               IsInitialBlockDownload() ||
               (
                vNodes.empty() 
                //&& !fTestNet      //TestNet can mint stand alone!
               )
               //|| (fTestNet && (pindexBest->nHeight < nCoinbaseMaturity))
              )
        {
            Sleep(1000);
            if (fShutdown)
                return;
        }

        // to temporarily stop mining
        //continue;
        CBlockIndex
            * pindexPrev = pindexBest;

        if ( fUseOld044Rules )
        {                                                   // behave as previously
            if (
                pindexPrev->IsProofOfStake() && // which was, if last block was a PoS
                ( pindexPrev->nHeight >= nConsecutiveStakeSwitchHeight )
               ) 
            {
                bool 
                    fFastPOS = GetArg("-fastpos", 0);

                if (!fFastPOS) 
                    Sleep(500);
                continue;       // does this mean we stay at this point?  It looks that way?
            }                   // we stall and don't attempt to PoS
        }

        if (pwallet->GetBalance() > 0 )
        {
        //
        // Create new block
        //
            auto_ptr<CBlock> 
                pblock(CreateNewBlock(pwallet, true));

            if (!pblock.get())
                return;
            IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

        // Trying to sign a block
            if (pblock->SignBlock(*pwallet))
            {
                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                if( CheckStake(pblock.get(), *pwallet) )
                {
                    printf(
                           "\nCPUMinter : proof-of-stake block found "
                           "\n\n\a"
                           ""
                          ); 
                }
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
                Sleep(5 * nOneHundredMilliseconds);
            }
            //else
        }
        Sleep(nMinerSleep);
        //continue;
    }
}
//_____________________________________________________________________________
//_____________________________________________________________________________
//_____________________________________________________________________________
//
static bool fGenerateBitcoins = false;
static bool fLimitProcessors = false;
static int nLimitProcessors = -1;

static string strMintMessage = "Info: Minting suspended due to locked wallet.";
static string strMintWarning;

double dHashesPerSec;
::int64_t nHPSTimerStart;
//_____________________________________________________________________________
bool
    check_for_stop_mining( CBlockIndex *pindexPrev )
{
    if (
        (pindexPrev != pindexBest) ||
        !fGenerateBitcoins ||
        fShutdown
       )
    {
#ifdef Yac1dot0 
    (void)printf(
                 "new block or shutdown!\n"
                 ""
                );
#endif
       return true;
    }
    return false;
}

//_____________________________________________________________________________
static void YacoinMiner(CWallet *pwallet)  // here fProofOfStake is always false
{
    printf("CPUMiner started for proof-of-work\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread("yacoin-PoW-miner");

    // Each thread has its own key and counter
    CReserveKey 
        reservekey(pwallet);

    unsigned int 
        nExtraNonce = 0;

    while ( fGenerateBitcoins )
    {
        while (
               IsInitialBlockDownload() || 
               (
                vNodes.empty() 
                //&& !fTestNet               //TestNet can mine stand alone!
                // could be that if there is more than one stand alone mining
                // forks on the blockchain can't be resolved?
               )
              )
        {
            //printf("vNodes.size() == %d, IsInitialBlockDownload() == %d\n", vNodes.size(), IsInitialBlockDownload());
            Sleep(nMillisecondsPerSecond);
            if (
                fShutdown
                ||
                !fGenerateBitcoins
               )        // someone shut off the miner
                break;
        }
        if (
            fShutdown
            ||
            !fGenerateBitcoins
           )        // someone shut off the miner
            break;

        while (pwallet->IsLocked())
        {
            strMintWarning = strMintMessage;
            Sleep(nMillisecondsPerSecond);
        }
        strMintWarning = "";

        //
        // Create new block
        //
        unsigned int 
            nTransactionsUpdatedLast = nTransactionsUpdated;

        CBlockIndex
            * pindexPrev = pindexBest;

        auto_ptr<CBlock> 
            pblock(CreateNewBlock(pwallet, false));

        if (!pblock.get())      // means what, I wonder?
            return;
        IncrementExtraNonce(pblock.get(), pindexPrev, nExtraNonce);

        bool
            fNotYac1dot0BlockOrTx = true;
        if( (pindexPrev->nHeight + 1) >= nTestNetNewLogicBlockNumber )
        {
            fNotYac1dot0BlockOrTx = false;
        }
        printf(
                "Running YACoinMiner with %" PRIszu " transaction"
                "%s"
                " in block (%u bytes)"
                "\n"
                ""
                , pblock->vtx.size()
                , pblock->vtx.size() > 1? "s": ""
                , ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION)
              );

        //
        // Pre-build hash buffers
        //
        char pmidstatebuf[32+16]; char* pmidstate = alignup<16>(pmidstatebuf);
        char pdatabuf[128+16];    char* pdata     = alignup<16>(pdatabuf);
        char phash1buf[64+16];    char* phash1    = alignup<16>(phash1buf);

        FormatHashBuffers(pblock.get(), pmidstate, pdata, phash1);

        unsigned int
            & nBlockTime = *(unsigned int*)(pdata + 64 + 4);
        unsigned int
            & nBlockNonce = *(unsigned int*)(pdata + 64 + 12);

        Big.randomize_the_nonce( nBlockNonce ); // lazy initialization performed here

        //
        // Search
        //
        ::int64_t
            nStart = GetTime();

        uint256 
            hashTarget = (CBigNum().SetCompact(pblock->nBits)).getuint256(); // PoW hashTarget

        (void)printf(
                     "Hash target %s"
                     "\n"
                     , hashTarget.GetHex().substr(0,16).c_str()
                    );

        block_header 
            res_header;

        uint256 
            result;
        unsigned int 
            nHashesDone = 0;

#ifndef _MSC_VER
        (void)printf(
                     "Starting mining loop\n"
                    );
#endif
        while( fGenerateBitcoins )
        {
            unsigned int nNonceFound;

            nNonceFound = scanhash_scrypt(
                                            (block_header *)&pblock->nVersion,
                                            //max_nonce,
                                            nHashesDone,
                                            UBEGIN(result),
                                            &res_header,
                                            GetNfactor(pblock->nTime, fNotYac1dot0BlockOrTx)
                                            , pindexPrev
                                            , &hashTarget
                                         );
            // Check if something found
            pblock->nNonce = nNonceFound;
#ifdef Yac1dot0
            (void)printf(
                         "hash count %d"
                         "\n"
                         , nHashesDone
                        );
#endif
            if (result <= hashTarget)
            {   // Found a solution
#ifdef _MSC_VER
    #ifdef _DEBUG
                (void)printf(
                            "target: %s\n", hashTarget.ToString().c_str()
                            );
                (void)printf(
                            "result: %s\n", result.ToString().c_str()
                            );
    #endif
#endif
                Yassert(result == pblock->GetHash());
                if (!pblock->SignBlock(*pwalletMain))   // wallet is locked
                {
                    strMintWarning = strMintMessage;
                    break;
                }
                strMintWarning = "";

                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                if( CheckWork(pblock.get(), *pwalletMain, reservekey) )
                {
                    printf(
                            "\nCPUMiner : proof-of-work block found \n"
                            "%s"
                            "\n\n\a"
                            "", 
                            pblock->GetHash().ToString().c_str()
                          ); 
                }
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
                    break;
            }
            else
            {
#ifdef _MSC_VER
//    #ifdef _DEBUG
//                (void)printf(
//                             "->GetHash(): %s\n", pblock->GetHash().ToString().c_str()
//                            );
//    #endif
#endif
            }
            // Meter hashes/sec
            static ::int64_t 
                nHashCounter;

            if (0 == nHPSTimerStart)
                nHPSTimerStart = GetTimeMillis();
            nHashCounter += nHashesDone;
            nHashesDone = 0;
                
#ifdef Yac1dot0
            (void)printf(
                         "hash counter %" PRId64 ""
                         "\n"
                         , nHashCounter
                        );
#endif
            ::int64_t 
                nNow = GetTimeMillis();

            if ((nNow - nHPSTimerStart) > (40 * nMillisecondsPerSecond))   // no comment needed!
            {
                static CCriticalSection mining_stats;
                {
                    LOCK(mining_stats);
                    if ((nNow - nHPSTimerStart) > (30 * nMillisecondsPerSecond))
                    {
                        static ::int64_t nLogTime;  // = 0
                        //if (GetTime() - nLogTime > 30 * 60)
                        if (GetTime() - nLogTime > 30 ) // 30 seconds always true the first time!
                        {
                            dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                            printf(
                                    "\n"
                                    "hashmeter %3d CPU%s %.1f hash/s\n"
                                    , vnThreadsRunning[THREAD_MINER]
                                    , (vnThreadsRunning[THREAD_MINER] > 1)? "s": ""
                                    , dHashesPerSec 
                                  );
                            if(
                                (nStatisticsNumberOfBlocks > 0)
                                &&
                                (nStatisticsNumberOfBlocks2000 > 0)
                                &&
                                (nStatisticsNumberOfBlocks1000 > 0)
                                &&
                                (nStatisticsNumberOfBlocks200 > 0)
                                &&
                                (nStatisticsNumberOfBlocks100 > 0)
                              )
                            {
                                printf(
                                    "long average block period %" PRId64 " sec (divisor %d)\n"
                                    "long average block period %" PRId64 " sec (divisor %d)\n"
                                    "long average block period %" PRId64 " sec (divisor %d)\n"
                                    "long average block period %" PRId64 " sec (divisor %d)\n"
                                    "long average block period %" PRId64 " sec (divisor %d)\n"
                                    ""
                                    , nLongAverageBP
                                    , nStatisticsNumberOfBlocks
                                    , nLongAverageBP2000 
                                    , nStatisticsNumberOfBlocks2000
                                    , nLongAverageBP1000 
                                    , nStatisticsNumberOfBlocks1000
                                    , nLongAverageBP200 
                                    , nStatisticsNumberOfBlocks200
                                    , nLongAverageBP100 
                                    , nStatisticsNumberOfBlocks100
                                      );
                            }
                            printf( "\n" );
                            nHPSTimerStart = GetTimeMillis();
                            nHashCounter = 0;
                            nLogTime = GetTime();
                        }
                    Sleep( nOneMillisecond );
                    }
                }
            }
            // Check for stop or if block needs to be rebuilt
            if( 
               check_for_stop_mining( pindexPrev )
               ||
               (vNodes.empty() && !fTestNet)
              )
                break;
            if (
                fLimitProcessors && 
                (vnThreadsRunning[THREAD_MINER] > nLimitProcessors)
               )
            {
                return;
            }
            //if (nBlockNonce >= 0xffff0000)
            //    break;

            //if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
            //   break;

            // Update nTime every few seconds
            pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime = max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
            pblock->UpdateTime(pindexPrev);
            nBlockTime = ByteReverse(pblock->nTime);

            if (pblock->GetBlockTime() >= ((::int64_t)pblock->vtx[0].nTime + nMaxClockDrift))
            {
#ifdef _MSC_VER
//    #ifdef _DEBUG
                (void)printf(
                             "block drift too far behind, restarting miner.\n"
                            );
//    #endif
#endif
                break;  // need to update coinbase timestamp
            }
        }
    }   
    printf("CPUMiner stopped for proof-of-work\n");
}
//_____________________________________________________________________________

void static ThreadYacoinMiner(void* parg)
{
    CWallet* pwallet = (CWallet*)parg;  // what kind of c++ cast is this? 
    try
    {
        ++vnThreadsRunning[THREAD_MINER];
        YacoinMiner(pwallet);
        --vnThreadsRunning[THREAD_MINER];
    }
    catch (std::exception& e) 
    {
        --vnThreadsRunning[THREAD_MINER];
        PrintException(&e, "ThreadYacoinMiner()");
    } catch (...) 
    {
        --vnThreadsRunning[THREAD_MINER];
        PrintException(NULL, "ThreadYacoinMiner()");
    }
    nHPSTimerStart = 0;
    if (0 == vnThreadsRunning[THREAD_MINER] )
        dHashesPerSec = 0;
    printf("ThreadYacoinMiner exiting, %d thread%s remaining\n", 
           vnThreadsRunning[THREAD_MINER],
           (0 < vnThreadsRunning[THREAD_MINER])? 
           ((1 < vnThreadsRunning[THREAD_MINER])? "s" : "" ):
           "s"
          );
}
//_____________________________________________________________________________

// here we add the missing PoW mining code from 0.4.4
void GenerateYacoins(bool fGenerate, CWallet* pwallet)
{
    fGenerateBitcoins = fGenerate;
    nLimitProcessors = GetArg("-genproclimit", -1);
    if (nLimitProcessors == 0)
        fGenerateBitcoins = false;
    fLimitProcessors = (nLimitProcessors != -1);

    if (fGenerate)
    {
        int 
            nProcessors = boost::thread::hardware_concurrency();

        printf("%d processors\n", nProcessors);
        if (nProcessors < 1)
            nProcessors = 1;
        if (
            fLimitProcessors && 
            (nProcessors > nLimitProcessors)
           )
            nProcessors = nLimitProcessors;
        int 
            nAddThreads = nProcessors - vnThreadsRunning[THREAD_MINER];

        printf( "Starting %d YacoinMiner thread%s\n", 
                nAddThreads,
                (1 < nAddThreads)? "s": "" 
              );
        for (int i = 0; i < nAddThreads; ++i)
        {
            if (!NewThread(ThreadYacoinMiner, pwallet))
                printf("Error: NewThread(ThreadBitcoinMiner) failed\n");
            Sleep( nTenMilliseconds );
        }
    }
}
//_____________________________________________________________________________
//_____________________________________________________________________________
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
