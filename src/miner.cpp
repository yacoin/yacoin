// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "miner.h"

#ifdef _MSC_VER
#include <stdint.h>

#include <memory>

#include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_TXDB_H
#include "txdb-leveldb.h"
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

#include "policy/fees.h"
#include "net_processing.h"
#include <openssl/sha.h>

using std::auto_ptr;
using std::list;
using std::map;
using std::max;
using std::set;
using std::string;
using std::vector;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

extern unsigned int nMinerSleep;
int nBlocksToGenerate = -10;

int static FormatHashBlocks(void* pbuffer, unsigned int len) {
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

static const unsigned int pSHA256InitState[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit) {
  SHA256_CTX ctx;
  unsigned char data[64];

  SHA256_Init(&ctx);

  for (int i = 0; i < 16; ++i)
    ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

  for (int i = 0; i < 8; ++i) ctx.h[i] = ((uint32_t*)pinit)[i];

  SHA256_Update(&ctx, data, sizeof(data));
  for (int i = 0; i < 8; ++i) ((uint32_t*)pstate)[i] = ctx.h[i];
}

// Some explaining would be appreciated
class COrphan {
 public:
  CTransaction* ptx;
  set<uint256> setDependsOn;
  double dPriority;
  double dFeePerKb;

  COrphan(CTransaction* ptxIn) {
    ptx = ptxIn;
    dPriority = dFeePerKb = 0;
  }

  void print() const {
    LogPrintf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
              ptx->GetHash().ToString().substr(0, 10), dPriority,
              dFeePerKb);
    BOOST_FOREACH (uint256 hash, setDependsOn)
        LogPrintf("   setDependsOn %s\n", hash.ToString().substr(0, 10));
  }
};

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
uint32_t nLastCoinStakeSearchInterval = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare {
  bool byFee;

 public:
  TxPriorityCompare(bool _byFee) : byFee(_byFee) {}
  bool operator()(const TxPriority& a, const TxPriority& b) {
    if (byFee) {
      if (a.get<1>() == b.get<1>()) return a.get<0>() < b.get<0>();
      return a.get<1>() < b.get<1>();
    } else {
      if (a.get<0>() == b.get<0>()) return a.get<1>() < b.get<1>();
      return a.get<0>() < b.get<0>();
    }
  }
};

//_____________________________________________________________________________

class CdoTempoaryMockTime {
 private:
  CdoTempoaryMockTime(const CdoTempoaryMockTime&);
  CdoTempoaryMockTime& operator=(const CdoTempoaryMockTime&);

 public:
  CdoTempoaryMockTime() {
    if (false
        //((chainActive.Tip()->nTime < YACOIN_NEW_LOGIC_SWITCH_TIME) &&
        //!fTestNet )
    ) {
      SetMockTime((int64_t)(chainActive.Tip()->nTime + nOneMinuteInSeconds));
    }
  }

  ~CdoTempoaryMockTime() {
    if (false
        //((chainActive.Tip()->nTime < YACOIN_NEW_LOGIC_SWITCH_TIME) &&
        //!fTestNet )
    ) {
      SetMockTime(0);  // restores time to now
    }
  }
};
//_____________________________________________________________________________

/* NEW IMPLEMENTATION START */
BlockAssembler::BlockAssembler()
{
    // Largest block you're willing to create
    nBlockMaxSize = GetMaxSize(MAX_BLOCK_SIZE);

    // Maximum number of sig operations in a block you're willing to create
    nBlockMaxSigOps = GetMaxSize(MAX_BLOCK_SIGOPS);
}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockSigOpsCost = 100;
    nBlockSize = 1000;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockSize += iter->GetTxSize();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    if (fDebug && gArgs.GetBoolArg("-printpriority")) {
        LogPrintf("fee %s txid %s\n",
                CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (const CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareModifiedEntry()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < GetMinFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockSize >
                    nBlockMaxSize - 1000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, iter, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost)
{
    if ((nBlockSize + packageSize) >= nBlockMaxSize)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= nBlockMaxSigOps)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (const CTxMemPool::txiter it : package) {
        const CTransaction& tx = it->GetTx();
        if (!tx.IsFinal(nHeight))
            return false;
    }
    return true;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(CWallet* pwallet)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CTransaction txNew;  // this uses real time
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);

    CReserveKey reservekey(pwallet);
    txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;

    // Add coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Next block height
    CBlockIndex* pindexPrev = chainActive.Tip();
    nHeight = pindexPrev->nHeight + 1;

    // Block version
    if (chainActive.Genesis() &&
        (chainActive.Height() + 1) >= nMainnetNewLogicBlockNumber) {
      pblock->nVersion = VERSION_of_block_for_yac_05x_new;
    } else {
      pblock->nVersion = CURRENT_VERSION_of_block;
    }
    // here we can fiddle with time to try to make block generation easier

    // Add transaction to block
    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    int64_t nTime1 = GetTimeMicros();

    // Used for getmininginfo rpc
    nLastBlockTx = nBlockTx;
    nLastBlockSize = nBlockSize;

    if (fDebug && gArgs.GetBoolArg("-printpriority"))
        LogPrintf("CreateNewBlock (): total size %" PRI64u "\n", nBlockSize);

    // Fill in block header and subsidy for coinbase
    pblock->nBits = GetNextTargetRequired(pindexPrev, false);

    pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pblock->nBits);

    pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1,
                        pblock->GetMaxTransactionTime());
    pblock->nTime = max(pblock->GetBlockTime(),  // lo & behold this is nTime!?
                        pindexPrev->GetBlockTime() - nMaxClockDrift);
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    LogPrintf(
        "CreateNewBlock() packages: %.2fms (%d packages, %d updated "
        "descendants)\n",
        0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated);

    return std::move(pblocktemplate);
}

/* NEW IMPLEMENTATION END */

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev,
                         unsigned int& nExtraNonce) {
  // Update nExtraNonce
  static uint256 hashPrevBlock;
  if (hashPrevBlock != pblock->hashPrevBlock) {
    nExtraNonce = 0;
    hashPrevBlock = pblock->hashPrevBlock;
  }
  ++nExtraNonce;

  unsigned int nHeight =
      pindexPrev->nHeight +
      1;  // Height first in coinbase required for block.version=2

  pblock->vtx[0].vin[0].scriptSig =
      (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
  Yassert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);
  pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata,
                       char* phash1) {
  //
  // Pre-build hash buffers
  //
  struct {
    struct unnamed2 {
      int nVersion;
      uint256 hashPrevBlock;
      uint256 hashMerkleRoot;
      unsigned int nTime;
      unsigned int nBits;
      unsigned int nNonce;
    } block;
    unsigned char pchPadding0[64];
    uint256 hash1;
    unsigned char pchPadding1[64];
  } tmp;
  memset(&tmp, 0, sizeof(tmp));

  tmp.block.nVersion = pblock->nVersion;
  tmp.block.hashPrevBlock = pblock->hashPrevBlock;
  tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
  tmp.block.nTime = pblock->nTime;
  tmp.block.nBits = pblock->nBits;
  tmp.block.nNonce = pblock->nNonce;

  FormatHashBlocks(&tmp.block, sizeof(tmp.block));
  FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

  // Byte swap all the input buffer
  for (uint32_t i = 0; i < sizeof(tmp) / sizeof(uint32_t); ++i)
  // for (unsigned int i = 0; i < sizeof(tmp)/4; ++i)    // this is only true
  {  // if an unsigned int
     // is 32 bits!!?? What
     // if it is 64 bits???????
    ((uint32_t*)&tmp)[i] = ByteReverse(((uint32_t*)&tmp)[i]);
  }
  // Precalc the first half of the first hash, which stays constant
  SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

  memcpy(pdata, &tmp.block, 128);
  memcpy(phash1, &tmp.hash1, 64);
}

void FormatHashBuffers_64bit_nTime(char* pblock, char* pmidstate, char* pdata,
                                   char* phash1) {
  //
  // Pre-build hash buffers
  //
  struct {
    struct block_header block;
    unsigned char pchPadding0[64];
    uint256 hash1;
    unsigned char pchPadding1[64];
  } tmp;
  memset(&tmp, 0, sizeof(tmp));

  char* pblockData = (char*)&tmp.block;
  memcpy((void*)pblockData, (const void*)pblock, 68);
  memcpy((void*)(pblockData + 68), (const void*)(pblock + 72), 16);

  FormatHashBlocks(&tmp.block, sizeof(tmp.block));
  FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

  // Byte swap all the input buffer
  for (uint32_t i = 0; i < sizeof(tmp) / sizeof(uint32_t); ++i)
  // for (unsigned int i = 0; i < sizeof(tmp)/4; ++i)    // this is only true
  {  // if an unsigned int
     // is 32 bits!!?? What
     // if it is 64 bits???????
    ((uint32_t*)&tmp)[i] = ByteReverse(((uint32_t*)&tmp)[i]);
  }
  // tmp.block.nTime = (tmp.block.nTime & 0x00000000FFFFFFFF) << 32 |
  // (tmp.block.nTime & 0xFFFFFFFF00000000) >> 32;
  // Precalc the first half of the first hash, which stays constant
  SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

  memcpy(pdata, &tmp.block, 128);
  memcpy(phash1, &tmp.hash1, 64);
}

bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey) {
  uint256 hashBlock = pblock->GetHash();
  uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

  if (!pblock->IsProofOfWork())
    return error("CheckWork () : %s is not a proof-of-work block",
                 hashBlock.GetHex().c_str());

  if (hashBlock > hashTarget) {
    return error("CheckWork () : proof-of-work not meeting target");
  }

  //// debug print
  LogPrintf(
      "CheckWork () : new proof-of-work block found  \n"
      "hash: %s  \n"
      "target: %s\n",
      hashBlock.GetHex(), hashTarget.GetHex());
  pblock->print();
  LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));

  // Found a solution
  {
    LOCK(cs_main);
    if (pblock->hashPrevBlock != hashBestChain)
      return error("CheckWork () : generated block is stale");
  }
  // Remove key from key pool
  reservekey.KeepKey();

  // Track how many getdata requests this block gets
  {
    LOCK(wallet.cs_wallet);
    wallet.mapRequestCount[hashBlock] = 0;
  }

  // Process this block the same as if we had received it from another node
  MeasureTime processBlock;
  CValidationState state;
  if (!ProcessBlock(state, pblock, true, nullptr)) {
    processBlock.mEnd.stamp();
    LogPrintf("CheckWork(), total time for ProcessBlock = %lu us\n",
           processBlock.getExecutionTime());
    return error("CheckWork () : ProcessBlock, block not accepted");
  }
  processBlock.mEnd.stamp();
  LogPrintf("CheckWork(), total time for ProcessBlock = %lu us\n",
         processBlock.getExecutionTime());

  return true;
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
bool check_for_stop_mining(CBlockIndex* pindexPrev) {
  if ((pindexPrev != chainActive.Tip()) || !fGenerateBitcoins || fShutdown) {
#ifdef Yac1dot0
    LogPrintf(
        "new block or shutdown!\n"
        "");
#endif
    return true;
  }
  return false;
}

//_____________________________________________________________________________
static void YacoinMiner(CWallet* pwallet)  // here fProofOfStake is always false
{
  LogPrintf("CPUMiner started for proof-of-work\n");
  SetThreadPriority(THREAD_PRIORITY_LOWEST);

  // Make this thread recognisable as the mining thread
  RenameThread("yacoin-PoW-miner");

  // Each thread has its own key and counter
  CReserveKey reservekey(pwallet);

  unsigned int nExtraNonce = 0;

  while (fGenerateBitcoins && nBlocksToGenerate != 0) {
    while (IsInitialBlockDownload() ||
           (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0 && !fTestNet  // TestNet can mine stand alone!
            // could be that if there is more than one stand alone mining
            // forks on the blockchain can't be resolved?
            )) {
      Sleep(nMillisecondsPerSecond);
      if (fShutdown || !fGenerateBitcoins)  // someone shut off the miner
        break;
    }
    if (fShutdown || !fGenerateBitcoins)  // someone shut off the miner
      break;

    while (pwallet->IsLocked()) {
      strMintWarning = strMintMessage;
      Sleep(nMillisecondsPerSecond);
    }
    strMintWarning = "";
    //
    // Create new block
    //
    unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();

    CBlockIndex* pindexPrev = chainActive.Tip();

    // Create new block
    std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler().CreateNewBlock(pwallet));
    if (!pblocktemplate.get())
        return;
    CBlock *pblock = &pblocktemplate->block;
    if (!pblock)
        return;

    IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

    bool fYac1dot0BlockOrTx = false;
    if ((pindexPrev->nHeight + 1) >= nMainnetNewLogicBlockNumber) {
      fYac1dot0BlockOrTx = true;
    }
    LogPrintf("Running YACoinMiner with %" PRIszu
              " transaction"
              "%s"
              " in block (%u bytes)"
              "\n"
              "",
              pblock->vtx.size(), pblock->vtx.size() > 1 ? "s" : "",
              ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));
    //
    // Pre-build hash buffers
    //
    char pmidstatebuf[32 + 16];
    char* pmidstate = alignup<16>(pmidstatebuf);
    char pdatabuf[128 + 16];
    char* pdata = alignup<16>(pdatabuf);
    char phash1buf[64 + 16];
    char* phash1 = alignup<16>(phash1buf);

    FormatHashBuffers(pblock, pmidstate, pdata, phash1);

    ::int64_t& nBlockTime = *(::int64_t*)(pdata + 64 + 4);
    unsigned int& nBlockNonce = *(unsigned int*)(pdata + 64 + 16);

    Big.randomize_the_nonce(nBlockNonce);  // lazy initialization performed here

    //
    // Search
    //
    ::int64_t nStart = GetTime();

    uint256 hashTarget =
        (CBigNum().SetCompact(pblock->nBits)).getuint256();  // PoW hashTarget

    LogPrintf("Hash target %s""\n", hashTarget.GetHex().substr(0, 16));

    uint256 result;
    unsigned int nHashesDone = 0;

#ifndef _MSC_VER
    LogPrintf("Starting mining loop\n");
#endif
    while (fGenerateBitcoins && nBlocksToGenerate != 0) {
      unsigned int nNonceFound;

      nNonceFound =
          scanhash_scrypt((char*)&pblock->nVersion,
                          // max_nonce,
                          nHashesDone, UBEGIN(result),
                          GetNfactor(pblock->nTime, fYac1dot0BlockOrTx),
                          pindexPrev, &hashTarget);
      // Check if something found
      pblock->nNonce = nNonceFound;
#ifdef Yac1dot0
      LogPrintf(
          "hash count %d"
          "\n",
          nHashesDone);
#endif
      if (result <= hashTarget) {  // Found a solution
#ifdef _MSC_VER
#ifdef _DEBUG
        LogPrintf("target: %s\n", hashTarget.ToString());
        LogPrintf("result: %s\n", result.ToString());
#endif
#endif
        Yassert(result == pblock->GetHash());
        if (!pblock->SignBlock(*pwalletMain))  // wallet is locked
        {
          strMintWarning = strMintMessage;
          break;
        }
        strMintWarning = "";

        SetThreadPriority(THREAD_PRIORITY_NORMAL);
        if (CheckWork(pblock, *pwalletMain, reservekey)) {
            LogPrintf(
              "\nCPUMiner : proof-of-work block found \n"
              "%s"
              "\n\n\a"
              "",
              pblock->GetHash().ToString());
          if (nBlocksToGenerate > 0) {
            nBlocksToGenerate--;
            LogPrintf("Remaining blocks to mine %d\n", nBlocksToGenerate);
          }
        }
        SetThreadPriority(THREAD_PRIORITY_LOWEST);
        break;
      }
      // Meter hashes/sec
      static ::int64_t nHashCounter;

      if (0 == nHPSTimerStart) nHPSTimerStart = GetTimeMillis();
      nHashCounter += nHashesDone;
      nHashesDone = 0;

      ::int64_t nNow = GetTimeMillis();

      if ((nNow - nHPSTimerStart) >
          (40 * nMillisecondsPerSecond))  // no comment needed!
      {
        static CCriticalSection mining_stats;
        {
          LOCK(mining_stats);
          if ((nNow - nHPSTimerStart) > (30 * nMillisecondsPerSecond)) {
            static ::int64_t nLogTime;  // = 0
            // if (GetTime() - nLogTime > 30 * 60)
            if (GetTime() - nLogTime >
                30)  // 30 seconds always true the first time!
            {
              dHashesPerSec =
                  1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
              LogPrintf(
                  "\n"
                  "hashmeter %3d CPU%s %.1f hash/s\n",
                  vnThreadsRunning[THREAD_MINER],
                  (vnThreadsRunning[THREAD_MINER] > 1) ? "s" : "",
                  dHashesPerSec);
              if ((nStatisticsNumberOfBlocks > 0) &&
                  (nStatisticsNumberOfBlocks2000 > 0) &&
                  (nStatisticsNumberOfBlocks1000 > 0) &&
                  (nStatisticsNumberOfBlocks200 > 0) &&
                  (nStatisticsNumberOfBlocks100 > 0)) {
                LogPrintf("long average block period %" PRId64
                       " sec (divisor %d)\n"
                       "long average block period %" PRId64
                       " sec (divisor %d)\n"
                       "long average block period %" PRId64
                       " sec (divisor %d)\n"
                       "long average block period %" PRId64
                       " sec (divisor %d)\n"
                       "long average block period %" PRId64
                       " sec (divisor %d)\n"
                       "",
                       nLongAverageBP, nStatisticsNumberOfBlocks,
                       nLongAverageBP2000, nStatisticsNumberOfBlocks2000,
                       nLongAverageBP1000, nStatisticsNumberOfBlocks1000,
                       nLongAverageBP200, nStatisticsNumberOfBlocks200,
                       nLongAverageBP100, nStatisticsNumberOfBlocks100);
              }
              LogPrintf("\n");
              nHPSTimerStart = GetTimeMillis();
              nHashCounter = 0;
              nLogTime = GetTime();
            }
            Sleep(nOneMillisecond);
          }
        }
      }
      // Check for stop or if block needs to be rebuilt
      if (check_for_stop_mining(pindexPrev) || (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0 && !fTestNet))
        break;
      if (fLimitProcessors &&
          (vnThreadsRunning[THREAD_MINER] > nLimitProcessors)) {
        return;
      }

      // Update nTime every few seconds
      pblock->nTime = max(pindexPrev->GetMedianTimePast() + 1,
                          pblock->GetMaxTransactionTime());
      pblock->nTime = max(pblock->GetBlockTime(),
                          pindexPrev->GetBlockTime() - nMaxClockDrift);
      pblock->UpdateTime(pindexPrev);
      nBlockTime = ByteReverse(pblock->nTime);

      if (pblock->GetBlockTime() >=
          ((::int64_t)pblock->vtx[0].nTime + nMaxClockDrift)) {
#ifdef _MSC_VER
        //    #ifdef _DEBUG
        LogPrintf("block drift too far behind, restarting miner.\n");
//    #endif
#endif
        break;  // need to update coinbase timestamp
      }
    }
  }
  LogPrintf("CPUMiner stopped for proof-of-work\n");
}
//_____________________________________________________________________________

void static ThreadYacoinMiner(void* parg) {
  CWallet* pwallet = (CWallet*)parg;  // what kind of c++ cast is this?
  try {
    ++vnThreadsRunning[THREAD_MINER];
    YacoinMiner(pwallet);
    --vnThreadsRunning[THREAD_MINER];
  } catch (std::exception& e) {
    --vnThreadsRunning[THREAD_MINER];
    PrintException(&e, "ThreadYacoinMiner()");
  } catch (...) {
    --vnThreadsRunning[THREAD_MINER];
    PrintException(NULL, "ThreadYacoinMiner()");
  }
  nHPSTimerStart = 0;
  if (0 == vnThreadsRunning[THREAD_MINER]) dHashesPerSec = 0;
  LogPrintf("ThreadYacoinMiner exiting, %d thread%s remaining\n",
         vnThreadsRunning[THREAD_MINER],
         (0 < vnThreadsRunning[THREAD_MINER])
             ? ((1 < vnThreadsRunning[THREAD_MINER]) ? "s" : "")
             : "s");
}
//_____________________________________________________________________________

// here we add the missing PoW mining code from 0.4.4
void GenerateYacoins(bool fGenerate, CWallet* pwallet, int nblocks) {
  fGenerateBitcoins = fGenerate;
  nLimitProcessors = gArgs.GetArg("-genproclimit", -1);
  if (nLimitProcessors == 0) fGenerateBitcoins = false;
  fLimitProcessors = (nLimitProcessors != -1);

  if (fGenerate) {
    nBlocksToGenerate = nblocks;
    int nProcessors = boost::thread::hardware_concurrency();

    LogPrintf("%d processors\n", nProcessors);
    if (nProcessors < 1) nProcessors = 1;
    if (fLimitProcessors && (nProcessors > nLimitProcessors))
      nProcessors = nLimitProcessors;
    int nAddThreads = nProcessors - vnThreadsRunning[THREAD_MINER];

    LogPrintf("Starting %d YacoinMiner thread%s\n", nAddThreads,
           (1 < nAddThreads) ? "s" : "");
    for (int i = 0; i < nAddThreads; ++i) {
      if (!NewThread(ThreadYacoinMiner, pwallet))
        LogPrintf("Error: NewThread(ThreadBitcoinMiner) failed\n");
      Sleep(nTenMilliseconds);
    }

    while (nBlocksToGenerate > 0) {
      Sleep(nMillisecondsPerSecond);
    }
  }
}
//_____________________________________________________________________________
//_____________________________________________________________________________
#ifdef _MSC_VER
#include "msvc_warnings.pop.h"
#endif
