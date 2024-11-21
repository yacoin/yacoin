#include "wallet.h"
#include "validation.h"
#include "txdb.h"
#include "tokens/tokens.h"
#ifdef QT_GUI
 #include "explorer.h"
#endif
#include "reverse_iterator.h"
#include "txmempool.h"

extern std::vector<CWallet*> vpwalletRegistered;
extern CChain chainActive;

bool isHardforkHappened()
{
    if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
    {
        return true;
    }
    else
    {
        return false;
    }
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTransactionRef& _tx, const CAmount& _nFee,
                                 int64_t _nTime, unsigned int _entryHeight,
                                 bool _spendsCoinbase, int64_t _sigOpsCost, LockPoints lp):
    tx(_tx), nFee(_nFee), nTime(_nTime), entryHeight(_entryHeight),
    spendsCoinbase(_spendsCoinbase), sigOpCost(_sigOpsCost), lockPoints(lp)
{
    nTxSize = tx->GetTotalSize();
    nUsageSize = RecursiveDynamicUsage(tx);

    nCountWithDescendants = 1;
    nSizeWithDescendants = GetTxSize();
    nModFeesWithDescendants = nFee;

    feeDelta = 0;

    nCountWithAncestors = 1;
    nSizeWithAncestors = GetTxSize();
    nModFeesWithAncestors = nFee;
    nSigOpCostWithAncestors = sigOpCost;
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTxMemPoolEntry& other)
{
    *this = other;
}

size_t CTxMemPoolEntry::GetTxSize() const
{
    return nTxSize;
}

void CTxMemPoolEntry::UpdateDescendantState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount)
{
    nSizeWithDescendants += modifySize;
    assert(int64_t(nSizeWithDescendants) > 0);
    nModFeesWithDescendants += modifyFee;
    nCountWithDescendants += modifyCount;
    assert(int64_t(nCountWithDescendants) > 0);
}

void CTxMemPoolEntry::UpdateAncestorState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount, int modifySigOps)
{
    nSizeWithAncestors += modifySize;
    assert(int64_t(nSizeWithAncestors) > 0);
    nModFeesWithAncestors += modifyFee;
    nCountWithAncestors += modifyCount;
    assert(int64_t(nCountWithAncestors) > 0);
    nSigOpCostWithAncestors += modifySigOps;
    assert(int(nSigOpCostWithAncestors) >= 0);
}

void CTxMemPoolEntry::UpdateFeeDelta(int64_t newFeeDelta)
{
    nModFeesWithDescendants += newFeeDelta - feeDelta;
    nModFeesWithAncestors += newFeeDelta - feeDelta;
    feeDelta = newFeeDelta;
}

void CTxMemPoolEntry::UpdateLockPoints(const LockPoints& lp)
{
    lockPoints = lp;
}

// Get parent of a transaction by using mapLinks
const CTxMemPool::setEntries & CTxMemPool::GetMemPoolParents(txiter entry) const
{
    assert (entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.parents;
}

// Get children of a transaction by using mapLinks
const CTxMemPool::setEntries & CTxMemPool::GetMemPoolChildren(txiter entry) const
{
    assert (entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.children;
}

// Update parent info of a transaction in mapLinks
void CTxMemPool::UpdateParent(txiter entry, txiter parent, bool add)
{
    setEntries s;
    if (add && mapLinks[entry].parents.insert(parent).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && mapLinks[entry].parents.erase(parent)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

// Update children info of a transaction in mapLinks
void CTxMemPool::UpdateChild(txiter entry, txiter child, bool add)
{
    setEntries s;
    if (add && mapLinks[entry].children.insert(child).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && mapLinks[entry].children.erase(child)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

bool CTxMemPool::CompareDepthAndScore(const uint256& hasha, const uint256& hashb)
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hasha);
    if (i == mapTx.end()) return false;
    indexed_transaction_set::const_iterator j = mapTx.find(hashb);
    if (j == mapTx.end()) return true;
    uint64_t counta = i->GetCountWithAncestors();
    uint64_t countb = j->GetCountWithAncestors();
    if (counta == countb) {
        return CompareTxMemPoolEntryByScore()(*i, *j);
    }
    return counta < countb;
}

namespace {
class DepthAndScoreComparator
{
public:
    bool operator()(const CTxMemPool::indexed_transaction_set::const_iterator& a, const CTxMemPool::indexed_transaction_set::const_iterator& b)
    {
        uint64_t counta = a->GetCountWithAncestors();
        uint64_t countb = b->GetCountWithAncestors();
        if (counta == countb) {
            return CompareTxMemPoolEntryByScore()(*a, *b);
        }
        return counta < countb;
    }
};
} // namespace

std::vector<CTxMemPool::indexed_transaction_set::const_iterator> CTxMemPool::GetSortedDepthAndScore() const
{
    std::vector<indexed_transaction_set::const_iterator> iters;
    // TODO: check this lock
//    AssertLockHeld(cs);

    iters.reserve(mapTx.size());

    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi) {
        iters.push_back(mi);
    }
    std::sort(iters.begin(), iters.end(), DepthAndScoreComparator());
    return iters;
}

CTxMemPool::CTxMemPool() : nTransactionsUpdated(0)
{
    _clear(); //lock free clear

    // Sanity checks off by default for performance, because otherwise
    // accepting transactions becomes O(N^2) where N is the number
    // of transactions in the pool
    nCheckFrequency = 0;
}

bool CTxMemPool::isSpent(const COutPoint& outpoint)
{
    LOCK(cs);
    return mapNextTx.count(outpoint);
}

// TODO: check this function
//void CTxMemPool::check(const CCoinsViewCache *pcoins) const
//{
//    if (nCheckFrequency == 0)
//        return;
//
//    if (GetRand(std::numeric_limits<uint32_t>::max()) >= nCheckFrequency)
//        return;
//
//    LogPrint(BCLog::MEMPOOL, "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());
//
//    uint64_t checkTotal = 0;
//    uint64_t innerUsage = 0;
//
//    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(pcoins));
//    const int64_t nSpendHeight = GetSpendHeight(mempoolDuplicate);
//
//    LOCK(cs);
//    std::list<const CTxMemPoolEntry*> waitingOnDependants;
//    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
//        unsigned int i = 0;
//        checkTotal += it->GetTxSize();
//        innerUsage += it->DynamicMemoryUsage();
//        const CTransaction& tx = it->GetTx();
//        txlinksMap::const_iterator linksiter = mapLinks.find(it);
//        assert(linksiter != mapLinks.end());
//        const TxLinks &links = linksiter->second;
//        innerUsage += memusage::DynamicUsage(links.parents) + memusage::DynamicUsage(links.children);
//        bool fDependsWait = false;
//        setEntries setParentCheck;
//        int64_t parentSizes = 0;
//        int64_t parentSigOpCost = 0;
//        for (const CTxIn &txin : tx.vin) {
//            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
//            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
//            if (it2 != mapTx.end()) {
//                const CTransaction& tx2 = it2->GetTx();
//                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
//                fDependsWait = true;
//                if (setParentCheck.insert(it2).second) {
//                    parentSizes += it2->GetTxSize();
//                    parentSigOpCost += it2->GetSigOpCost();
//                }
//            } else {
//                assert(pcoins->HaveCoin(txin.prevout));
//            }
//            // Check whether its inputs are marked in mapNextTx.
//            auto it3 = mapNextTx.find(txin.prevout);
//            assert(it3 != mapNextTx.end());
//            assert(it3->first == &txin.prevout);
//            assert(it3->second == &tx);
//            i++;
//        }
//        assert(setParentCheck == GetMemPoolParents(it));
//        // Verify ancestor state is correct.
//        setEntries setAncestors;
//        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
//        std::string dummy;
//        CalculateMemPoolAncestors(*it, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy);
//        uint64_t nCountCheck = setAncestors.size() + 1;
//        uint64_t nSizeCheck = it->GetTxSize();
//        CAmount nFeesCheck = it->GetModifiedFee();
//        int64_t nSigOpCheck = it->GetSigOpCost();
//
//        for (txiter ancestorIt : setAncestors) {
//            nSizeCheck += ancestorIt->GetTxSize();
//            nFeesCheck += ancestorIt->GetModifiedFee();
//            nSigOpCheck += ancestorIt->GetSigOpCost();
//        }
//
//        assert(it->GetCountWithAncestors() == nCountCheck);
//        assert(it->GetSizeWithAncestors() == nSizeCheck);
//        assert(it->GetSigOpCostWithAncestors() == nSigOpCheck);
//        assert(it->GetModFeesWithAncestors() == nFeesCheck);
//
//        // Check children against mapNextTx
//        CTxMemPool::setEntries setChildrenCheck;
//        auto iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetHash(), 0));
//        int64_t childSizes = 0;
//        for (; iter != mapNextTx.end() && iter->first->hash == it->GetTx().GetHash(); ++iter) {
//            txiter childit = mapTx.find(iter->second->GetHash());
//            assert(childit != mapTx.end()); // mapNextTx points to in-mempool transactions
//            if (setChildrenCheck.insert(childit).second) {
//                childSizes += childit->GetTxSize();
//            }
//        }
//        assert(setChildrenCheck == GetMemPoolChildren(it));
//        // Also check to make sure size is greater than sum with immediate children.
//        // just a sanity check, not definitive that this calc is correct...
//        assert(it->GetSizeWithDescendants() >= childSizes + it->GetTxSize());
//
//        if (fDependsWait)
//            waitingOnDependants.push_back(&(*it));
//        else {
//            CValidationState state;
//            bool fCheckResult = tx.IsCoinBase() ||
//                Consensus::CheckTxInputs(tx, state, mempoolDuplicate, nSpendHeight);
//            assert(fCheckResult);
//            UpdateCoins(tx, mempoolDuplicate, 1000000);
//        }
//    }
//    unsigned int stepsSinceLastRemove = 0;
//    while (!waitingOnDependants.empty()) {
//        const CTxMemPoolEntry* entry = waitingOnDependants.front();
//        waitingOnDependants.pop_front();
//        CValidationState state;
//        if (!mempoolDuplicate.HaveInputs(entry->GetTx())) {
//            waitingOnDependants.push_back(entry);
//            stepsSinceLastRemove++;
//            assert(stepsSinceLastRemove < waitingOnDependants.size());
//        } else {
//            bool fCheckResult = entry->GetTx().IsCoinBase() ||
//                Consensus::CheckTxInputs(entry->GetTx(), state, mempoolDuplicate, nSpendHeight);
//            assert(fCheckResult);
//            UpdateCoins(entry->GetTx(), mempoolDuplicate, 1000000);
//            stepsSinceLastRemove = 0;
//        }
//    }
//    for (auto it = mapNextTx.cbegin(); it != mapNextTx.cend(); it++) {
//        uint256 hash = it->second->GetHash();
//        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
//        const CTransaction& tx = it2->GetTx();
//        assert(it2 != mapTx.end());
//        assert(&tx == it->second);
//    }
//
//    assert(totalTxSize == checkTotal);
//    assert(innerUsage == cachedInnerUsage);
//}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 15 pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 15 * sizeof(void*)) * mapTx.size() + memusage::DynamicUsage(mapNextTx) + memusage::DynamicUsage(mapDeltas) + memusage::DynamicUsage(mapLinks) + memusage::DynamicUsage(vTxHashes) + cachedInnerUsage;
}

static TxMempoolInfo GetInfo(CTxMemPool::indexed_transaction_set::const_iterator it) {
    return TxMempoolInfo{it->GetSharedTx(), it->GetTime(), CFeeRate(it->GetFee(), it->GetTxSize()), it->GetModifiedFee() - it->GetFee()};
}

std::vector<TxMempoolInfo> CTxMemPool::infoAll() const
{
    LOCK(cs);
    auto iters = GetSortedDepthAndScore();

    std::vector<TxMempoolInfo> ret;
    ret.reserve(mapTx.size());
    for (auto it : iters) {
        ret.push_back(GetInfo(it));
    }

    return ret;
}

CTransaction CTxMemPool::get(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    return i->GetTx();
}

TxMempoolInfo CTxMemPool::info(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return TxMempoolInfo();
    return GetInfo(i);
}

void CTxMemPool::PrioritiseTransaction(const uint256& hash, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        CAmount &delta = mapDeltas[hash];
        delta += nFeeDelta;
        txiter it = mapTx.find(hash);
        if (it != mapTx.end()) {
            mapTx.modify(it, update_fee_delta(delta));
            // Now update all ancestors' modified fees with descendants
            setEntries setAncestors;
            uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
            std::string dummy;
            CalculateMemPoolAncestors(*it, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
            for (txiter ancestorIt : setAncestors) {
                mapTx.modify(ancestorIt, update_descendant_state(0, nFeeDelta, 0));
            }
            // Now update all descendants' modified fees with ancestors
            setEntries setDescendants;
            CalculateDescendants(it, setDescendants);
            setDescendants.erase(it);
            for (txiter descendantIt : setDescendants) {
                mapTx.modify(descendantIt, update_ancestor_state(0, nFeeDelta, 0, 0));
            }
            ++nTransactionsUpdated;
        }
    }
    LogPrintf("PrioritiseTransaction: %s feerate += %s\n", hash.ToString(), FormatMoney(nFeeDelta));
}

void CTxMemPool::ApplyDelta(const uint256 hash, CAmount &nFeeDelta) const
{
    LOCK(cs);
    std::map<uint256, CAmount>::const_iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const CAmount &delta = pos->second;
    nFeeDelta += delta;
}

void CTxMemPool::ClearPrioritisation(const uint256 hash)
{
    LOCK(cs);
    mapDeltas.erase(hash);
}

bool CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, setEntries &setAncestors, uint64_t limitAncestorCount, uint64_t limitAncestorSize, uint64_t limitDescendantCount, uint64_t limitDescendantSize, std::string &errString, bool fSearchForParents /* = true */) const
{
    LOCK(cs);

    setEntries parentHashes;
    const CTransaction &tx = entry.GetTx();

    if (fSearchForParents) {
        // Get parents of this transaction that are in the mempool
        // GetMemPoolParents() is only valid for entries in the mempool, so we
        // iterate mapTx to find parents.
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            txiter piter = mapTx.find(tx.vin[i].prevout.hash);
            if (piter != mapTx.end()) {
                parentHashes.insert(piter);
                if (parentHashes.size() + 1 > limitAncestorCount) {
                    errString = strprintf("too many unconfirmed parents [limit: %u]", limitAncestorCount);
                    return false;
                }
            }
        }
    } else {
        // If we're not searching for parents, we require this to be an
        // entry in the mempool already.
        txiter it = mapTx.iterator_to(entry);
        parentHashes = GetMemPoolParents(it);
    }

    size_t totalSizeWithAncestors = entry.GetTxSize();

    while (!parentHashes.empty()) {
        txiter stageit = *parentHashes.begin();

        setAncestors.insert(stageit);
        parentHashes.erase(stageit);
        totalSizeWithAncestors += stageit->GetTxSize();

        if (stageit->GetSizeWithDescendants() + entry.GetTxSize() > limitDescendantSize) {
            errString = strprintf("exceeds descendant size limit for tx %s [limit: %u]", stageit->GetTx().GetHash().ToString(), limitDescendantSize);
            return false;
        } else if (stageit->GetCountWithDescendants() + 1 > limitDescendantCount) {
            errString = strprintf("too many descendants for tx %s [limit: %u]", stageit->GetTx().GetHash().ToString(), limitDescendantCount);
            return false;
        } else if (totalSizeWithAncestors > limitAncestorSize) {
            errString = strprintf("exceeds ancestor size limit [limit: %u]", limitAncestorSize);
            return false;
        }

        const setEntries & setMemPoolParents = GetMemPoolParents(stageit);
        for (const txiter &phash : setMemPoolParents) {
            // If this is a new ancestor, add it.
            if (setAncestors.count(phash) == 0) {
                parentHashes.insert(phash);
            }
            if (parentHashes.size() + setAncestors.size() + 1 > limitAncestorCount) {
                errString = strprintf("too many unconfirmed ancestors [limit: %u]", limitAncestorCount);
                return false;
            }
        }
    }

    return true;
}

// Calculates descendants of entry that are not already in setDescendants, and adds to
// setDescendants. Assumes entryit is already a tx in the mempool and setMemPoolChildren
// is correct for tx and all descendants.
// Also assumes that if an entry is in setDescendants already, then all
// in-mempool descendants of it are already in setDescendants as well, so that we
// can save time by not iterating over those entries.
void CTxMemPool::CalculateDescendants(txiter entryit, setEntries &setDescendants)
{
    setEntries stage;
    if (setDescendants.count(entryit) == 0) {
        stage.insert(entryit);
    }
    // Traverse down the children of entry, only adding children that are not
    // accounted for in setDescendants already (because those children have either
    // already been walked, or will be walked in this iteration).
    while (!stage.empty()) {
        txiter it = *stage.begin();
        setDescendants.insert(it);
        stage.erase(it);

        const setEntries &setChildren = GetMemPoolChildren(it);
        for (const txiter &childiter : setChildren) {
            if (!setDescendants.count(childiter)) {
                stage.insert(childiter);
            }
        }
    }
}

void CTxMemPool::UpdateChildrenForRemoval(txiter it)
{
    const setEntries &setMemPoolChildren = GetMemPoolChildren(it);
    for (txiter updateIt : setMemPoolChildren) {
        UpdateParent(updateIt, it, false);
    }
}

void CTxMemPool::UpdateForRemoveFromMempool(const setEntries &entriesToRemove, bool updateDescendants)
{
    // For each entry, walk back all ancestors and decrement size associated with this
    // transaction
    const uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    if (updateDescendants) {
        // updateDescendants should be true whenever we're not recursively
        // removing a tx and all its descendants, eg when a transaction is
        // confirmed in a block.
        // Here we only update statistics and not data in mapLinks (which
        // we need to preserve until we're finished with all operations that
        // need to traverse the mempool).
        for (txiter removeIt : entriesToRemove) {
            setEntries setDescendants;
            CalculateDescendants(removeIt, setDescendants);
            setDescendants.erase(removeIt); // don't update state for self
            int64_t modifySize = -((int64_t)removeIt->GetTxSize());
            CAmount modifyFee = -removeIt->GetModifiedFee();
            int modifySigOps = -removeIt->GetSigOpCost();
            for (txiter dit : setDescendants) {
                mapTx.modify(dit, update_ancestor_state(modifySize, modifyFee, -1, modifySigOps));
            }
        }
    }
    for (txiter removeIt : entriesToRemove) {
        setEntries setAncestors;
        const CTxMemPoolEntry &entry = *removeIt;
        std::string dummy;
        // Since this is a tx that is already in the mempool, we can call CMPA
        // with fSearchForParents = false.  If the mempool is in a consistent
        // state, then using true or false should both be correct, though false
        // should be a bit faster.
        // However, if we happen to be in the middle of processing a reorg, then
        // the mempool can be in an inconsistent state.  In this case, the set
        // of ancestors reachable via mapLinks will be the same as the set of
        // ancestors whose packages include this transaction, because when we
        // add a new transaction to the mempool in addUnchecked(), we assume it
        // has no children, and in the case of a reorg where that assumption is
        // false, the in-mempool children aren't linked to the in-block tx's
        // until UpdateTransactionsFromBlock() is called.
        // So if we're being called during a reorg, ie before
        // UpdateTransactionsFromBlock() has been called, then mapLinks[] will
        // differ from the set of mempool parents we'd calculate by searching,
        // and it's important that we use the mapLinks[] notion of ancestor
        // transactions as the set of things to update for removal.
        CalculateMemPoolAncestors(entry, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
        // Note that UpdateAncestorsOf severs the child links that point to
        // removeIt in the entries for the parents of removeIt.
        UpdateAncestorsOf(false, removeIt, setAncestors);
    }
    // After updating all the ancestor sizes, we can now sever the link between each
    // transaction being removed and any mempool children (ie, update setMemPoolParents
    // for each direct child of a transaction being removed).
    for (txiter removeIt : entriesToRemove) {
        UpdateChildrenForRemoval(removeIt);
    }
}

void CTxMemPool::RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason) {
//    AssertLockHeld(cs);
    UpdateForRemoveFromMempool(stage, updateDescendants);
    for (const txiter& it : stage) {
        removeUnchecked(it, reason);
    }
}

// Update the given tx for any in-mempool descendants.
// Assumes that setMemPoolChildren is correct for the given tx and all
// descendants.
void CTxMemPool::UpdateForDescendants(txiter updateIt, cacheMap &cachedDescendants, const std::set<uint256> &setExclude)
{
    setEntries stageEntries, setAllDescendants;
    stageEntries = GetMemPoolChildren(updateIt);

    while (!stageEntries.empty()) {
        const txiter cit = *stageEntries.begin();
        setAllDescendants.insert(cit);
        stageEntries.erase(cit);
        const setEntries &setChildren = GetMemPoolChildren(cit);
        for (const txiter childEntry : setChildren) {
            cacheMap::iterator cacheIt = cachedDescendants.find(childEntry);
            if (cacheIt != cachedDescendants.end()) {
                // We've already calculated this one, just add the entries for this set
                // but don't traverse again.
                for (const txiter cacheEntry : cacheIt->second) {
                    setAllDescendants.insert(cacheEntry);
                }
            } else if (!setAllDescendants.count(childEntry)) {
                // Schedule for later processing
                stageEntries.insert(childEntry);
            }
        }
    }
    // setAllDescendants now contains all in-mempool descendants of updateIt.
    // Update and add to cached descendant map
    int64_t modifySize = 0;
    CAmount modifyFee = 0;
    int64_t modifyCount = 0;
    for (txiter cit : setAllDescendants) {
        if (!setExclude.count(cit->GetTx().GetHash())) {
            modifySize += cit->GetTxSize();
            modifyFee += cit->GetModifiedFee();
            modifyCount++;
            cachedDescendants[updateIt].insert(cit);
            // Update ancestor state for each descendant
            mapTx.modify(cit, update_ancestor_state(updateIt->GetTxSize(), updateIt->GetModifiedFee(), 1, updateIt->GetSigOpCost()));
        }
    }
    mapTx.modify(updateIt, update_descendant_state(modifySize, modifyFee, modifyCount));
}

// Used in case of reorg
// vHashesToUpdate is the set of transaction hashes from a disconnected block
// which has been re-added to the mempool.
// for each entry, look for descendants that are outside vHashesToUpdate, and
// add fee/size information for such descendants to the parent.
// for each such descendant, also update the ancestor state to include the parent.
void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<uint256> &vHashesToUpdate)
{
    LOCK(cs);
    // For each entry in vHashesToUpdate, store the set of in-mempool, but not
    // in-vHashesToUpdate transactions, so that we don't have to recalculate
    // descendants when we come across a previously seen entry.
    cacheMap mapMemPoolDescendantsToUpdate;

    // Use a set for lookups into vHashesToUpdate (these entries are already
    // accounted for in the state of their ancestors)
    std::set<uint256> setAlreadyIncluded(vHashesToUpdate.begin(), vHashesToUpdate.end());

    // Iterate in reverse, so that whenever we are looking at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    // This maximizes the benefit of the descendant cache and guarantees that
    // setMemPoolChildren will be updated, an assumption made in
    // UpdateForDescendants.
    for (const uint256 &hash : reverse_iterate(vHashesToUpdate)) {
        // we cache the in-mempool children to avoid duplicate updates
        setEntries setChildren;
        // calculate children from mapNextTx
        txiter it = mapTx.find(hash);
        if (it == mapTx.end()) {
            continue;
        }
        auto iter = mapNextTx.lower_bound(COutPoint(hash, 0));
        // First calculate the children, and update setMemPoolChildren to
        // include them, and update their setMemPoolParents to include this tx.
        for (; iter != mapNextTx.end() && iter->first->hash == hash; ++iter) {
            const uint256 &childHash = iter->second->GetHash();
            txiter childIter = mapTx.find(childHash);
            assert(childIter != mapTx.end());
            // We can skip updating entries we've encountered before or that
            // are in the block (which are already accounted for).
            if (setChildren.insert(childIter).second && !setAlreadyIncluded.count(childHash)) {
                UpdateChild(it, childIter, true);
                UpdateParent(childIter, it, true);
            }
        }
        UpdateForDescendants(it, mapMemPoolDescendantsToUpdate, setAlreadyIncluded);
    }
}

bool CTxMemPool::accept(CValidationState &state, CTxDB& txdb, const CTransaction &tx, bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    /** YAC_TOKEN START */
    std::vector<std::pair<std::string, uint256>> vReissueTokens;
    /** YAC_TOKEN END */

    if (tx.nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old && isHardforkHappened())
        return error("CTxMemPool::accept() : Not accept transaction with old version");

    if (!tx.CheckTransaction(state))
        return error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // ppcoin: coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return state.DoS(100, error("CTxMemPool::accept() : coinstake as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((::int64_t)tx.nLockTime > std::numeric_limits<int>::max())
        return error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    std::string strNonStd;
    if (!fTestNet && !tx.IsStandard(strNonStd))
        return error("CTxMemPool::accept() : nonstandard transaction (%s)", strNonStd.c_str());

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!tx.IsFinal())
        return error("CTxMemPool::accept() : non-final transaction");

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    if (exists(hash)) {
        return error("CTxMemPool::accept() : txn-already-in-mempool");
    }

    if (txdb.ContainsTx(hash))
        return false;

    // Check for conflicts with in-memory transactions
    std::set<uint256> setConflicts;
    {
        LOCK(cs); // protect pool.mapNextTx
        for (const CTxIn &txin : tx.vin)
        {
            auto itConflicting = mapNextTx.find(txin.prevout);
            if (itConflicting != mapNextTx.end())
            {
                const CTransaction *ptxConflicting = itConflicting->second;
                if (!setConflicts.count(ptxConflicting->GetHash()))
                {
                    // Disable replacement feature for now
                    return false;

                    // BELOW CODE ARE FOR Replace-by-fee (RBF) FEATURE
                    // Allow opt-out of transaction replacement by setting
                    // nSequence > MAX_BIP125_RBF_SEQUENCE (SEQUENCE_FINAL-2) on all inputs.
                    //
                    // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by
                    // non-replaceable transactions. All inputs rather than just one
                    // is for the sake of multi-party protocols, where we don't
                    // want a single party to be able to disable replacement.
                    //
                    // The opt-out ignores descendants as anyone relying on
                    // first-seen mempool behavior should be checking all
                    // unconfirmed ancestors anyway; doing otherwise is hopelessly
                    // insecure.
//                    bool fReplacementOptOut = true;
//                    if (fEnableReplacement)
//                    {
//                        for (const CTxIn &_txin : ptxConflicting->vin)
//                        {
//                            if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE)
//                            {
//                                fReplacementOptOut = false;
//                                break;
//                            }
//                        }
//                    }
//                    if (fReplacementOptOut) {
//                        return state.Invalid(false, REJECT_DUPLICATE, "txn-mempool-conflict");
//                    }

//                    setConflicts.insert(ptxConflicting->GetHash());
                }
            }
        }
    }


    LockPoints lp;
    MapPrevTx mapInputs;
    std::map<uint256, CTxIndex> mapUnused;
    bool fInvalid = false;
    // do all inputs exist?
    if (!tx.FetchInputs(state, txdb, mapUnused, false, false, mapInputs, fInvalid))
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
    if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
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
    // includes any fee deltas from PrioritiseTransaction
    ApplyDelta(hash, nFees);

    /** YAC_TOKEN START */
    if (!AreTokensDeployed()) {
        for (auto out : tx.vout) {
            if (out.scriptPubKey.IsTokenScript())
                LogPrintf("WARNING: bad-txns-contained-token-when-not-active\n");
        }
    }

    if (AreTokensDeployed()) {
        if (!CheckTxTokens(tx, state, mapInputs, GetCurrentTokenCache(), true, vReissueTokens))
            return error("%s: CheckTxTokens: %s, %s", __func__, tx.GetHash().ToString().c_str(),
                         FormatStateMessage(state).c_str());
    }
    /** YAC_TOKEN END */

    // Keep track of transactions that spend a coinbase, which we re-scan
    // during reorgs to ensure COINBASE_MATURITY is still met.
    bool fSpendsCoinbase = false;
    for (unsigned int i = 0; i < tx.vin.size(); ++i)
    {
        COutPoint
            prevout = tx.vin[i].prevout;
        CTransaction
            & txPrev = mapInputs[prevout.COutPointGetHash()].second;
        // If prev is coinbase or coinstake, check that it's matured
        if (txPrev.IsCoinBase())
        {
            fSpendsCoinbase = true;
            break;
        }
    }

    int64_t nSigOpsCost = tx.GetLegacySigOpCount();
    nSigOpsCost += tx.GetP2SHSigOpCount(mapInputs);
    CTxMemPoolEntry entry(std::make_shared<CTransaction>(tx), nFees, GetTime(), chainActive.Height(),
                          fSpendsCoinbase, nSigOpsCost, lp);

    // Calculate in-mempool ancestors, up to a limit.
    CTxMemPool::setEntries setAncestors;
    size_t nLimitAncestors = DEFAULT_ANCESTOR_LIMIT;
    size_t nLimitAncestorSize = DEFAULT_ANCESTOR_SIZE_LIMIT * 1000;
    size_t nLimitDescendants = DEFAULT_DESCENDANT_LIMIT;
    size_t nLimitDescendantSize = DEFAULT_DESCENDANT_SIZE_LIMIT * 1000;
    std::string errString;
    if (!CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
        return error("%s: too-long-mempool-chain: %s", __func__, errString.c_str());
    }

    // BELOW CODE ARE FOR Replace-by-fee (RBF) FEATURE
//    // A transaction that spends outputs that would be replaced by it is invalid. Now
//    // that we have the set of all ancestors we can detect this
//    // pathological case by making sure setConflicts and setAncestors don't
//    // intersect.
//    for (CTxMemPool::txiter ancestorIt : setAncestors)
//    {
//        const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
//        if (setConflicts.count(hashAncestor))
//        {
//            return state.DoS(10, false,
//                             REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
//                             strprintf("%s spends conflicting transaction %s",
//                                       hash.ToString(),
//                                       hashAncestor.ToString()));
//        }
//    }
//    // Check if it's economically rational to mine this transaction rather
//    // than the ones it replaces.
//    CAmount nConflictingFees = 0;
//    size_t nConflictingSize = 0;
//    uint64_t nConflictingCount = 0;
//    CTxMemPool::setEntries allConflicting;
//
//    // If we don't hold the lock allConflicting might be incomplete; the
//    // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
//    // mempool consistency for us.
//    LOCK(cs);
//    const bool fReplacementTransaction = setConflicts.size();
//    if (fReplacementTransaction)
//    {
//        CFeeRate newFeeRate(nFees, nSize);
//        std::set<uint256> setConflictsParents;
//        const int maxDescendantsToVisit = 100;
//        CTxMemPool::setEntries setIterConflicting;
//        for (const uint256 &hashConflicting : setConflicts)
//        {
//            CTxMemPool::txiter mi = mapTx.find(hashConflicting);
//            if (mi == mapTx.end())
//                continue;
//
//            // Save these to avoid repeated lookups
//            setIterConflicting.insert(mi);
//
//            // Don't allow the replacement to reduce the feerate of the
//            // mempool.
//            //
//            // We usually don't want to accept replacements with lower
//            // feerates than what they replaced as that would lower the
//            // feerate of the next block. Requiring that the feerate always
//            // be increased is also an easy-to-reason about way to prevent
//            // DoS attacks via replacements.
//            //
//            // The mining code doesn't (currently) take children into
//            // account (CPFP) so we only consider the feerates of
//            // transactions being directly replaced, not their indirect
//            // descendants. While that does mean high feerate children are
//            // ignored when deciding whether or not to replace, we do
//            // require the replacement to pay more overall fees too,
//            // mitigating most cases.
//            CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
//            if (newFeeRate <= oldFeeRate)
//            {
//                return state.DoS(0, false,
//                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
//                        strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
//                              hash.ToString(),
//                              newFeeRate.ToString(),
//                              oldFeeRate.ToString()));
//            }
//
//            for (const CTxIn &txin : mi->GetTx().vin)
//            {
//                setConflictsParents.insert(txin.prevout.hash);
//            }
//
//            nConflictingCount += mi->GetCountWithDescendants();
//        }
//        // This potentially overestimates the number of actual descendants
//        // but we just want to be conservative to avoid doing too much
//        // work.
//        if (nConflictingCount <= maxDescendantsToVisit) {
//            // If not too many to replace, then calculate the set of
//            // transactions that would have to be evicted
//            for (CTxMemPool::txiter it : setIterConflicting) {
//                CalculateDescendants(it, allConflicting);
//            }
//            for (CTxMemPool::txiter it : allConflicting) {
//                nConflictingFees += it->GetModifiedFee();
//                nConflictingSize += it->GetTxSize();
//            }
//        } else {
//            return state.DoS(0, false,
//                    REJECT_NONSTANDARD, "too many potential replacements", false,
//                    strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
//                        hash.ToString(),
//                        nConflictingCount,
//                        maxDescendantsToVisit));
//        }
//
//        for (unsigned int j = 0; j < tx.vin.size(); j++)
//        {
//            // We don't want to accept replacements that require low
//            // feerate junk to be mined first. Ideally we'd keep track of
//            // the ancestor feerates and make the decision based on that,
//            // but for now requiring all new inputs to be confirmed works.
//            if (!setConflictsParents.count(tx.vin[j].prevout.hash))
//            {
//                // Rather than check the UTXO set - potentially expensive -
//                // it's cheaper to just check if the new input refers to a
//                // tx that's in the mempool.
//                if (pool.mapTx.find(tx.vin[j].prevout.hash) != pool.mapTx.end())
//                    return state.DoS(0, false,
//                                     REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
//                                     strprintf("replacement %s adds unconfirmed input, idx %d",
//                                              hash.ToString(), j));
//            }
//        }
//
//        // The replacement must pay greater fees than the transactions it
//        // replaces - if we did the bandwidth used by those conflicting
//        // transactions would not be paid for.
//        if (nFees < nConflictingFees)
//        {
//            return state.DoS(0, false,
//                             REJECT_INSUFFICIENTFEE, "insufficient fee", false,
//                             strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
//                                      hash.ToString(), FormatMoney(nFees), FormatMoney(nConflictingFees)));
//        }
//
//        // Finally in addition to paying more fees than the conflicts the
//        // new transaction must pay for its own bandwidth.
//        CAmount nDeltaFees = nFees - nConflictingFees;
//        if (nDeltaFees < ::incrementalRelayFee.GetFee(nSize))
//        {
//            return state.DoS(0, false,
//                    REJECT_INSUFFICIENTFEE, "insufficient fee", false,
//                    strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
//                          hash.ToString(),
//                          FormatMoney(nDeltaFees),
//                          FormatMoney(::incrementalRelayFee.GetFee(nSize))));
//        }
//    }

    // Check against previous transactions
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.
    if (
        !tx.ConnectInputs(state,
                          txdb,
                          mapInputs,
                          mapUnused,
                          CDiskTxPos(1,1,1),
                          chainActive.Tip(),
                          false,
                          false,
                          true,
                          SIG_SWITCH_TIME < tx.nTime ? STRICT_FLAGS : SOFT_FLAGS
                         )
       )
    {
        return error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
    }

    // BELOW CODE ARE FOR Replace-by-fee (RBF) FEATURE
//    // Remove conflicting transactions from the mempool
//    for (const CTxMemPool::txiter it : allConflicting)
//    {
//        LogPrint(BCLog::MEMPOOL, "replacing tx %s with %s for %s BTC additional fees, %d delta bytes\n",
//                it->GetTx().GetHash().ToString(),
//                hash.ToString(),
//                FormatMoney(nModifiedFees - nConflictingFees),
//                (int)nSize - (int)nConflictingSize);
//        if (plTxnReplaced)
//            plTxnReplaced->push_back(it->GetSharedTx());
//    }
//    RemoveStaged(allConflicting, false, MemPoolRemovalReason::REPLACED);

    // Store transaction in memory
    {
        LOCK(cs);
        addUnchecked(hash, entry, setAncestors);
    }

    // TODO: Add memory address index
//    if (fAddressIndex) {
//        pool.addAddressIndex(entry, view);
//    }

    /** YAC_TOKEN START */
    if (AreTokensDeployed()) {
        for (auto out : vReissueTokens) {
            mapReissuedTokens.insert(out);
            mapReissuedTx.insert(std::make_pair(out.second, out.first));
        }
        for (auto out : tx.vout) {
            if (out.scriptPubKey.IsTokenScript()) {
                CTokenOutputEntry data;
                if (!GetTokenData(out.scriptPubKey, data))
                    continue;
                if (data.type == TX_NEW_TOKEN && !IsTokenNameAnOwner(data.tokenName)) {
                    mapTokenToHash[data.tokenName] = hash;
                    mapHashToToken[hash] = data.tokenName;
                }
            }
        }
    }
    /** YAC_TOKEN END */

    // BELOW CODE ARE FOR Replace-by-fee (RBF) FEATURE
    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
//    if (ptxOld)
//        EraseFromWallets(ptxOld->GetHash());

    LogPrintf("CTxMemPool::accept() : accepted %s (poolsz %" PRIszu ")\n",
           hash.ToString().substr(0,10),
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

// Update ancestors of a mempool entry to add/remove it as a descendant transaction.
void CTxMemPool::UpdateAncestorsOf(bool add, txiter it, setEntries &setAncestors)
{
    setEntries parentIters = GetMemPoolParents(it);
    // add or remove this tx as a child of each parent
    for (txiter piter : parentIters) {
        UpdateChild(piter, it, add);
    }
    const int64_t updateCount = (add ? 1 : -1);
    const int64_t updateSize = updateCount * it->GetTxSize();
    const CAmount updateFee = updateCount * it->GetModifiedFee();
    for (txiter ancestorIt : setAncestors) {
        mapTx.modify(ancestorIt, update_descendant_state(updateSize, updateFee, updateCount));
    }
}

// Update ancestor state for a mempool entry
void CTxMemPool::UpdateEntryForAncestors(txiter it, const setEntries &setAncestors)
{
    int64_t updateCount = setAncestors.size();
    int64_t updateSize = 0;
    CAmount updateFee = 0;
    int64_t updateSigOpsCost = 0;
    for (txiter ancestorIt : setAncestors) {
        updateSize += ancestorIt->GetTxSize();
        updateFee += ancestorIt->GetModifiedFee();
        updateSigOpsCost += ancestorIt->GetSigOpCost();
    }
    mapTx.modify(it, update_ancestor_state(updateSize, updateFee, updateCount, updateSigOpsCost));
}

bool CTxMemPool::addUnchecked(const uint256&hash, const CTxMemPoolEntry &entry)
{
    LOCK(cs);
    setEntries setAncestors;
    uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    CalculateMemPoolAncestors(entry, setAncestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy);
    return addUnchecked(hash, entry, setAncestors);
}

bool CTxMemPool::addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, setEntries &setAncestors)
{
//    NotifyEntryAdded(entry.GetSharedTx());
    // Add to memory pool without checking anything.
    // Used by AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    LOCK(cs);
    indexed_transaction_set::iterator newit = mapTx.insert(entry).first;
    mapLinks.insert(make_pair(newit, TxLinks()));

    // Update transaction for any feeDelta created by PrioritiseTransaction
    // TODO: refactor so that the fee delta is calculated before inserting
    // into mapTx.
    std::map<uint256, CAmount>::const_iterator pos = mapDeltas.find(hash);
    if (pos != mapDeltas.end()) {
        const CAmount &delta = pos->second;
        if (delta) {
            mapTx.modify(newit, update_fee_delta(delta));
        }
    }

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction& tx = newit->GetTx();
    std::set<uint256> setParentTransactions;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        mapNextTx.insert(std::make_pair(&tx.vin[i].prevout, &tx));
        setParentTransactions.insert(tx.vin[i].prevout.hash);
    }
    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will call UpdateTransactionsFromBlock
    // to clean up the mess we're leaving here.

    // Update ancestors with information about this tx
    for (const uint256 &phash : setParentTransactions) {
        txiter pit = mapTx.find(phash);
        if (pit != mapTx.end()) {
            UpdateParent(newit, pit, true);
        }
    }
    UpdateAncestorsOf(true, newit, setAncestors);
    UpdateEntryForAncestors(newit, setAncestors);

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();

    vTxHashes.emplace_back(tx.GetHash(), newit);
    newit->vTxHashesIdx = vTxHashes.size() - 1;

    return true;
}

void CTxMemPool::removeRecursive(const CTransaction &origTx, MemPoolRemovalReason reason)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        setEntries txToRemove;
        txiter origit = mapTx.find(origTx.GetHash());
        if (origit != mapTx.end()) {
            txToRemove.insert(origit);
        } else {
            // When recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                auto it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txiter nextit = mapTx.find(it->second->GetHash());
                assert(nextit != mapTx.end());
                txToRemove.insert(nextit);
            }
        }
        setEntries setAllRemoves;
        for (txiter it : txToRemove) {
            CalculateDescendants(it, setAllRemoves);
        }

        RemoveStaged(setAllRemoves, false, reason);
    }
}

// Used in case of reorg to remove any now-immature tx and any no-longer-final timelock tx
void CTxMemPool::removeForReorg(unsigned int nMemPoolHeight, int flags)
{
    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    LOCK(cs);
    setEntries txToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        const CTransaction& tx = it->GetTx();
        LockPoints lp = it->GetLockPoints();
        bool validLP =  TestLockPointValidity(&lp);
        if (!tx.IsFinal() || !CheckSequenceLocks(tx, flags, &lp, validLP)) {
            // Note if CheckSequenceLocks fails the LockPoints may still be invalid
            // So it's critical that we remove the tx and not depend on the LockPoints.
            txToRemove.insert(it);
        } else if (it->GetSpendsCoinbase()) {
            // Fetch all inputs
            MapPrevTx mapInputs;
            std::map<uint256, CTxIndex> mapUnused;
            bool fInvalid = false;
            CValidationState stateDummy;
            CTxDB txdb;
            if (!tx.FetchInputs(stateDummy, txdb, mapUnused, false, false, mapInputs, fInvalid))
            {
                LogPrintf("TxMemPool::removeForReorg : Can't FetchInputs for tx %s\n", tx.GetHash().ToString().substr(0,10));
                continue;
            }

            for (const CTxIn& txin : tx.vin) {
                indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
                if (it2 != mapTx.end())
                    continue;
                COutPoint
                    prevout = txin.prevout;
                CTxIndex
                    & txindex = mapInputs[prevout.COutPointGetHash()].first;
                CTransaction
                    & txPrev = mapInputs[prevout.COutPointGetHash()].second;
                // txindex.vSpent[prevout.COutPointGet_n()].IsNull() = true => not spent
                if (!txindex.vSpent[prevout.COutPointGet_n()].IsNull() || (txPrev.IsCoinBase() && ((signed long)nMemPoolHeight) - txindex.GetDepthInMainChain() < GetCoinbaseMaturity())) {
                    txToRemove.insert(it);
                    break;
                }
            }
        }
        if (!validLP) {
            mapTx.modify(it, update_lock_points(lp));
        }
    }
    setEntries setAllRemoves;
    for (txiter it : txToRemove) {
        CalculateDescendants(it, setAllRemoves);
    }
    RemoveStaged(setAllRemoves, false, MemPoolRemovalReason::REORG);
}

void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason)
{
//    NotifyEntryRemoved(it->GetSharedTx(), reason);
    const uint256 hash = it->GetTx().GetHash();
    for (const CTxIn& txin : it->GetTx().vin)
        mapNextTx.erase(txin.prevout);

    if (vTxHashes.size() > 1) {
        vTxHashes[it->vTxHashesIdx] = std::move(vTxHashes.back());
        vTxHashes[it->vTxHashesIdx].second->vTxHashesIdx = it->vTxHashesIdx;
        vTxHashes.pop_back();
        if (vTxHashes.size() * 2 < vTxHashes.capacity())
            vTxHashes.shrink_to_fit();
    } else
        vTxHashes.clear();

    totalTxSize -= it->GetTxSize();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    cachedInnerUsage -= memusage::DynamicUsage(mapLinks[it].parents) + memusage::DynamicUsage(mapLinks[it].children);
    mapLinks.erase(it);
    mapTx.erase(it);
    nTransactionsUpdated++;

    /** YAC_TOKEN START */
    if (AreTokensDeployed()) {
        // If the transaction being removed from the mempool is locking other reissues. Free them
        if (mapReissuedTx.count(hash)) {
            if (mapReissuedTokens.count(mapReissuedTx.at(hash))) {
                mapReissuedTokens.erase(mapReissuedTx.at((hash)));
                mapReissuedTx.erase(hash);
            }
        }

        // Erase from the token mempool maps if they match txid
        if (mapHashToToken.count(hash)) {
            mapTokenToHash.erase(mapHashToToken.at(hash));
            mapHashToToken.erase(hash);
        }
    }
    /** YAC_TOKEN END */
}

void CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    for (const CTxIn &txin : tx.vin) {
        auto it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second;
            if (txConflict != tx)
            {
                ClearPrioritisation(txConflict.GetHash());
                removeRecursive(txConflict, MemPoolRemovalReason::CONFLICT);
            }
        }
    }
}

/**
 * Called when a block is connected. Removes from mempool.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransaction>& vtx, ConnectedBlockTokenData& connectedBlockData)
{
    LOCK(cs);

    for (const auto& tx : vtx)
    {
        txiter it = mapTx.find(tx.GetHash());
        if (it != mapTx.end()) {
            setEntries stage;
            stage.insert(it);
            RemoveStaged(stage, true, MemPoolRemovalReason::BLOCK);
        }
        removeConflicts(tx);
        ClearPrioritisation(tx.GetHash());
    }

    /** YAC_TOKEN START */
    if (AreTokensDeployed()) {
        // Get the newly added assets, and make sure they are in the entries
        std::vector<const CTxMemPoolEntry*> entries;
        std::vector<CTransaction> trans;
        for (auto it : connectedBlockData.newTokensToAdd) {
            if (mapTokenToHash.count(it.token.strName)) {
                indexed_transaction_set::iterator i = mapTx.find(mapTokenToHash.at(it.token.strName));
                if (i != mapTx.end()) {
                    entries.push_back(&*i);
                    trans.emplace_back(i->GetTx());
                }
            }
        }

        // Remove newly added asset issue transactions from the mempool if they haven't been removed already
        for (auto tx : trans)
        {
            txiter it = mapTx.find(tx.GetHash());
            if (it != mapTx.end()) {
                setEntries stage;
                stage.insert(it);
                RemoveStaged(stage, true, MemPoolRemovalReason::BLOCK);
            }
            removeConflicts(tx);
            ClearPrioritisation(tx.GetHash());
        }
    }
    /** YAC_TOKEN END */
}

void CTxMemPool::_clear()
{
    mapLinks.clear();
    mapTx.clear();
    mapNextTx.clear();
    totalTxSize = 0;
    cachedInnerUsage = 0;
    ++nTransactionsUpdated;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    _clear();
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    LOCK(cs);
    auto iters = GetSortedDepthAndScore();

    vtxid.clear();
    vtxid.reserve(mapTx.size());

    for (auto it : iters) {
        vtxid.push_back(it->GetTx().GetHash());
    }
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    LOCK(cs);
    nTransactionsUpdated += n;
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(tx.vin[i].prevout.hash))
            return false;
    return true;
}

bool CTxMemPool::TransactionWithinChainLimit(const uint256& txid, size_t chainLimit) const {
    LOCK(cs);
    auto it = mapTx.find(txid);
    return it == mapTx.end() || (it->GetCountWithAncestors() < chainLimit &&
       it->GetCountWithDescendants() < chainLimit);
}
