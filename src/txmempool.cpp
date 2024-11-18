#include "txmempool.h"
#include "wallet.h"
#include "validation.h"
#include "txdb.h"
#include "tokens/tokens.h"
#ifdef QT_GUI
 #include "explorer.h"
#endif

extern std::vector<CWallet*> vpwalletRegistered;
extern CChain chainActive;

CTxMemPoolEntry::CTxMemPoolEntry(const CTransactionRef& _tx, const CAmount& _nFee,
                                 int64_t _nTime, unsigned int _entryHeight,
                                 bool _spendsCoinbase, LockPoints lp):
    tx(_tx), nFee(_nFee), nTime(_nTime), entryHeight(_entryHeight),
    spendsCoinbase(_spendsCoinbase), lockPoints(lp)
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

void CTxMemPoolEntry::UpdateAncestorState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount)
{
    nSizeWithAncestors += modifySize;
    assert(int64_t(nSizeWithAncestors) > 0);
    nModFeesWithAncestors += modifyFee;
    nCountWithAncestors += modifyCount;
    assert(int64_t(nCountWithAncestors) > 0);
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

const CTxMemPool::setEntries & CTxMemPool::GetMemPoolParents(txiter entry) const
{
    assert (entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.parents;
}

const CTxMemPool::setEntries & CTxMemPool::GetMemPoolChildren(txiter entry) const
{
    assert (entry != mapTx.end());
    txlinksMap::const_iterator it = mapLinks.find(entry);
    assert(it != mapLinks.end());
    return it->second.children;
}

void CTxMemPool::UpdateParent(txiter entry, txiter parent, bool add)
{
    setEntries s;
    if (add && mapLinks[entry].parents.insert(parent).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && mapLinks[entry].parents.erase(parent)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

void CTxMemPool::UpdateChild(txiter entry, txiter child, bool add)
{
    setEntries s;
    if (add && mapLinks[entry].children.insert(child).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && mapLinks[entry].children.erase(child)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
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

void CTxMemPool::_clear()
{
    mapLinks.clear();
    mapTx.clear();
    mapNextTx.clear();
    totalTxSize = 0;
    cachedInnerUsage = 0;
//    lastRollingFeeUpdate = GetTime();
//    blockSinceLastRollingFeeBump = false;
//    rollingMinimumFeeRate = 0;
    ++nTransactionsUpdated;
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

CTransaction CTxMemPool::get(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetTx();
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

void CTxMemPool::RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason) {
//    AssertLockHeld(cs);
    UpdateForRemoveFromMempool(stage, updateDescendants);
    for (const txiter& it : stage) {
        removeUnchecked(it, reason);
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
                printf("WARNING: bad-txns-contained-token-when-not-active\n");
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

    CTxMemPoolEntry entry(std::make_shared<CTransaction>(tx), nFees, GetTime(), chainActive.Height(),
                          fSpendsCoinbase, lp);

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

// NEW
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

void CTxMemPool::UpdateEntryForAncestors(txiter it, const setEntries &setAncestors)
{
    int64_t updateCount = setAncestors.size();
    int64_t updateSize = 0;
    CAmount updateFee = 0;
    for (txiter ancestorIt : setAncestors) {
        updateSize += ancestorIt->GetTxSize();
        updateFee += ancestorIt->GetModifiedFee();
    }
    mapTx.modify(it, update_ancestor_state(updateSize, updateFee, updateCount));
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

void CTxMemPool::removeUnchecked(const CTransaction& tx, const uint256& hash)
{
    for (const CTxIn& txin :tx.vin)
    {
        mapNextTx.erase(txin.prevout);
    }
    mapTx.erase(hash);
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

void CTxMemPool::remove(const CTransaction& tx)
{
    ConnectedBlockTokenData connectedBlockData;
    std::vector<CTransaction> vtx = {tx};
    remove(vtx, connectedBlockData);
}

void CTxMemPool::remove(const std::vector<CTransaction>& vtx)
{
    ConnectedBlockTokenData connectedBlockData;
    remove(vtx, connectedBlockData);
}

void CTxMemPool::remove(const std::vector<CTransaction>& vtx, ConnectedBlockTokenData& connectedBlockData)
{
    // Remove transaction from memory pool
    for(const CTransaction& tx : vtx)
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            removeUnchecked(tx, hash);
        }
    }

    /** YAC_TOKEN START */
    if (AreTokensDeployed()) {
        // Remove newly added token issue transactions from the mempool if they haven't been removed already    std::vector<CTransaction> trans;
        for (auto it : connectedBlockData.newTokensToAdd) {
            if (mapTokenToHash.count(it.token.strName)) {
                const uint256& hash = mapTokenToHash.at(it.token.strName);
                auto itMapTx = mapTx.find(hash);
                if (itMapTx != mapTx.end()) {
                    removeUnchecked(itMapTx->second, hash);
                }
            }
        }
    }
    /** YAC_TOKEN END */
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
    for (std::map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    nTransactionsUpdated += n;
}

