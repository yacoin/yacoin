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

bool CTxMemPool::accept(CValidationState &state, CTxDB& txdb, const CTransaction &tx, bool fCheckInputs,
                        bool* pfMissingInputs)
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
        std::map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
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

        /** YAC_TOKEN START */
        if (!AreTokensDeployed()) {
            for (auto out : tx.vout) {
                if (out.scriptPubKey.IsTokenScript())
                    printf("WARNING: bad-txns-contained-token-when-not-active\n");
            }
        }

        if (AreTokensDeployed()) {
            if (!CheckTxTokens(tx, state, mapInputs, GetCurrentTokenCache(), true, vReissueTokens))
                return error("%s: CheckTxTokens: %s, %s", __func__, tx.GetHash().ToString(),
                             FormatStateMessage(state));
        }
        /** YAC_TOKEN END */

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
    }

    // Store transaction in memory
    {
        LOCK(cs);
        if (ptxOld)
        {
            printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            ConnectedBlockTokenData connectedBlockData;
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
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

bool CTxMemPool::addUnchecked(const uint256& hash, const CTransaction &tx)
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
