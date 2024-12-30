// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokens/tokens.h"
#include "primitives/transaction.h"
#include "txdb.h"
#include "wallet.h"
#include "policy/fees.h"

#include <map>

using std::vector;
using std::map;
using std::set;

void CTransaction::SetNull()
{
	// TODO: Need update for mainet
	if (chainActive.Height() != -1 && chainActive.Genesis() && (chainActive.Height() + 1) >= nMainnetNewLogicBlockNumber)
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
}

bool CTransaction::IsFinal(int nBlockHeight, ::int64_t nBlockTime) const
{
    // Time based nLockTime implemented in 0.1.6
    if (nLockTime == 0)
        return true;
    if (nBlockHeight == 0)
        nBlockHeight = chainActive.Height() + 1;
    if (nBlockTime == 0)
        nBlockTime = GetAdjustedTime();
    if ((::int64_t)nLockTime < ((::int64_t)nLockTime < LOCKTIME_THRESHOLD ? (::int64_t)nBlockHeight : nBlockTime))
        return true;
    BOOST_FOREACH(const CTxIn& txin, vin)
        if (!txin.IsFinal())
            return false;
    return true;
}

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

bool CTransaction::ReadFromDisk(CDiskTxPos pos, FILE** pfileRet)
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

bool CTransaction::IsStandard(std::string& strReason) const
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
    for (const CTxIn& txin : vin)
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
//        if (!txin.scriptSig.HasCanonicalPushes()) {
//            strReason = "txin-scriptsig-not-canonicalpushes";
//            return false;
//        }
    }

    for (const CTxOut& txout : vout) {
        if (!::IsStandard(txout.scriptPubKey, whichType)) {
            strReason = "scriptpubkey";
            return false;
        }
        if (whichType == TX_NULL_DATA)
            nDataOut++;
        else if (txout.nValue == 0 && !txout.scriptPubKey.IsTokenScript())
        {
            strReason = "txout-value=0";
            return false;
        }
//        else if (!txout.scriptPubKey.HasCanonicalPushes())
//        {
//            strReason = "txout-scriptsig-not-canonicalpushes";
//            return false;
//        }
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        strReason = "multi-op-return";
        return false;
    }

    return true;
}

//
// Check transaction inputs to mitigate two
// potential denial-of-service attacks:
//
// 1. scriptSigs with extra data stuffed into them,
//    not consumed by scriptPubKey (or P2SH script)
// 2. P2SH scripts with a crazy number of expensive
//    CHECKSIG/CHECKMULTISIG operations
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
        {
            return false;
        }
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
        {
            return false;
        }

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig
        // IsStandard() will have already returned false
        // and this method isn't called.
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, vin[i].scriptSig, *this, i, false, 0))
        {
            return false;
        }

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
            {
                return false;
            }
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (Solver(subscript, whichType2, vSolutions2))
            {
                int tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
                if (tmpExpected < 0)
                {
                    return false;
                }
                nArgsExpected += tmpExpected;
            }
            else
            {
                // Any other Script with less than 15 sigops OK:
                unsigned int sigops = subscript.GetSigOpCount(true);
                // ... extra data left on the stack after execution is OK, too:
                return (sigops <= MAX_P2SH_SIGOPS);
            }
        }

        if (stack.size() != (unsigned int)nArgsExpected)
        {
            return false;
        }
    }

    return true;
}

unsigned int
CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    for (const auto& txin : vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

bool CTransaction::CheckTransaction(CValidationState &state) const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return state.DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty())
        return state.DoS(10, error("CTransaction::CheckTransaction() : vout empty"));
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > GetMaxSize(MAX_BLOCK_SIZE))
        return state.DoS(100, error("CTransaction::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    ::int64_t
        nValueOut = 0;

    /** YAC_TOKEN START */
    std::set<std::string> setTokenTransferNames;
    /** YAC_TOKEN END */

    // Check transaction output
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut
            & txout = vout[i];

        if (txout.IsEmpty() && !IsCoinBase() && !IsCoinStake())
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout empty for user transaction"));

        if (txout.nValue < 0)
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout.nValue is negative"));
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout.nValue too high"));
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout total out of range"));

        /** YAC_TOKEN START */
        if (AreTokensDeployed())
        {
            bool isToken = false;
            int nType;
            bool fIsOwner;
            if (txout.scriptPubKey.IsTokenScript(nType, fIsOwner))
                isToken = true;

            // Check for transfers that don't meet the tokens units only if the tokenCache is not null
            if (isToken) {
                // Get the transfer transaction data from the scriptPubKey
                if (nType == TX_TRANSFER_TOKEN) {
                    CTokenTransfer transfer;
                    std::string address;
                    if (!TransferTokenFromScript(txout.scriptPubKey, transfer, address))
                        return state.DoS(100, error("bad-txns-transfer-token-bad-deserialize"));

                    // insert into set, so that later on we can check token null data transactions
                    setTokenTransferNames.insert(transfer.strName);

                    // Check token name validity and get type
                    ETokenType tokenType;
                    if (!IsTokenNameValid(transfer.strName, tokenType)) {
                        return state.DoS(100, error("bad-txns-transfer-token-name-invalid"));
                    }

                    // If the transfer is an ownership token. Check to make sure that it is OWNER_TOKEN_AMOUNT
                    if (IsTokenNameAnOwner(transfer.strName)) {
                        if (transfer.nAmount != OWNER_TOKEN_AMOUNT)
                            return state.DoS(100, error("bad-txns-transfer-owner-amount-was-not-1"));
                    }

                    // If the transfer is a unique token. Check to make sure that it is UNIQUE_TOKEN_AMOUNT
                    if (tokenType == ETokenType::UNIQUE) {
                        if (transfer.nAmount != UNIQUE_TOKEN_AMOUNT)
                            return state.DoS(100, error("bad-txns-transfer-unique-amount-was-not-1"));
                    }

                    // Specific check and error message to go with to make sure the amount is 0
                    if (txout.nValue != 0)
                        return state.DoS(100, error("bad-txns-token-transfer-amount-isn't-zero"));
                } else if (nType == TX_NEW_TOKEN) {
                    // Specific check and error message to go with to make sure the amount is 0
                    if (txout.nValue != 0)
                        return state.DoS(100, error("bad-txns-token-issued-amount-isn't-zero"));
                } else if (nType == TX_REISSUE_TOKEN) {
                    // Specific check and error message to go with to make sure the amount is 0
                    if (txout.nValue != 0) {
                        return state.DoS(0, error("bad-txns-token-reissued-amount-isn't-zero"));
                    }
                } else {
                    return state.DoS(0, error("bad-token-type-not-any-of-the-main-three"));
                }
            }
        }
        /** YAC_TOKEN END */
    }

    // Check for duplicate inputs
    set<COutPoint>
        vInOutPoints;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, error("CheckTransaction() : duplicate inputs"));
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
            return state.DoS(100, error("CTransaction::CheckTransaction() : coinbase script size is invalid"));
        for (auto cbVout : vout) {
            if (cbVout.scriptPubKey.IsTokenScript()) {
                return state.DoS(0, error("%s: coinbase contains token transaction", __func__));
            }
        }
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, error("CTransaction::CheckTransaction() : prevout is null"));
    }

    /* YAC_TOKEN START */
    if (AreTokensDeployed())
    {
        if (IsNewToken()) {
            /** Verify the reissue tokens data */
            std::string strError = "";
            if(!VerifyNewToken(strError))
                return state.DoS(100, error(strError.c_str()));

            CNewToken token;
            std::string strAddress;
            if (!TokenFromTransaction(*this, token, strAddress))
                return state.DoS(100, error("bad-txns-issue-token-from-transaction"));

            // Validate the new tokens information
            if (!IsNewOwnerTxValid(*this, token.strName, strAddress, strError))
                return state.DoS(100, error(strError.c_str()));

            if(!CheckNewToken(token, strError))
                return state.DoS(100, error(strError.c_str()));

        } else if (IsReissueToken()) {

            /** Verify the reissue tokens data */
            std::string strError;
            if (!VerifyReissueToken(strError))
                return state.DoS(100, error(strError.c_str()));

            CReissueToken reissue;
            std::string strAddress;
            if (!ReissueTokenFromTransaction(*this, reissue, strAddress))
                return state.DoS(100, error("bad-txns-reissue-token"));

            if (!CheckReissueToken(reissue, strError))
                return state.DoS(100, error(strError.c_str()));

            // Get the tokenType
            ETokenType type;
            IsTokenNameValid(reissue.strName, type);

        } else if (IsNewUniqueToken()) {

            /** Verify the unique tokens data */
            std::string strError = "";
            if (!VerifyNewUniqueToken(strError)) {
                return state.DoS(100, error(strError.c_str()));
            }


            for (auto out : vout)
            {
                if (IsScriptNewUniqueToken(out.scriptPubKey))
                {
                    CNewToken token;
                    std::string strAddress;
                    if (!TokenFromScript(out.scriptPubKey, token, strAddress))
                        return state.DoS(100, error("bad-txns-check-transaction-issue-unique-token-serialization"));

                    if (!CheckNewToken(token, strError))
                        return state.DoS(100, error(strError.c_str()));
                }
            }
        }
        else {
            // Fail if transaction contains any non-transfer token scripts and hasn't conformed to one of the
            // above transaction types.  Also fail if it contains OP_YAC_TOKEN opcode but wasn't a valid script.
            for (auto out : vout) {
                int nType;
                bool _isOwner;
                if (out.scriptPubKey.IsTokenScript(nType, _isOwner)) {
                    if (nType != TX_TRANSFER_TOKEN) {
                        return state.DoS(100, error("bad-txns-bad-token-transaction"));
                    }
                } else {
                    if (out.scriptPubKey.Find(OP_YAC_TOKEN)) {
                        if (out.scriptPubKey[0] != OP_YAC_TOKEN) {
                            return state.DoS(100, error("bad-txns-op-yac-token-not-in-right-script-location"));
                        }
                    }
                }
            }
        }
    }
    /* YAC_TOKEN END */

    return true;
}

::int64_t CTransaction::GetMinFee(unsigned int nBytes) const
{
    return ::GetMinFee(nBytes);
}

bool CTransaction::AcceptToMemoryPool(CValidationState &state, CTxDB& txdb, bool* pfMissingInputs) const
{
    return mempool.accept(state, txdb, *this, pfMissingInputs);
}

bool CTransaction::DisconnectInputs(CValidationState &state, CTxDB& txdb)
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


bool CTransaction::FetchInputs(CValidationState &state, CTxDB& txdb, const map<uint256, CTxIndex>& mapTestPool,
                               bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid) const
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
            return fMiner ? false : state.Invalid(error("FetchInputs() : %s prev tx %s index entry not found", GetHash().ToString().substr(0,10).c_str(),  prevout.COutPointGetHash().ToString().substr(0,10).c_str()));

        // Read txPrev
        CTransaction& txPrev = inputsRet[prevout.COutPointGetHash()].second;
        if (!fFound || txindex.pos == CDiskTxPos(1,1,1))
        {
            // Get prev tx from single transactions in memory
            {
                LOCK(mempool.cs);
                if (!mempool.exists(prevout.COutPointGetHash()))
                    return state.Invalid(error("FetchInputs() : %s mempool Tx prev not found %s", GetHash().ToString().substr(0,10).c_str(),  prevout.COutPointGetHash().ToString().substr(0,10).c_str()));
                txPrev = mempool.get(prevout.COutPointGetHash());
            }
            if (!fFound)
                txindex.vSpent.resize(txPrev.vout.size());
        }
        else
        {
            // Get prev tx from disk
            if (!txPrev.ReadFromDisk(txindex.pos))
                return state.Invalid(error("FetchInputs() : %s ReadFromDisk prev tx %s failed", GetHash().ToString().substr(0,10).c_str(),  prevout.COutPointGetHash().ToString().substr(0,10).c_str()));
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
            return state.DoS(100, error("FetchInputs() : %s prevout.n out of range %d %" PRIszu " %" PRIszu " prev tx %s\n%s", GetHash().ToString().substr(0,10).c_str(), prevout.COutPointGet_n(), txPrev.vout.size(), txindex.vSpent.size(), prevout.COutPointGetHash().ToString().substr(0,10).c_str(), txPrev.ToString().c_str()));
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

bool CTransaction::ConnectInputs(CValidationState &state,
                                 CTxDB& txdb,
                                 MapPrevTx inputs,
                                 map<uint256, CTxIndex>& mapTestPool,
                                 const CDiskTxPos& posThisTx,
                                 const CBlockIndex* pindexBlock,
                                 bool fBlock,
                                 bool fMiner,
                                 bool fScriptChecks,
                                 unsigned int flags,
                                 std::vector<CScriptCheck> *pvChecks
                                ) const
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
                return state.DoS(
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
                if (chainActive.Height() != -1 && chainActive.Genesis() && chainActive.Height() >= nMainnetNewLogicBlockNumber)
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
                        return state.Invalid(
                                error(
                                     "ConnectInputs() : tried to spend %s at depth %d",
                                     txPrev.IsCoinBase()? "coinbase": "coinstake",
                                     pindexBlock->nHeight - pindex->nHeight + coinbaseMaturityOffset
                                    ));
            }

            // ppcoin: check transaction timestamp
            if (txPrev.nTime > nTime)
                return state.DoS(100, error("ConnectInputs() : transaction timestamp earlier than input transaction"));

            // Check for negative or overflow input values
            nValueIn += txPrev.vout[prevout.COutPointGet_n()].nValue;
            if (!MoneyRange(txPrev.vout[prevout.COutPointGet_n()].nValue) || !MoneyRange(nValueIn))
                return state.DoS(100, error("ConnectInputs() : txin values out of range"));

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
                return fMiner ? false : state.Invalid(error("ConnectInputs() : %s prev tx already used at %s", GetHash().ToString().substr(0,10).c_str(), txindex.vSpent[prevout.COutPointGet_n()].ToString().c_str()));

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
                            return state.Invalid(error("ConnectInputs() : %s strict VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
                    }
                    return state.DoS(100,error("ConnectInputs() : %s VerifySignature failed", GetHash().ToString().substr(0,10).c_str()));
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
                return state.DoS(100, error(
                            "ConnectInputs() : %s unable to get coin age for coinstake",
                            GetHash().ToString().substr(0,10).c_str()
                            ));

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
                return state.DoS(100, error("ConnectInputs() : coinstake pays too much(actual=%" PRId64 " vs calculated=%" PRId64 ")", nReward, nCalculatedReward));
        }
        else
        {
            if (nValueIn < GetValueOut())
                return state.DoS(100, error("ConnectInputs() : %s value in < value out", GetHash().ToString().substr(0,10).c_str()));

            // Tally transaction fees
            ::int64_t nTxFee = nValueIn - GetValueOut();
            if (nTxFee < 0)
                return state.DoS(100, error("ConnectInputs() : %s nTxFee < 0", GetHash().ToString().substr(0,10).c_str()));

            nFees += nTxFee;
            if (!MoneyRange(nFees))
                return state.DoS(100, error("ConnectInputs() : nFees out of range"));
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
            const CTransaction& txPrev = mempool.get(prevout.COutPointGetHash());

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
