// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_PRIMITIVES_TRANSACTION_H
#define YACOIN_PRIMITIVES_TRANSACTION_H

#include <stdint.h>
#include <memory>
#include "amount.h"
#include "script/script.h"
#include "serialize.h"
#include "uint256.h"

class CTxDB;
class CTxIndex;
class CValidationState;
class CDiskTxPos;
class CScriptCheck;
class CBlockIndex;
typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");

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
public:
    uint256 hash;
    ::uint32_t n;

    uint256 COutPointGetHash() const { return hash; }
    ::uint32_t COutPointGet_n() const { return n; }
    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, unsigned int nIn) { hash = hashIn; n = nIn; }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
        READWRITE(n);
    }
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
        LogPrintf("%s\n", ToString());
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

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    }

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
        LogPrintf("%s\n", ToString());
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

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
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
        LogPrintf("%s\n", ToString());
    }
};

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

    CTransaction()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        // nTime is extended to 64-bit since yacoin 1.0.0
        if (this->nVersion >= CURRENT_VERSION_of_Tx_for_yac_new) // 64-bit nTime
        {
			READWRITE(nTime);
        }
        else // 32-bit nTime
        {
            ::uint32_t time = (::uint32_t)nTime; // needed for GetSerializeSize, Serialize function
			READWRITE(time);
			nTime = time; // needed for Unserialize function
        }
        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
    }

    void SetNull();

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    const uint256 GetNormalizedHash() const
    {
        // Coinbase transactions cannot be malleated and may not change after
        // publication. We cannot zero out the scripts, otherwise we get collisions
        // among coinbase transactions by the same miner.
        if (IsCoinBase())
        {
            return SerializeHash(*this);
        }
        else
        {
            CTransaction tmp(*this);
            // Replace scriptSigs in inputs with empty strings
            for (unsigned int i = 0; i < tmp.vin.size(); i++)
            {
                tmp.vin[i].scriptSig = CScript();
            }

            CHashWriter ss(SER_GETHASH, 0);
            ss << tmp;
            return ss.GetHash();
        }
    }

    uint256 GetHash() const
    {
        // transaction with version >=2 fixes tx malleability
        if (this->nVersion >= CURRENT_VERSION_of_Tx_for_yac_new)
        {
            return GetNormalizedHash();
        }
        else
        {
            return SerializeHash(*this);
        }
    }

    bool IsFinal(int nBlockHeight=0, ::int64_t nBlockTime=0) const;

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

    unsigned int GetTotalSize() const;

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

    bool ReadFromDisk(CDiskTxPos pos, FILE** pfileRet=NULL);

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
            "nTime=%" PRId64 ", "
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
        LogPrintf("%s", ToString());
    }


    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout, CTxIndex& txindexRet);
    bool ReadFromDisk(CTxDB& txdb, COutPoint prevout);
    bool ReadFromDisk(COutPoint prevout);
    bool DisconnectInputs(CValidationState &state, CTxDB& txdb);

    /** Fetch from memory and/or disk. inputsRet keys are transaction hashes.

     @param[in] txdb	Transaction database
     @param[in] mapTestPool	List of pending changes to the transaction index database
     @param[in] fBlock	True if being called to add a new best-block to the chain
     @param[in] fMiner	True if being called by CreateNewBlock
     @param[out] inputsRet	Pointers to this transaction's inputs
     @param[out] fInvalid	returns true if transaction is invalid
     @return	Returns true if all inputs are in txdb or mapTestPool
     */
    bool FetchInputs(CValidationState &state, CTxDB& txdb, const std::map<uint256, CTxIndex>& mapTestPool,
                     bool fBlock, bool fMiner, MapPrevTx& inputsRet, bool& fInvalid) const;

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
    bool ConnectInputs(CValidationState &state, CTxDB& txdb, MapPrevTx inputs, std::map<uint256, CTxIndex>& mapTestPool, const CDiskTxPos& posThisTx, const CBlockIndex* pindexBlock,
                     bool fBlock, bool fMiner, bool fScriptChecks=true,
                     unsigned int flags=STRICT_FLAGS, std::vector<CScriptCheck> *pvChecks = NULL) const;
    bool ClientConnectInputs();
    bool CheckTransaction(CValidationState &state) const;
    bool AcceptToMemoryPool(CValidationState &state, CTxDB& txdb, bool *pfMissingInputs=NULL) const;
    bool GetCoinAge(CTxDB& txdb, ::uint64_t& nCoinAge) const;  // ppcoin: get transaction coin age

    /** YAC_TOKEN START */
    bool IsNewToken() const;
    bool VerifyNewToken(std::string& strError) const;
    bool IsNewUniqueToken() const;
    bool VerifyNewUniqueToken(std::string& strError) const;
    bool IsReissueToken() const;
    bool VerifyReissueToken(std::string& strError) const;
    /** YAC_TOKEN END */

protected:
    const CTxOut& GetOutputFor(const CTxIn& input, const MapPrevTx& inputs) const;
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
#endif // YACOIN_PRIMITIVES_TRANSACTION_H
