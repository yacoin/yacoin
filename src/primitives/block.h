// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef YACOIN_PRIMITIVES_BLOCK_H
#define YACOIN_PRIMITIVES_BLOCK_H

#include "tokens/tokens.h"
#include "serialize.h"
#include "uint256.h"
#include "scrypt.h"
#include "checkqueue.h"

class CWallet;
class CTransaction;
class CScriptCheck;
struct CDiskBlockPos;

// block version header
static const int
    VERSION_of_block_for_yac_05x_new = 7,
    VERSION_of_block_for_yac_049     = 6,
    VERSION_of_block_for_yac_044_old = 3,
    CURRENT_VERSION_of_block = VERSION_of_block_for_yac_049;

static const unsigned char MAXIMUM_N_FACTOR = 25;  //30; since uint32_t fails on 07 Feb 2106 06:28:15 GMT
                                                   //    when stored as an uint32_t in a block
                                                   //    so there is no point going past Nf = 25
extern CCheckQueue<CScriptCheck> scriptcheckqueue;

extern const ::int64_t
    nChainStartTime,
    nChainStartTimeTestNet;
extern std::map<uint256, uint256> mapProofOfStake;
extern CBigNum bnProofOfWorkLimit;
extern const int64_t INITIAL_MONEY_SUPPLY;
extern bool fReindexOnlyHeaderSync;
extern bool fUseFastIndex;

#if defined(Yac1dot0)
       const ::uint32_t Nfactor_1dot0 = 17;
#endif

FILE* AppendBlockFile(unsigned int& nFileRet);
bool IsInitialBlockDownload();

struct ConnectedBlockTokenData
{
    std::set<CTokenCacheNewToken> newTokensToAdd;
};

enum BlockStatus {
    // Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    // Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER       =    1,

    // All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    // are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    // Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
    // sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
    // parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
    BLOCK_VALID_TRANSACTIONS =    3,

    // Outputs do not overspend inputs, no double spends, coinbase output ok, immature coinbase spends, BIP30.
    // Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    // Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    // All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, // full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, // undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,
    BLOCK_FAILED_VALID       =   32, // stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, // descends from failed block
    BLOCK_FAILED_MASK = BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,
};

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 *
 * Blocks are appended to blk0001.dat files on disk.  Their location on disk
 * is indexed by CBlockIndex objects in memory.
 */
class CBlockHeader
{
public:
    // Block header
    ::int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    mutable ::int64_t nTime;
    ::uint32_t nBits;
    ::uint32_t nNonce;

    // Store following info to avoid calculating hash many times
    mutable struct block_header previousBlockHeader;
    mutable uint256 blockHash;

    // (memory-only) Store to avoid calculating hash many times at initial-block-sync
    mutable uint256 blockSHA256Hash;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        // nTime is extended to 64-bit since yacoin 1.0.0
        if (this->nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
               READWRITE(nTime);
        }
        else // 32-bit nTime
        {
               ::uint32_t time = (::uint32_t)nTime; // needed for GetSerializeSize, Serialize function
               READWRITE(time);
               nTime = time; // needed for Unserialize function
        }
        READWRITE(nBits);
        READWRITE(nNonce);
        previousBlockHeader.version = this->nVersion;
        previousBlockHeader.prev_block = hashPrevBlock;
        previousBlockHeader.merkle_root = hashMerkleRoot;
        previousBlockHeader.timestamp = nTime;
        previousBlockHeader.bits = nBits;
        previousBlockHeader.nonce = nNonce;
    }

    void SetNull();

    bool IsNull() const
    {
        return (nBits == 0);
    }

    // yacoin2015 update
    uint256 CalculateHash() const
    {
        uint256
            thash;

        if (nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
            struct block_header block_data;
            block_data.version = nVersion;
            block_data.prev_block = hashPrevBlock;
            block_data.merkle_root = hashMerkleRoot;
            block_data.timestamp = nTime;
            block_data.bits = nBits;
            block_data.nonce = nNonce;
            if(
               !scrypt_hash(
                           CVOIDBEGIN(block_data),
                           sizeof(struct block_header),
                           UINTBEGIN(thash),
                           MAXIMUM_YAC1DOT0_N_FACTOR
                          )
              )
            {
                thash = 0;  // perhaps? should error("lack of memory for scrypt hash?");
            }
        }
        else // 32-bit nTime
        {
            const ::uint64_t
                nSpanOf4  = 1368515488 - nChainStartTime,
                nSpanOf5  = 1368777632 - nChainStartTime,
                nSpanOf6  = 1369039776 - nChainStartTime,
                nSpanOf7  = 1369826208 - nChainStartTime,
                nSpanOf8  = 1370088352 - nChainStartTime,
                nSpanOf9  = 1372185504 - nChainStartTime,
                nSpanOf10 = 1373234080 - nChainStartTime,
                nSpanOf11 = 1376379808 - nChainStartTime,
                nSpanOf12 = 1380574112 - nChainStartTime,   // Mon, 30 Sep 2013 20:48:32 GMT
                nSpanOf13 = 1384768416 - nChainStartTime,   // Mon, 18 Nov 2013 09:53:36 GMT
                nSpanOf14 = 1401545632 - nChainStartTime,   // Sat, 31 May 2014 14:13:52 GMT
                nSpanOf15 = 1409934240 - nChainStartTime,   // Fri, 05 Sep 2014 16:24:00 GMT (Nf) 16
                nSpanOf16 = 1435100064 - nChainStartTime,   // Tue, 23 Jun 2015 22:54:24 GMT (Nf) 17
                nSpanOf17 = 1468654496 - nChainStartTime,   // Sat, 16 Jul 2016 07:34:56 GMT (Nf) 18
                nSpanOf18 = 1502208928 - nChainStartTime,   // Tue, 08 Aug 2017 16:15:28 GMT (Nf) 19
                nSpanOf19 = 1602872224 - nChainStartTime,   // Fri, 16 Oct 2020 18:17:04 GMT
                nSpanOf20 = 1636426656 - nChainStartTime,   // Tue, 09 Nov 2021 02:57:36 GMT
                nSpanOf21 = 1904862112 - nChainStartTime,   // Mon, 13 May 2030 00:21:52 GMT
                nSpanOf22 = 2173297568U - nChainStartTime,   // Sat, 13 Nov 2038 21:46:08 GMT
                nSpanOf23 = 2441733024U - nChainStartTime,   // Fri, 17 May 2047 19:10:24 GMT
                nSpanOf24 = 3247039392U - nChainStartTime,   // Tue, 22 Nov 2072 11:23:12 GMT
                nSpanOf25 = 3515474848U - nChainStartTime;   // Mon, 26 May 2081 08:47:28 GMT
                // uint_32 fails here                          Sun, 07 Feb 2106 06:28:15 GMT
              //nSpanOf26 = 5662958496 - nChainStartTime,   // Sat, 14 Jun 2149 12:01:36 GMT
              //nSpanOf27 = 6736700320 - nChainStartTime,   // Tue, 24 Jun 2183 01:38:40 GMT
              //nSpanOf28 = 9957925792 - nChainStartTime,   // Tue, 21 Jul 2285 18:29:52 GMT
              //nSpanOf29 = 14252893088 - nChainStartTime,  // Sat, 28 Aug 2421 00:58:08 GMT
              //nSpanOf30 = 18547860384 - nChainStartTime;  // Tue, 04 Oct 2557 07:26:24 GMT

            unsigned char
                nfactor;
            if( !fTestNet )
            {     // nChainStartTime = 1367991200 is start
    		    if      ( nTime < (nChainStartTime + nSpanOf4 ) ) nfactor = 4;
                else if ( nTime < (nChainStartTime + nSpanOf5 ) ) nfactor = 5;
                else if ( nTime < (nChainStartTime + nSpanOf6 ) ) nfactor = 6;
                else if ( nTime < (nChainStartTime + nSpanOf7 ) ) nfactor = 7;
                else if ( nTime < (nChainStartTime + nSpanOf8 ) ) nfactor = 8;
                else if ( nTime < (nChainStartTime + nSpanOf9 ) ) nfactor = 9;
                else if ( nTime < (nChainStartTime + nSpanOf10) ) nfactor = 10;
                else if ( nTime < (nChainStartTime + nSpanOf11) ) nfactor = 11;
                else if ( nTime < (nChainStartTime + nSpanOf12) ) nfactor = 12;
                else if ( nTime < (nChainStartTime + nSpanOf13) ) nfactor = 13;
                else if ( nTime < (nChainStartTime + nSpanOf14) ) nfactor = 14;
                else if ( nTime < (nChainStartTime + nSpanOf15) ) nfactor = 15;
                else if ( nTime < (nChainStartTime + nSpanOf16) ) nfactor = 16;
                else if ( nTime < (nChainStartTime + nSpanOf17) ) nfactor = 17;
                else if ( nTime < (nChainStartTime + nSpanOf18) ) nfactor = 18;
                else if ( nTime < (nChainStartTime + nSpanOf19) ) nfactor = 19;
                else if ( nTime < (nChainStartTime + nSpanOf20) ) nfactor = 20;
                else if ( nTime < (nChainStartTime + nSpanOf21) ) nfactor = 21;
                else if ( nTime < (nChainStartTime + nSpanOf22) ) nfactor = 22;
                else if ( nTime < (nChainStartTime + nSpanOf23) ) nfactor = 23;
                else if ( nTime < (nChainStartTime + nSpanOf24) ) nfactor = 24;
                else if ( nTime < (nChainStartTime + nSpanOf25) ) nfactor = 25;
              //  else if ( nTime < (nChainStartTime + nSpanOf26) ) nfactor = 26;
                // uint_32 fails here
              //  else if ( nTime < (nChainStartTime + nSpanOf27) ) nfactor = 27;
              //  else if ( nTime < (nChainStartTime + nSpanOf28) ) nfactor = 28;
              //  else if ( nTime < (nChainStartTime + nSpanOf29) ) nfactor = 29;
              //  else if ( nTime < (nChainStartTime + nSpanOf30) ) nfactor = 30;
                else
                    nfactor = MAXIMUM_N_FACTOR;
            }
            else    // is TestNet
            {
#if defined(Yac1dot0)
                nfactor = Nfactor_1dot0;
#else
                nfactor = 4;
#endif
            }

            old_block_header oldBlock;
            oldBlock.version = nVersion;
            oldBlock.prev_block = hashPrevBlock;
            oldBlock.merkle_root = hashMerkleRoot;
            oldBlock.timestamp = nTime;
            oldBlock.bits = nBits;
            oldBlock.nonce = nNonce;
            if(
               !scrypt_hash(
                           CVOIDBEGIN(oldBlock),
                           sizeof(old_block_header),
                           UINTBEGIN(thash),
                           nfactor
                          )
              )
            {
                thash = 0;  // perhaps? should error("lack of memory for scrypt hash?");
            }
        }
		return thash;
    }

    bool IsHeaderDifferent() const
    {
        if(
           (nVersion == previousBlockHeader.version)
           && (hashPrevBlock == previousBlockHeader.prev_block)
           && (hashMerkleRoot == previousBlockHeader.merkle_root)
           && (nTime == previousBlockHeader.timestamp)
           && (nBits == previousBlockHeader.bits)
           && (nNonce == previousBlockHeader.nonce)
          )
        {
            return false;
        }
        return true;
    }

    uint256 GetHash(int blockHeight = 0) const
    {
        if(blockHash == 0 || IsHeaderDifferent())
        {
            blockHash = CalculateHash();
            previousBlockHeader.version = nVersion;
            previousBlockHeader.prev_block = hashPrevBlock;
            previousBlockHeader.merkle_root = hashMerkleRoot;
            previousBlockHeader.timestamp = nTime;
            previousBlockHeader.bits = nBits;
            previousBlockHeader.nonce = nNonce;
        }
        return blockHash;
    }

    uint256 GetSHA256Hash() const
    {
        if(blockSHA256Hash == 0 || IsHeaderDifferent())
        {
            previousBlockHeader.version = nVersion;
            previousBlockHeader.prev_block = hashPrevBlock;
            previousBlockHeader.merkle_root = hashMerkleRoot;
            previousBlockHeader.timestamp = nTime;
            previousBlockHeader.bits = nBits;
            previousBlockHeader.nonce = nNonce;
            blockSHA256Hash = Hash(BEGIN(previousBlockHeader.version), END(previousBlockHeader.nonce));
        }
        return blockSHA256Hash;
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const
    {
        bool proofOfStake = false;
        if (nTime <= nYac10HardforkTime && nNonce == 0 &&
                ((nBits <= 486801407 && blockHash != uint256("0x0000000009415c983b503189080df17423b193176634b6e489120e0189a6829c"))
                        || (blockHash == uint256("0x5fc9a11b3ffd0118a0031eeb9ed2860bd8ceb8c71e3226e02e6eb82c90cbbf99"))
                        || (blockHash == uint256("0x5dc2a000963f075f3dec7fa8f220987bff3c4a978528594e5408448155cdc8e4"))))
        {
            proofOfStake = true;
        }
        return proofOfStake;
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    // ppcoin: entropy bit for stake modifier if chosen by modifier
    unsigned int GetStakeEntropyBit(unsigned int nHeight) const
    {

            // Take last bit of block hash as entropy bit
            unsigned int nEntropyBit = ((GetHash().Get64()) & 1ULL);
            if (fDebug && gArgs.GetBoolArg("-printstakemodifier"))
                LogPrintf(
                        "GetStakeEntropyBit: nTime=%" PRId64 " \nhashBlock=%s\nnEntropyBit=%u\n",
                        nTime,
                        GetHash().ToString(),
                        nEntropyBit
                      );
            return nEntropyBit;

    }
    bool CheckBlockHeader(CValidationState& state, bool fCheckPOW = true) const;
    bool AcceptBlockHeader(CValidationState& state, CBlockIndex **ppindex= NULL);
    CBlockIndex* AddToBlockIndex();
};

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // ppcoin: block signature - signed by one of the coin base txout[N]'s owner
    std::vector<unsigned char> vchBlockSig;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &blockHeader)
    {
        SetNull();
        *((CBlockHeader*)this) = blockHeader;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(s.GetType() & (SER_GETHASH|SER_BLOCKHEADERONLY)))
        {
            READWRITE(vtx);
            READWRITE(vchBlockSig);
        }
        else if (ser_action.ForRead())
        {
            const_cast<CBlock*>(this)->vtx.clear();
            const_cast<CBlock*>(this)->vchBlockSig.clear();
        }
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vchBlockSig.clear();
        vMerkleTree.clear();
    }

    void UpdateTime(const CBlockIndex* pindexPrev);

    std::pair<COutPoint, unsigned int> GetProofOfStake() const
    {
        return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, (unsigned int)vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }

    // ppcoin: get max transaction timestamp
    ::int64_t GetMaxTransactionTime() const
    {
        ::int64_t maxTransactionTime = 0;
        BOOST_FOREACH(const CTransaction& tx, vtx)
            maxTransactionTime = std::max(maxTransactionTime, (::int64_t)tx.nTime);
        return maxTransactionTime;
    }

    uint256 BuildMerkleTree() const
    {
        vMerkleTree.clear();
        BOOST_FOREACH(const CTransaction& tx, vtx)
            vMerkleTree.push_back(tx.GetHash());
        int j = 0;
        for (int nSize = (int)vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            for (int i = 0; i < nSize; i += 2)
            {
                int i2 = std::min(i+1, nSize-1);
                vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                           BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
            }
            j += nSize;
        }
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const
    {
        if (vMerkleTree.empty())
            BuildMerkleTree();
        std::vector<uint256> vMerkleBranch;
        int j = 0;
        for (int nSize = (int)vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
        {
            int i = std::min(nIndex^1, nSize-1);
            vMerkleBranch.push_back(vMerkleTree[j+i]);
            nIndex >>= 1;
            j += nSize;
        }
        return vMerkleBranch;
    }

    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
    {
        if (nIndex == -1)
            return 0;
        BOOST_FOREACH(const uint256& otherside, vMerkleBranch)
        {
            if (nIndex & 1)
                hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
            else
                hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
            nIndex >>= 1;
        }
        return hash;
    }


    bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet);

    void print() const
    {
        LogPrintf("CBlock(\n"
                "hash=%s,\n"
                "ver=%d,\n"
                "hashPrevBlock=%s,\n"
                "hashMerkleRoot=%s,\n"
                "nTime=%" PRId64 ", "
                "nBits=%08x, "
                "nNonce=%u, "
                "vtx=%" PRIszu ",\n"
                "vchBlockSig=%s\n"
                ")\n",
            GetHash().ToString(),
            nVersion,
            hashPrevBlock.ToString(),
            hashMerkleRoot.ToString(),
            nTime,
            nBits,
            nNonce,
            vtx.size(),
            HexStr(vchBlockSig.begin(), vchBlockSig.end())
              );
        for (unsigned int i = 0; i < vtx.size(); ++i)
        {
            LogPrintf("  ");
            vtx[i].print();
        }
        LogPrintf("  vMerkleTree: ");
        for (unsigned int i = 0; i < vMerkleTree.size(); ++i)
            LogPrintf("%s ", vMerkleTree[i].ToString().substr(0,10));
        LogPrintf("\n");
    }

    bool DisconnectBlock(CValidationState& state, CTxDB& txdb,
                         CBlockIndex* pindex,
                         CTokensCache* tokensCache,
                         bool ignoreAddressIndex = false);
    bool ConnectBlock(CValidationState& state, CTxDB& txdb, CBlockIndex* pindex,
                      CTokensCache* tokensCache, bool fJustCheck = false,
                      bool ignoreAddressIndex = false);
    bool ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions=true, bool fCheckHeader = true);
    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos,
            bool fReadTransactions = true, bool fCheckHeader = true);
    bool ReceivedBlockTransactions(CValidationState &state, unsigned int nFile, unsigned int nBlockPos, CBlockIndex *pindexNew);
    bool CheckBlock(CValidationState& state, bool fCheckPOW=true, bool fCheckMerkleRoot=true, bool fCheckSig=true) const;
    bool AcceptBlock(CValidationState &state, CBlockIndex **ppindex, CDiskBlockPos* dbp = NULL);
    bool GetCoinAge(::uint64_t& nCoinAge) const; // ppcoin: calculate total coin age spent in block
    bool SignBlock044(const CKeyStore& keystore);
    bool SignBlock(CWallet& keystore);
    bool CheckBlockSignature() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
class CBlockLocator
{
public:
    std::vector<uint256> vHave;

    CBlockLocator()
    {
    }

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(_nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

struct CDiskBlockPos
{
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nFile);
        READWRITE(nPos);
    }

    CDiskBlockPos() {
        SetNull();
    }

    CDiskBlockPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return !(a == b);
    }

    void SetNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 *
 * What about the top index? What is its pnext? NULL?
 *
 */
class CBlockIndex
{
protected:
    std::string ToString() const
    {
        return strprintf(
                         "CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d "
                         "nHeight=%d, nMint=%s, nMoneySupply=%s, nFlags=(%s)(%d)(%s), "
                         "nStakeModifier=%016" PRIx64 ", nStakeModifierChecksum=%08x, "
                         "hashProofOfStake=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, "
                         "hashBlock=%s)",
                         pprev, pnext, nFile, nBlockPos, nHeight,
                         FormatMoney(nMint).c_str(), FormatMoney(nMoneySupply).c_str(),
                         GeneratedStakeModifier() ? "MOD" : "-", GetStakeEntropyBit(), IsProofOfStake()? "PoS" : "PoW",
                         nStakeModifier, nStakeModifierChecksum,
                         hashProofOfStake.ToString().c_str(),
                         prevoutStake.ToString().c_str(), nStakeTime,
                         hashMerkleRoot.ToString().c_str(),
                         GetBlockHash().ToString().c_str()
                        );
    }

public:
    const uint256* phashBlock;
    CBlockIndex* pprev;
    CBlockIndex* pnext;
    // pointer to the index of some further predecessor of this block
    CBlockIndex* pskip;
    ::uint32_t nFile;
    ::uint32_t nBlockPos;
    CBigNum bnChainTrust; // ppcoin: trust score of block chain
    ::int32_t nHeight;

    ::int64_t nMint;
    ::int64_t nMoneySupply;

    ::uint32_t nFlags;  // ppcoin: block index flags
    enum
    {
        BLOCK_PROOF_OF_STAKE = (1 << 0), // is proof-of-stake block
        BLOCK_STAKE_ENTROPY  = (1 << 1), // entropy bit for stake modifier
        BLOCK_STAKE_MODIFIER = (1 << 2), // regenerated stake modifier
    };

    ::uint64_t nStakeModifier; // hash modifier for proof-of-stake
    ::uint32_t nStakeModifierChecksum; // checksum of index; in-memeory only

    // proof-of-stake specific fields
    COutPoint prevoutStake;
    ::uint32_t nStakeTime;
    uint256 hashProofOfStake;

    // block header
    ::int32_t  nVersion;
    uint256  hashMerkleRoot;
    mutable ::int64_t nTime;
    ::uint32_t nBits;
    ::uint32_t nNonce;

    ::uint256 blockHash; // store hash to avoid calculating many times
    // Verification status of this block. See enum BlockStatus
    unsigned int nStatus;
    // (memory only) Sequencial id assigned to distinguish order in which blocks are received.
    uint32_t nSequenceId;
    // (memory only) This value will be set to true only if and only if transactions for this block and all its parents are available.
    bool validTx;

public:
    CBlockIndex()
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        pskip = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
        bnChainTrust = CBigNum(0);
        nMint = 0;
        nMoneySupply = INITIAL_MONEY_SUPPLY;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        prevoutStake.SetNull();
        nStakeTime = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
        blockHash      = 0;
        nStatus = 0;
        nSequenceId = 0;
        validTx = false;
    }

    CBlockIndex(CBlockHeader &blockHeader) :
            CBlockIndex(0, 0, blockHeader) {

    }

    CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlockHeader& blockHeader)
    {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        pskip = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;
        bnChainTrust = CBigNum(0);
        nMint = 0;
        nMoneySupply = INITIAL_MONEY_SUPPLY;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        nStatus = 0;
        nSequenceId = 0;
        validTx = false;
        if (blockHeader.IsProofOfStake())
        {
            SetProofOfStake();
        }
        prevoutStake.SetNull();
        nStakeTime = 0;

        nVersion       = blockHeader.nVersion;
        hashMerkleRoot = blockHeader.hashMerkleRoot;
        nTime          = blockHeader.nTime;
        nBits          = blockHeader.nBits;
        nNonce         = blockHeader.nNonce;
        blockHash      = blockHeader.blockHash;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader blockHeader;
        blockHeader.nVersion       = nVersion;
        if (pprev)
            blockHeader.hashPrevBlock = pprev->GetBlockHash();
        blockHeader.hashMerkleRoot = hashMerkleRoot;
        blockHeader.nTime          = nTime;
        blockHeader.nBits          = nBits;
        blockHeader.nNonce         = nNonce;
        return blockHeader;
    }

    uint256 GetBlockHash() const
    {
        return *phashBlock;
    }

    uint256 GetSHA256Hash() const
    {
        CBlockHeader blockHeader = GetBlockHeader();
        return blockHeader.GetSHA256Hash();
    }

    ::int64_t GetBlockTime() const
    {
        return (::int64_t)nTime;
    }

    CBigNum GetBlockTrust() const;

    bool IsInMainChain() const;

    bool CheckIndex() const
    {
        return true;
    }

    enum { nMedianTimeSpan=11 };

    ::int64_t GetMedianTimePast() const
    {
        ::int64_t pmedian[nMedianTimeSpan];
        ::int64_t* pbegin = &pmedian[nMedianTimeSpan];
        ::int64_t* pend = &pmedian[nMedianTimeSpan];

        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
            *(--pbegin) = pindex->GetBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    ::int64_t GetMedianTime() const
    {
        const CBlockIndex* pindex = this;
        for (int i = 0; i < nMedianTimeSpan/2; i++)
        {
            if (!pindex->pnext)
                return GetBlockTime();
            pindex = pindex->pnext;
        }
        return pindex->GetMedianTimePast();
    }

    /**
     * Returns true if there are nRequired or more blocks of minVersion or above
     * in the last nToCheck blocks, starting at pstart and going backwards.
     */
    static bool IsSuperMajority(int minVersion, const CBlockIndex* pstart,
                                unsigned int nRequired, unsigned int nToCheck);


    bool IsProofOfWork() const
    {
        return !(nFlags & BLOCK_PROOF_OF_STAKE);
    }

    bool IsProofOfStake() const
    {
        return (nFlags & BLOCK_PROOF_OF_STAKE);
    }

    void SetProofOfStake()
    {
        nFlags |= BLOCK_PROOF_OF_STAKE;
    }

    unsigned int GetStakeEntropyBit() const
    {
        return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
    }

    bool SetStakeEntropyBit(unsigned int nEntropyBit)
    {
        if (nEntropyBit > 1)
            return false;
        nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
        return true;
    }

    bool GeneratedStakeModifier() const
    {
        return (nFlags & BLOCK_STAKE_MODIFIER) != 0;
    }

    void SetStakeModifier(::uint64_t nModifier, bool fGeneratedStakeModifier)
    {
        nStakeModifier = nModifier;
        if (fGeneratedStakeModifier)
            nFlags |= BLOCK_STAKE_MODIFIER;
    }

    void print() const
    {
        LogPrintf("%s\n", ToString());
    }

    // Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }

    // Raise the validity level of this block index entry.
    // Returns true if the validity was changed.
    bool RaiseValidity(enum BlockStatus nUpTo)
    {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        }
        return false;
    }
    // Build the skiplist pointer for this entry.
    void BuildSkip();

    // Efficiently find an ancestor of this block.
    CBlockIndex* GetAncestor(int height);
    const CBlockIndex* GetAncestor(int height) const;
};



/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public CBlockIndex
{
public:
    uint256 hashPrev;
    uint256 hashNext;

    CDiskBlockIndex()
    {
        hashPrev = 0;
        hashNext = 0;
    }

    explicit CDiskBlockIndex(CBlockIndex* pindex) : CBlockIndex(*pindex)
    {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int _nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);

        READWRITE(hashNext);
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nHeight);
        READWRITE(nMint);
        READWRITE(nMoneySupply);
        READWRITE(nFlags);
        READWRITE(nStakeModifier);
        if (IsProofOfStake())
        {
            READWRITE(prevoutStake);
            READWRITE(nStakeTime);
            READWRITE(hashProofOfStake);
        }
        else if (ser_action.ForRead())
        {
            const_cast<CDiskBlockIndex*>(this)->prevoutStake.SetNull();
            const_cast<CDiskBlockIndex*>(this)->nStakeTime = 0;
            const_cast<CDiskBlockIndex*>(this)->hashProofOfStake = 0;
        }

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        // nTime is extended to 64-bit since yacoin 1.0.0
        if (this->nVersion >= VERSION_of_block_for_yac_05x_new) // 64-bit nTime
        {
            READWRITE(nTime);
        }
        else // 32-bit nTime
        {
            ::uint32_t time = (::uint32_t)nTime; // needed for GetSerializeSize, Serialize function
            READWRITE(time);
            nTime = time; // needed for Unserialize function
        }
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(blockHash);
        if (!fReindexOnlyHeaderSync)
        {
            READWRITE(nStatus);
        }
    }

    uint256 GetBlockHash() const
    {
        if (fUseFastIndex && (blockHash != 0))
            return blockHash;

        CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;

        const_cast<CDiskBlockIndex*>(this)->blockHash = block.GetHash();

        return blockHash;
    }

    uint256 GetSHA256Hash() const
    {
        CBlockHeader blockHeader = GetBlockHeader();
        blockHeader.hashPrevBlock = hashPrev;
        return blockHeader.GetSHA256Hash();
    }

    std::string ToString() const
    {
        std::string str = "CDiskBlockIndex(";
        str += CBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
            GetBlockHash().ToString().c_str(),
            hashPrev.ToString().c_str(),
            hashNext.ToString().c_str());
        return str;
    }

    void print() const
    {
        LogPrintf("%s\n", ToString());
    }
};

struct CBlockIndexWorkComparator
{
    bool operator()(CBlockIndex *pa, CBlockIndex *pb) {
        // First sort by most total work, ...
        if (pa->bnChainTrust > pb->bnChainTrust) return false;
        if (pa->bnChainTrust < pb->bnChainTrust) return true;

        // ... then by earliest time received, ...
        if (pa->nSequenceId < pb->nSequenceId) return false;
        if (pa->nSequenceId > pb->nSequenceId) return true;

        // Use pointer address as tie breaker (should only happen with blocks
        // loaded from disk, as those all have id 0).
        if (pa < pb) return false;
        if (pa > pb) return true;

        // Identical blocks.
        return false;
    }
};

#endif // YACOIN_PRIMITIVES_BLOCK_H
