// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addressindex.h"
#include "tokens/tokendb.h"
#include "primitives/block.h"
#include "txdb-leveldb.h"
#include "checkpoints.h"
#include "kernel.h"
#include "wallet.h"
#include "validationinterface.h"
#include "net_processing.h"

using std::vector;
using std::map;
using std::set;
using std::make_pair;
using std::max;
using std::deque;

const ::int64_t
    nChainStartTime = 1367991200,           // unix time???? ~ Wed May 08 2013 05:33:20
//    nChainStartTimeTestNet = 1464123328;    //Tue, 24 May 2016 20:55:28 GMT
//                                            // 1464373956  Fri, 27 May 2016 18:32:36 GMT
    nChainStartTimeTestNet = 1546300800;    // 1546116950 ~12/29/2018
                                            // 1546300800 1/1/2019 00:00:00 GMT

// Every received block is assigned a unique and increasing identifier, so we
// know which one to give priority in case of a fork.
CCriticalSection cs_nBlockSequenceId;
// Blocks loaded from disk are assigned id 0, so start the counter at 1.
uint32_t nBlockSequenceId = 1;

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, vpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

void CBlockHeader::SetNull()
{
	// TODO: Need update for mainnet
	if (chainActive.Height() != -1 && chainActive.Genesis() && (chainActive.Height() + 1) >= nMainnetNewLogicBlockNumber)
	{
		nVersion = VERSION_of_block_for_yac_05x_new;
	}
	else
	{
		nVersion = CURRENT_VERSION_of_block;
	}
	hashPrevBlock = 0;
	hashMerkleRoot = 0;
	nTime = 0;
	nBits = 0;
	nNonce = 0;
	blockHash = 0;
	blockSHA256Hash = 0;
	memset(UVOIDBEGIN(previousBlockHeader), 0, sizeof(struct block_header));
}

bool CBlockHeader::AcceptBlockHeader(CValidationState &state,
                                     CBlockIndex **ppindex)
{
    // Check for duplicate
    uint256 hash = GetHash();
    BlockMap::iterator miSelf = mapBlockIndex.find(hash);
    CBlockIndex *pindex = NULL;
    if (miSelf != mapBlockIndex.end())
    {
        // Block header is already known.
        pindex = miSelf->second;
        if (ppindex)
            *ppindex = pindex;
        if (pindex->nStatus & BLOCK_FAILED_MASK)
            return state.Invalid(error("AcceptBlockHeader() : block is marked invalid"), 0,
                                 "duplicate");
        return true;
    }

    if (!CheckBlockHeader(state, true))
        return false;

    // Get prev block index
    BlockMap::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return state.DoS(10, error("AcceptBlockHeader () : prev block not found"));
    CBlockIndex* pindexPrev = (*mi).second;

    if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
        return state.DoS(100, error("AcceptBlockHeader () : prev block invalid"));
    int nHeight = pindexPrev->nHeight+1;

    // Check proof-of-work or proof-of-stake
    // In case there is a block reorg between two nodes, the mininum difficulty (minEase) can affect the return value of GetNextTargetRequired
    // In order the node which have weaker-chain can sync blocks of stronger-chain, we lower the DoS score from 100 to 10, so that we don't ban the node which have weaker-chain
    if (nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake()))
        return state.DoS(
            10, error("AcceptBlockHeader () : incorrect %s",
                       IsProofOfWork() ? "proof-of-work" : "proof-of-stake"));

    ::int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetMedianTimePast() ||
        FutureDrift(GetBlockTime()) < pindexPrev->GetBlockTime())
        return error("AcceptBlockHeader () : block's timestamp is too early");

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return state.DoS(
            100,
            error("AcceptBlockHeader () : rejected by hardened checkpoint lock-in at %d",
                  nHeight));

    if (pindex == NULL)
        pindex = AddToBlockIndex();

    if (ppindex)
        *ppindex = pindex;

    return true;
}

CBlockIndex* CBlockHeader::AddToBlockIndex()
{
    // Check for duplicate
    uint256 hash = GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(*(CBlockHeader*)this);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;

    // Add to mapBlockIndex
    BlockMap::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(hashPrevBlock); // this bothers me when mapBlockIndex == NULL!?

    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }

    // ppcoin: compute chain trust score
    pindexNew->bnChainTrust = (pindexNew->pprev ?
                                pindexNew->pprev->bnChainTrust :
                                CBigNum(0)
                              ) +
                              pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->nHeight)))
        error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == NULL || pindexBestHeader->bnChainTrust < pindexNew->bnChainTrust)
        pindexBestHeader = pindexNew;

    // Write to disk block index
    CTxDB txdb;
    if (!txdb.TxnBegin())
    {
        LogPrintf("AddToBlockIndex(): TxnBegin failed\n");
    }
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindexNew)))
    {
        LogPrintf("AddToBlockIndex(): Can't WriteBlockHash\n");
    }
    if (!txdb.TxnCommit())
    {
        LogPrintf("AddToBlockIndex(): TxnCommit failed\n");
    }

    return pindexNew;
}

bool CBlockHeader::CheckBlockHeader(CValidationState& state, bool fCheckPOW) const
{
    bool fProofOfStake = IsProofOfStake();

    if (fProofOfStake)
    {
        // Proof-of-STake related checkings. Note that we know here that 1st transactions is coinstake. We don't need
        //   check the type of 1st transaction because it's performed earlier by IsProofOfStake()

        // nNonce must be zero for proof-of-stake blocks
        if (nNonce != 0)
            return state.DoS(100, error("CheckBlockHeader () : non-zero nonce in proof-of-stake block"));

        // Check timestamp  06/04/2018 missing test in this 0.4.5-0.48 code.  Thanks Joe! ;>
        if (GetBlockTime() > FutureDrift(GetAdjustedTime()))
            return error("CheckBlockHeader () : block timestamp too far in the future");
    }
    else    // is PoW block
    {
        // Check proof of work matches claimed amount
        if (fCheckPOW && !CheckProofOfWork(GetHash(), nBits))
            return state.DoS(50, error("CheckBlockHeader () : proof of work failed"));

        // Check timestamp
        if (GetBlockTime() > FutureDrift(GetAdjustedTime())){
            LogPrintf("Block timestamp in future: blocktime %d futuredrift %d\n",GetBlockTime(),FutureDrift(GetAdjustedTime()));
            return error("CheckBlockHeader () : block timestamp too far in the future");
        }
    }

    return true;
}

bool CBlock::WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
{
    // Open history file to append
    CAutoFile fileout(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("CBlock::WriteToDisk() : AppendBlockFile failed");

    // Write index header
    unsigned int nSize = ::GetSerializeSize(fileout, *this);
    fileout << FLATDATA(pchMessageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout);
    if (fileOutPos < 0)
        return error("CBlock::WriteToDisk() : ftell failed");
    nBlockPosRet = fileOutPos;
    fileout << *this;

    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    if (!IsInitialBlockDownload() || (chainActive.Height()+1) % 500 == 0)
        FileCommit(fileout);

    return true;
}

bool CBlock::CheckBlock(CValidationState &state, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    if (!CheckBlockHeader(state, fCheckPOW))
        return false;

    // Check merkle root
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
        return state.DoS(100, error("CheckBlock () : hashMerkleRoot mismatch"));

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    set<uint256>
        uniqueTx; // tx hashes
    unsigned int
        nSigOps = 0; // total sigops

    // Size limits
    if (vtx.empty() || vtx.size() > GetMaxSize(MAX_BLOCK_SIZE) || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > GetMaxSize(MAX_BLOCK_SIZE))
        return state.DoS(100, error("CheckBlock () : size limits failed"));

    bool fProofOfStake = IsProofOfStake();

    // First transaction must be coinbase, the rest must not be
    if (!vtx[0].IsCoinBase())
        return state.DoS(100, error("CheckBlock () : first tx is not coinbase"));

    if (!vtx[0].CheckTransaction(state))
        return state.Invalid(error("CheckBlock () : CheckTransaction failed on coinbase"));

    uniqueTx.insert(vtx[0].GetHash());
    nSigOps += vtx[0].GetLegacySigOpCount();

    if (fProofOfStake)
    {
        // Proof-of-STake related checkings. Note that we know here that 1st transactions is coinstake. We don't need
        //   check the type of 1st transaction because it's performed earlier by IsProofOfStake()

        // Coinbase output should be empty if proof-of-stake block
        if (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty())
            return state.DoS(100, error("CheckBlock () : coinbase output not empty for proof-of-stake block"));

        // Check coinstake timestamp
        if (GetBlockTime() != (::int64_t)vtx[1].nTime)
            return state.DoS(50, error("CheckBlock () : coinstake timestamp violation nTimeBlock=%" PRId64 " nTimeTx=%ld", GetBlockTime(), vtx[1].nTime));

        // NovaCoin: check proof-of-stake block signature
        if (fCheckSig && !CheckBlockSignature())
        {
            LogPrintf( "\n" );
            LogPrintf(
                "bad PoS block signature, in block:"
                "\n"
                  );
            print();
            LogPrintf( "\n" );

            return state.DoS(100, error("CheckBlock () : bad proof-of-stake block signature"));
        }

        if (!vtx[1].CheckTransaction(state))
            return state.Invalid(error("CheckBlock () : CheckTransaction failed on coinstake"));

        uniqueTx.insert(vtx[1].GetHash());
        nSigOps += vtx[1].GetLegacySigOpCount();
    }
    else    // is PoW block
    {
        // Check coinbase timestamp
        if (GetBlockTime() < PastDrift((::int64_t)vtx[0].nTime))
            return state.DoS(50, error("CheckBlock () : coinbase timestamp is too late"));
    }

    // Iterate all transactions starting from second for proof-of-stake block
    //    or first for proof-of-work block
    for (unsigned int i = (fProofOfStake ? 2 : 1); i < vtx.size(); ++i)
    {
        const CTransaction& tx = vtx[i];

        // Reject coinbase transactions at non-zero index
        if (tx.IsCoinBase())
            return state.DoS(100, error("CheckBlock () : coinbase at wrong index"));

        // Reject coinstake transactions at index != 1
        if (tx.IsCoinStake())
            return state.DoS(100, error("CheckBlock () : coinstake at wrong index"));

        // Check transaction timestamp
        if (GetBlockTime() < (::int64_t)tx.nTime)
            return state.DoS(50, error("CheckBlock () : block timestamp earlier than transaction timestamp"));

        // Check transaction consistency
        if (!tx.CheckTransaction(state))
            return state.Invalid(error("CheckBlock () : CheckTransaction failed"));

        // Add transaction hash into list of unique transaction IDs
        uniqueTx.insert(tx.GetHash());

        // Calculate sigops count
        nSigOps += tx.GetLegacySigOpCount();
    }

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    if (uniqueTx.size() != vtx.size())
        return state.DoS(100, error("CheckBlock () : duplicate transaction"));

    // Reject block if validation would consume too much resources.
    if (nSigOps > GetMaxSize(MAX_BLOCK_SIGOPS))
        return state.DoS(100, error("CheckBlock () : out-of-bounds SigOpCount"));

    return true;
}

bool CBlock::AcceptBlock(CValidationState &state, CBlockIndex **ppindex, bool fRequested, bool* fNewBlock, CDiskBlockPos* dbp)
{
    // // Check for duplicate
    // uint256 hash = GetHash();
    // if (mapBlockIndex.count(hash))
    //     return error("AcceptBlock () : block already in mapBlockIndex");

    if (fNewBlock) *fNewBlock = false;
    CBlockIndex *&pindex = *ppindex;

    if (!AcceptBlockHeader(state, &pindex))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreOrSameWork = (chainActive.Tip() ? pindex->bnChainTrust >= chainActive.Tip()->bnChainTrust : true);

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (!fHasMoreOrSameWork) return true; // Don't process less-work chains
    }
    if (fNewBlock) *fNewBlock = true;

    if (!CheckBlock(state))
    {
        if (state.IsInvalid() && !state.CorruptionPossible())
        {
            pindex->nStatus |= BLOCK_FAILED_VALID;
        }
        return false;
    }

    int nHeight = pindex->nHeight;

    // Since hardfork block, new blocks don't accept transactions with version 1
    // anymore
    if (nHeight >= nMainnetNewLogicBlockNumber)
    {
        bool fProofOfStake = IsProofOfStake();

        if (vtx[0].nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old)
        {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            return state.Invalid(error(
                "AcceptBlock () : Not accept coinbase transaction with version 1"));
        }

        if (fProofOfStake &&
            vtx[1].nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old)
        {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            return state.Invalid(error(
                "AcceptBlock () : Not accept coinstake transaction with version 1"));
        }

        // Iterate all transactions starting from second for proof-of-stake block
        //    or first for proof-of-work block
        for (unsigned int i = (fProofOfStake ? 2 : 1); i < vtx.size(); ++i)
        {
            if (vtx[i].nVersion == CTransaction::CURRENT_VERSION_of_Tx_for_yac_old)
            {
                pindex->nStatus |= BLOCK_FAILED_VALID;
                return state.Invalid(
                    error("AcceptBlock () : Not accept transaction with version 1"));
            }
        }
    }

    // Check that all transactions are finalized
    BOOST_FOREACH (const CTransaction &tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
        {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            return state.DoS(
                10, error("AcceptBlock () : contains a non-final transaction"));
        }

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (!std::equal(expect.begin(), expect.end(),
                    vtx[0].vin[0].scriptSig.begin()))
    {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        return state.DoS(
            100, error("AcceptBlock () : block height mismatch in coinbase"));
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    const std::shared_ptr<const CBlock> block = std::make_shared<CBlock>(*this);
    if (!IsInitialBlockDownload() && chainActive.Tip() == pindex->pprev)
        GetMainSignals().NewPoWValidBlock(pindex, block);

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
    {
        state.Error();
        return error("AcceptBlock () : out of disk space");
    }

    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    // Only write block to disk if we aren't in reindex phase
    if (dbp == NULL && !WriteToDisk(nFile, nBlockPos))
        return state.Abort("AcceptBlock () : WriteToDisk failed");
    if (dbp != NULL)
    {
        nFile = dbp->nFile;
        nBlockPos = dbp->nPos;
    }
    if (!ReceivedBlockTransactions(state, nFile, nBlockPos, pindex))
        return error("AcceptBlock () : ReceivedBlockTransactions failed");

    // here would be a good place to check for new logic

    return true;
}


bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions, bool fCheckHeader)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions, fCheckHeader))
        return false;

    if (
        fCheckHeader &&
        (GetHash() != pindex->GetBlockHash())
       )
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

bool CBlock::ReadFromDisk(unsigned int nFile, unsigned int nBlockPos,
        bool fReadTransactions, bool fCheckHeader)
{
    SetNull();

    int nType = fReadTransactions ? SER_DISK : SER_DISK | SER_BLOCKHEADERONLY;
    // Open history file to read
    CAutoFile filein(OpenBlockFile(nFile, nBlockPos, "rb"),
            nType, CLIENT_VERSION);
    if (filein.IsNull())
        return error("CBlock::ReadFromDisk() : OpenBlockFile failed");

    // Read block
    try {
        filein >> *this;
    } catch (std::exception &e)
    //catch (...)
    {
        //(void)e;
        return error("%s() : deserialize or I/O error",
                BOOST_CURRENT_FUNCTION);
    }

    CTxDB txdb("r");
    if (fStoreBlockHashToDb && !txdb.ReadBlockHash(nFile, nBlockPos, blockHash))
    {
        LogPrintf("CBlock::ReadFromDisk(): can't read block hash at file = %d, block pos = %d\n", nFile, nBlockPos);
    }
    // Check the header
    if (fReadTransactions && IsProofOfWork()
            && (fCheckHeader && !CheckProofOfWork(GetHash(), nBits)))
        return error("CBlock::ReadFromDisk() : errors in block header");

    return true;
}

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}

bool CBlock::DisconnectBlock(CValidationState& state, CTxDB& txdb,
                             CBlockIndex* pindex, CTokensCache* tokensCache,
                             bool ignoreAddressIndex)
{
    LogPrintf("CBlock::DisconnectBlock, disconnect block (height: %d, hash: %s)\n", pindex->nHeight, GetHash().GetHex());
    /** YAC_TOKEN START */
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndoData;
    if (!ptokensdb->ReadBlockUndoTokenData(this->GetHash(), vUndoData)) {
        return error("DisconnectBlock(): block token undo data inconsistent");
    }
    /** YAC_TOKEN END */

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;

    // Disconnect in reverse order
    for (int i = vtx.size() - 1; i >= 0; i--)
    {
        const CTransaction &tx = vtx[i];
        uint256 hash = tx.GetHash();

        std::vector<int> vTokenTxIndex;
        // Update address index database
        if (fAddressIndex) {
            for (unsigned int k = tx.vout.size(); k-- > 0;) {
                const CTxOut &out = tx.vout[k];

                std::vector<unsigned char> hashBytes;
                if (out.scriptPubKey.IsPayToScriptHash()) {
                    hashBytes.assign(out.scriptPubKey.begin()+2, out.scriptPubKey.begin()+22);

                    // undo receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(2, uint160(hashBytes), pindex->nHeight, i, hash, k, false), out.nValue));

                    // undo unspent index
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(2, uint160(hashBytes), hash, k), CAddressUnspentValue()));

                } else if (out.scriptPubKey.IsPayToPublicKeyHash()) {
                    hashBytes.assign(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);

                    // undo receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(1, uint160(hashBytes), pindex->nHeight, i, hash, k, false), out.nValue));

                    // undo unspent index
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, uint160(hashBytes), hash, k), CAddressUnspentValue()));

                } else if (out.scriptPubKey.IsPayToPublicKey()) {
                    uint160 hashBytesUint160(Hash160(out.scriptPubKey.begin()+1, out.scriptPubKey.end()-1));

                    // undo receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(1, hashBytesUint160, pindex->nHeight, i, hash, k, false), out.nValue));

                    // undo unspent index
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, hashBytesUint160, hash, k), CAddressUnspentValue()));
                } else if (out.scriptPubKey.IsP2PKHTimelock(hashBytes)) {
                    // undo receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(1, uint160(hashBytes), pindex->nHeight, i, hash, k, false), out.nValue));

                    // undo unspent index
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, uint160(hashBytes), hash, k), CAddressUnspentValue()));
                } else {
                    /** YAC_TOKEN START */
                    if (AreTokensDeployed()) {
                        std::string tokenName;
                        CAmount tokenAmount;
                        uint160 hashBytesUint160;

                        if (ParseTokenScript(out.scriptPubKey, hashBytesUint160, tokenName, tokenAmount)) {
//                            std::cout << "ConnectBlock(): pushing tokens onto addressIndex: " << "1" << ", " << hashBytes.GetHex() << ", " << tokenName << ", " << pindex->nHeight
//                                      << ", " << i << ", " << hash.GetHex() << ", " << k << ", " << "true" << ", " << tokenAmount << std::endl;

                            // undo receiving activity
                            addressIndex.push_back(std::make_pair(
                                    CAddressIndexKey(1, uint160(hashBytesUint160), tokenName, pindex->nHeight, i, hash, k,
                                                     false), tokenAmount));

                            // undo unspent index
                            addressUnspentIndex.push_back(
                                    std::make_pair(CAddressUnspentKey(1, uint160(hashBytesUint160), tokenName, hash, k),
                                                   CAddressUnspentValue()));
                        } else {
                            continue;
                        }
                    }
                    /** YAC_TOKEN END */
                }
            }
        }

        // Check that all outputs are available and match the outputs in the block itself exactly.
        /** YAC_TOKEN START */
        if (AreTokensDeployed()) {
            if (tokensCache) {
                for (size_t o = 0; o < tx.vout.size(); o++) {
                    if (IsScriptTransferToken(tx.vout[o].scriptPubKey))
                        vTokenTxIndex.emplace_back(o);
                }
            }
        }
        /** YAC_TOKEN START */

        /** YAC_TOKEN START */
        // Update token cache, it is used for updating token database later
        if (AreTokensDeployed()) {
            if (tokensCache) {
                if (tx.IsNewToken()) {
                    // Remove the newly created token
                    CNewToken token;
                    std::string strAddress;
                    if (!TokenFromTransaction(tx, token, strAddress)) {
                        return error("%s : Failed to get token from transaction. TXID : %s", __func__, tx.GetHash().GetHex());
                    }
                    if (tokensCache->ContainsToken(token)) {
                        if (!tokensCache->RemoveNewToken(token, strAddress)) {
                            return error("%s : Failed to Remove Token. Token Name : %s", __func__, token.strName);
                        }
                    }

                    // Get the owner from the transaction and remove it
                    std::string ownerName;
                    std::string ownerAddress;
                    if (!OwnerFromTransaction(tx, ownerName, ownerAddress)) {
                        return error("%s : Failed to get owner from transaction. TXID : %s", __func__, tx.GetHash().GetHex());
                    }

                    if (!tokensCache->RemoveOwnerToken(ownerName, ownerAddress)) {
                        return error("%s : Failed to Remove Owner from transaction. TXID : %s", __func__, tx.GetHash().GetHex());
                    }
                } else if (tx.IsReissueToken()) {
                    CReissueToken reissue;
                    std::string strAddress;

                    if (!ReissueTokenFromTransaction(tx, reissue, strAddress)) {
                        return  error("%s : Failed to get reissue token from transaction. TXID : %s", __func__, tx.GetHash().GetHex());
                    }

                    if (tokensCache->ContainsToken(reissue.strName)) {
                        if (!tokensCache->RemoveReissueToken(reissue, strAddress,
                                                             COutPoint(tx.GetHash(), tx.vout.size() - 1),
                                                             vUndoData)) {
                            return error("%s : Failed to Undo Reissue Token. Token Name : %s", __func__, reissue.strName);
                        }
                    }
                } else if (tx.IsNewUniqueToken()) {
                    for (int n = 0; n < (int)tx.vout.size(); n++) {
                        auto out = tx.vout[n];
                        CNewToken token;
                        std::string strAddress;

                        if (IsScriptNewUniqueToken(out.scriptPubKey)) {
                            if (!TokenFromScript(out.scriptPubKey, token, strAddress)) {
                                return error("%s : Failed to get unique token from transaction. TXID : %s, vout: %s", __func__,
                                        tx.GetHash().GetHex(), n);
                            }

                            if (tokensCache->ContainsToken(token.strName)) {
                                if (!tokensCache->RemoveNewToken(token, strAddress)) {
                                    return error("%s : Failed to Undo Unique Token. Token Name : %s", __func__, token.strName);
                                }
                            }
                        }
                    }
                }

                for (auto index : vTokenTxIndex) {
                    CTokenTransfer transfer;
                    std::string strAddress;
                    if (!TransferTokenFromScript(tx.vout[index].scriptPubKey, transfer, strAddress)) {
                        return error("%s : Failed to get transfer token from transaction. CTxOut : %s", __func__,
                                tx.vout[index].ToString());
                    }

                    COutPoint out(hash, index);
                    if (!tokensCache->RemoveTransfer(transfer, strAddress, out)) {
                        return error("%s : Failed to Remove the transfer of an token. Token Name : %s, COutPoint : %s",
                                __func__,
                                transfer.strName, out.ToString());
                    }
                }
            }
        }
        /** YAC_TOKEN END */

        // restore inputs
        // Relinquish previous transactions' spent pointers
        if (!tx.IsCoinBase())
        {
            for (unsigned int j = tx.vin.size(); j-- > 0;)
            {
                const CTxIn& input = tx.vin[j];
                const COutPoint &prevout = tx.vin[j].prevout;

                // Get prev txindex from disk
                CTxIndex txindex;
                if (!txdb.ReadTxIndex(prevout.COutPointGetHash(), txindex))
                    return error("CBlock::DisconnectBlock() : ReadTxIndex failed");

                if (prevout.COutPointGet_n() >= txindex.vSpent.size())
                    return error("CBlock::DisconnectBlock() : prevout.n out of range");

                // Mark outpoint as not spent
                txindex.vSpent[prevout.COutPointGet_n()].SetNull();

                // Write back
                if (!txdb.UpdateTxIndex(prevout.COutPointGetHash(), txindex))
                    return error("CBlock::DisconnectBlock() : UpdateTxIndex failed");

                CTransaction txPrev;
                // Get prev tx from disk
                if (!txPrev.ReadFromDisk(txindex.pos))
                    return error("CBlock::DisconnectBlock() : %s ReadFromDisk prev tx %s failed", tx.GetHash().ToString().substr(0,10).c_str(),  prevout.COutPointGetHash().ToString().substr(0,10).c_str());
                const CTxOut &prevTxOut = txPrev.vout[prevout.COutPointGet_n()];

                /** YAC_TOKEN START */
                if (AreTokensDeployed()) {
                    if (tokensCache && prevTxOut.scriptPubKey.IsTokenScript()) {
                        if (!tokensCache->UndoTokenCoin(prevTxOut, prevout))
                            return error("CBlock::DisconnectBlock() : Failed to undo token coin");
                    }
                }

                // Update address index database
                if (fAddressIndex) {
                    std::vector<unsigned char> hashBytes;
                    if (prevTxOut.scriptPubKey.IsPayToScriptHash()) {
                        hashBytes.assign(prevTxOut.scriptPubKey.begin()+2, prevTxOut.scriptPubKey.begin()+22);

                        // undo spending activity
                        addressIndex.push_back(std::make_pair(CAddressIndexKey(2, uint160(hashBytes), pindex->nHeight, i, hash, j, true), prevTxOut.nValue * -1));

                        // restore unspent index
                        addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(2, uint160(hashBytes), input.prevout.hash, input.prevout.n), CAddressUnspentValue(prevTxOut.nValue, prevTxOut.scriptPubKey, pindex->nHeight -1)));


                    } else if (prevTxOut.scriptPubKey.IsPayToPublicKeyHash()) {
                        hashBytes.assign(prevTxOut.scriptPubKey.begin()+3, prevTxOut.scriptPubKey.begin()+23);

                        // undo spending activity
                        addressIndex.push_back(std::make_pair(CAddressIndexKey(1, uint160(hashBytes), pindex->nHeight, i, hash, j, true), prevTxOut.nValue * -1));

                        // restore unspent index
                        addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, uint160(hashBytes), input.prevout.hash, input.prevout.n), CAddressUnspentValue(prevTxOut.nValue, prevTxOut.scriptPubKey, pindex->nHeight -1)));

                    } else if (prevTxOut.scriptPubKey.IsPayToPublicKey()) {
                        uint160 hashBytesUint160(Hash160(prevTxOut.scriptPubKey.begin()+1, prevTxOut.scriptPubKey.end()-1));

                        // undo spending activity
                        addressIndex.push_back(std::make_pair(CAddressIndexKey(1, hashBytesUint160, pindex->nHeight, i, hash, j, true), prevTxOut.nValue * -1));

                        // restore unspent index
                        addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, hashBytesUint160, input.prevout.hash, j), CAddressUnspentValue(prevTxOut.nValue, prevTxOut.scriptPubKey, pindex->nHeight -1)));
                    } else if (prevTxOut.scriptPubKey.IsP2PKHTimelock(hashBytes)) {
                        // undo spending activity
                        addressIndex.push_back(std::make_pair(CAddressIndexKey(1, uint160(hashBytes), pindex->nHeight, i, hash, j, true), prevTxOut.nValue * -1));

                        // restore unspent index
                        addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, uint160(hashBytes), input.prevout.hash, input.prevout.n), CAddressUnspentValue(prevTxOut.nValue, prevTxOut.scriptPubKey, pindex->nHeight -1)));
                    } else {
                        if (AreTokensDeployed()) {
                            std::string tokenName;
                            CAmount tokenAmount;
                            uint160 hashBytesUint160;

                            if (ParseTokenScript(prevTxOut.scriptPubKey, hashBytesUint160, tokenName, tokenAmount)) {
//                                std::cout << "ConnectBlock(): pushing tokens onto addressIndex: " << "1" << ", " << hashBytes.GetHex() << ", " << tokenName << ", " << pindex->nHeight
//                                          << ", " << i << ", " << hash.GetHex() << ", " << j << ", " << "true" << ", " << tokenAmount * -1 << std::endl;

                                // undo spending activity
                                addressIndex.push_back(std::make_pair(
                                        CAddressIndexKey(1, uint160(hashBytesUint160), tokenName, pindex->nHeight, i, hash, j,
                                                         true), tokenAmount * -1));

                                // restore unspent index
                                addressUnspentIndex.push_back(std::make_pair(
                                        CAddressUnspentKey(1, uint160(hashBytesUint160), tokenName, input.prevout.hash,
                                                           input.prevout.n),
                                        CAddressUnspentValue(tokenAmount, prevTxOut.scriptPubKey, pindex->nHeight -1)));
                            } else {
                                continue;
                            }
                        }
                    }
                }
                /** YAC_TOKEN END */
            }
        }

        // Remove transaction from index
        // This can fail if a duplicate of this transaction was in a chain that got
        // reorganized away. This is only possible if this transaction was completely
        // spent, so erasing it would be a no-op anyway.
        txdb.EraseTxIndex(tx);
    }

    if (!ignoreAddressIndex && fAddressIndex) {
        if (!txdb.EraseAddressIndex(addressIndex)) {
            return error("Failed to delete address index");
        }
        if (!txdb.UpdateAddressUnspentIndex(addressUnspentIndex)) {
            return error("Failed to write address unspent index");
        }
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("DisconnectBlock() : WriteBlockIndex failed");
        if (fStoreBlockHashToDb && !txdb.WriteBlockHash(blockindexPrev))
        {
            LogPrintf("CBlock::DisconnectBlock(): Can't WriteBlockHash\n");
            return error("DisconnectBlock() : WriteBlockHash failed");
        }
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    BOOST_FOREACH (CTransaction& tx, vtx)
        SyncWithWallets(tx, this, false, false);

    return true;
}

bool CBlock::ConnectBlock(CValidationState &state, CTxDB& txdb, CBlockIndex* pindex, CTokensCache* tokensCache, bool fJustCheck, bool ignoreAddressIndex)
{
    LogPrintf("CBlock::ConnectBlock, connect block (height: %d, hash: %s)\n", pindex->nHeight, GetHash().GetHex());
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock(state, !fJustCheck, !fJustCheck, false))
        return false;

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes in their
    // initial block download.
    bool fEnforceBIP30 = true;
    bool fScriptChecks = pindex->nHeight >= Checkpoints::GetTotalBlocksEstimate();

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck)
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    else
        nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    ::int64_t nFees = 0;
    ::int64_t nValueIn = 0;
    ::int64_t nValueOut = 0;
    unsigned int nSigOps = 0;

    /** YAC_TOKEN START */
    std::vector<std::pair<std::string, CBlockTokenUndo> > vUndoTokenData;
    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;
    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > addressUnspentIndex;
    /** YAC_TOKEN END */

    // Iterate through all transaction to check double spent, connect inputs
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        const CTransaction &tx = vtx[i];
        const uint256 hashTx = tx.GetHash();
        if (fEnforceBIP30) {
            CTxIndex txindexOld;
            if (txdb.ReadTxIndex(hashTx, txindexOld)) {
                for (const CDiskTxPos &pos : txindexOld.vSpent)
                {
                    if (pos.IsNull())
                    {
                        return state.DoS(100, error("ConnectBlock() : tried to overwrite transaction"));
                    }
                }
            }
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > GetMaxSize(MAX_BLOCK_SIGOPS))
            return state.DoS(100, error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        MapPrevTx mapInputs;
        if (tx.IsCoinBase())
            nValueOut += tx.GetValueOut();
        else
        {
            bool fInvalid;
            if (!tx.FetchInputs(state, txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
                return false;

            /** YAC_TOKEN START */
            if (!AreTokensDeployed()) {
                for (auto out : tx.vout)
                    if (out.scriptPubKey.IsTokenScript())
                    {
                        LogPrintf("WARNING: Received Block with tx that contained an token when tokens wasn't active\n");
                    }
            }

            if (AreTokensDeployed()) {
                std::vector<std::pair<std::string, uint256>> vReissueTokens;
                if (!CheckTxTokens(tx, state, mapInputs, tokensCache, false, vReissueTokens))
                {
                    state.SetFailedTransaction(tx.GetHash());
                    return error("%s: CheckTxTokens: %s, %s", __func__, tx.GetHash().ToString(),
                                 FormatStateMessage(state));
                }
            }

            /** YAC_TOKEN END */

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            std::vector<int> prevheights;
            prevheights.resize(tx.vin.size());
            int nLockTimeFlags = 0;
            for (unsigned int i = 0; i < tx.vin.size(); ++i)
            {
                COutPoint
                    prevout = tx.vin[i].prevout;
                CTransaction tx;
                uint256 hashBlock = 0;
                if (GetTransaction(prevout.COutPointGetHash(), tx, hashBlock))
                {
                    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
                    if (mi != mapBlockIndex.end() && (*mi).second)
                    {
                        CBlockIndex* pTmpIndex = (*mi).second;
                        prevheights[i] = pTmpIndex->nHeight;
                    }
                    else
                    {
                        prevheights[i] = pindex->nHeight;
                    }
                }
                else
                {
                    prevheights[i] = pindex->nHeight;
                }
            }
            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex))
            {
                return state.DoS(100, error("ConnectBlock(): contains a non-BIP68-final transaction"));
            }

            /** YAC_TOKEN START */
            // Iterate through transaction inputs and update address index database
            if (fAddressIndex)
            {
                for (size_t j = 0; j < tx.vin.size(); j++)
                {
                    const CTxIn& input = tx.vin[j];
                    CTransaction &txPrev = mapInputs[input.prevout.COutPointGetHash()].second;
                    const CTxOut &prevout = txPrev.vout[input.prevout.COutPointGet_n()];
                    uint160 hashBytesUint160;
                    std::vector<unsigned char> hashBytes;
                    int addressType = 0;
                    bool isToken = false;
                    std::string tokenName;
                    CAmount tokenAmount;

                    if (prevout.scriptPubKey.IsPayToScriptHash()) {
                        hashBytes.assign(prevout.scriptPubKey.begin()+2, prevout.scriptPubKey.begin()+22);
                        hashBytesUint160 = uint160(hashBytes);
                        addressType = 2;
                    } else if (prevout.scriptPubKey.IsPayToPublicKeyHash()) {
                        hashBytes.assign(prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23);
                        hashBytesUint160 = uint160(hashBytes);
                        addressType = 1;
                    } else if (prevout.scriptPubKey.IsPayToPublicKey()) {
                        hashBytesUint160 = Hash160(prevout.scriptPubKey.begin() + 1, prevout.scriptPubKey.end() - 1);
                        addressType = 1;
                    } else if (prevout.scriptPubKey.IsP2PKHTimelock(hashBytes)) {
                        hashBytesUint160 = uint160(hashBytes);
                        addressType = 1;
                    } else {
                        if (AreTokensDeployed()) {
                            hashBytesUint160.SetNull();
                            addressType = 0;

                            if (ParseTokenScript(prevout.scriptPubKey, hashBytesUint160, tokenName, tokenAmount)) {
                                addressType = 1;
                                isToken = true;
                            }
                        }
                    }

                    if (fAddressIndex && addressType > 0)
                    {
                        if (isToken) {
                            // record spending activity
                            addressIndex.push_back(std::make_pair(CAddressIndexKey(addressType, hashBytesUint160, tokenName, pindex->nHeight, i, hashTx, j, true), tokenAmount * -1));

                            // remove address from unspent index
                            addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(addressType, hashBytesUint160, tokenName, input.prevout.hash, input.prevout.n), CAddressUnspentValue()));
                        } else {
                            // record spending activity
                            addressIndex.push_back(std::make_pair(CAddressIndexKey(addressType, hashBytesUint160, pindex->nHeight, i, hashTx, j, true), prevout.nValue * -1));

                            // remove address from unspent index
                            addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(addressType, hashBytesUint160, input.prevout.hash, input.prevout.n), CAddressUnspentValue()));
                        }
                    }
                }
            }
            /** YAC_TOKEN END */

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nSigOps > GetMaxSize(MAX_BLOCK_SIGOPS))
                return state.DoS(100, error("ConnectBlock() : too many sigops"));

            ::int64_t nTxValueIn = tx.GetValueIn(mapInputs);
            ::int64_t nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            if (!tx.IsCoinStake())
                nFees += nTxValueIn - nTxValueOut;

            std::vector<CScriptCheck> vChecks;
            if (
                !tx.ConnectInputs(state,
                                  txdb,
                                  mapInputs,
                                  mapQueuedChanges,
                                  posThisTx,
                                  pindex,
                                  true,
                                  false,
                                  fScriptChecks,
                                  SCRIPT_VERIFY_NOCACHE | SCRIPT_VERIFY_P2SH,
                                  nScriptCheckThreads ? &vChecks : NULL
                                 )
               )
                return false;
            control.Add(vChecks);
        }

        // This map is used to update block/tx index database later
        // It contains all latest info about UTXOs
        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());

        /** YAC_TOKEN START */
        // Iterate through transaction outputs and update address index database
        if (fAddressIndex)
        {
            for (unsigned int k = 0; k < tx.vout.size(); k++) {
                const CTxOut &out = tx.vout[k];
                std::vector<unsigned char> hashBytes;
                if (out.scriptPubKey.IsPayToScriptHash()) {
                    hashBytes.assign(out.scriptPubKey.begin()+2, out.scriptPubKey.begin()+22);

                    // record receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(2, uint160(hashBytes), pindex->nHeight, i, hashTx, k, false), out.nValue));

                    // record unspent output
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(2, uint160(hashBytes), hashTx, k), CAddressUnspentValue(out.nValue, out.scriptPubKey, pindex->nHeight)));

                } else if (out.scriptPubKey.IsPayToPublicKeyHash()) {
                    hashBytes.assign(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);

                    // record receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(1, uint160(hashBytes), pindex->nHeight, i, hashTx, k, false), out.nValue));

                    // record unspent output
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, uint160(hashBytes), hashTx, k), CAddressUnspentValue(out.nValue, out.scriptPubKey, pindex->nHeight)));

                } else if (out.scriptPubKey.IsPayToPublicKey()) {
                    uint160 hashBytesUint160(Hash160(out.scriptPubKey.begin() + 1, out.scriptPubKey.end() - 1));

                    // record receiving activity
                    addressIndex.push_back(
                            std::make_pair(CAddressIndexKey(1, hashBytesUint160, pindex->nHeight, i, hashTx, k, false),
                                           out.nValue));

                    // record unspent output
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, hashBytesUint160, hashTx, k),
                                                                 CAddressUnspentValue(out.nValue, out.scriptPubKey,
                                                                                      pindex->nHeight)));
                } else if (out.scriptPubKey.IsP2PKHTimelock(hashBytes)) {
                    // record receiving activity
                    addressIndex.push_back(std::make_pair(CAddressIndexKey(1, uint160(hashBytes), pindex->nHeight, i, hashTx, k, false), out.nValue));

                    // record unspent output
                    addressUnspentIndex.push_back(std::make_pair(CAddressUnspentKey(1, uint160(hashBytes), hashTx, k), CAddressUnspentValue(out.nValue, out.scriptPubKey, pindex->nHeight)));
                } else {
                    if (AreTokensDeployed()) {
                        std::string tokenName;
                        CAmount tokenAmount;
                        uint160 hashBytesUint160;

                        if (ParseTokenScript(out.scriptPubKey, hashBytesUint160, tokenName, tokenAmount)) {
                            // record receiving activity
                            addressIndex.push_back(std::make_pair(
                                    CAddressIndexKey(1, hashBytesUint160, tokenName, pindex->nHeight, i, hashTx, k, false),
                                    tokenAmount));

                            // record unspent output
                            addressUnspentIndex.push_back(
                                    std::make_pair(CAddressUnspentKey(1, hashBytesUint160, tokenName, hashTx, k),
                                                   CAddressUnspentValue(tokenAmount, out.scriptPubKey,
                                                                        pindex->nHeight)));
                        }
                    } else {
                        continue;
                    }
                }
            }
        }
        /** YAC_TOKEN END */

        /** YAC_TOKEN START */
        if (AreTokensDeployed()) {
            // Create the basic empty string pair for the undoblock
            std::pair<std::string, CBlockTokenUndo> undoPair = std::make_pair("", CBlockTokenUndo());
            std::pair<std::string, CBlockTokenUndo>* undoTokenData = &undoPair;

            // Update token info (tokenCache, undoTokenData)
            UpdateTokenInfo(tx, mapInputs, pindex->nHeight, GetHash(), tokensCache, undoTokenData);

            if (!undoTokenData->first.empty()) {
                vUndoTokenData.emplace_back(*undoTokenData);
            }
        }
        /** YAC_TOKEN END */
    } // END OF for (unsigned int i = 0; i < vtx.size(); i++)

//_____________________ this is new code here
    if (!control.Wait())
    {
        LogPrintf( "\nDoS ban of whom?\n\n" );   //maybe all nodes?
        return state.DoS(100, false);     // a direct ban
    }

	if (IsProofOfWork()) {
		::int64_t nBlockReward = GetProofOfWorkReward(nBits, nFees);

		// Check coinbase reward
		if (vtx[0].GetValueOut() > nBlockReward) {
			return state.DoS(100,
					error("CheckBlock () : coinbase reward exceeded "
							"(actual=%" PRId64 " vs calculated=%" PRId64 ")",
							vtx[0].GetValueOut(), nBlockReward));
		}
	}
//_____________________

    // track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    if (!txdb.WriteBlockIndex(CDiskBlockIndex(pindex)))
        return error("Connect() : WriteBlockIndex for pindex failed");
    if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindex)))
    {
        LogPrintf("Connect(): Can't WriteBlockHash\n");
        return error("Connect() : WriteBlockHash failed");
    }

    // fees are not collected by proof-of-stake miners
    // fees are destroyed to compensate the entire network
    if (fDebug && IsProofOfStake() && gArgs.GetBoolArg("-printcreation"))
        LogPrintf("ConnectBlock() : destroy=%s nFees=%" PRId64 "\n", FormatMoney(nFees), nFees);

    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock() : UpdateTxIndex failed");
    }

    /** YAC_TOKEN START */
    if (vUndoTokenData.size()) {
        if (!ptokensdb->WriteBlockUndoTokenData(GetHash(), vUndoTokenData))
            return error("ConnectBlock(): Failed to write token undo data");
    }

    if (!ignoreAddressIndex && fAddressIndex) {
        if (!txdb.WriteAddressIndex(addressIndex)) {
            return error("ConnectBlock(): Failed to write address index");
        }

        if (!txdb.UpdateAddressUnspentIndex(addressUnspentIndex)) {
            return error("ConnectBlock(): Failed to write address unspent index");
        }
    }
    /** YAC_TOKEN END */

    pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!txdb.WriteBlockIndex(blockindexPrev))
            return error("ConnectBlock() : WriteBlockIndex failed");
        if (fStoreBlockHashToDb && !txdb.WriteBlockHash(blockindexPrev))
        {
            LogPrintf("ConnectBlock(): Can't WriteBlockHash\n");
            return error("ConnectBlock() : WriteBlockHash failed");
        }
    }

    // Watch for transactions paying to me
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, true);

    // Notify UI to display prev block's coinbase if it was ours
    static uint256 hashPrevBestCoinBase;
    UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = vtx[0].GetHash();

    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(::uint64_t& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        ::uint64_t nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && gArgs.GetBoolArg("-printcoinage"))
        LogPrintf("block coin age total nCoinDays=%" PRId64 "\n", nCoinAge);
    return true;
}

// Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS).
bool CBlock::ReceivedBlockTransactions(CValidationState &state, unsigned int nFile, unsigned int nBlockPos, CBlockIndex *pindexNew)
{
    // ppcoin: record proof-of-stake hash value
    uint256 hash = GetHash();
    if (pindexNew->IsProofOfStake())
    {
        if (!mapProofOfStake.count(hash))
            return error("AcceptBlock() : hashProofOfStake not found in map");
        pindexNew->hashProofOfStake = mapProofOfStake[hash];
    }

    pindexNew->nFile = nFile;
    pindexNew->nBlockPos = nBlockPos;
    pindexNew->validTx = false;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;

    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    {
         LOCK(cs_nBlockSequenceId);
         pindexNew->nSequenceId = nBlockSequenceId++;
    }

    CTxDB txdb;
    if (!txdb.TxnBegin())
    {
        LogPrintf("AddToBlockIndex(): TxnBegin failed\n");
        return false;
    }

    if (pindexNew->pprev == NULL || pindexNew->pprev->validTx) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->validTx = (pindex->pprev ? pindex->pprev->validTx : true);
            setBlockIndexCandidates.insert(pindex);
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
            txdb.WriteBlockIndex(CDiskBlockIndex(pindex));

            if (!chainActive.Tip() || (chainActive.Tip()->nHeight + 1) < nMainnetNewLogicBlockNumber)
            {
                // ppcoin: compute stake modifier
                ::uint64_t nStakeModifier = 0;
                bool fGeneratedStakeModifier = false;
                if (!ComputeNextStakeModifier(pindex, nStakeModifier, fGeneratedStakeModifier))
                    return error("AcceptBlock() : ComputeNextStakeModifier() failed");
                pindex->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);

                pindex->nStakeModifierChecksum = GetStakeModifierChecksum(pindex);
                if (!CheckStakeModifierCheckpoints(pindex->nHeight, pindex->nStakeModifierChecksum))
                    LogPrintf("AcceptBlock() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016\n" PRIx64, pindex->nHeight, nStakeModifier);
            }

            if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindex)))
            {
                LogPrintf("AddToBlockIndex(): Can't WriteBlockHash\n");
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
        txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
        if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindexNew)))
        {
            LogPrintf("AddToBlockIndex(): Can't WriteBlockHash\n");
        }
    }

    // Write to disk block index
    if (!txdb.TxnCommit())
    {
        LogPrintf("AddToBlockIndex(): TxnCommit failed\n");
        return false;
    }

    return true;
}

//_____________________________________________________________________________
// ppcoin: sign block
bool CBlock::SignBlock044(const CKeyStore& keystore)
//bool SignBlock044(const CKeyStore& keystore)
{
    vector<valtype> vSolutions;
    txnouttype whichType;

    if(!IsProofOfStake())
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                continue;

            if (whichType == TX_PUBKEY)
            {
                // Sign
                valtype& vchPubKey = vSolutions[0];
                CKey key;

                if (!keystore.GetKey(Hash160(vchPubKey), key))
                    continue;
                if (key.GetPubKey() != vchPubKey)
                    continue;
                if(
                    !key.Sign(
                                GetHash(),    //<<<<<<<<<<<<<<< test
                                //GetHash(),
                                vchBlockSig
                             )
                  )
                    continue;
                return true;
            }
        }
    }
    else
    {
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            // Sign
            valtype& vchPubKey = vSolutions[0];
            CKey key;

            if (!keystore.GetKey(Hash160(vchPubKey), key))
                return false;
            if (key.GetPubKey() != vchPubKey)
                return false;

            return key.Sign(GetHash(), vchBlockSig);
        }
    }

    LogPrintf("Sign failed\n");
    return false;
}

//_____________________________________________________________________________
// novacoin: attempt to generate suitable proof-of-stake
bool CBlock::SignBlock(CWallet& wallet)
{
    // if we are doing 0.4.4 blocks, let's check using 0.4.4 code
    if(
       !IsProofOfStake()    // i.e PoW then immaterial what version!
       ||
       (VERSION_of_block_for_yac_05x_new == nVersion)
       ||
       (VERSION_of_block_for_yac_05x_new == nVersion)
       ||
       (VERSION_of_block_for_yac_044_old == nVersion)
      )
    {
        bool
            fOldVersion = SignBlock044( wallet );
        return fOldVersion;
    }
    // if we are trying to sign
    //    something except proof-of-stake block template
    if (
        !vtx[0].vout[0].IsEmpty()
       )
        return false;

    // if we are trying to sign
    //    a complete proof-of-stake block
    if (IsProofOfStake())   // seems like no signature on a PoS???
        return true;

    return false;
}

// ppcoin: check block signature
bool CBlock::CheckBlockSignature() const
{
    if (GetHash() == hashGenesisBlock)  // from 0.4.4 code
        return vchBlockSig.empty();

    vector<valtype>
        vSolutions;

    txnouttype
        whichType;

    if (IsProofOfWork())
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                return false;

            if (whichType == TX_PUBKEY)
            {
                // Verify
                valtype& vchPubKey = vSolutions[0];
                CKey key;
                if (!key.SetPubKey(vchPubKey))
                    continue;
                if (vchBlockSig.empty())
                    continue;
                if(!key.Verify(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    else  // is PoS
    {
        // so we are only concerned with PoS blocks!
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            valtype
                & vchPubKey = vSolutions[0];

            CKey
                key;

            if (!key.SetPubKey(vchPubKey))
                return false;
            if (vchBlockSig.empty())
                return false;

            bool
                fVerifyOK = key.Verify(GetHash(), vchBlockSig);

            if( false == fVerifyOK )
                return false;       // so I can trap it
            else
            {   // just to see if it ever is true? It is!!!
                return true;
            }
        }
    }
    return false;
}

// yacoin2015 GetBlockTrust upgrade
CBigNum CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);
    if (bnTarget <= 0)
        return CBigNum(0);

    // saironiq: new trust rules (since CONSECUTIVE_STAKE_SWITCH_TIME on mainnet and always on testnet)
    if (
        fTestNet
        ||
        (GetBlockTime() >= CONSECUTIVE_STAKE_SWITCH_TIME)
       )
    {
        // first block trust - for future compatibility (i.e., forks :P)
        if (pprev == NULL)
            return CBigNum(1);

        // PoS after PoS? no trust for ya!
        // (no need to explicitly disallow consecutive PoS
        // blocks now as they won't get any trust anyway)
        if (IsProofOfStake() && pprev->IsProofOfStake())
            return CBigNum(0);

        // PoS after PoW? trust = prev_trust + 1!
        if (IsProofOfStake() && pprev->IsProofOfWork())
            return pprev->GetBlockTrust() + 1;  //<<<<<<<<<<<<< does this mean this is recursive??????
                                                // sure looks thatway!  Is this the intent?
        // PoW trust calculation
        if (IsProofOfWork())
        {
            // set trust to the amount of work done in this block
            CBigNum bnTrust = bnProofOfWorkLimit / bnTarget;

            // double the trust if previous block was PoS
            // (to prevent orphaning of PoS)
            if (pprev->IsProofOfStake())
                bnTrust *= 2;

            return bnTrust;
        }
        // what the hell?!
        return CBigNum(0);
    }
    return (IsProofOfStake()? (CBigNum(1)<<256) / (bnTarget+1) : CBigNum(1));
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    if (height > nHeight || height < 0)
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (heightSkip == height ||
            (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                      heightSkipPrev >= height))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

bool CBlockIndex::IsInMainChain() const
{
    return (pnext || this == chainActive.Tip());
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-NULL. */
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}
