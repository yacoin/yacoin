// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"
#include "txdb.h"
#include "checkpoints.h"
#include "kernel.h"
#include "wallet.h"

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
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
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
    std::map<uint256, CBlockIndex *>::iterator miSelf = mapBlockIndex.find(hash);
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
    map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hashPrevBlock);
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
    std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(*(CBlockHeader*)this);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;

    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock); // this bothers me when mapBlockIndex == NULL!?

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
        printf("AddToBlockIndex(): TxnBegin failed\n");
    }
    txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
    if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindexNew)))
    {
        printf("AddToBlockIndex(): Can't WriteBlockHash\n");
    }
    if (!txdb.TxnCommit())
    {
        printf("AddToBlockIndex(): TxnCommit failed\n");
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
            printf("Block timestamp in future: blocktime %d futuredrift %d",GetBlockTime(),FutureDrift(GetAdjustedTime()));
            return error("CheckBlockHeader () : block timestamp too far in the future");
        }
    }

    return true;
}

bool CBlock::WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
{
    // Open history file to append
    CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
    if (!fileout)
        return error("CBlock::WriteToDisk() : AppendBlockFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(*this);
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
            printf( "\n" );
            printf(
                "bad PoS block signature, in block:"
                "\n"
                  );
            print();
            printf( "\n" );

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

bool CBlock::AcceptBlock(CValidationState &state, CBlockIndex **ppindex)
{
    // // Check for duplicate
    // uint256 hash = GetHash();
    // if (mapBlockIndex.count(hash))
    //     return error("AcceptBlock () : block already in mapBlockIndex");

    CBlockIndex *&pindex = *ppindex;

    if (!AcceptBlockHeader(state, &pindex))
        return false;

    if (pindex->nStatus & BLOCK_HAVE_DATA) {
        // TODO: deal better with duplicate blocks.
        // return state.DoS(20, error("AcceptBlock() : already have block %d %s", pindex->nHeight, pindex->GetBlockHash().ToString()), REJECT_DUPLICATE, "duplicate");
        return true;
    }

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
    if (((!fUseOld044Rules) &&
         (vtx[0].vin[0].scriptSig.size() < expect.size())) ||
        !std::equal(expect.begin(), expect.end(),
                    vtx[0].vin[0].scriptSig.begin()))
    {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        return state.DoS(
            100, error("AcceptBlock () : block height mismatch in coinbase"));
    }

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
    {
        state.Error();
        return error("AcceptBlock () : out of disk space");
    }

    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return state.Abort("AcceptBlock () : WriteToDisk failed");
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

    // Open history file to read
    CAutoFile filein = CAutoFile(OpenBlockFile(nFile, nBlockPos, "rb"),
            SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
    if (!fReadTransactions)
        filein.nType |= SER_BLOCKHEADERONLY;

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
        printf("CBlock::ReadFromDisk(): can't read block hash at file = %d, block pos = %d\n", nFile, nBlockPos);
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

bool CBlock::DisconnectBlock(CValidationState &state, CTxDB& txdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(state, txdb))
            return false;

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
            printf("CBlock::DisconnectBlock(): Can't WriteBlockHash\n");
            return error("DisconnectBlock() : WriteBlockHash failed");
        }
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, false, false);

    return true;
}

bool CBlock::ConnectBlock(CValidationState &state, CTxDB& txdb, CBlockIndex* pindex, bool fJustCheck)
{
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
    // Iterate through all transaction to check double spent, connect inputs
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();

        if (fEnforceBIP30) {
            CTxIndex txindexOld;
            if (txdb.ReadTxIndex(hashTx, txindexOld)) {
                BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
                    if (pos.IsNull())
                    {
                        return state.DoS(100, error("ConnectBlock() : tried to overwrite transaction"));
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
                    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
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
                return state.DoS(100, error("ConnectBlock(): contains a non-BIP68-final transaction", __func__));
            }

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

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }
//_____________________ this is new code here
    if (!control.Wait())
    {
        (void)printf( "\nDoS ban of whom?\n\n" );   //maybe all nodes?
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
        printf("Connect(): Can't WriteBlockHash\n");
        return error("Connect() : WriteBlockHash failed");
    }

    // fees are not collected by proof-of-stake miners
    // fees are destroyed to compensate the entire network
    if (fDebug && IsProofOfStake() && GetBoolArg("-printcreation"))
        printf("ConnectBlock() : destroy=%s nFees=%" PRId64 "\n", FormatMoney(nFees).c_str(), nFees);

    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock() : UpdateTxIndex failed");
    }

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
            printf("ConnectBlock(): Can't WriteBlockHash\n");
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
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("block coin age total nCoinDays=%" PRId64 "\n", nCoinAge);
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
        printf("AddToBlockIndex(): TxnBegin failed\n");
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
                    printf("AcceptBlock() : Rejected by stake modifier checkpoint height=%d, modifier=0x%016\n" PRIx64, pindex->nHeight, nStakeModifier);
            }

            if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindex)))
            {
                printf("AddToBlockIndex(): Can't WriteBlockHash\n");
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
        txdb.WriteBlockIndex(CDiskBlockIndex(pindexNew));
        if (fStoreBlockHashToDb && !txdb.WriteBlockHash(CDiskBlockIndex(pindexNew)))
        {
            printf("AddToBlockIndex(): Can't WriteBlockHash\n");
        }
    }

    // Write to disk block index
    if (!txdb.TxnCommit())
    {
        printf("AddToBlockIndex(): TxnCommit failed\n");
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

    printf("Sign failed\n");
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
