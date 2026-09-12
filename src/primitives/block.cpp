// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addressindex.h"
#include "tokens/tokendb.h"
#include "primitives/block.h"
#include "txdb.h"
#include "checkpoints.h"
#include "kernel.h"
#include "wallet/wallet.h"
#include "validationinterface.h"
#include "net_processing.h"
#include "keystore.h"

using std::vector;
using std::map;
using std::set;
using std::make_pair;
using std::max;
using std::deque;

const ::int64_t nChainStartTime = 1367991200;           // unix time???? ~ Wed May 08 2013 05:33:20

// Every received block is assigned a unique and increasing identifier, so we
// know which one to give priority in case of a fork.
CCriticalSection cs_nBlockSequenceId;
// Blocks loaded from disk are assigned id 0, so start the counter at 1.
uint32_t nBlockSequenceId = 1;

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

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
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
