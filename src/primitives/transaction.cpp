// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/transaction.h"

#include "chain.h"
#include "consensus/consensus.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "tokens/tokens.h"
#include "txdb.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "wallet/wallet.h"


#include <map>

using std::vector;
using std::map;
using std::set;

CTransaction::CTransaction(const CMutableTransaction &tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) {}
CTransaction::CTransaction(CMutableTransaction &&tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(std::move(tx.vin)), vout(std::move(tx.vout)), nLockTime(tx.nLockTime) {}
void CTransaction::SetNull()
{
	// TODO: Need update for mainet
	if (chainActive.Height() != -1 && chainActive.Genesis() && (chainActive.Height() + 1) >= nMainnetNewLogicBlockNumber)
	{
		nVersion = CTransaction::CURRENT_VERSION;
	}
	else
	{
		nVersion = CTransaction::CURRENT_VERSION_of_Tx_for_yac_old;
	}
	nTime = GetAdjustedTime();
	vin.clear();
	vout.clear();
	nLockTime = 0;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTxOut::ToString() const
{
    if (IsEmpty()) return "CTxOut(empty)";
    if (scriptPubKey.size() < 6)
        return "CTxOut(error)";
    return strprintf("CTxOut(nValue=%s, scriptPubKey=%s)", FormatMoney(nValue).c_str(), scriptPubKey.ToString().c_str());
}

CMutableTransaction::CMutableTransaction(){
    // TODO: Need update for mainet
    if (chainActive.Height() != -1 && chainActive.Genesis() && (chainActive.Height() + 1) >= nMainnetNewLogicBlockNumber)
    {
        nVersion = CTransaction::CURRENT_VERSION;
    }
    else
    {
        nVersion = CTransaction::CURRENT_VERSION_of_Tx_for_yac_old;
    }
    nTime = GetAdjustedTime();
    vin.clear();
    vout.clear();
    nLockTime = 0;
}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime) {}
