// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb.h"
#endif

#ifndef BITCOIN_WALLET_H
 #include "wallet.h"
#endif

#ifndef PPCOIN_KERNEL_H
 #include "kernel.h"
#endif

#ifndef COINCONTROL_H
 #include "coincontrol.h"
#endif

#include <boost/algorithm/string/replace.hpp>

using std::list;
using std::pair;
using std::vector;
using std::map;
using std::make_pair;
using std::max;
using std::string;
using std::runtime_error;
using std::set;
using std::min;
using std::multimap;

bool fCoinsDataActual;

//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

struct CompareValueOnly
{
    bool operator()(const CInputCoin& t1,
                    const CInputCoin& t2) const
    {
        return t1.txout.nValue < t2.txout.nValue;
    }
};

struct CompareTokenValueOnly
{
    bool operator()(const std::pair<CInputCoin, CAmount>& t1,
                    const std::pair<CInputCoin, CAmount>& t2) const
    {
        return t1.second < t2.second;
    }
};

bool compareUTXO(COutput u1, COutput u2)
{
    return (u1.nDepth > u2.nDepth);
}


CPubKey CWallet::GenerateNewKey()
{
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    RandAddSeedPerfmon();
    CKey key;
    key.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = key.GetPubKey();

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKey(key))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
    return key.GetPubKey();
}

bool CWallet::AddKey(const CKey& key)
{
    CPubKey pubkey = key.GetPubKey();
    if (!CCryptoKeyStore::AddKey(key))
        return false;
    if (!fFileBacked)
        return true;
    if (!IsCrypted())
        return CWalletDB(strWalletFile).WriteKey(pubkey, key.GetPrivKey(), mapKeyMetadata[pubkey.GetID()]);
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script.SetDestination(vchPubKey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in commit 5ed0a2b to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = CBitcoinAddress(redeemScript.GetID()).ToString();
        printf("LoadCScript() : Warning: This wallet contains a redeemScript of size %" PRIszu " which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
          redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr.c_str());
          return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}


bool CWallet::AddWatchOnly(const CScript &dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys.
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

// ppcoin: optional setting to unlock wallet for block minting only;
//         serves to disable the trivial sendmoney when OS account compromised
bool fWalletUnlockMintOnly = false;

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                printf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

// This class implements an addrIncoming entry that causes pre-0.4
// clients to crash on startup if reading a private-key-encrypted wallet.
class CCorruptAddress
{
public:
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
            READWRITE(nVersion);
    )
};

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    printf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
                return false;
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
#ifdef _MSC_VER
            // a rather crude thing to do, don't you think?  Can't we shutdown gracefully?
            // perhaps just
            return false;   // looking at what encryptwallet() in rpcwallet.cpp does
#else
            exit(23); 
#endif
            //We now probably have half of our keys encrypted in memory, 
            //and half not...die and let the user reload their unencrypted wallet.
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
            exit(24); //We now have keys encrypted in memory, but no on disk...die to avoid confusion and let the user reload their unencrypted wallet.

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

bool CWallet::DecryptWallet(const SecureString& strWalletPassphrase)
{
    if (!IsCrypted())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (!CCryptoKeyStore::Unlock(vMasterKey))
                return false;
        }

        if (fFileBacked)
        {
            pwalletdbDecryption = new CWalletDB(strWalletFile);
            if (!pwalletdbDecryption->TxnBegin())
                return false;
        }

        if (!DecryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbDecryption->TxnAbort();
            exit(25); //We now probably have half of our keys decrypted in memory, and half not...die and let the user reload their encrypted wallet.
        }

        if (fFileBacked)
        {
            // Overwrite crypted keys
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                CKey key;
                key.SetSecret((*mi).second.first, (*mi).second.second);
                pwalletdbDecryption->EraseCryptedKey(key.GetPubKey());
                pwalletdbDecryption->WriteKey(key.GetPubKey(), key.GetPrivKey(), mapKeyMetadata[(*mi).first]);
                mi++;
            }

            // Erase master keys
            MasterKeyMap::const_iterator mk = mapMasterKeys.begin();
            while (mk != mapMasterKeys.end())
            {
                pwalletdbDecryption->EraseMasterKey((*mk).first);
                mk++;
            }

            if (!pwalletdbDecryption->TxnCommit())
                exit(26); //We now have keys decrypted in memory, but no on disk...die to avoid confusion and let the user reload their encrypted wallet.

            delete pwalletdbDecryption;
            pwalletdbDecryption = NULL;
        }

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // encrypted private keys in the database file which can be a reason of consistency issues.
        CDB::Rewrite(strWalletFile);
    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

CWallet::TxItems CWallet::OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount)
{
    CWalletDB walletdb(strWalletFile);

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-order multimap.
    TxItems txOrdered;

    // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
    // would make this much faster for applications that do this a lot.
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, (CAccountingEntry*)0)));
    }
    acentries.clear();
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));
    }

    return txOrdered;
}

void CWallet::WalletUpdateSpent(const CTransaction &tx, bool fBlock)
{
    // Anytime a signature is successfully verified, it's proof the outpoint is spent.
    // Update the wallet spent flag if it doesn't know due to wallet.dat being
    // restored from backup or the user making copies of wallet.dat.
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.COutPointGetHash());
            if (mi != mapWallet.end())
            {
                CWalletTx& wtx = (*mi).second;
                if (txin.prevout.COutPointGet_n() >= wtx.vout.size())
                    printf("WalletUpdateSpent: bad wtx %s\n", wtx.GetHash().ToString().c_str());
                else if (!wtx.IsSpent(txin.prevout.COutPointGet_n()) && IsMine(wtx.vout[txin.prevout.COutPointGet_n()]))
                {
                    printf("WalletUpdateSpent found spent coin %syac %s\n", 
                            FormatMoney(wtx.GetCredit(MINE_ALL)).c_str(), 
                            wtx.GetHash().ToString().c_str()
                          );
                    wtx.MarkSpent(txin.prevout.COutPointGet_n());
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, txin.prevout.COutPointGetHash(), CT_UPDATED);
                    vMintingWalletUpdated.push_back(txin.prevout.COutPointGetHash());
                }
            }
        }

        if (fBlock)
        {
            uint256 hash = tx.GetHash();
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(hash);
            CWalletTx& wtx = (*mi).second;

            BOOST_FOREACH(const CTxOut& txout, tx.vout)
            {
                if (IsMine(txout))
                {
                    wtx.MarkUnspent(&txout - &tx.vout[0]);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, hash, CT_UPDATED);
                    vMintingWalletUpdated.push_back(hash);
                }
            }
        }

    }
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext();

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (wtxIn.hashBlock != 0)
            {
                if (mapBlockIndex.count(wtxIn.hashBlock))
                {
                    int64_t latestNow = wtx.nTimeReceived;
                    int64_t latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        std::list<CAccountingEntry> acentries;
                        TxItems txOrdered = OrderedTxItems(acentries);
                        for (TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    int64_t& blocktime = mapBlockIndex[wtxIn.hashBlock]->nTime;
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    printf("AddToWallet() : found %s in block %s not in index\n",
                           wtxIn.GetHash().ToString().substr(0,10).c_str(),
                           wtxIn.hashBlock.ToString().c_str());
            }
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        //// debug print
        printf(
                "\nAddToWallet %s  %s%s\r"
                , wtxIn.GetHash().ToString().substr(0,10).c_str()
                , (fInsertedNew ? "new" : "")
                , (fUpdated ? "update" : "")
              );

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk())
                return false;
#ifndef QT_GUI
        // If default receiving address gets used, replace it with a new one
        CScript scriptDefaultKey;
        scriptDefaultKey.SetDestination(vchDefaultKey.GetID());
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            if (txout.scriptPubKey == scriptDefaultKey)
            {
                CPubKey newDefaultKey;
                if (GetKeyFromPool(newDefaultKey, false))
                {
                    SetDefaultKey(newDefaultKey);
                    SetAddressBookName(vchDefaultKey.GetID(), "");
                }
            }
        }
#endif
        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx, (wtxIn.hashBlock != 0));

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);
        vMintingWalletUpdated.push_back(hash);
        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    return true;
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
    uint256 hash = tx.GetHash();
    {
        LOCK(cs_wallet);
        bool fExisted = mapWallet.count(hash);
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this,tx);
            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(pblock);
            return AddToWallet(wtx);
        }
        else
            WalletUpdateSpent(tx);
    }
    return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}


isminetype CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.COutPointGetHash());
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.COutPointGet_n() < prev.vout.size())
                return IsMine(prev.vout[txin.prevout.COutPointGet_n()]);
        }
    }
    return MINE_NO;
}

int64_t CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.COutPointGetHash());
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.COutPointGet_n() < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.COutPointGet_n()]) & filter)
                    return prev.vout[txin.prevout.COutPointGet_n()].nValue;
        }
    }
    return 0;
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but isn't in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

bool CWallet::IsTimelockUTXOExpired(const CInputCoin& inputCoin, txnouttype utxoType, uint32_t lockDuration) const
{
    CWalletTx tempWalletTx;
    tempWalletTx.fTimeReceivedIsTxTime = true;
    tempWalletTx.vin.clear();
    tempWalletTx.vout.clear();
    tempWalletTx.fFromMe = true;
    unsigned int nSequenceIn = CTxIn::SEQUENCE_FINAL;
    switch (utxoType)
    {
        case TX_CLTV_P2SH:
        case TX_CLTV_P2PKH:
        {
            nSequenceIn = 0;
            tempWalletTx.nLockTime = lockDuration;
            break;
        }
        case TX_CSV_P2SH:
        case TX_CSV_P2PKH:
        {
            nSequenceIn = lockDuration;
            break;
        }
        default:
            // not time lock UTXO
            return true;
    }
    tempWalletTx.vin.push_back(CTxIn(inputCoin.outpoint, CScript(), nSequenceIn));

    // Check if nLockTime and BIP68 sequence locked satisfy
    if (!tempWalletTx.IsFinal() || !CheckSequenceLocks(tempWalletTx, STANDARD_LOCKTIME_VERIFY_FLAGS))
    {
        return false;
    }
    return true;
}

int64_t CWalletTx::GetTxTime() const
{
    return nTime;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase() || IsCoinStake())
        {
            // Generated block
            if (hashBlock != 0)
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0)
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(::int64_t& nGeneratedImmature,
                           ::int64_t& nGeneratedMature,
                           std::list<COutputEntry>& listReceived,
                           std::list<COutputEntry>& listSent, CAmount& nFee,
                           std::string& strSentAccount,
                           const isminefilter& filter,
                           std::list<CTokenOutputEntry>& tokensReceived,
                           std::list<CTokenOutputEntry>& tokensSent,
                           bool fExcludeNotExpiredTimelock) const
{
    nGeneratedImmature = nGeneratedMature = nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    if (IsCoinBase() || IsCoinStake())
    {
        if (GetBlocksToMaturity() > 0)
            nGeneratedImmature = pwallet->GetCredit(*this, filter);
        else
            nGeneratedMature = GetCredit(filter);
        return;
    }

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut& txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
        {
            printf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                   this->GetHash().ToString().c_str());
            address = CNoDestination();
        }

        if (!txout.scriptPubKey.IsTokenScript()) {
            COutputEntry output = {address, txout.nValue, (int) i};

            // If we are debited by the transaction, add the output as a "sent" entry
            if (nDebit > 0)
                listSent.push_back(output);

            // If we are receiving the output, add it as a "received" entry
            if (fIsMine & filter)
            {
                if (fExcludeNotExpiredTimelock)
                {
                    // Only count timelock UTXO if the timelock already expired
                    txnouttype utxoType = TX_NONSTANDARD;
                    uint32_t lockDuration = 0;
                    bool isSpendableTimelockUTXO = pwallet->IsSpendableTimelockUTXO(txout, utxoType, lockDuration);

                    if (isSpendableTimelockUTXO)
                    {
                        CInputCoin inputCoin(this, i);
                        if(!pwallet->IsTimelockUTXOExpired(inputCoin, utxoType, lockDuration))
                        {
                            continue;
                        }
                    }
                }
                listReceived.push_back(output);
            }
        }

        /** YAC_TOKEN START */
        if (AreTokensDeployed()) {
            if (txout.scriptPubKey.IsTokenScript()) {
                CTokenOutputEntry tokenoutput;
                tokenoutput.vout = i;
                GetTokenData(txout.scriptPubKey, tokenoutput);

                // The only token type we send is transfer_token. We need to skip all other types for the sent category
                if (nDebit > 0 && tokenoutput.type == TX_TRANSFER_TOKEN)
                    tokensSent.emplace_back(tokenoutput);

                if (fIsMine & filter)
                    tokensReceived.emplace_back(tokenoutput);
            }
        }
        /** YAC_TOKEN END */
    }
}

void CWalletTx::GetAmounts(::int64_t& nGeneratedImmature, ::int64_t& nGeneratedMature,
                std::list<COutputEntry>& listReceived,
                std::list<COutputEntry>& listSent, CAmount& nFee,
                std::string& strSentAccount, const isminefilter& filter,
                bool fExcludeNotExpiredTimelock) const
{
    std::list<CTokenOutputEntry> tokensReceived;
    std::list<CTokenOutputEntry> tokensSent;
    GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount, filter, tokensReceived, tokensSent, fExcludeNotExpiredTimelock);
}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64_t& nGenerated, int64_t& nReceived,
                                  int64_t& nSent, int64_t& nFee, const isminefilter& filter, bool fExcludeNotExpiredTimelock) const
{
    nGenerated = nReceived = nSent = nFee = 0;

    int64_t allGeneratedImmature, allGeneratedMature, allFee;
    allGeneratedImmature = allGeneratedMature = allFee = 0;
    string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    GetAmounts(allGeneratedImmature, allGeneratedMature, listReceived, listSent, allFee, strSentAccount, filter, fExcludeNotExpiredTimelock);

    if (strAccount == "")
        nGenerated = allGeneratedMature;
    if (strAccount == strSentAccount)
    {
        for (const COutputEntry& s : listSent)
        {
            nSent += s.amount;
        }
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        for (const COutputEntry& r : listReceived)
        {
            if (pwallet->mapAddressBook.count(r.destination))
            {
                map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
                    nReceived += r.amount;
            }
            else if (strAccount.empty())
            {
                nReceived += r.amount;
            }
        }
    }
}

::int64_t CWalletTx::GetAvailableCredit(bool fUseCache, bool fExcludeNotExpiredTimelock) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (
        (IsCoinBase() || IsCoinStake()) &&
        (GetBlocksToMaturity() > 0)
       )
        return 0;

    if (fUseCache & !fExcludeNotExpiredTimelock)
    {
        if (fAvailableCreditCached)
            return nAvailableCreditCached;
    }

    ::int64_t
        nCredit = 0;
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        if (!IsSpent(i))
        {
            const CTxOut
                &txout = vout[i];

            if (fExcludeNotExpiredTimelock)
            {
                // Only count timelock UTXO if the timelock already expired
                txnouttype utxoType = TX_NONSTANDARD;
                uint32_t lockDuration = 0;
                bool isSpendableTimelockUTXO = pwallet->IsSpendableTimelockUTXO(txout, utxoType, lockDuration);

                if (isSpendableTimelockUTXO)
                {
                    CInputCoin inputCoin(this, i);
                    if(!pwallet->IsTimelockUTXOExpired(inputCoin, utxoType, lockDuration))
                    {
                        continue;
                    }
                }
            }


            nCredit += pwallet->GetCredit(txout, MINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    if (fUseCache & !fExcludeNotExpiredTimelock)
    {
        nAvailableCreditCached = nCredit;
        fAvailableCreditCached = true;
    }

    return nCredit;
}

void CWalletTx::AddSupportingTransactions(CTxDB& txdb)
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        BOOST_FOREACH(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.COutPointGetHash());

        // This critsect is OK because txdb is already open
        {
            LOCK(pwallet->cs_wallet);
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
                if (mi != pwallet->mapWallet.end())
                {
                    tx = (*mi).second;
                    BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else if (!fClient && txdb.ReadDiskTx(hash, tx))
                {
                    ;
                }
                else
                {
                    printf("ERROR: AddSupportingTransactions() : unsupported transaction\n");
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                {
                    BOOST_FOREACH(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.COutPointGetHash());
                }
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

#ifdef WIN32
//_____________________________________________________________________________
//static inline void
void
    DoRescanProgress( int nCount, int nTotalToScan, int64_t n64MsStartTime )
{
    int64_t
        n64SecondsEstimatedTotalTime,
        n64MsEstimatedTotalTime,
        n64MsDeltaTime;
    #ifdef QT_GUI
    std::string
        sTextString;
    #endif
    if(
        (0 == (nCount % 60) )   // every 60th times due to Matjaz's speedup
      )
    {
        if( 0 == nCount )       // first time
        {
            (void)printf(
                    "%6d "
                    ""
                    , nCount
                        );
    #ifdef QT_GUI
            uiInterface.InitMessage(
                                    strprintf(
                                               _( "%6d " ), 
                                               nCount
                                             ).c_str() 
                                   );
    #endif
        }
        else                    // all the next times
        {
            n64SecondsEstimatedTotalTime = 0;
    #ifndef QT_GUI
            if( 
              //(0 == (nCount % 100) )   // every 100th time (every 10th next time)
                (0 == (nCount % 120) )   // every 120th time (every 60th next time)
              )
    #endif
            {   // let's estimate the time remaining too!
                n64MsDeltaTime = GetTimeMillis() - n64MsStartTime;
                // we have done nCount / nTotalToScan th of them in n64MsDeltaTime
                // so total time in ms ~ n64MsDeltaTime * nTotalToScan / nCount
                n64MsEstimatedTotalTime = n64MsDeltaTime * nTotalToScan / nCount;
                // time (seconds) remaining is
                n64SecondsEstimatedTotalTime =
                    ( n64MsEstimatedTotalTime + n64MsStartTime - GetTimeMillis() ) / 1000;
            }
            if (fPrintToConsole)
                (void)printf(
                            "%6d "
                            "%2.2f%% "
                            ""
                            , nCount
                            , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                            );
    #ifdef QT_GUI
            uiInterface.InitMessage(
                                    strprintf(
                                              _("%6d "
                                                "%2.2f%% "
                                                ""
                                               )
                                                , nCount
                                                , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                                             ).c_str() 
                                   );
    #endif
            if( 0 != n64SecondsEstimatedTotalTime )
            {
                const int64_t
                    nSecondsPerMinute = 60,
                    nMinutesPerHour = 60;
                int64_t
                    nSeconds = 0,
                    nMinutes = 0,
                    nHours = 0;

                if( n64SecondsEstimatedTotalTime >= nSecondsPerMinute )
                {                   // there are minutes to go
                    nSeconds = n64SecondsEstimatedTotalTime % nSecondsPerMinute;
                    nMinutes = n64SecondsEstimatedTotalTime / nSecondsPerMinute;
                    if( nMinutes >= nMinutesPerHour ) // there are hours to go
                    {
                        nHours = nMinutes / nMinutesPerHour;
                        nMinutes %= nMinutesPerHour;
                        if (fPrintToConsole)
                            (void)printf(
                                        "~%d:%02d:%02d hrs:min:sec"
                                        ""
                                        ,
                                        (int)nHours,
                                        (int)nMinutes,
                                        (int)nSeconds
                                        );
    #ifdef QT_GUI
                        uiInterface.InitMessage( 
                                                strprintf(
                                                          _("%6d "
                                                            "%2.2f%% "
                                                            ""
                                                            "~%d:%02d:%02d hrs:min:sec"
                                                            ""
                                                           )
                                                            , nCount
                                                            , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                                                            ,
                                                            (int)nHours,
                                                            (int)nMinutes,
                                                            (int)nSeconds
                                                         ).c_str() 
                                               );
    #endif
                    }
                    else    // there are only minutes
                    {
                        if (fPrintToConsole)
                            (void)printf(
                                        "~%2d:%02d min:sec      "
                                        "\r"
                                        ""
                                        ,
                                        (int)nMinutes,
                                        (int)nSeconds
                                        );
    #ifdef QT_GUI
                        uiInterface.InitMessage( 
                                                strprintf(
                                                          _("%6d "
                                                            "%2.2f%% "
                                                            ""
                                                            "~%2d:%02d min:sec    "
                                                            ""
                                                           )
                                                           , nCount
                                                           , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                                                           ,
                                                         (int)nMinutes,
                                                         (int)nSeconds
                                                         ).c_str() 
                                               );
    #endif
                    }
                }
                else    // there are only seconds
                {
                    nSeconds = n64SecondsEstimatedTotalTime;
                    if (fPrintToConsole)
                        (void)printf(
                                    "~%2d sec       "
                                    ""
                                    ,
                                    (int)nSeconds
                                    );
    #ifdef QT_GUI
                    uiInterface.InitMessage(
                                            strprintf(
                                                      _("%6d "
                                                        "%2.2f%% "
                                                        ""
                                                        "~%2d sec         "
                                                        ""
                                                       )
                                                       , nCount
                                                       , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                                                       ,
                                                      (int)nSeconds
                                                     ).c_str() 
                                           );
    #endif
                }
            }
        }
        (void)printf( "\r" );
    }
}
//_____________________________________________________________________________
#endif
// Scan the block chain (starting in pindexStart) for transactions
// from or to us. If fUpdate is true, found transactions that already
// exist in the wallet will be updated.
#ifdef WIN32
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate, int nTotalToScan)
#else
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
#endif
{
    int ret = 0;

    CBlockIndex* pindex = pindexStart;
    {
#ifdef WIN32
        int
            nCount = 0;
        int64_t
            n64MsStartTime = GetTimeMillis();
#endif        
        LOCK(cs_wallet);
        while (pindex)
        {
            CBlock block;
            block.ReadFromDisk(pindex, true, false);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate))
                    //ret++;
                    ++ret;
            }
            pindex = pindex->pnext;
            // Stop the scan if shutting down
            if(
               fShutdown ||
               (true == fRequestShutdown)
              )
            {
                fRequestShutdown = true;
                return ret;
            }
#ifdef WIN32
            ++nCount;
            DoRescanProgress( nCount, nTotalToScan, n64MsStartTime );
        }
        if (fPrintToConsole)     // this could be a progress bar, % meter etc.
            (void)printf( "\n" );// but we would need another parameter of the total
                                 // # of blocks to scan
#else
        }
#endif        
    }
    return ret;
}

/**********************************************************
// not used anywhere????????
int CWallet::ScanForWalletTransaction(const uint256& hashTx)
{
    CTransaction tx;
    tx.ReadFromDisk(COutPoint(hashTx, 0));
    if (AddToWalletIfInvolvingMe(tx, NULL, true, true))
        return 1;
    return 0;
}
***********************************************************/
void CWallet::ReacceptWalletTransactions()
{
    CTxDB txdb("r");
    bool fRepeat = true;
    while (fRepeat)
    {
        LOCK(cs_wallet);
        fRepeat = false;
        vector<CDiskTxPos> vMissingTx;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if ((wtx.IsCoinBase() && wtx.IsSpent(0)) || (wtx.IsCoinStake() && wtx.IsSpent(1)))
                continue;

            CTxIndex txindex;
            bool fUpdated = false;
            if (txdb.ReadTxIndex(wtx.GetHash(), txindex))
            {
                // Update fSpent if a tx got spent somewhere else by a copy of wallet.dat
                if (txindex.vSpent.size() != wtx.vout.size())
                {
                    printf("ERROR: ReacceptWalletTransactions() : txindex.vSpent.size() %" PRIszu " != wtx.vout.size() %" PRIszu "\n", txindex.vSpent.size(), wtx.vout.size());
                    continue;
                }
                for (unsigned int i = 0; i < txindex.vSpent.size(); i++)
                {
                    if (wtx.IsSpent(i))
                        continue;
                    if (!txindex.vSpent[i].IsNull() && IsMine(wtx.vout[i]))
                    {
                        wtx.MarkSpent(i);
                        fUpdated = true;
                        vMissingTx.push_back(txindex.vSpent[i]);
                    }
                }
                if (fUpdated)
                {
                    printf("ReacceptWalletTransactions found spent coin %syac %s\n", FormatMoney(wtx.GetCredit(MINE_ALL)).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkDirty();
                    wtx.WriteToDisk();
                }
            }
            else
            {
                // Re-accept any txes of ours that aren't already in a block
                if (!(wtx.IsCoinBase() || wtx.IsCoinStake()))
                    wtx.AcceptWalletTransaction(txdb, false);
            }
        }
        if (!vMissingTx.empty())
        {
            // TODO: optimize this to scan just part of the block chain?
            if (ScanForWalletTransactions(chainActive.Genesis()))
                fRepeat = true;  // Found missing transactions: re-do re-accept.
        }
    }
}

void CWalletTx::RelayWalletTransaction(CTxDB& txdb)
{
    BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
    {
        if (!(tx.IsCoinBase() || tx.IsCoinStake()))
        {
            uint256 hash = tx.GetHash();
            if (!txdb.ContainsTx(hash))
                RelayTransaction((CTransaction)tx, hash);
        }
    }
    if (!(IsCoinBase() || IsCoinStake()))
    {
        uint256 hash = GetHash();
        if (!txdb.ContainsTx(hash))
        {
            printf("Relaying wtx %s\n", hash.ToString().substr(0,10).c_str());
            RelayTransaction((CTransaction)*this, hash);
        }
    }
}

void CWalletTx::RelayWalletTransaction()
{
   CTxDB txdb("r");
   RelayWalletTransaction(txdb);
}

void CWallet::ResendWalletTransactions()
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    static int64_t 
        nNextTime;

    if (GetTime() < nNextTime)
        return;
    
    bool 
        fFirst = (nNextTime == 0);

    nNextTime = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    static int64_t 
        nLastTime;

    if (nTimeBestReceived < nLastTime)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    printf("ResendWalletTransactions()\n");
    CTxDB txdb("r");
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> 
            mapSorted;

        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            // Don't rebroadcast until it's had plenty of time that
            // it should have gotten in already by now.
            if (nTimeBestReceived - (int64_t)wtx.nTimeReceived > 5 * 60)
                mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            CValidationState state;
            if (wtx.CheckTransaction(state))
                wtx.RelayWalletTransaction(txdb);
            else
                printf("ResendWalletTransactions() : CheckTransaction failed for transaction %s\n", wtx.GetHash().ToString().c_str());
        }
    }
}






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//

int64_t CWallet::GetBalance(bool fExcludeNotExpiredTimelock) const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit(true, fExcludeNotExpiredTimelock);
        }
    }

    return nTotal;
}

int64_t CWallet::GetWatchOnlyBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchCredit();
        }
    }

    return nTotal;
}

int64_t CWallet::GetUnconfirmedBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

int64_t CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchCredit();
        }
    }
    return nTotal;
}

int64_t CWallet::GetImmatureBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

int64_t CWallet::GetImmatureWatchOnlyBalance() const
{
    int64_t nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

// populate vCoins with vector of available COutputs
void CWallet::AvailableCoins(std::vector<COutput>& vCoins, bool fOnlySafe,
                             const CCoinControl* coinControl,
                             const CScript* fromScriptPubKey,
                             bool useExpiredTimelockUTXO,
                             const CAmount& nMinimumAmount,
                             const CAmount& nMaximumAmount,
                             const CAmount& nMinimumSumAmount,
                             const uint64_t nMaximumCount, const int nMinDepth,
                             const int nMaxDepth) const
{
  std::map<std::string, std::vector<COutput> > mapTokenCoins;
  AvailableCoinsAll(vCoins, mapTokenCoins, true, false, fOnlySafe, coinControl,
                    fromScriptPubKey, useExpiredTimelockUTXO, nMinimumAmount,
                    nMaximumAmount, nMinimumSumAmount, nMaximumCount, nMinDepth,
                    nMaxDepth);
}

void CWallet::AvailableTokens(
    std::map<std::string, std::vector<COutput> >& mapTokenCoins, bool fOnlySafe,
    const CCoinControl* coinControl, const CAmount& nMinimumAmount,
    const CAmount& nMaximumAmount, const CAmount& nMinimumSumAmount,
    const uint64_t& nMaximumCount, const int& nMinDepth,
    const int& nMaxDepth) const
{
  if (!AreTokensDeployed()) return;

  std::vector<COutput> vCoins;

  AvailableCoinsAll(vCoins, mapTokenCoins, false, true, fOnlySafe, coinControl,
                    NULL, false, nMinimumAmount, nMaximumAmount,
                    nMinimumSumAmount, nMaximumCount, nMinDepth, nMaxDepth);
}

void CWallet::AvailableCoinsWithTokens(
    std::vector<COutput>& vCoins,
    std::map<std::string, std::vector<COutput> >& mapTokenCoins, bool fOnlySafe,
    const CCoinControl* coinControl, const CScript *fromScriptPubKey,
    bool useExpiredTimelockUTXO, const CAmount& nMinimumAmount,
    const CAmount& nMaximumAmount, const CAmount& nMinimumSumAmount,
    const uint64_t& nMaximumCount, const int& nMinDepth,
    const int& nMaxDepth) const
{
  AvailableCoinsAll(vCoins, mapTokenCoins, true, AreTokensDeployed(), fOnlySafe,
                    coinControl, fromScriptPubKey, useExpiredTimelockUTXO, nMinimumAmount, nMaximumAmount,
                    nMinimumSumAmount, nMaximumCount, nMinDepth, nMaxDepth);
}

void CWallet::AvailableCoinsAll(
    std::vector<COutput>& vCoins,
    std::map<std::string, std::vector<COutput> >& mapTokenCoins, bool fGetYAC,
    bool fGetTokens, bool fOnlySafe, const CCoinControl* coinControl,
    const CScript* fromScriptPubKey, bool useExpiredTimelockUTXO,
    const CAmount& nMinimumAmount, const CAmount& nMaximumAmount,
    const CAmount& nMinimumSumAmount, const uint64_t& nMaximumCount,
    const int& nMinDepth, const int& nMaxDepth) const
{
  vCoins.clear();

  {
    LOCK2(cs_main, cs_wallet);

    CAmount nTotal = 0;

    bool fYACLimitHit = false;
    std::map<std::string, CAmount> mapTokenTotals;
    std::set<std::string> setTokenMaxFound;

    for (const auto& entry : mapWallet) {
      const uint256& wtxid = entry.first;
      const CWalletTx* pcoin = &entry.second;

      if (!pcoin->IsFinal()) continue;

      if (pcoin->IsCoinBase() && (pcoin->GetBlocksToMaturity() > 0)) continue;

      if (pcoin->IsCoinStake() && (pcoin->GetBlocksToMaturity() > 0)) continue;

      int nDepth = pcoin->GetDepthInMainChain();
      if (nDepth < 0) continue;

      bool safeTx = pcoin->IsTrusted();
      if (fOnlySafe && !safeTx) continue;
      //
      //            bool safeTx = pcoin->IsTrusted();
      //
      //            // We should not consider coins from transactions that are
      //            replacing
      //            // other transactions.
      //            //
      //            // Example: There is a transaction A which is replaced by
      //            bumpfee
      //            // transaction B. In this case, we want to prevent creation
      //            of
      //            // a transaction B' which spends an output of B.
      //            //
      //            // Reason: If transaction A were initially confirmed,
      //            transactions B
      //            // and B' would no longer be valid, so the user would have
      //            to create
      //            // a new transaction C to replace B'. However, in the case
      //            of a
      //            // one-block reorg, transactions B' and C might BOTH be
      //            accepted,
      //            // when the user only wanted one of them. Specifically,
      //            there could
      //            // be a 1-block reorg away from the chain where transactions
      //            A and C
      //            // were accepted to another chain where B, B', and C were
      //            all
      //            // accepted.
      //            if (nDepth == 0 && pcoin->mapValue.count("replaces_txid")) {
      //                safeTx = false;
      //            }
      //
      //            // Similarly, we should not consider coins from transactions
      //            that
      //            // have been replaced. In the example above, we would want
      //            to prevent
      //            // creation of a transaction A' spending an output of A,
      //            because if
      //            // transaction B were initially confirmed, conflicting with
      //            A and
      //            // A', we wouldn't want to the user to create a transaction
      //            D
      //            // intending to replace A', but potentially resulting in a
      //            scenario
      //            // where A, A', and D could all be accepted (instead of just
      //            B and
      //            // D, or just A and A' like the user would want).
      //            if (nDepth == 0 &&
      //            pcoin->mapValue.count("replaced_by_txid")) {
      //                safeTx = false;
      //            }
      //
      //            if (fOnlySafe && !safeTx) {
      //                continue;
      //            }

      if (nDepth < nMinDepth || nDepth > nMaxDepth) continue;

      for (unsigned int i = 0; i < pcoin->vout.size(); i++) {

        /** YAC_TOKEN START */
        int nType;
        bool fIsOwner;
        bool isTokenScript =
            pcoin->vout[i].scriptPubKey.IsTokenScript(nType, fIsOwner);
        /** YAC_TOKEN END */

        // If there is coin control, only select coins from selected set
        if (coinControl && !isTokenScript && coinControl->HasSelected() &&
            !coinControl->fAllowOtherInputs &&
            !coinControl->IsSelected(entry.first, i))
          continue;

        if (coinControl && isTokenScript && coinControl->HasTokenSelected() &&
            !coinControl->fAllowOtherInputs &&
            !coinControl->IsTokenSelected(COutPoint(entry.first, i)))
          continue;

        // Ignore spent coins
        if (pcoin->IsSpent(i)) continue;

        // Ignore coins which isn't mine
        isminetype mine = IsMine(pcoin->vout[i]);

        if (mine == MINE_NO) {
          continue;
        }
        bool fSpendableIn = ((mine & MINE_SPENDABLE) != MINE_NO);

        // Looking for Token Tx OutPoints Only
        if (fGetTokens && AreTokensDeployed() && isTokenScript) {
            std::string address;
            CTokenOutputEntry output_data;
            if (!GetTokenData(pcoin->vout[i].scriptPubKey, output_data))
                continue;

            address = EncodeDestination(output_data.destination);

            // If we already have the maximum amount or size for this token, skip it
            if (setTokenMaxFound.count(output_data.tokenName))
                continue;

            // Initialize the map vector is it doesn't exist yet
            if (!mapTokenCoins.count(output_data.tokenName)) {
                std::vector<COutput> vOutput;
                mapTokenCoins.insert(std::make_pair(output_data.tokenName, vOutput));
            }

            // Add the COutput to the map of available Token Coins
            mapTokenCoins.at(output_data.tokenName).push_back(
                    COutput(pcoin, i, nDepth, fSpendableIn, safeTx));

            // Initialize the map of current token totals
            if (!mapTokenTotals.count(output_data.tokenName))
                mapTokenTotals[output_data.tokenName] = 0;

            // Update the map of totals depending the which type of token tx we are looking at
            mapTokenTotals[output_data.tokenName] += output_data.nAmount;

            // Checks the sum amount of all UTXO's, and adds to the set of tokens that we found the max for
            if (nMinimumSumAmount != MAX_MONEY) {
                if (mapTokenTotals[output_data.tokenName] >= nMinimumSumAmount)
                    setTokenMaxFound.insert(output_data.tokenName);
            }

            // Checks the maximum number of UTXO's, and addes to set of of token that we found the max for
            if (nMaximumCount > 0 && mapTokenCoins[output_data.tokenName].size() >= nMaximumCount) {
                setTokenMaxFound.insert(output_data.tokenName);
            }
        }

        if (fGetYAC && !isTokenScript) { // Looking for YAC Tx OutPoints Only
            if (fYACLimitHit) // We hit our limit
                continue;

            // Check if the UTXO is locked by OP_CHECKLOCKTIMEVERIFY or OP_CHECKSEQUENCEVERIFY
            // useExpiredTimelockUTXO = true => can use any lock time UTXO
            // locked UTXO fromScriptPubKey = NULL => Don't select locked coin
            // fromScriptPubKey != NULL => only choose coin from this script
            txnouttype utxoType = TX_NONSTANDARD;
            uint32_t lockDuration = 0;
            bool isSpendableTimelockUTXO = IsSpendableTimelockUTXO(pcoin->vout[i], utxoType, lockDuration);

            if (isSpendableTimelockUTXO && !useExpiredTimelockUTXO &&
                (!fromScriptPubKey ||
                 (fromScriptPubKey &&
                  pcoin->vout[i].scriptPubKey != *fromScriptPubKey))) {
              continue;
            }
            if (!isSpendableTimelockUTXO && fromScriptPubKey &&
                pcoin->vout[i].scriptPubKey != *fromScriptPubKey) {
              continue;
            }

            // Only add timelock UTXO if the timelock already expired
            if (isSpendableTimelockUTXO)
            {
                CInputCoin inputCoin(pcoin, i);
                if(!IsTimelockUTXOExpired(inputCoin, utxoType, lockDuration))
                {
                    continue;
                }
            }

            vCoins.push_back(COutput(pcoin, i, nDepth, fSpendableIn, safeTx));

            // Checks the sum amount of all UTXO's.
            if (nMinimumSumAmount != MAX_MONEY) {
                nTotal += pcoin->vout[i].nValue;

                if (nTotal >= nMinimumSumAmount) {
                    fYACLimitHit = true;
                }
            }

            // Checks the maximum number of UTXO's.
            if (nMaximumCount > 0 && vCoins.size() >= nMaximumCount) {
                fYACLimitHit = true;
            }
            continue;
        }
      }
    }
  }
}

void CWallet::AvailableCoinsMinConf(vector<COutput>& vCoins, int nConf, int64_t nMinValue, int64_t nMaxValue) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if(pcoin->GetDepthInMainChain() < nConf)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                isminetype mine = IsMine(pcoin->vout[i]);

                // ignore coin if it was already spent or we don't own it
                if (pcoin->IsSpent(i) || mine == MINE_NO)
                    continue;

                // if coin value is between required limits then add new item to vector
                if (pcoin->vout[i].nValue >= nMinValue && pcoin->vout[i].nValue < nMaxValue)
                    vCoins.push_back(COutput(pcoin, i, pcoin->GetDepthInMainChain(), mine == MINE_SPENDABLE));
            }
        }
    }
}

static void ApproximateBestSubset(const std::vector<CInputCoin>& vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,
                                  std::vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64_t nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                if (nPass == 0 ? rand() % 2 : !vfIncluded[i])
                {
                    nTotal += vValue[i].txout.nValue;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].txout.nValue;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

static void ApproximateBestTokenSubset(
    const std::vector<std::pair<CInputCoin, CAmount> >& vValue,
    const CAmount& nTotalLower, const CAmount& nTargetValue,
    std::vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
  vector<char> vfIncluded;

  vfBest.assign(vValue.size(), true);
  nBest = nTotalLower;

  for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++) {
    vfIncluded.assign(vValue.size(), false);
    int64_t nTotal = 0;
    bool fReachedTarget = false;
    for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++) {
      for (unsigned int i = 0; i < vValue.size(); i++) {
        if (nPass == 0 ? rand() % 2 : !vfIncluded[i]) {
          nTotal += vValue[i].second;
          vfIncluded[i] = true;
          if (nTotal >= nTargetValue) {
            fReachedTarget = true;
            if (nTotal < nBest) {
              nBest = nTotal;
              vfBest = vfIncluded;
            }
            nTotal -= vValue[i].second;
            vfIncluded[i] = false;
          }
        }
      }
    }
  }
}

int64_t CWallet::GetStake() const
{
    int64_t nTotal = 0;
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (
            pcoin->IsCoinStake() && 
            pcoin->GetBlocksToMaturity() > 0 && 
            pcoin->GetDepthInMainChain() > 0
           )
        {
            if(
               fUseOld044Rules
              )
            {
                nTotal += CWallet::GetDebit(*pcoin, MINE_ALL );
            }
            else   // fTestnet || (pcoin->nTimeReceived >= YACOIN_NEW_LOGIC_SWITCH_TIME)
            {
              //nTotal += CWallet::GetDebit(*pcoin, MINE_ALL);  //<<<<<<<<<<<<<<<< test
                nTotal += CWallet::GetCredit(*pcoin, MINE_ALL);
            }
        }
    }
    return nTotal;
}

int64_t CWallet::GetWatchOnlyStake() const
{
    int64_t nTotal = 0;
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*pcoin, MINE_WATCH_ONLY);
    }
    return nTotal;
}

int64_t CWallet::GetNewMint() const
{
    int64_t nTotal = 0;
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*pcoin, MINE_ALL);
    }
    return nTotal;
}

int64_t CWallet::GetWatchOnlyNewMint() const
{
    int64_t nTotal = 0;
    LOCK(cs_wallet);
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*pcoin, MINE_WATCH_ONLY);
    }
    return nTotal;
}

bool CWallet::SelectCoinsMinConf(const CAmount &nTargetValue, int64_t nSpendTime,
        int nConfMine, int nConfTheirs, std::vector<COutput> vCoins,
        std::set<CInputCoin> &setCoinsRet, CAmount &nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    boost::optional<CInputCoin> coinLowestLarger;
    std::vector<CInputCoin> vValue;
    CAmount nTotalLower = 0;
    sort(vCoins.begin(), vCoins.end(), compareUTXO);

    for (const COutput &output : vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(MINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;

        // Follow the timestamp rules
        if (pcoin->nTime > nSpendTime)
            continue;

        CInputCoin coin = CInputCoin(pcoin, i);

        if (coin.txout.nValue == nTargetValue)
        {
            setCoinsRet.insert(coin);
            nValueRet += coin.txout.nValue;
            return true;
        }
        else if (coin.txout.nValue < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += coin.txout.nValue;
        }
        else if (!coinLowestLarger || coin.txout.nValue < coinLowestLarger->txout.nValue)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (const auto& input : vValue)
        {
            setCoinsRet.insert(input);
            nValueRet += input.txout.nValue;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (!coinLowestLarger)
            return false;
        setCoinsRet.insert(coinLowestLarger.get());
        nValueRet += coinLowestLarger->txout.nValue;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    int64_t nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger->txout.nValue <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.get());
        nValueRet += coinLowestLarger->txout.nValue;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i]);
                nValueRet += vValue[i].txout.nValue;
            }

        if (fDebug && GetBoolArg("-printpriority"))
        {
            //// debug print
            printf("SelectCoins() best subset: ");
            for (unsigned int i = 0; i < vValue.size(); i++)
                if (vfBest[i])
                    printf("%s ", FormatMoney(vValue[i].txout.nValue).c_str());
            printf("total %s\n", FormatMoney(nBest).c_str());
        }
    }

    return true;
}

bool CWallet::SelectCoins(const CAmount &nTargetValue, int64_t nSpendTime,
        const std::vector<COutput> &vAvailableCoins,
        std::set<CInputCoin> &setCoinsRet, CAmount &nValueRet,
        const CCoinControl *coinControl) const
{
    std::vector<COutput> vCoins(vAvailableCoins);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs)
    {
        for (const COutput& out : vCoins)
        {
            if (!out.fSpendable)
                 continue;
            nValueRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(CInputCoin(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    std::set<CInputCoin> setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    for (const COutPoint& outpoint : vPresetInputs)
    {
        std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.COutPointGetHash());
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->vout.size() <= outpoint.COutPointGet_n())
                return false;
            nValueFromPresetInputs += pcoin->vout[outpoint.COutPointGet_n()].nValue;
            setPresetCoins.insert(CInputCoin(pcoin, outpoint.COutPointGet_n()));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (std::vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coinControl && coinControl->HasSelected();)
    {
        if (setPresetCoins.count(CInputCoin(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }

    bool res = nTargetValue <= nValueFromPresetInputs ||
            SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, nSpendTime, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, nSpendTime, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, nSpendTime, 0, 1, vCoins, setCoinsRet, nValueRet);

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

// Select some coins without random shuffle or best subset approximation
bool CWallet::SelectCoinsSimple(int64_t nTargetValue, int64_t nMinValue, int64_t nMaxValue, int64_t nSpendTime, int nMinConf, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    vector<COutput> vCoins;
    AvailableCoinsMinConf(vCoins, nMinConf, nMinValue, nMaxValue);

    setCoinsRet.clear();
    nValueRet = 0;

    BOOST_FOREACH(COutput output, vCoins)
    {
        if(!output.fSpendable)
            continue;
        const CWalletTx *pcoin = output.tx;
        int i = output.i;

        // Ignore immature coins
        if (pcoin->GetBlocksToMaturity() > 0)
            continue;

        // Stop if we've chosen enough inputs
        if (nValueRet >= nTargetValue)
            break;

        // Follow the timestamp rules
        if (pcoin->nTime > nSpendTime)
            continue;

        int64_t n = pcoin->vout[i].nValue;

        pair< int64_t,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n >= nTargetValue)
        {
            // If input value is greater or equal to target then simply insert
            //    it into the current subset and exit
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            break;
        }
        else if (n < nTargetValue + CENT)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
        }
    }

    return true;
}

/** YAC_TOKEN START */
bool CWallet::SelectTokens(
    int64_t nSpendTime,
    const std::map<std::string, std::vector<COutput> >& mapAvailableTokens,
    const std::map<std::string, CAmount>& mapTokenTargetValue,
    std::set<CInputCoin>& setCoinsRet,
    std::map<std::string, CAmount>& mapValueRet) const
{
    if (!AreTokensDeployed())
        return false;

    for (auto tokenVector : mapAvailableTokens) {
        // Setup temporay variables
        std::vector<COutput> vTokens(tokenVector.second);

        std::set<CInputCoin> tempCoinsRet;
        CAmount nTempAmountRet;
        CAmount nTempTargetValue;
        std::string strTokenName = tokenVector.first;

        CAmount nValueFromPresetInputs = 0; // This is used with coincontrol, which tokens doesn't support yet

        // If we dont have a target value for this token, don't select coins for it
        if (!mapTokenTargetValue.count(strTokenName))
            continue;

        // If we dont have a target value greater than zero, don't select coins for it
        if (mapTokenTargetValue.at(strTokenName) <= 0)
            continue;

        // Add the starting value into the mapValueRet
        if (!mapValueRet.count(strTokenName))
            mapValueRet.insert(std::make_pair(strTokenName, 0));

        // assign our temporary variable
        nTempAmountRet = mapValueRet.at(strTokenName);
        nTempTargetValue = mapTokenTargetValue.at(strTokenName);

        bool res =
            nTempTargetValue <= nValueFromPresetInputs ||
            SelectTokensMinConf(nTempTargetValue - nValueFromPresetInputs,
                                nSpendTime, 1, 6, strTokenName, vTokens,
                                tempCoinsRet, nTempAmountRet) ||
            SelectTokensMinConf(nTempTargetValue - nValueFromPresetInputs,
                                nSpendTime, 1, 1, strTokenName, vTokens,
                                tempCoinsRet, nTempAmountRet) ||
            SelectTokensMinConf(nTempTargetValue - nValueFromPresetInputs,
                                nSpendTime, 0, 1, strTokenName, vTokens,
                                tempCoinsRet, nTempAmountRet);

        if (res) {
            setCoinsRet.insert(tempCoinsRet.begin(), tempCoinsRet.end());
            mapValueRet.at(strTokenName) = nTempAmountRet + nValueFromPresetInputs;
        } else {
            return false;
        }
    }

  return true;
}

bool CWallet::SelectTokensMinConf(const CAmount& nTargetValue,
                                  int64_t nSpendTime, int nConfMine,
                                  int nConfTheirs,
                                  const std::string& strTokenName,
                                  std::vector<COutput> vCoins,
                                  std::set<CInputCoin>& setCoinsRet,
                                  CAmount& nValueRet) const
{
  setCoinsRet.clear();
  nValueRet = 0;

  // List of values less than target
  boost::optional<CInputCoin> coinLowestLarger;
//  std::vector<CInputCoin> vValue;
  boost::optional<CAmount> coinLowestLargerAmount;
  std::vector<std::pair<CInputCoin, CAmount> > vValue;
  std::map<COutPoint, CAmount> mapValueAmount;
  CAmount nTotalLower = 0;
  sort(vCoins.begin(), vCoins.end(), compareUTXO);

  #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
  for (const COutput& output : vCoins) {
    if (!output.fSpendable) continue;

    const CWalletTx* pcoin = output.tx;

    if (output.nDepth < (pcoin->IsFromMe(MINE_ALL) ? nConfMine : nConfTheirs))
      continue;

    int i = output.i;

    // Follow the timestamp rules
    if (pcoin->nTime > nSpendTime) continue;

    CInputCoin coin = CInputCoin(pcoin, i);

    //-------------------------------

    int nType = -1;
    bool fIsOwner = false;
    if (!coin.txout.scriptPubKey.IsTokenScript(nType, fIsOwner)) {
        continue;
    }

    CAmount nTempAmount = 0;
    if (nType == TX_NEW_TOKEN && !fIsOwner) { // Yatoken/Sub Token
        CNewToken tokenTemp;
        std::string address;
        if (!TokenFromScript(coin.txout.scriptPubKey, tokenTemp, address))
            continue;
        nTempAmount = tokenTemp.nAmount;
    } else if (nType == TX_TRANSFER_TOKEN) { // Transfer Token
        CTokenTransfer transferTemp;
        std::string address;
        if (!TransferTokenFromScript(coin.txout.scriptPubKey, transferTemp, address))
            continue;
        nTempAmount = transferTemp.nAmount;
    } else if (nType == TX_NEW_TOKEN && fIsOwner) { // Owner Token
        std::string ownerName;
        std::string address;
        if (!OwnerTokenFromScript(coin.txout.scriptPubKey, ownerName, address))
            continue;
        nTempAmount = OWNER_TOKEN_AMOUNT;
    } else if (nType == TX_REISSUE_TOKEN) { // Reissue Token
        CReissueToken reissueTemp;
        std::string address;
        if (!ReissueTokenFromScript(coin.txout.scriptPubKey, reissueTemp, address))
            continue;
        nTempAmount = reissueTemp.nAmount;
    } else {
        continue;
    }

    if (nTempAmount == nTargetValue) {
      setCoinsRet.insert(coin);
      nValueRet += nTempAmount;
      return true;
    } else if (nTempAmount < nTargetValue + CENT) {
      vValue.push_back(std::make_pair(coin, nTempAmount));
      nTotalLower += nTempAmount;
    } else if (!coinLowestLarger || !coinLowestLargerAmount ||
               nTempAmount < coinLowestLargerAmount) {
      coinLowestLarger = coin;
      coinLowestLargerAmount = nTempAmount;
    }
  }

  if (nTotalLower == nTargetValue) {
    for (const auto& pair : vValue) {
      setCoinsRet.insert(pair.first);
      nValueRet += pair.second;
    }
    return true;
  }

  if (nTotalLower < nTargetValue)
  {
      if (!coinLowestLarger || !coinLowestLargerAmount)
          return false;
      setCoinsRet.insert(coinLowestLarger.get());

      #pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
      nValueRet += coinLowestLargerAmount.get();
      return true;
  }

  // Solve subset sum by stochastic approximation
  std::sort(vValue.begin(), vValue.end(), CompareTokenValueOnly());
  vector<char> vfBest;
  int64_t nBest;

  ApproximateBestTokenSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
  if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
      ApproximateBestTokenSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

  // If we have a bigger coin and (either the stochastic approximation didn't
  // find a good solution,
  //                                   or the next bigger coin is closer),
  //                                   return the bigger coin
  if (coinLowestLarger && coinLowestLargerAmount &&
      ((nBest != nTargetValue && nBest < nTargetValue + CENT) ||
              coinLowestLargerAmount <= nBest)) {
    setCoinsRet.insert(coinLowestLarger.get());
    nValueRet += coinLowestLargerAmount.get();
  } else {
    for (unsigned int i = 0; i < vValue.size(); i++)
      if (vfBest[i]) {
        setCoinsRet.insert(vValue[i].first);
        nValueRet += vValue[i].second;
      }

    if (fDebug && GetBoolArg("-printpriority")) {
      //// debug print
      printf("SelectTokens() best subset: ");
      for (unsigned int i = 0; i < vValue.size(); i++)
        if (vfBest[i])
          printf("%s : %s ", strTokenName,
                 FormatMoney(vValue[i].second).c_str());
      printf("total %s : %s\n", strTokenName, FormatMoney(nBest).c_str());
    }
  }

  return true;
}
/** YAC_TOKEN END */

/** YAC_TOKEN START */
bool CWallet::CreateTransactionWithTokens(
    const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
    CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
    std::string& strFailReason, const CCoinControl& coinControl,
    const std::vector<CNewToken> tokens, const CTxDestination destination,
    const ETokenType& type)
{
  CReissueToken reissueToken;
  /*
   *    fNewToken: true
        tokens: contains CNewToken info
        fTransferToken: false
        fReissueToken: false
        vecSend: contains fee lock address + owner token address
        coinControl.destChange: YAC change address
        destination: address containing new token
        tokenType: ETokenType::YATOKEN, ETokenType::SUB, ETokenType::UNIQUE
   */
  return CreateTransactionAll(vecSend, wtxNew, reservekey, nFeeRet,
                              nChangePosInOut, strFailReason, coinControl,
                              NULL, true, true, tokens, destination, false, false,
                              reissueToken, type);
}

bool CWallet::CreateTransactionWithTransferToken(
    const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
    CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
    std::string& strFailReason, const CCoinControl& coinControl)
{
  CNewToken token;
  CReissueToken reissueToken;
  CTxDestination destination;
  ETokenType tokenType = ETokenType::INVALID;
/*
 *  vecSend: contains receiver's token scriptPubKey
    coinControl: contain YAC change address and token change address
    fNewToken: false
    tokens: contains empty CNewToken info
    destination: contains empty destination
    fTransferToken: true
    fReissueToken: false
    reissueToken: contains empty CReissueToken info
    tokenType: ETokenType::INVALID
 */
  return CreateTransactionAll(vecSend, wtxNew, reservekey, nFeeRet,
                              nChangePosInOut, strFailReason, coinControl,
                              NULL, true, false, token, destination, true, false,
                              reissueToken, tokenType);
}

bool CWallet::CreateTransactionWithReissueToken(
    const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
    CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
    std::string& strFailReason, const CCoinControl& coinControl,
    const CReissueToken& reissueToken, const CTxDestination destination)
{
  CNewToken token;
  ETokenType tokenType = ETokenType::REISSUE;
  /*
   *    vecSend: contains scriptPubKey for ownership token transfer and scriptPubKey for reissue fee lock
        coinControl: contain YAC change address
        fNewToken: false
        tokens: contains empty CNewToken info
        destination: address containing reissued token
        fTransferToken: false
        fReissueToken: true
        reissueToken: contains CReissueToken info
        tokenType: ETokenType::REISSUE
   */
  return CreateTransactionAll(vecSend, wtxNew, reservekey, nFeeRet,
                              nChangePosInOut, strFailReason, coinControl,
                              NULL, true, false, token, destination, false, true,
                              reissueToken, tokenType);
}

bool CWallet::CreateNewChangeAddress(CReserveKey& reservekey, CKeyID& keyID, std::string& strFailReason)
{
    // Called with coin control doesn't have a change_address
    // no coin control: send change to newly generated address
    // Note: We use a new key here to keep it from being obvious which side is the change.
    //  The drawback is that by not reusing a previous key, the change may be lost if a
    //  backup is restored, if the backup doesn't have the new private key for the change.
    //  If we reused the old key, it would be possible to add code to look for and
    //  rediscover unknown transactions that were written with keys of ours to recover
    //  post-backup change.

    // Reserve a new key pair from key pool
    CPubKey vchPubKey = reservekey.GetReservedKey();
    keyID = vchPubKey.GetID();
    return true;
}
/** YAC_TOKEN END */

bool CWallet::CreateTransaction(CScript scriptPubKey, ::int64_t nValue,
        CWalletTx &wtxNew, CReserveKey &reservekey, CAmount &nFeeRet,
        int &nChangePosInOut, std::string &strFailReason,
        const CCoinControl &coinControl,
        const CScript *fromScriptPubKey,
        bool useExpiredTimelockUTXO)
{
    vector<CRecipient> vecSend;
    CRecipient recipient = {scriptPubKey, nValue, false};
    vecSend.push_back(recipient);
    return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePosInOut, strFailReason, coinControl, fromScriptPubKey, useExpiredTimelockUTXO);
}

bool CWallet::CreateTransaction(const std::vector<CRecipient> &vecSend,
        CWalletTx &wtxNew, CReserveKey &reservekey, CAmount &nFeeRet,
        int &nChangePosInOut, std::string &strFailReason,
        const CCoinControl &coinControl,
        const CScript *fromScriptPubKey,
        bool useExpiredTimelockUTXO)
{
    CNewToken token;
    CReissueToken reissueToken;
    CTxDestination destination;
    ETokenType tokenType = ETokenType::INVALID;
    return CreateTransactionAll(vecSend, wtxNew, reservekey, nFeeRet, nChangePosInOut, strFailReason, coinControl, fromScriptPubKey, useExpiredTimelockUTXO, false, token, destination, false, false, reissueToken, tokenType);
}

bool CWallet::CreateTransactionAll(
    const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
    CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
    std::string& strFailReason, const CCoinControl& coinControl,
    const CScript* fromScriptPubKey, bool useExpiredTimelockUTXO, bool fNewToken,
    const CNewToken& token, const CTxDestination destination,
    bool fTransferToken, bool fReissueToken,
    const CReissueToken& reissueToken, const ETokenType& tokenType)
{
    std::vector<CNewToken> tokens;
    tokens.push_back(token);
    return CreateTransactionAll(
        vecSend, wtxNew, reservekey, nFeeRet, nChangePosInOut, strFailReason,
        coinControl, fromScriptPubKey, useExpiredTimelockUTXO, fNewToken, tokens, destination,
        fTransferToken, fReissueToken, reissueToken, tokenType);
}

bool CWallet::CreateTransactionAll(
    const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew,
    CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
    std::string& strFailReason, const CCoinControl& coinControl,
    const CScript* fromScriptPubKey, bool useExpiredTimelockUTXO, bool fNewToken,
    const std::vector<CNewToken> tokens, const CTxDestination destination,
    bool fTransferToken, bool fReissueToken,
    const CReissueToken& reissueToken, const ETokenType& tokenType)
{
    /** YAC_TOKEN START */
    if (!AreTokensDeployed() && (fTransferToken || fNewToken || fReissueToken))
        return false;

    if (fNewToken && (tokens.size() < 1 || !IsValidDestination(destination)))
        return error("%s : Tried creating a new token transaction and the token was null or the destination was invalid", __func__);

    if ((fNewToken && fTransferToken) || (fReissueToken && fTransferToken) || (fReissueToken && fNewToken))
        return error("%s : Only one type of token transaction allowed per transaction");

    if (fReissueToken && (reissueToken.IsNull() || !IsValidDestination(destination)))
        return error("%s : Tried reissuing an token and the reissue data was null or the destination was invalid", __func__);
    /** YAC_TOKEN END */

    CAmount nValue = 0; // Contains YAC amount, not token amount
    std::map<std::string, CAmount> mapTokenValue; // Contains token amount for each token
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    for (const auto& recipient : vecSend)
    {
        /** YAC_TOKEN START */
        if (fTransferToken || fReissueToken || tokenType == ETokenType::SUB || tokenType == ETokenType::UNIQUE) {
            CTokenTransfer tokenTransfer;
            std::string address;
            if (TransferTokenFromScript(recipient.scriptPubKey, tokenTransfer, address)) {
                if (!mapTokenValue.count(tokenTransfer.strName))
                    mapTokenValue[tokenTransfer.strName] = 0;

                if (tokenTransfer.nAmount <= 0) {
                    strFailReason = _("Token Transfer amounts must be greater than 0");
                    return false;
                }

                mapTokenValue[tokenTransfer.strName] += tokenTransfer.nAmount;
            }
        }
        /** YAC_TOKEN END */

        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must not be negative");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty())
    {
        strFailReason = _("Transaction must have at least one recipient");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);

    CAmount nFeeNeeded;
    unsigned int nBytes;
    {
        std::set<CInputCoin> setCoins;
        std::set<CInputCoin> setTokens;
        LOCK2(cs_main, cs_wallet);
        // txdb must be opened before the mapWallet lock
        CTxDB txdb("r");
        {
            /** YAC_TOKEN START */
            std::vector<COutput> vAvailableCoins;
            std::map<std::string, std::vector<COutput> > mapTokenCoins;

            if (fTransferToken || fReissueToken || tokenType == ETokenType::SUB || tokenType == ETokenType::UNIQUE)
                AvailableCoinsWithTokens(vAvailableCoins, mapTokenCoins, true, &coinControl, fromScriptPubKey, useExpiredTimelockUTXO);
            else
                AvailableCoins(vAvailableCoins, true, &coinControl, fromScriptPubKey, useExpiredTimelockUTXO);
            /** YAC_TOKEN END */

            // Create change script that will be used if we need change
            // TODO: pass in scriptChange instead of reservekey so
            // change transaction isn't always pay-to-bitcoin-address
            CScript scriptChange;
            CScript tokenScriptChange;

            // coin control: send change to custom address
            if (!boost::get<CNoDestination>(&coinControl.destChange))
            {
                scriptChange = GetScriptForDestination(coinControl.destChange);
            }
            // no coin control: send change to newly generated address
            else
            {
                // Note: We use a new key here to keep it from being obvious which side is the change.
                //  The drawback is that by not reusing a previous key, the change may be lost if a
                //  backup is restored, if the backup doesn't have the new private key for the change.
                //  If we reused the old key, it would be possible to add code to look for and
                //  rediscover unknown transactions that were written with keys of ours to recover
                //  post-backup change.

                // Reserve a new key pair from key pool
                CKeyID keyID;
                if (!CreateNewChangeAddress(reservekey, keyID, strFailReason))
                    return false;

                scriptChange = GetScriptForDestination(keyID);
            }

            /** YAC_TOKEN START */
            if (!boost::get<CNoDestination>(&coinControl.tokenDestChange)) {
                tokenScriptChange = GetScriptForDestination(coinControl.tokenDestChange);
            } else {
                tokenScriptChange = scriptChange;
            }
            /** YAC_TOKEN END */

            nFeeRet = nTransactionFee;
            CAmount nValueIn = 0;
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                std::map<std::string, CAmount> mapTokensIn;
                nChangePosInOut = nChangePosRequest;
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                wtxNew.fFromMe = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;

                // vouts to the payees (for both YAC and token)
                for (const auto& recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
                    wtxNew.vout.push_back(txout);
                }

                // Choose coins to use
                nValueIn = 0;
                setCoins.clear();
                if (!SelectCoins(nValueToSelect, wtxNew.nTime, vAvailableCoins, setCoins, nValueIn, &coinControl))
                {
                    strFailReason = _("Insufficient funds");
                    return false;
                }
                /** YAC_TOKEN START */
                if (AreTokensDeployed()) {
                    setTokens.clear();
                    mapTokensIn.clear();
                    if (!SelectTokens(wtxNew.nTime, mapTokenCoins, mapTokenValue, setTokens, mapTokensIn)) {
                        strFailReason = _("Insufficient token funds");
                        return false;
                    }
                }
                /** YAC_TOKEN END */

                const CAmount nChange = nValueIn - nValueToSelect;

                /** YAC_TOKEN START */
                // token vouts to ourself (for token change)
                if (AreTokensDeployed()) {
                    // Add the change for the tokens
                    std::map<std::string, CAmount> mapTokenChange;
                    for (auto token : mapTokenValue) {
                        if (mapTokensIn.count(token.first))
                            mapTokenChange.insert(
                                    std::make_pair(token.first, (mapTokensIn.at(token.first) - token.second)));
                    }

                    for (auto tokenChange : mapTokenChange) {
                        if (tokenChange.second > 0) {
                            CScript scriptTokenChange = tokenScriptChange;
                            CTokenTransfer tokenTransfer(tokenChange.first, tokenChange.second);

                            tokenTransfer.ConstructTransaction(scriptTokenChange);
                            CTxOut newTokenTxOut(0, scriptTokenChange);

                            wtxNew.vout.emplace_back(newTokenTxOut);
                        }
                    }
                }
                /** YAC_TOKEN END */

                if (nChange > 0)
                {
                    // Fill a vout to ourself (for YAC change)
                    CTxOut newTxOut(nChange, scriptChange);

                    if (nChangePosInOut == -1)
                    {
                        // Insert change txn at random position:
                        nChangePosInOut = GetRandInt(wtxNew.vout.size());
                    }
                    else if ((unsigned int)nChangePosInOut > wtxNew.vout.size())
                    {
                        strFailReason = _("Change index out of range");
                        return false;
                    }

                    std::vector<CTxOut>::iterator position = wtxNew.vout.begin()+nChangePosInOut;
                    wtxNew.vout.insert(position, newTxOut);
                } else {
                    nChangePosInOut = -1;
                }

                /** YAC_TOKEN START */
                if (AreTokensDeployed()) {
                    if (fNewToken) {
                        for (auto token : tokens) {
                            // Create the owner token output for non-unique tokens
                            if (tokenType != ETokenType::UNIQUE) {
                                CScript ownerScript = GetScriptForDestination(destination);
                                token.ConstructOwnerTransaction(ownerScript);
                                CTxOut ownerTxOut(0, ownerScript);
                                wtxNew.vout.push_back(ownerTxOut);
                            }

                            // Create the token transaction and push it back so it is the last CTxOut in the transaction
                            CScript scriptPubKey = GetScriptForDestination(destination);
                            token.ConstructTransaction(scriptPubKey);
                            CTxOut newTxOut(0, scriptPubKey);
                            wtxNew.vout.push_back(newTxOut);
                        }
                    } else if (fReissueToken) {
                        // Create the token transaction and push it back so it is the last CTxOut in the transaction
                        CScript reissueScript = GetScriptForDestination(destination);

                        // Create the scriptPubKeys for the reissue data, and that owner token
                        reissueToken.ConstructTransaction(reissueScript);

                        CTxOut reissueTxOut(0, reissueScript);
                        wtxNew.vout.push_back(reissueTxOut);
                    }
                }
                /** YAC_TOKEN END */

                // Fill vin
                for (const auto& coin : setCoins)
                {
                    // In order nLockTime and OP_CHECKLOCKTIMEVERIFY can work, set nSequence to another value which different with maxint
                    unsigned int nSequenceIn = CTxIn::SEQUENCE_FINAL;
                    const CTxOut& txout = coin.txout;
                    txnouttype utxoType = TX_NONSTANDARD;
                    uint32_t lockDuration = 0;

                    if (IsSpendableTimelockUTXO(txout, utxoType, lockDuration))
                    {
                        switch (utxoType)
                        {
                        case TX_CLTV_P2SH:
                        case TX_CLTV_P2PKH:
                        {
                            nSequenceIn = 0;
                            wtxNew.nLockTime = lockDuration;
                            break;
                        }
                        case TX_CSV_P2SH:
                        case TX_CSV_P2PKH:
                        {
                            nSequenceIn = lockDuration;
                            break;
                        }
                        }
                    }

                    wtxNew.vin.push_back(
                            CTxIn(coin.outpoint, CScript(), nSequenceIn));
                }
                /** YAC_TOKEN START */
                if (AreTokensDeployed()) {
                    unsigned int nSequenceIn = CTxIn::SEQUENCE_FINAL;
                    for (const auto &token : setTokens)
                    {
                      wtxNew.vin.push_back(
                          CTxIn(token.outpoint, CScript(), nSequenceIn));
                    }
                }
                /** YAC_TOKEN END */

                // Sign
                int nIn = 0;
                for (const auto& coin : setCoins)
                {
                    if (!SignSignature(*this, coin.txout, wtxNew, nIn++))
                    {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    }
                }
                /** YAC_TOKEN START */
                if (AreTokensDeployed()) {
                    for (const auto& token : setTokens)
                    {
                        if (!SignSignature(*this, token.txout, wtxNew, nIn++))
                        {
                            strFailReason = _("Signing token transaction failed");
                            return false;
                        }
                    }
                }
                /** YAC_TOKEN END */

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                if (nBytes >= (2*GetMaxSize(MAX_BLOCK_SIZE_GEN)/3) )    // was MAX_BLOCK_SIZE_GEN/5 why????????????
                    return false;

                // Check that enough fee is included
                // nPayFee is the min transaction fee is set by user. There are two methods to set nPayFee:
                // 1) Set with option "paytxfee" in yacoin.conf
                // 2) Set with rpc command "settxfee"
                int64_t nPayFee = (nBytes * nTransactionFee) / 1000;
                int64_t nMinFee = wtxNew.GetMinFee(nBytes);

                printf("CWallet::CreateTransaction, nBytes = %d, "
                       "nPayFee = %ld, "
                       "nMinFee = %ld\n",
                       nBytes, nPayFee, nMinFee);
                if (nFeeRet < max(nPayFee, nMinFee))
                {
                    nFeeRet = max(nPayFee, nMinFee);
                    continue;
                }

                printf("CWallet::CreateTransaction, nBytes = %d, "
                                               "total UTXO value = %ld, "
                                               "send %ld, "
                                               "change %ld, "
                                               "expected fee = %ld, "
                                               "nFeeRet = %ld\n",
                       nBytes, nValueIn, nValue, nChange, nValueIn - nValue - nChange, nFeeRet);

                // Fill vtxPrev by copying from previous transactions vtxPrev
                wtxNew.AddSupportingTransactions(txdb);
                wtxNew.fTimeReceivedIsTxTime = true;

                break;
            }
        }
    }
    return true;
}

void CWallet::GetStakeWeightFromValue(const int64_t& nTime, const int64_t& nValue, uint64_t& nWeight)
{
    int64_t nTimeWeight = GetWeight(nTime, (int64_t)GetTime());

    // If time weight is lower or equal to zero then weight is zero.
    if (nTimeWeight <= 0)
    {
        nWeight = 0;
        return;
    }

    CBigNum bnCoinDayWeight = CBigNum(nValue) * nTimeWeight / COIN / (24 * 60 * 60);
    nWeight = bnCoinDayWeight.getuint64();
}


// NovaCoin: get current stake miner statistics
void CWallet::GetStakeStats(float &nKernelsRate, float &nCoinDaysRate)
{
    static uint64_t nLastKernels = 0, nLastCoinDays = 0;
    static float nLastKernelsRate = 0, nLastCoinDaysRate = 0;
    static int64_t nLastTime = GetTime();

    if (nKernelsTried < nLastKernels)
    {
        nLastKernels = 0;
        nLastCoinDays = 0;

        nLastTime = GetTime();
    }

    int64_t nInterval = GetTime() - nLastTime;
    //if (nKernelsTried > 1000 && nInterval > 5)
    if (nInterval > 10)
    {
        nKernelsRate = nLastKernelsRate = ( nKernelsTried - nLastKernels ) / (float) nInterval;
        nCoinDaysRate = nLastCoinDaysRate = ( nCoinDaysTried - nLastCoinDays ) / (float) nInterval;

        nLastKernels = nKernelsTried;
        nLastCoinDays = nCoinDaysTried;
        nLastTime = GetTime();
    }
    else
    {
        nKernelsRate = nLastKernelsRate;
        nCoinDaysRate = nLastCoinDaysRate;
    }
}

bool CWallet::MergeCoins(const int64_t& nAmount, const int64_t& nMinValue, const int64_t& nOutputValue, list<uint256>& listMerged)
{
    int64_t nBalance = GetBalance();

    if (nAmount > nBalance)
        return false;

    listMerged.clear();
    int64_t nValueIn = 0;
    set<pair<const CWalletTx*,unsigned int> > setCoins;

    // Simple coins selection - no randomization
    if (!SelectCoinsSimple(nAmount, nMinValue, nOutputValue, GetTime(), 1, setCoins, nValueIn))
        return false;

    if (setCoins.empty())
        return false;

    CWalletTx wtxNew;
    vector<const CWalletTx*> vwtxPrev;

    // Reserve a new key pair from key pool
    CReserveKey reservekey(this);
    CPubKey vchPubKey = reservekey.GetReservedKey();

    // Output script
    CScript scriptOutput;
    scriptOutput.SetDestination(vchPubKey.GetID());

    // Insert output
    wtxNew.vout.push_back(CTxOut(0, scriptOutput));

    double dWeight = 0;
    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
    {
        int64_t nCredit = pcoin.first->vout[pcoin.second].nValue;

        // Add current coin to inputs list and add its credit to transaction output
        wtxNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
        wtxNew.vout[0].nValue += nCredit;
        vwtxPrev.push_back(pcoin.first);

/*
        // Replaced with estimation for performance purposes

        for (unsigned int i = 0; i < wtxNew.vin.size(); i++) {
            const CWalletTx *txin = vwtxPrev[i];

            // Sign scripts to get actual transaction size for fee calculation
            if (!SignSignature(*this, *txin, wtxNew, i))
                return false;
        }
*/

        // Assuming that average scriptsig size is 110 bytes
        int64_t nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION) + wtxNew.vin.size() * 110;

        // Get actual transaction fee according to its estimated size
        int64_t nMinFee = wtxNew.GetMinFee(nBytes);

        // Prepare transaction for commit if sum is enough ot its size is too big
        if (nBytes >= GetMaxSize(MAX_BLOCK_SIZE_GEN)/6 || wtxNew.vout[0].nValue >= nOutputValue)
        {
            wtxNew.vout[0].nValue -= nMinFee; // Set actual fee

            for (unsigned int i = 0; i < wtxNew.vin.size(); i++) {
                const CWalletTx *txin = vwtxPrev[i];

                // Sign all scripts
                if (!SignSignature(*this, *txin, wtxNew, i))
                    return false;
            }

            // Try to commit, return false on failure
            if (!CommitTransaction(wtxNew, reservekey))
                return false;

            listMerged.push_back(wtxNew.GetHash()); // Add to hashes list

            dWeight = 0;  // Reset all temporary values
            vwtxPrev.clear();
            wtxNew.SetNull();
            wtxNew.vout.push_back(CTxOut(0, scriptOutput));
        }
    }

    // Create transactions if there are some unhandled coins left
    if (wtxNew.vout[0].nValue > 0) {
        int64_t nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION) + wtxNew.vin.size() * 110;

        // Get actual transaction fee according to its size and priority
        int64_t nMinFee = wtxNew.GetMinFee(nBytes);

        wtxNew.vout[0].nValue -= nMinFee; // Set actual fee

        if (wtxNew.vout[0].nValue <= 0)
            return false;

        for (unsigned int i = 0; i < wtxNew.vin.size(); i++) {
            const CWalletTx *txin = vwtxPrev[i];

            // Sign all scripts again
            if (!SignSignature(*this, *txin, wtxNew, i))
                return false;
        }

        // Try to commit, return false on failure
        if (!CommitTransaction(wtxNew, reservekey))
            return false;

        listMerged.push_back(wtxNew.GetHash()); // Add to hashes list
    }

    return true;
}

// yacoin2015
static int64_t GetCombineCredit(int64_t nTime)
{
	// function to produce target credit value (rising with nTime) high enough
	// for stake kernel hashing on stakeNfactor=4 three months after nTime 
    // until year 2020.
	// after that date credit value continues to rise (but also GetStakeNfactor 
    // calculated from this credit input rises above 4)

    // really? Is that what this mish mash of context challenged #s does?
    // let's see if we can figure out, no, let's guess what these #s are!
    // One should NEVER have to guess in reading code.
	return (
            ( 
             (
              nTime + 
              24 *      // hours / day
              60 *      // minutes / hour
              60 *      // seconds / minute
              90        // # of days
             )          // so this whole thing is just nStakeMaxAge!  Or is it?????
                        // WTF knows.
             / 79       // What the f... is this 79 all about? Anyone?
                        // Let's see, in binary it's 64 + 16 -1 or 0101 0000b -1 = 0100 1111b
            ) - 
            17268736    // 19 Jul 1970 20:52:16 GMT
           ) 
           / 90         // for extra points, is this 90 related to the above 90? Or not?
                        // If so, why?
           / 90         // Ditto.  And also, is this a / or a * on whats to the left??
           * COIN;      // So can we infer (again we should NEVER have to infer), finally
                        // that this return value is a scaling factor of one YACoin?
}         // the laughable documentation mentions "... until 2020". OK 1/1/2020 is
          // 1,577,836,800.  How is this reflected in the # 17,268,736 (or is it a date????) above,
          // or anywhere?  Beats me!

          // The kind of questions one SHOULD ask are:
          // If the 90s referred to above are really 'Net nStakeMaxAge, then SHOULD they be changed
          // for TestNet? Or not? 
          // ????????????????????

          // Since this function is not in old YAC 0.4.4, I must deduce that this is Novacoin code.
          // What crap!!!
          // End of epilogue.

// Call after CreateTransaction unless you want to abort
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{
    {
        printf("CommitTransaction:\n%s", wtxNew.ToString().c_str());

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Try to broadcast before saving
        if (!wtxNew.AcceptToMemoryPool())
        {
            // This must not fail. The transaction has already been signed.
            printf("CommitTransaction() : Error: Transaction not valid");
            return false;
        }

        wtxNew.RelayWalletTransaction();

        {
            LOCK2(cs_main, cs_wallet);

            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Mark old coins as spent
            set<CWalletTx*> setCoins;
            BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.COutPointGetHash()];
                coin.BindWallet(this);
                coin.MarkSpent(txin.prevout.COutPointGet_n());
                coin.WriteToDisk();
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
                vMintingWalletUpdated.push_back(coin.GetHash());
            }

            if (fFileBacked)
                delete pwalletdb;
        }
    }
    return true;
}




string CWallet::SendMoney(CScript scriptPubKey, int64_t nValue, CWalletTx& wtxNew, bool fAskFee, const CScript* fromScriptPubKey, bool useExpiredTimelockUTXO)
{
    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    if (fWalletUnlockMintOnly)
    {
        string strError = _("Error: Wallet unlocked for block minting only, unable to create transaction.");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

    int nChangePosInOut = -1;
    std::string strFailReason;
    CCoinControl coinControl;
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired, nChangePosInOut, strFailReason, coinControl, fromScriptPubKey, useExpiredTimelockUTXO))
    {
        string strError;
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds"), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed: ") + strFailReason;
        printf("SendMoney() : %s\n", strError.c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired, _("Sending...")))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}



string CWallet::SendMoneyToDestination(const CTxDestination& address, int64_t nValue, CWalletTx& wtxNew, bool fAskFee, const CScript* fromScriptPubKey, bool useExpiredTimelockUTXO)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(scriptPubKey, nValue, wtxNew, fAskFee, fromScriptPubKey, useExpiredTimelockUTXO);
}




DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;

    fFirstRunRet = !vchDefaultKey.IsValid();

    if( !NewThread(ThreadFlushWalletDB, &strWalletFile) )    //NFG
    {       // we should say something!!!
        if( fPrintToConsole )
        {
            (void)printf("The Flush Wallet (periodically) Thread FAILED to attach?\n");
        }
    }
    return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
    mapAddressBook[address] = strName;
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address), (mi == mapAddressBook.end()) ? CT_NEW : CT_UPDATED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    mapAddressBook.erase(address);
    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address), CT_DELETED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}


void CWallet::PrintWallet(const CBlock& block)
{
    {
        LOCK(cs_wallet);
        if (block.IsProofOfStake() && mapWallet.count(block.vtx[1].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[1].GetHash()];
            printf("    PoS: %d  %d  %" PRId64 "", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit(MINE_ALL));
        }
        else if (mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    PoW:  %d  %d  %" PRId64 "", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit(MINE_ALL));
        }
    }
    printf("\n");
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

//bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
//{
//    if (!pwallet->fFileBacked)
//        return false;
//    strWalletFileOut = pwallet->strWalletFile;
//    return true;
//}

//
// Mark old keypool keys as used,
// and generate all new keys
//
bool CWallet::NewKeyPool(unsigned int nSize)
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64_t nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        uint64_t nKeys;
        if (nSize > 0)
            nKeys = nSize;
        else
            nKeys = max< uint64_t>(GetArg("-keypool", 100), 0);

        for (uint64_t i = 0; i < nKeys; i++)
        {
            uint64_t nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        printf("CWallet::NewKeyPool wrote %" PRIu64 " new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int nSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        uint64_t nTargetSize;
        if (nSize > 0)
            nTargetSize = nSize;
        else
            nTargetSize = max< uint64_t>(GetArg("-keypool", 100), 0);

        while (setKeyPool.size() < (nTargetSize + 1))
        {
            uint64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
            printf("keypool added key %" PRIu64 ", size=%" PRIszu "\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        Yassert(keypool.vchPubKey.IsValid());
        if (fDebug && GetBoolArg("-printkeypool"))
            printf("keypool reserve %" PRId64 "\n", nIndex);
    }
}

int64_t CWallet::AddReserveKey(const CKeyPool& keypool)
{
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile);

        int64_t nIndex = 1 + *(--setKeyPool.end());
        if (!walletdb.WritePool(nIndex, keypool))
            throw runtime_error("AddReserveKey() : writing added key failed");
        setKeyPool.insert(nIndex);
        return nIndex;
    }
    return -1;
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    if(fDebug)
        printf("keypool keep %" PRId64 "\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    //if(fDebug)
    //    printf("keypool return %" PRId64 "\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool fAllowReuse)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && vchDefaultKey.IsValid())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, int64_t> CWallet::GetAddressBalances()
{
    map<CTxDestination, int64_t> balances;
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsFinal() || !pcoin->IsTrusted())
                continue;

            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(MINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                int64_t n = pcoin->IsSpent(i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set< set<CTxDestination> > CWallet::GetAddressGroupings()
{
    set< set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0 && IsMine(pcoin->vin[0]))
        {
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if(!ExtractDestination(mapWallet[txin.prevout.COutPointGetHash()].vout[txin.prevout.COutPointGet_n()].scriptPubKey, address))
                    continue;
                grouping.insert(address);
            }

            // group change with input addresses
            BOOST_FOREACH(CTxOut txout, pcoin->vout)
                if (IsChange(txout))
                {
                    CWalletTx tx = mapWallet[pcoin->vin[0].prevout.COutPointGetHash()];
                    CTxDestination txoutAddr;
                    if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                        continue;
                    grouping.insert(txoutAddr);
                }
            groupings.insert(grouping);
            grouping.clear();
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits;
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

// ppcoin: check 'spent' consistency between wallet and txindex
// ppcoin: fix wallet spent state according to txindex
void CWallet::FixSpentCoins(int& nMismatchFound, int64_t& nBalanceInQuestion, bool fCheckOnly)
{
    nMismatchFound = 0;
    nBalanceInQuestion = 0;

    LOCK(cs_wallet);
    vector<CWalletTx*> vCoins;
    vCoins.reserve(mapWallet.size());
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        vCoins.push_back(&(*it).second);

    CTxDB txdb("r");
    BOOST_FOREACH(CWalletTx* pcoin, vCoins)
    {
        // Find the corresponding transaction index
        CTxIndex txindex;
        if (!txdb.ReadTxIndex(pcoin->GetHash(), txindex))
            continue;
        for (unsigned int n=0; n < pcoin->vout.size(); n++)
        {
            if (IsMine(pcoin->vout[n]) && pcoin->IsSpent(n) && (txindex.vSpent.size() <= n || txindex.vSpent[n].IsNull()))
            {
                printf("FixSpentCoins found lost coin %sppc %s[%d], %s\n",
                    FormatMoney(pcoin->vout[n].nValue).c_str(), pcoin->GetHash().ToString().c_str(), n, fCheckOnly? "repair not attempted" : "repairing");
                nMismatchFound++;
                nBalanceInQuestion += pcoin->vout[n].nValue;
                if (!fCheckOnly)
                {
                    pcoin->MarkUnspent(n);
                    pcoin->WriteToDisk();
                }
            }
            else if (IsMine(pcoin->vout[n]) && !pcoin->IsSpent(n) && (txindex.vSpent.size() > n && !txindex.vSpent[n].IsNull()))
            {
                printf("FixSpentCoins found spent coin %sppc %s[%d], %s\n",
                    FormatMoney(pcoin->vout[n].nValue).c_str(), pcoin->GetHash().ToString().c_str(), n, fCheckOnly? "repair not attempted" : "repairing");
                nMismatchFound++;
                nBalanceInQuestion += pcoin->vout[n].nValue;
                if (!fCheckOnly)
                {
                    pcoin->MarkSpent(n);
                    pcoin->WriteToDisk();
                }
            }

        }

        if(IsMine((CTransaction)*pcoin) && (pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetDepthInMainChain() == 0)
        {
            printf("FixSpentCoins %s tx %s\n", fCheckOnly ? "found" : "removed", pcoin->GetHash().ToString().c_str());
            if (!fCheckOnly)
            {
                EraseFromWallet(pcoin->GetHash());
            }
        }
    }
}

// ppcoin: disable transaction (only for coinstake)
void CWallet::DisableTransaction(const CTransaction &tx)
{
    if (!tx.IsCoinStake() || !IsFromMe(tx))
        return; // only disconnecting coinstake requires marking input unspent

    LOCK(cs_wallet);
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.COutPointGetHash());
        if (mi != mapWallet.end())
        {
            CWalletTx& prev = (*mi).second;
            if (txin.prevout.COutPointGet_n() < prev.vout.size() && IsMine(prev.vout[txin.prevout.COutPointGet_n()]))
            {
                prev.MarkUnspent(txin.prevout.COutPointGet_n());
                prev.WriteToDisk();
            }
        }
    }
}

CPubKey CReserveKey::GetReservedKey()
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else
        {
            printf("CReserveKey::GetReservedKey(): Warning: Using default key instead of a new key, top up your keypool!");
            vchPubKey = pwallet->vchDefaultKey;
        }
    }
    Yassert(vchPubKey.IsValid());
    return vchPubKey;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64_t& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
        Yassert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

ScriptMap CWallet::GetP2SHRedeemScriptMap() const
{
    return this->mapScripts;
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
            vMintingWalletUpdated.push_back(hashTx);
        }
    }
}

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const 
{
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); 
         it != mapKeyMetadata.end(); 
         //it++
         ++it
        )
    {
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;
    }
    // map in which we'll infer heights of other keys
    CBlockIndex                                 // if this is one day in btc? then what for yac??
      //*pindexMax = FindBlockByHeight(std::max(0, chainActive.Height() - 144)); // the tip can be reorganised; use a 144-block safety margin
        *pindexMax = FindBlockByHeight(std::max(0, chainActive.Height()
         - (int)nOnedayOfAverageBlocks)); // the tip can be reorganised; use a 144-block safety margin

    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) 
    {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); 
         it != mapWallet.end(); 
         //it++
         ++it
        ) 
    {
        // iterate over all wallet transactions...
        const CWalletTx 
            &wtx = (*it).second;

        std::map<uint256, CBlockIndex*>::const_iterator 
            blit = mapBlockIndex.find(wtx.hashBlock);

        if (
            (blit != mapBlockIndex.end()) && 
            blit->second->IsInMainChain()
           ) 
        {
            // ... which are already in a block
            int 
                nHeight = blit->second->nHeight;

            BOOST_FOREACH(const CTxOut &txout, wtx.vout) 
            {
                // iterate over all their outputs
                ::ExtractAffectedKeys(*this, txout.scriptPubKey, vAffected);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) 
                {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator 
                        rit = mapKeyFirstBlock.find(keyid);

                    if (
                        (rit != mapKeyFirstBlock.end()) && 
                        (nHeight < rit->second->nHeight)
                       )
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); 
         it != mapKeyFirstBlock.end(); 
         //it++
         ++it
        )
        mapKeyBirth[it->first] = it->second->nTime - 7200; // block times can be 2h off
}

void CWallet::ClearOrphans()
{
    list<uint256> orphans;

    LOCK(cs_wallet);
    for(map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx *wtx = &(*it).second;
        if((wtx->IsCoinBase() || wtx->IsCoinStake()) && !wtx->IsInMainChain())
        {
            orphans.push_back(wtx->GetHash());
        }
    }

    for(list<uint256>::const_iterator it = orphans.begin(); it != orphans.end(); ++it)
        EraseFromWallet(*it);
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
