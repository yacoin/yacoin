// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_KEYSTORE_H
#define BITCOIN_KEYSTORE_H

#ifndef __CRYPTER_H__
 #include "crypter.h"
#endif

#ifndef BITCOIN_SYNC_H
 #include "sync.h"
#endif

#include <boost/signals2/signal.hpp>
#include <boost/variant.hpp>

class CScript;

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

/** A txout script template with a specific destination. It is either:
  * CNoDestination: no destination set
  * CKeyID: TX_PUBKEYHASH destination
  * CScriptID: TX_SCRIPTHASH destination
  *
  * A CTxDestination is the internal data type encoded in a CBitcoinAddress.
  */
typedef boost::variant<CNoDestination, CKeyID, CScriptID> CTxDestination;

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {}

    // Add a key to the store.
    virtual bool AddKey(const CKey& key) =0;

    // Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0;
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;

    // Support for BIP 0013 : see https://en.bitcoin.it/wiki/BIP_0013
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    // Support for Watch-only addresses
    virtual bool AddWatchOnly(const CScript &dest) =0;
    virtual bool RemoveWatchOnly(const CScript &dest) =0;
    virtual bool HaveWatchOnly(const CScript &dest) const =0;
    virtual bool HaveWatchOnly() const =0;

    virtual bool GetSecret(const CScript& scriptPubKey, CSecret& vchSecret, bool &fCompressed, txnouttype& whichTypeRet, CScript& subscript) const
    {
        vector<valtype> vSolutions;
        if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
            return false;

        CKeyID keyID;
    #ifdef _MSC_VER
        bool
            fTest = false;
        if( vSolutions.empty() )
            {       // one can't technically access vSolutions[ 0 ]
            fTest = true;
            return false;
            }
    #endif
        switch (whichTypeRet)
        {
        case TX_NONSTANDARD:
        case TX_NULL_DATA:  // this is not in 0.4.4 code
            return false;
        case TX_PUBKEY:
        case TX_CLTV_P2SH:
        case TX_CSV_P2SH:
            keyID = CPubKey(vSolutions[0]).GetID();
            break;
        case TX_NEW_TOKEN:
        case TX_REISSUE_TOKEN:
        case TX_TRANSFER_TOKEN:
        case TX_CLTV_P2PKH:
        case TX_CSV_P2PKH:
        case TX_PUBKEYHASH:
            keyID = CKeyID(uint160(vSolutions[0]));
            break;
        case TX_SCRIPTHASH:
            CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
            CScript tempScript;
            if (GetCScript(scriptID, subscript)) {
                if (GetSecret(subscript, vchSecret, fCompressed, whichTypeRet, tempScript)) {
                    return true;
                }
            }
            return false;
        case TX_MULTISIG:
            return false;
        }

        CKey key;
        if (!GetKey(keyID, key))
            return false;
        vchSecret = key.GetSecret(fCompressed);
        return true;
    }

    virtual bool GetSecret(const CKeyID &address, CSecret& vchSecret, bool &fCompressed) const
    {
        CKey key;
        if (!GetKey(address, key))
            return false;
        vchSecret = key.GetSecret(fCompressed);
        return true;
    }
};

typedef std::map<CKeyID, std::pair<CSecret, bool> > KeyMap;
typedef std::map<CScriptID, CScript > ScriptMap;
typedef std::set<CScript> WatchOnlySet;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys;
    ScriptMap mapScripts;
    WatchOnlySet setWatchOnly;

public:
    bool AddKey(const CKey& key);
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut.Reset();
                keyOut.SetSecret((*mi).second.first, (*mi).second.second);
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const;

    virtual bool AddWatchOnly(const CScript &dest);
    virtual bool RemoveWatchOnly(const CScript &dest);
    virtual bool HaveWatchOnly(const CScript &dest) const;
    virtual bool HaveWatchOnly() const;
};

typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;

/** Keystore which keeps the private keys encrypted.
 * It derives from the basic key store, which is used if no encryption is active.
 */
class CCryptoKeyStore : public CBasicKeyStore
{
private:
    CryptedKeyMap mapCryptedKeys;

    CKeyingMaterial vMasterKey;

    // if fUseCrypto is true, mapKeys must be empty
    // if fUseCrypto is false, vMasterKey must be empty
    bool fUseCrypto;

protected:
    bool SetCrypted();

    // will encrypt previously unencrypted keys
    bool EncryptKeys(CKeyingMaterial& vMasterKeyIn);
    bool DecryptKeys(const CKeyingMaterial& vMasterKeyIn);

    bool Unlock(const CKeyingMaterial& vMasterKeyIn);

public:
    CCryptoKeyStore() : fUseCrypto(false)
    {
    }

    bool IsCrypted() const
    {
        return fUseCrypto;
    }

    bool IsLocked() const
    {
        if (!IsCrypted())
            return false;
        bool result;
        {
            LOCK(cs_KeyStore);
            result = vMasterKey.empty();
        }
        return result;
    }

    bool Lock();

    virtual bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddKey(const CKey& key);
    bool HaveKey(const CKeyID &address) const
    {
        {
            LOCK(cs_KeyStore);
            if (!IsCrypted())
                return CBasicKeyStore::HaveKey(address);
            return mapCryptedKeys.count(address) > 0;
        }
        return false;
    }
    bool GetKey(const CKeyID &address, CKey& keyOut) const;
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        if (!IsCrypted())
        {
            CBasicKeyStore::GetKeys(setAddress);
            return;
        }
        setAddress.clear();
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        while (mi != mapCryptedKeys.end())
        {
            setAddress.insert((*mi).first);
            mi++;
        }
    }

    /* Wallet status (encrypted, locked) changed.
     * Note: Called without locks held.
     */
    boost::signals2::signal<void (CCryptoKeyStore* wallet)> NotifyStatusChanged;
};

#endif
