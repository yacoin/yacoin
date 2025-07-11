// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_WALLET_H
 #include "wallet.h"
#endif

#ifndef _BITCOINRPC_H_
 #include "bitcoinrpc.h"
#endif

#ifndef BITCOIN_INIT_H
 #include "init.h"
#endif

#include "coincontrol.h"
#include "streams.h"
#include <sstream>

using namespace json_spirit;

using std::runtime_error;
using std::string;
using std::map;
using std::list;
using std::vector;
using std::set;
using std::pair;
using std::max;
using std::min;

int64_t nWalletUnlockTime;
static CCriticalSection cs_nWalletUnlockTime;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);

std::string HelpRequiringPassphrase()
{
    return pwalletMain->IsCrypted()
        ? "\n\nRequires wallet passphrase to be set with walletpassphrase first"
        : "";
}

void EnsureWalletIsUnlocked()
{
    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    if (fWalletUnlockMintOnly)
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Wallet unlocked for block minting only.");
}

void WalletTxToJSON(const CWalletTx& wtx, Object& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms));
    if (wtx.IsCoinBase() || wtx.IsCoinStake())
        entry.push_back(Pair("generated", true));
    if (confirms)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", (boost::int64_t)(mapBlockIndex[wtx.hashBlock]->nTime)));
    }
    entry.push_back(Pair("txid", wtx.GetHash().GetHex()));
    entry.push_back(Pair("time", (boost::int64_t)wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (boost::int64_t)wtx.nTimeReceived));
    for(const PAIRTYPE(string,string)& item : wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

void LockTimeRedeemScriptToJSON(const CScript& redeemScript, txnouttype type, Object& out)
{
    vector<CTxDestination> addresses;
    uint32_t nLockTime = 0;
    std::string addressType = "";
    std::string lockCondition = "";
    bool isTimeBasedLock = false;
    std::string redeemScriptFormat = redeemScript.ToString();

    out.push_back(Pair("RedeemScriptHex", HexStr(redeemScript.begin(), redeemScript.end())));
    out.push_back(Pair("RedeemScriptFormat", redeemScriptFormat));

    // Get locktime and public key
    std::string delimiter = " ";
    std::string data;
    size_t pos = 0;
    bool firstPos = true;
    while ((pos = redeemScriptFormat.find(delimiter)) != std::string::npos)
    {
        data = redeemScriptFormat.substr(0, pos);
        if (firstPos)
        {
            nLockTime = atoi(data.c_str());
            firstPos = false;
        }
        redeemScriptFormat.erase(0, pos + delimiter.length());
    }
    out.push_back(Pair("PublicKey", data));

    // Convert to address
    CScriptID redeemScriptID = redeemScript.GetID();
    if (type == TX_CLTV_P2SH)
    {
        addressType += "CltvAddress";
        if (nLockTime < LOCKTIME_THRESHOLD)
        {
            std::stringstream ss;
            ss << nLockTime;
            lockCondition += "locked until block height " + ss.str();
            isTimeBasedLock = false;
        }
        else
        {
            lockCondition += "locked until " + DateTimeStrFormat(nLockTime);
            isTimeBasedLock = true;
        }
    }
    else // TX_CSV_P2SH
    {
        addressType += "CsvAddress";
        if (nLockTime & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            std::stringstream ss;
            ss << ((nLockTime & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY);
            lockCondition += "locked for a period of " + ss.str() + " seconds";
            isTimeBasedLock = true;
        }
        else
        {
            std::stringstream ss;
            ss << nLockTime;
            lockCondition += "locked within " + ss.str() + " blocks";
            isTimeBasedLock = false;
        }
    }
    out.push_back(Pair("LockType", isTimeBasedLock ? "Time-based lock" : "Block-based lock"));
    out.push_back(Pair(addressType, CBitcoinAddress(redeemScriptID).ToString()));
    out.push_back(Pair("Description", "This is a redeemscript of " + addressType + "."
                                    + " Any coins sent to this " + addressType + " will be " + lockCondition + "."
                                    + " After the lock time, if anyone has a signature signed by private key matching"
                                      " with public key then they can spend coins from this address"));
}

string AccountFromValue(const Value& value)
{
    string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

static void
    ConvertUpTimeToNiceString( ::int64_t nUpTimeSeconds, string & sUpTime )
{
    ::int64_t
        nUpCopy = nUpTimeSeconds;

    if( nUpTimeSeconds >= nSecondsPerDay )
    {
        int
            nDaysUp = nUpTimeSeconds / nSecondsPerDay;

        nUpTimeSeconds -= (nDaysUp * nSecondsPerDay);
        sUpTime += strprintf( "%d day%s ", nDaysUp, 1 == nDaysUp? "": "s" );
    }
    if( nUpTimeSeconds >= nSecondsPerHour )     // & less than 1 day
    {
        sUpTime += strprintf( 
                             "%s (%"PRId64" sec)",
                             DateTimeStrFormat("%H hrs %M mins %S sec", 
                                                nUpTimeSeconds
                                              ).c_str(),
                             nUpCopy
                            );
    }
    else
    if( nUpTimeSeconds >= nSecondsperMinute )   // & less than 1 hour
    {
        sUpTime += strprintf( 
                             "%s (%"PRId64" sec)",
                             DateTimeStrFormat("%M mins %S sec", 
                                               nUpTimeSeconds
                                              ).c_str(),
                             nUpCopy
                            );
    }
    else    // < one minute
    {
        sUpTime = strprintf( "%"PRId64" sec", nUpCopy );
    }
}


Value getinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.");

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    Object obj, diff;
    obj.push_back(Pair("version",       FormatFullVersion()));
    obj.push_back(Pair("protocolversion",(int)PROTOCOL_VERSION));
    obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
    obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));
    obj.push_back(Pair("unspendable",   ValueFromAmount(pwalletMain->GetWatchOnlyBalance())));
    obj.push_back(Pair("newmint",       ValueFromAmount(pwalletMain->GetNewMint())));
    obj.push_back(Pair("stake",         ValueFromAmount(pwalletMain->GetStake())));
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("timeoffset",    (boost::int64_t)GetTimeOffset()));

    ::int64_t
        nUpTimeSeconds = GetTime() - nUpTimeStart;
    string
        sUpTime = "";
    ConvertUpTimeToNiceString( nUpTimeSeconds, sUpTime );

    obj.push_back(Pair("up-time",       sUpTime));

    obj.push_back(Pair("moneysupply",   ValueFromAmount(chainActive.Tip()->nMoneySupply)));
    if(g_connman)
        obj.push_back(Pair("connections",   (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL)));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : std::string())));
    for (const std::pair<CNetAddr, LocalServiceInfo> &item : mapLocalHost)
    {
        obj.push_back(Pair("ip", item.first.ToString()));
        obj.push_back(Pair("port", item.second.nPort));
        obj.push_back(Pair("score", item.second.nScore));
    }

    diff.push_back(Pair("proof-of-work",  GetDifficulty()));
    diff.push_back(Pair("proof-of-stake", GetDifficulty(GetLastBlockIndex(chainActive.Tip(), true))));
    obj.push_back(Pair("difficulty",    diff));

    obj.push_back(Pair("testnet",       fTestNet));
    obj.push_back(Pair("keypoololdest", (boost::int64_t)pwalletMain->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(nTransactionFee)));
    obj.push_back(Pair("mininput",      ValueFromAmount(nMinimumInputValue)));
    if (pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", (boost::int64_t)nWalletUnlockTime / 1000));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

Value getnewaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getnewaddress [account]\n"
            "Returns a new Yacoin address for receiving payments.  "
            "If [account] is specified (recommended), it is added to the address book "
            "so payments received with the address will be credited to [account].");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBookName(keyID, strAccount);

    return CBitcoinAddress(keyID).ToString();
}


CBitcoinAddress GetAccountAddress(string strAccount, bool bForceNew=false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    bool bKeyUsed = false;

    // Check if the current key has been used
    if (account.vchPubKey.IsValid())
    {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin();
             it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid();
             ++it)
        {
            const CWalletTx& wtx = (*it).second;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }

    // Generate a new key
    if (!account.vchPubKey.IsValid() || bForceNew || bKeyUsed)
    {
        if (!pwalletMain->GetKeyFromPool(account.vchPubKey, false))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        pwalletMain->SetAddressBookName(account.vchPubKey.GetID(), strAccount);
        walletdb.WriteAccount(strAccount, account);
    }

    return CBitcoinAddress(account.vchPubKey.GetID());
}

Value getaccountaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccountaddress <account>\n"
            "Returns the current Yacoin address for receiving payments to this account.");

    // Parse the account first so we don't generate a key if there's an error
    string strAccount = AccountFromValue(params[0]);

    Value ret;

    ret = GetAccountAddress(strAccount).ToString();

    return ret;
}



Value setaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setaccount <yacoinaddress> <account>\n"
            "Sets the account associated with the given address.");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");


    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Detect when changing the account of an address that is the 'unused current key' of another account:
    if (pwalletMain->mapAddressBook.count(address.Get()))
    {
        string strOldAccount = pwalletMain->mapAddressBook[address.Get()];
        if (address == GetAccountAddress(strOldAccount))
            GetAccountAddress(strOldAccount, true);
    }

    pwalletMain->SetAddressBookName(address.Get(), strAccount);

    return Value::null;
}


Value getaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaccount <yacoinaddress>\n"
            "Returns the account associated with the given address.");

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");

    string strAccount;
    map<CTxDestination, string>::iterator mi = pwalletMain->mapAddressBook.find(address.Get());
    if (mi != pwalletMain->mapAddressBook.end() && !(*mi).second.empty())
        strAccount = (*mi).second;
    return strAccount;
}


Value getaddressesbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressesbyaccount <account>\n"
            "Returns the list of addresses for the given account.");

    string strAccount = AccountFromValue(params[0]);

    // Find all addresses that have the given account
    Array ret;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            ret.push_back(address.ToString());
    }
    return ret;
}

Value mergecoins(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "mergecoins <amount> <minvalue> <outputvalue>\n"
            "<amount> is resulting inputs sum\n"
            "<minvalue> is minimum value of inputs which are used in join process\n"
            "<outputvalue> is resulting value of inputs which will be created\n"
            "All values are real and and rounded to the nearest " + FormatMoney(MIN_TXOUT_AMOUNT)
            + HelpRequiringPassphrase());

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Total amount
    int64_t nAmount = AmountFromValue(params[0]);

    // Min input amount
    int64_t nMinValue = AmountFromValue(params[1]);

    // Output amount
    int64_t nOutputValue = AmountFromValue(params[2]);

    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Send amount too small");

    if (nMinValue < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Max value too small");

    if (nOutputValue < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Output value too small");

    if (nOutputValue < nMinValue)
        throw JSONRPCError(-101, "Output value is lower than min value");

    list<uint256> listMerged;
    if (!pwalletMain->MergeCoins(nAmount, nMinValue, nOutputValue, listMerged))
        return Value::null;

    Array mergedHashes;
    BOOST_FOREACH(const uint256 txHash, listMerged)
        mergedHashes.push_back(txHash.GetHex());

    return mergedHashes;
}

Value sendtoaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "sendtoaddress <yacoinaddress> <amount> [useExpiredTimelockUTXO] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + FormatMoney(MIN_TXOUT_AMOUNT)
            + HelpRequiringPassphrase());

    CBitcoinAddress address(params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");

    // Amount
    int64_t nAmount = AmountFromValue(params[1]);

    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Send amount too small");

    // Allow to use locktime UTXO
    bool useExpiredTimelockUTXO = true;
    if (params.size() > 2 && params[2].type() == bool_type)
        useExpiredTimelockUTXO = params[2].get_bool();

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["to"]      = params[4].get_str();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx, false, NULL, useExpiredTimelockUTXO);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

Value listaddressgroupings(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listaddressgroupings\n"
            "Lists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions");

    Array jsonGroupings;
    map<CTxDestination, int64_t> balances = pwalletMain->GetAddressBalances();
    BOOST_FOREACH(set<CTxDestination> grouping, pwalletMain->GetAddressGroupings())
    {
        Array jsonGrouping;
        BOOST_FOREACH(CTxDestination address, grouping)
        {
            Array addressInfo;
            addressInfo.push_back(CBitcoinAddress(address).ToString());
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                LOCK(pwalletMain->cs_wallet);
                if (pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get()) != pwalletMain->mapAddressBook.end())
                    addressInfo.push_back(pwalletMain->mapAddressBook.find(CBitcoinAddress(address).Get())->second);
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

Value signmessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessage <yacoinaddress> <message>\n"
            "Sign a message with the private key of an address");

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    string strMessage = params[1].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(Hash(ss.begin(), ss.end()), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

Value verifymessage(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage <yacoinaddress> <signature> <message>\n"
            "Verify a signed message");

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CDataStream ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CKey key;
    if (!key.SetCompactSignature(Hash(ss.begin(), ss.end()), vchSig))
        return false;

    return (key.GetPubKey().GetID() == keyID);
}


Value getreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaddress <yacoinaddress> [minconf=1]\n"
            "Returns the total amount received by <yacoinaddress> in transactions with at least [minconf] confirmations.");

    // Bitcoin address
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    CScript scriptPubKey;
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");
    scriptPubKey.SetDestination(address.Get());
    if (!IsMine(*pwalletMain,scriptPubKey))
        return (double)0.0;

    CTxDestination dest = address.Get();

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Tally
    int64_t nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal())
            continue;

        for (const auto& txout : wtx.vout)
        {
            CTxDestination addressRet;
            if (ExtractDestination(txout.scriptPubKey, addressRet) && addressRet == dest)
            {
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
            }
        }
    }

    return  ValueFromAmount(nAmount);
}


void GetAccountAddresses(string strAccount, set<CTxDestination>& setAddress)
{
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& item, pwalletMain->mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strName = item.second;
        if (strName == strAccount)
            setAddress.insert(address);
    }
}

Value getreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getreceivedbyaccount <account> [minconf=1]\n"
            "Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.");

    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();

    // Get the set of pub keys assigned to account
    string strAccount = AccountFromValue(params[0]);
    set<CTxDestination> setAddress;
    GetAccountAddresses(strAccount, setAddress);

    // Tally
    int64_t nAmount = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwalletMain, address) && setAddress.count(address))
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
        }
    }

    return (double)nAmount / (double)COIN;
}


int64_t GetAccountBalance(CWalletDB& walletdb, const string& strAccount, int nMinDepth, const isminefilter& filter, bool fExcludeNotExpiredTimelock=false)
{
    int64_t nBalance = 0;

    // Tally wallet transactions
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (!wtx.IsFinal())
            continue;

        int64_t nGenerated, nReceived, nSent, nFee;
        wtx.GetAccountAmounts(strAccount, nGenerated, nReceived, nSent, nFee, filter, fExcludeNotExpiredTimelock);

        if (nReceived != 0 && wtx.GetDepthInMainChain() >= nMinDepth)
            nBalance += nReceived;
        nBalance += nGenerated - nSent - nFee;
    }

    // Tally internal accounting entries
    nBalance += walletdb.GetAccountCreditDebit(strAccount);

    return nBalance;
}

int64_t GetAccountBalance(const string& strAccount, int nMinDepth, const isminefilter& filter, bool fExcludeNotExpiredTimelock=false)
{
    CWalletDB walletdb(pwalletMain->strWalletFile);
    return GetAccountBalance(walletdb, strAccount, nMinDepth, filter, fExcludeNotExpiredTimelock);
}


Value getbalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getbalance [account] [minconf=1] [watchonly=0]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.\n"
            "if [includeWatchonly] is specified, include balance in watchonly addresses (see 'importaddress').");

    if (params.size() == 0)
        return  ValueFromAmount(pwalletMain->GetBalance());

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();
    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | MINE_WATCH_ONLY;

    if (params[0].get_str() == "*")
    {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' 0 should return the same number.
        int64_t nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!wtx.IsTrusted())
                continue;

            int64_t allGeneratedImmature, allGeneratedMature, allFee;
            allGeneratedImmature = allGeneratedMature = allFee = 0;

            string strSentAccount;
            std::list<COutputEntry> listReceived;
            std::list<COutputEntry> listSent;
            wtx.GetAmounts(
                            allGeneratedImmature, 
                            allGeneratedMature, 
                            listReceived, 
                            listSent, 
                            allFee, 
                            strSentAccount, 
                            filter
                          );
            if (wtx.GetDepthInMainChain() >= nMinDepth)
            {
                for (const COutputEntry& r : listReceived)
                {
                    nBalance += r.amount;
                }
            }
            for (const COutputEntry& r : listSent)
            {
                nBalance -= r.amount;
            }
            nBalance -= allFee;
            nBalance += allGeneratedMature;
        }
        return  ValueFromAmount(nBalance);
    }

    string 
        strAccount = AccountFromValue(params[0]);

    int64_t 
        nBalance = GetAccountBalance(strAccount, nMinDepth, filter);

    return ValueFromAmount(nBalance);
}

Value getavailablebalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getavailablebalance [account] [minconf=1] [watchonly=0]\n"
            "If [account] is not specified, returns the server's total available balance.\n"
            "If [account] is specified, returns the balance in the account.\n"
            "if [includeWatchonly] is specified, include balance in watchonly addresses (see 'importaddress').");

    bool fExcludeNotExpiredTimelock = true;
    if (params.size() == 0)
        return  ValueFromAmount(pwalletMain->GetBalance(fExcludeNotExpiredTimelock));

    int nMinDepth = 1;
    if (params.size() > 1)
        nMinDepth = params[1].get_int();
    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | MINE_WATCH_ONLY;

    if (params[0].get_str() == "*")
    {
        // Calculate total balance a different way from GetBalance()
        // (GetBalance() sums up all unspent TxOuts)
        // getbalance and getbalance '*' 0 should return the same number.
        int64_t nBalance = 0;
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            if (!wtx.IsTrusted())
                continue;

            int64_t allGeneratedImmature, allGeneratedMature, allFee;
            allGeneratedImmature = allGeneratedMature = allFee = 0;

            string strSentAccount;
            std::list<COutputEntry> listReceived;
            std::list<COutputEntry> listSent;
            wtx.GetAmounts(
                            allGeneratedImmature,
                            allGeneratedMature,
                            listReceived,
                            listSent,
                            allFee,
                            strSentAccount,
                            filter,
                            fExcludeNotExpiredTimelock
                          );
            if (wtx.GetDepthInMainChain() >= nMinDepth)
            {
                for (const COutputEntry& r : listReceived)
                {
                    nBalance += r.amount;
                }
            }
            for (const COutputEntry& r : listSent)
            {
                nBalance -= r.amount;
            }
            nBalance -= allFee;
            nBalance += allGeneratedMature;
        }
        return  ValueFromAmount(nBalance);
    }

    string
        strAccount = AccountFromValue(params[0]);

    int64_t
        nBalance = GetAccountBalance(strAccount, nMinDepth, filter, fExcludeNotExpiredTimelock);

    return ValueFromAmount(nBalance);
}

Value movecmd(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
        throw runtime_error(
            "move <fromaccount> <toaccount> <amount> [minconf=1] [comment]\n"
            "Move from one account in your wallet to another.");

    string strFrom = AccountFromValue(params[0]);
    string strTo = AccountFromValue(params[1]);
    int64_t nAmount = AmountFromValue(params[2]);

    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Send amount too small");

    if (params.size() > 3)
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)params[3].get_int();
    string strComment;
    if (params.size() > 4)
        strComment = params[4].get_str();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    if (!walletdb.TxnBegin())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    int64_t nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    walletdb.WriteAccountingEntry(debit);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = pwalletMain->IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    walletdb.WriteAccountingEntry(credit);

    if (!walletdb.TxnCommit())
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

    return true;
}


Value sendfrom(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 7)
        throw runtime_error(
            "sendfrom <fromaccount> <toyacoinaddress> <amount> [useExpiredTimelockUTXO] [minconf=1] [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest " + FormatMoney(MIN_TXOUT_AMOUNT)
            + HelpRequiringPassphrase());

    string strAccount = AccountFromValue(params[0]);
    CBitcoinAddress address(params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address");
    int64_t nAmount = AmountFromValue(params[2]);

    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(-101, "Send amount too small");

    // Allow to use locktime UTXO
    bool useExpiredTimelockUTXO = true;
    if (params.size() > 3 && params[3].type() == bool_type)
        useExpiredTimelockUTXO = params[3].get_bool();

    int nMinDepth = 1;
    if (params.size() > 4)
        nMinDepth = params[4].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 5 && params[5].type() != null_type && !params[5].get_str().empty())
        wtx.mapValue["comment"] = params[5].get_str();
    if (params.size() > 6 && params[6].type() != null_type && !params[6].get_str().empty())
        wtx.mapValue["to"]      = params[6].get_str();

    EnsureWalletIsUnlocked();

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, MINE_SPENDABLE);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx, false, NULL, useExpiredTimelockUTXO);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}


Value sendmany(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 5)
        throw runtime_error(
            "sendmany <fromaccount> {address:amount,...} [useExpiredTimelockUTXO] [minconf=1] [comment]\n"
            "amounts are double-precision floating point numbers"
            + HelpRequiringPassphrase());

    string strAccount = AccountFromValue(params[0]);
    Object sendTo = params[1].get_obj();

    // Allow to use locktime UTXO
    bool useExpiredTimelockUTXO = true;
    if (params.size() > 2 && params[2].type() == bool_type)
        useExpiredTimelockUTXO = params[2].get_bool();

    int nMinDepth = 1;
    if (params.size() > 3)
        nMinDepth = params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["comment"] = params[4].get_str();

    set<CBitcoinAddress> setAddress;
    vector<CRecipient> vecSend;

    int64_t totalAmount = 0;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Yacoin address: ")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        int64_t nAmount = AmountFromValue(s.value_);

        if (nAmount < MIN_TXOUT_AMOUNT)
            throw JSONRPCError(-101, "Send amount too small");

        totalAmount += nAmount;

        CRecipient recipient = {scriptPubKey, nAmount, false};
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked();

    // Check funds
    int64_t nBalance = GetAccountBalance(strAccount, nMinDepth, MINE_SPENDABLE);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwalletMain);
    int64_t nFeeRequired = 0;
    int nChangePosRet = -1;
    std::string strFailReason;
    CCoinControl coinControl;
    bool fCreated = pwalletMain->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason, coinControl, NULL, useExpiredTimelockUTXO);
    if (!fCreated)
    {
        int64_t nTotal = pwalletMain->GetBalance(), nWatchOnly = pwalletMain->GetWatchOnlyBalance();
        if (totalAmount + nFeeRequired > nTotal - nWatchOnly)
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
        throw JSONRPCError(RPC_WALLET_ERROR, std::string("Transaction creation failed: ") + strFailReason);
    }
    if (!pwalletMain->CommitTransaction(wtx, keyChange))
        throw JSONRPCError(RPC_WALLET_ERROR, "Transaction commit failed");

    return wtx.GetHash().GetHex();
}

Value addmultisigaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
    {
        string msg = "addmultisigaddress <nrequired> <'[\"key\",\"key\"]'> [account]\n"
            "Add a nrequired-to-sign multisignature address to the wallet\"\n"
            "each key is a Yacoin address or hex-encoded public key\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    int nRequired = params[0].get_int();
    const Array& keys = params[1].get_array();
    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %" PRIszu " keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    std::vector<CKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();

        // Case 1: Bitcoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks.c_str()));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks.c_str()));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }

        // Case 2: hex public key
        else if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsValid() || !pubkeys[i].SetPubKey(vchPubKey))
                throw runtime_error(" Invalid public key: "+ks);
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner;
    inner.SetMultisig(nRequired, pubkeys);

    if (inner.size() > MAX_SCRIPT_ELEMENT_SIZE)
    throw runtime_error(
        strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), MAX_SCRIPT_ELEMENT_SIZE));

    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return CBitcoinAddress(innerID).ToString();
}

Value describeredeemscript(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1)
    {
        string msg = "describeredeemscript <redeemScript>\n"
            "Parse redeem script and give more information\n";
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    vector<unsigned char> innerData = ParseHexV(params[0], "redeemScript");
    CScript redeemScript(innerData.begin(), innerData.end());

    // Check if it is CLTV/CSV redeemscript
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(redeemScript, whichType, vSolutions))
    {
        string msg = "This is non-standard redeemscript\n";
        throw runtime_error(msg);
    }

    if (whichType != TX_CLTV_P2SH && whichType != TX_CSV_P2SH)
    {
        string msg = "This is not CLTV/CSV redeemscript\n";
        throw runtime_error(msg);
    }

    // Parse redeemscript
    Object output;
    LockTimeRedeemScriptToJSON(redeemScript, whichType, output);

    return output;
}

Value spendcltv(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
    {
	    string msg = "spendcltv <cltv_address> <destination_address> <amount> [comment] [comment-to]\n"
            "send coin from cltv address to another address\n";
        throw runtime_error(msg);
    }

    // Check if cltv address exist in the wallet
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    CScript scriptPubKey;
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid cltv address");
    scriptPubKey.SetDestination(address.Get());
    if (!IsMine(*pwalletMain,scriptPubKey))
    	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wallet doesn't manage coins in this address");

    // Get redeemscript
    CTxDestination tmpAddr;
    CScript redeemScript;
    if (ExtractDestination(scriptPubKey, tmpAddr))
    {
        const CScriptID& hash = boost::get<CScriptID>(tmpAddr);
        if (!pwalletMain->GetCScript(hash, redeemScript))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wallet doesn't manage redeemscript of this address");
    }

    // Scan information from redeemscript to get lock time
    CScript::const_iterator pc = redeemScript.begin();
    opcodetype opcode;
    vector<unsigned char> vch;
    if (!redeemScript.GetOp(pc, opcode, vch))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wallet can't get lock time from redeemscript");
    const CScriptNum nLockTime(vch);

    // Check if destination address is valid
    CBitcoinAddress destAddress(params[1].get_str());
    if (!destAddress.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destination address");

    // Check if number coins in cltv address is enough to spend
    int64_t nAmount = AmountFromValue(params[2]);
    int64_t nTotalValue = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
            	nTotalValue += txout.nValue;
    }

    if (nTotalValue < nAmount)
    	throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not enough coin in the wallet to spend");

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["to"]      = params[4].get_str();

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = pwalletMain->SendMoneyToDestination(destAddress.Get(), nAmount, wtx, false, &scriptPubKey);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

Value spendcsv(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 3 || params.size() > 5)
    {
        string msg = "spendcsv <cltv_address> <destination_address> <amount> [comment] [comment-to]\n"
            "send coin from csv address to another address\n"
            "<csv_address>: required param. csv address containing locked coins. This address is created by \"createcsvaddress\" rpc command\n"
            "<destination_address>: required param. Coins will be sent to this address\n"
            "<amount>: required param. Number coins will be sent to <destination_address>. It excludes the transaction fee, so that it must be smaller"
                    " than number of locked coins in csv address. The remaining coins (= locked coins - <amount> - transaction fee) will be sent to a newly"
                    " generated address which manages by wallet (same behaviour as \"sendtoaddress\" rpc command)\n"
            "[comment], [comment-to]: optional param. Wallet comments\n";
        throw runtime_error(msg);
    }

    // Check if csv address exist in the wallet
    CBitcoinAddress address = CBitcoinAddress(params[0].get_str());
    CScript scriptPubKey;
    if (!address.IsValid())
        throw runtime_error("Invalid csv address");
    scriptPubKey.SetDestination(address.Get());
    if (!IsMine(*pwalletMain,scriptPubKey))
        throw runtime_error("Wallet doesn't manage coins in this address");

    // Check if destination address is valid
    CBitcoinAddress destAddress(params[1].get_str());
    if (!destAddress.IsValid())
        throw runtime_error("Invalid destination address");

    // Check if number coins in csv address is enough to spend
    int64_t nAmount = AmountFromValue(params[2]);
    int64_t nTotalValue = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal())
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            if (txout.scriptPubKey == scriptPubKey)
                nTotalValue += txout.nValue;
    }

    if (nTotalValue < nAmount)
        throw runtime_error("Not enough coin in the wallet to spend");

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["comment"] = params[3].get_str();
    if (params.size() > 4 && params[4].type() != null_type && !params[4].get_str().empty())
        wtx.mapValue["to"]      = params[4].get_str();

    if (pwalletMain->IsLocked())
        throw runtime_error("Error: Please enter the wallet passphrase with walletpassphrase first.");

    string strError = pwalletMain->SendMoneyToDestination(destAddress.Get(), nAmount, wtx, false, &scriptPubKey);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return wtx.GetHash().GetHex();
}

Value createcltvaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        string msg = "createcltvaddress <lock_time> [account]\n"
            "Create a P2SH address which lock coins until lock_time\n";
        throw runtime_error(msg);
    }

    // Generate a new key that is added to wallet
    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    CPubKey pubkey;
    if (!pwalletMain->GetKeyFromPool(pubkey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    // Get lock time
    uint32_t nLockTime = params[0].get_int64();

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Construct using pay-to-script-hash:
    CScript inner;
    inner.SetCltvP2SH(nLockTime, pubkey);

    if (inner.size() > MAX_SCRIPT_ELEMENT_SIZE)
    throw runtime_error(
        strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), MAX_SCRIPT_ELEMENT_SIZE));

    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    CBitcoinAddress address(innerID);

    std::string warnMsg = "Any coins sent to this cltv address will be locked until ";
    if (nLockTime < LOCKTIME_THRESHOLD)
    {
        std::stringstream ss;
        ss << nLockTime;
        warnMsg += "block height " + ss.str();
    }
    else
        warnMsg += DateTimeStrFormat(nLockTime);
    Object result;
    result.push_back(Pair("cltv address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));
    result.push_back(Pair("Warning", warnMsg));

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return result;
}

Value createcsvaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
    {
        string msg = "createcsvaddress <lock_time> [isBlockHeightLock] [account]\n"
            "Create a P2SH address which lock coins within a number of blocks/seconds\n"
            "<lock_time>: required param. Specify time in seconds or number of blocks which coins will be locked within. Valid range 1->1073741823\n"
            "[isBlockHeightLock]: optional true/false param. Determine <lock_time> is number of blocks or seconds. By default isBlockHeightLock=false\n"
            "[account]: optional param. Account name corresponds to csv address\n";
        throw runtime_error(msg);
    }

    // Generate a new key that is added to wallet
    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    CPubKey pubkey;
    if (!pwalletMain->GetKeyFromPool(pubkey, false))
        throw runtime_error("Error: Keypool ran out, please call keypoolrefill first");

    // Get lock time
    ::uint32_t nLockTime = params[0].get_int64();
    if (nLockTime < 1 || nLockTime > CTxIn::SEQUENCE_LOCKTIME_MASK)
        throw runtime_error("<lock_time> must be between 1 and 1073741823");

    bool fBlockHeightLock = false;
    if (params.size() > 1)
        fBlockHeightLock = params[1].get_bool();

    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    // Construct using pay-to-script-hash:
    CScript inner;
    ::uint32_t nSequence = fBlockHeightLock? nLockTime: (nLockTime | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG);
    inner.SetCsvP2SH(nSequence, pubkey);

    if (inner.size() > MAX_SCRIPT_ELEMENT_SIZE)
    throw runtime_error(
        strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", inner.size(), MAX_SCRIPT_ELEMENT_SIZE));

    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    CBitcoinAddress address(innerID);

    std::string warnMsg = "Any coins sent to this csv address will be locked ";
    if (fBlockHeightLock)
    {
        std::stringstream ss;
        ss << nLockTime;
        warnMsg += "within " + ss.str() + " blocks";
    }
    else
    {
        std::stringstream ss;
        ss << (nLockTime * (1 << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY));
        warnMsg += "for a period of " + ss.str() + " seconds";
    }
    Object result;
    result.push_back(Pair("csv address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));
    result.push_back(Pair("Warning", warnMsg));

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return result;
}

Value timelockcoins(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 5)
    {
        throw runtime_error(
            "timelockcoins <amount> <lock_time> [isRelativeTimelock] [isBlockHeightLock] [to_address]\n"
            "\nTimelocks an amount of coins within a number of blocks/seconds (relative timelock) or until a specific block/time (absolute timelock)\n"

            "\nArguments:\n"
            "1. \"amount\"                (numeric, required) Number of YAC you want to timelock\n"
            "2. \"lock_time\"             (integer, required) The meaning of lock_time depends on isRelativeTimelock, isBlockHeightLock and the value itself\n"
            "                                                 If isRelativeTimelock = true: Specify time in seconds (isBlockHeightLock = false) or number of blocks (isBlockHeightLock = true) which coins will be locked within. Valid range 1->1073741823\n"
            "                                                 If isRelativeTimelock = false: Specify specific time (lock_time >= 500000000) or a specific block number (lock_time < 500000000) which coins will be locked until. Valid range 1->4294967295\n"
            "3. \"isRelativeTimelock\"    (boolean, optional, default=true), Whether it is relative or absolute timelock\n"
            "4. \"isBlockHeightLock\"     (boolean, optional, default=true), Whether <lock_time> is in units of block or time (in seconds)\n"
            "                                                                This argument is only used in case isRelativeTimelock = true\n"
            "5. \"to_address\"            (string), optional, default=\"\"), Address contains the timelocked coins, if it is empty, address will be generated for you\n"

            "\nResult:\n"
            "\"txid\"                     (string) The transaction id\n"

            "\nExamples:\n"
            "Lock 1000 YAC within 21000 blocks: timelockcoins 1000 21000\n"
            "Lock 1000 YAC within 600 seconds: timelockcoins 1000 600 true false\n"
            "Lock 1000 YAC until block height = 1990000: timelockcoins 1000 1990000 false\n"
            "Lock 1000 YAC until Tuesday, March 4, 2025 12:00:00 AM UTC: 1000 1741046400 false false\n"
            "Lock 1000 YAC within 21000 blocks at address YCk26dUcaXu8vu6zG3E2PrbBeECAV8RNFp: timelockcoins 1000 21000 true true YCk26dUcaXu8vu6zG3E2PrbBeECAV8RNFp\n"
        );
    }

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");

    // Amount
    CAmount nAmount = AmountFromValue(params[0]);
    if (nAmount < MIN_TXOUT_AMOUNT)
        throw JSONRPCError(RPC_TYPE_ERROR, "Lock amount too small");

    // isRelativeTimelock
    bool isRelativeTimelock = true;
    if (params.size() > 2)
        isRelativeTimelock = params[2].get_bool();

    // isBlockHeightLock
    bool isBlockHeightLock = true;
    if (params.size() > 3)
        isBlockHeightLock = params[3].get_bool();

    // Get lock time
    int64_t nLockTime = params[1].get_int64();
    if (isRelativeTimelock && (nLockTime < 1 || nLockTime > CTxIn::SEQUENCE_LOCKTIME_MASK))
        throw JSONRPCError(RPC_INVALID_PARAMS, std::string("For relative timelock, <lock_time> must be in range of 1->1073741823"));
    else if (!isRelativeTimelock && (nLockTime < 1 || nLockTime > std::numeric_limits<uint32_t>::max()))
        throw JSONRPCError(RPC_INVALID_PARAMS, std::string("For absolute timelock, <lock_time> must be in range of 1->4294967295"));

    // to_address
    std::string address = "";
    if (params.size() > 4)
        address = params[4].get_str();
    CKeyID keyID;

    if (!address.empty()) {
        CTxDestination destination = DecodeDestination(address);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Yacoin address: ") + address);
        }
        keyID = boost::get<CKeyID>(destination);
    } else {
        // Create a new address
        std::string strAccount;

        if (!pwalletMain->IsLocked()) {
            pwalletMain->TopUpKeyPool();
        }

        // Generate a new key that is added to wallet
        CPubKey newKey;
        if (!pwalletMain->GetKeyFromPool(newKey)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
        }
        keyID = newKey.GetID();

        pwalletMain->SetAddressBookName(keyID, strAccount);

        address = EncodeDestination(keyID);
    }

    // Create timelock script
    CScript timeLockScriptPubKey;
    if (isRelativeTimelock)
    {
        ::uint32_t nSequence = isBlockHeightLock? nLockTime: (nLockTime | CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG);
        timeLockScriptPubKey.SetCsvP2PKH(nSequence, keyID);
    }
    else
    {
        timeLockScriptPubKey.SetCltvP2PKH(::uint32_t(nLockTime), keyID);
    }

    if (timeLockScriptPubKey.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw runtime_error(
            strprintf("redeemScript exceeds size limit: %" PRIszu " > %d", timeLockScriptPubKey.size(), MAX_SCRIPT_ELEMENT_SIZE));

    Object result;

    // Create transaction
    CWalletTx wtx;
    string strError = pwalletMain->SendMoney(timeLockScriptPubKey, nAmount, wtx, false, NULL, true);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    // Output the message
    std::stringstream ss;
    if (isRelativeTimelock)
    {
        ss << ValueFromAmountStr(nAmount) << " YAC are now locked. These coins will be locked ";
        if (isBlockHeightLock)
        {
            ss << "within " << nLockTime << " blocks";
        }
        else
        {
            ss << "for a period of " << (nLockTime * (1 << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY)) << " seconds";
        }
    }
    else
    {
        ss << ValueFromAmountStr(nAmount) << " YAC are now locked. These coins will be locked until ";
        if (nLockTime < LOCKTIME_THRESHOLD)
        {
            ss << "block height " << nLockTime;
        }
        else
        {
            ss << DateTimeStrFormat(nLockTime);
        }
    }
    result.push_back(Pair("message", ss.str()));
    result.push_back(Pair("address_containing_timelocked_coins", address));
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));

    return result;
}

Value addredeemscript(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
    {
        string msg = "addredeemscript <redeemScript> [account]\n"
            "Add a P2SH address with a specified redeemScript to the wallet.\n"
            "If [account] is specified, assign address to [account].";
        throw runtime_error(msg);
    }

    string strAccount;
    if (params.size() > 1)
        strAccount = AccountFromValue(params[1]);

    // Construct using pay-to-script-hash:
    vector<unsigned char> innerData = ParseHexV(params[0], "redeemScript");
    CScript inner(innerData.begin(), innerData.end());
    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return CBitcoinAddress(innerID).ToString();
}

struct tallyitem
{
    int64_t nAmount;
    int nConf;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
    }
};

Value ListReceived(const Array& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (params.size() > 1)
        fIncludeEmpty = params[1].get_bool();

    // Tally
    map<CBitcoinAddress, tallyitem> mapTally;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;

        if (wtx.IsCoinBase() || wtx.IsCoinStake() || !wtx.IsFinal())
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address) || !IsMine(*pwalletMain, address))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = min(item.nConf, nDepth);
        }
    }

    // Reply
    Array ret;
    map<string, tallyitem> mapAccountTally;
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const string& strAccount = item.second;
        map<CBitcoinAddress, tallyitem>::iterator it = mapTally.find(address);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        int64_t nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
        }

        if (fByAccounts)
        {
            tallyitem& item = mapAccountTally[strAccount];
            item.nAmount += nAmount;
            item.nConf = min(item.nConf, nConf);
        }
        else
        {
            Object obj;
            obj.push_back(Pair("address",       address.ToString()));
            obj.push_back(Pair("account",       strAccount));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (map<string, tallyitem>::iterator it = mapAccountTally.begin(); it != mapAccountTally.end(); ++it)
        {
            int64_t nAmount = (*it).second.nAmount;
            int nConf = (*it).second.nConf;
            Object obj;
            obj.push_back(Pair("account",       (*it).first));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

Value listreceivedbyaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaddress [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include addresses that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"address\" : receiving address\n"
            "  \"account\" : the account of the receiving address\n"
            "  \"amount\" : total amount received by the address\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, false);
}

Value listreceivedbyaccount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listreceivedbyaccount [minconf=1] [includeempty=false]\n"
            "[minconf] is the minimum number of confirmations before payments are included.\n"
            "[includeempty] whether to include accounts that haven't received any payments.\n"
            "Returns an array of objects containing:\n"
            "  \"account\" : the account of the receiving addresses\n"
            "  \"amount\" : total amount received by addresses with this account\n"
            "  \"confirmations\" : number of confirmations of the most recent transaction included");

    return ListReceived(params, true);
}

static void MaybePushAddress(Object & entry, const CTxDestination &dest)
{
    CBitcoinAddress addr;
    if (addr.Set(dest))
        entry.push_back(Pair("address", addr.ToString()));
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret, Array& retTokens, const isminefilter& filter)
{
    int64_t nGeneratedImmature, nGeneratedMature, nFee;
    string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    std::list<CTokenOutputEntry> listTokensReceived;
    std::list<CTokenOutputEntry> listTokensSent;

    wtx.GetAmounts(nGeneratedImmature, nGeneratedMature, listReceived, listSent, nFee, strSentAccount, filter, listTokensReceived, listTokensSent);

    bool fAllAccounts = (strAccount == string("*"));
    bool involvesWatchonly = wtx.IsFromMe(MINE_WATCH_ONLY);

    // Generated blocks assigned to account ""
    if ((nGeneratedMature+nGeneratedImmature) != 0 && (fAllAccounts || strAccount == ""))
    {
        Object entry;
        entry.push_back(Pair("account", string("")));
        if (nGeneratedImmature)
        {
            entry.push_back(Pair("category", wtx.GetDepthInMainChain() ? "immature" : "orphan"));
            entry.push_back(Pair("amount", ValueFromAmount(nGeneratedImmature)));
        }
        else
        {
            entry.push_back(Pair("category", "generate"));
            entry.push_back(Pair("amount", ValueFromAmount(nGeneratedMature)));
        }
        if (fLong)
            WalletTxToJSON(wtx, entry);
        ret.push_back(entry);
    }

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        for (const COutputEntry& s : listSent)
        {
            Object entry;
            entry.push_back(Pair("account", strSentAccount));
            if(involvesWatchonly || (::IsMine(*pwalletMain, s.destination) & MINE_WATCH_ONLY))
                entry.push_back(Pair("involvesWatchonly", true));
            MaybePushAddress(entry, s.destination);

            if (wtx.GetDepthInMainChain() < 0) {
                entry.push_back(Pair("category", "conflicted"));
            } else {
                entry.push_back(Pair("category", "send"));
            }

            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        for (const COutputEntry& r : listReceived)
        {
            string account;
            if (pwalletMain->mapAddressBook.count(r.destination))
                account = pwalletMain->mapAddressBook[r.destination];
            if (fAllAccounts || (account == strAccount))
            {
                Object entry;
                entry.push_back(Pair("account", account));
                if(involvesWatchonly || (::IsMine(*pwalletMain, r.destination) & MINE_WATCH_ONLY))
                    entry.push_back(Pair("involvesWatchonly", true));
                MaybePushAddress(entry, r.destination);
                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                }
                else
                    entry.push_back(Pair("category", "receive"));
                entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }

    /** YAC_TOKEN START */
    if (AreTokensDeployed()) {
        if (listTokensReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth) {
            for (const CTokenOutputEntry &data : listTokensReceived){
                Object entry;

                if (involvesWatchonly || (::IsMine(*pwalletMain, data.destination) & MINE_WATCH_ONLY)) {
                    entry.push_back(Pair("involvesWatchonly", true));
                }

                ETokenType tokenType;
                std::string tokenError = "";
                if (!IsTokenNameValid(data.tokenName, tokenType, tokenError)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid token name: ") + data.tokenName + std::string("\nError: ") + tokenError);
                }

                entry.push_back(Pair("token_operation", GetTxnOutputType(data.type)));
                entry.push_back(Pair("token_name", data.tokenName));
                entry.push_back(Pair("token_type", ETokenTypeToString(tokenType)));
                entry.push_back(Pair("amount", TokenValueFromAmount(data.nAmount, data.tokenName)));
                MaybePushAddress(entry, data.destination);
                entry.push_back(Pair("vout", data.vout));
                entry.push_back(Pair("category", "receive"));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                retTokens.push_back(entry);
            }
        }

        if ((!listTokensSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount)) {
            for (const CTokenOutputEntry &data : listTokensSent) {
                Object entry;

                if (involvesWatchonly || (::IsMine(*pwalletMain, data.destination) & MINE_WATCH_ONLY)) {
                    entry.push_back(Pair("involvesWatchonly", true));
                }

                entry.push_back(Pair("token_type", GetTxnOutputType(data.type)));
                entry.push_back(Pair("token_name", data.tokenName));
                entry.push_back(Pair("amount", TokenValueFromAmount(data.nAmount, data.tokenName)));
                MaybePushAddress(entry, data.destination);
                entry.push_back(Pair("vout", data.vout));
                entry.push_back(Pair("category", "send"));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                retTokens.push_back(entry);
            }
        }
    }
    /** YAC_TOKEN END */
}

void ListTransactions(const CWalletTx& wtx, const string& strAccount, int nMinDepth, bool fLong, Array& ret, const isminefilter& filter)
{
    Array tokenDetails;
    ListTransactions(wtx, strAccount, nMinDepth, fLong, ret, tokenDetails, filter);
}

void AcentryToJSON(const CAccountingEntry& acentry, const string& strAccount, Array& ret)
{
    bool fAllAccounts = (strAccount == string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        Object entry;
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", (boost::int64_t)acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

Value listtransactions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listtransactions [account] [count=10] [from=0]\n"
            "Returns up to [count] most recent transactions skipping the first [from] transactions for account [account].");

    string strAccount = "*";
    if (params.size() > 0)
        strAccount = params[0].get_str();
    int nCount = 10;
    if (params.size() > 1)
        nCount = params[1].get_int();
    int nFrom = 0;
    if (params.size() > 2)
        nFrom = params[2].get_int();

    isminefilter filter = MINE_SPENDABLE;
    if(params.size() > 3)
        if(params[3].get_bool())
            filter = filter | MINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    Array ret;

    std::list<CAccountingEntry> acentries;
    CWallet::TxItems txOrdered = pwalletMain->OrderedTxItems(acentries, strAccount);

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
            ListTransactions(*pwtx, strAccount, 0, true, ret, filter);
        CAccountingEntry *const pacentry = (*it).second.second;
        if (pacentry != 0)
            AcentryToJSON(*pacentry, strAccount, ret);

        if ((int)ret.size() >= (nCount+nFrom)) break;
    }
    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;
    Array::iterator first = ret.begin();
    std::advance(first, nFrom);
    Array::iterator last = ret.begin();
    std::advance(last, nFrom+nCount);

    if (last != ret.end()) ret.erase(last, ret.end());
    if (first != ret.begin()) ret.erase(ret.begin(), first);

    std::reverse(ret.begin(), ret.end()); // Return oldest to newest

    return ret;
}

Value listaccounts(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "listaccounts [minconf=1]\n"
            "Returns Object that has account names as keys, account balances as values.");

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    isminefilter 
        includeWatchonly = MINE_SPENDABLE;

    if(params.size() > 1)
    {
        bool
            fTemp = params[1].get_bool();
        if(fTemp)
        {
          //includeWatchonly = includeWatchonly | MINE_WATCH_ONLY;
            includeWatchonly |= MINE_WATCH_ONLY;
        }
    }

    map<string, int64_t> 
        mapAccountBalances;

    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook) 
    {
        if (IsMine(*pwalletMain, entry.first)) // This address belongs to me
            mapAccountBalances[entry.second] = 0;
    }

    for (
        map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); 
        it != pwalletMain->mapWallet.end();
        ++it
        )
    {
        const CWalletTx& 
            wtx = (*it).second;

        int64_t 
            nGeneratedImmature, 
            nGeneratedMature, nFee;

        string 
            strSentAccount;

        std::list<COutputEntry> listReceived;

        std::list<COutputEntry> listSent;

        wtx.GetAmounts(
                        nGeneratedImmature, 
                        nGeneratedMature, 
                        listReceived, 
                        listSent, 
                        nFee, 
                        strSentAccount, 
                        includeWatchonly
                       );

        mapAccountBalances[strSentAccount] -= nFee;
        for (const COutputEntry& s : listSent)
        {
            mapAccountBalances[strSentAccount] -= s.amount;
        }
        if (wtx.GetDepthInMainChain() >= nMinDepth)
        {
            mapAccountBalances[""] += nGeneratedMature;
            for (const COutputEntry& r : listReceived)
            {
                if (pwalletMain->mapAddressBook.count(r.destination))
                    mapAccountBalances[pwalletMain->mapAddressBook[r.destination]] += r.amount;
                else
                    mapAccountBalances[""] += r.amount;            }
        }
    }

    list<CAccountingEntry> 
        acentries;

    CWalletDB(pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
    for (const CAccountingEntry& entry : acentries)
    {
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;
    }

    Object 
        ret;

    for (const PAIRTYPE(string, int64_t)& accountBalance : mapAccountBalances)
    {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));

    }
    return ret;
}

Value listsinceblock(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "listsinceblock [blockhash] [target-confirmations]\n"
            "Get all transactions in blocks since block [blockhash], or all transactions if omitted");

    CBlockIndex 
        *pindex = NULL;
    int 
        target_confirms = 1;
    isminefilter 
        filter = MINE_SPENDABLE;

    if (params.size() > 0)
    {
        uint256 
            blockId = 0;

        blockId.SetHex(params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it != mapBlockIndex.end())
            pindex = it->second;
    }

    if (params.size() > 1)
    {
        target_confirms = params[1].get_int();

        if (target_confirms < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
    }

    if(params.size() > 2)
        if(params[2].get_bool())
            filter = filter | MINE_WATCH_ONLY;

    int 
        depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    Array 
        transactions;

    for (
        map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); 
        it != pwalletMain->mapWallet.end(); 
        ++it
        )
    {
        CWalletTx 
            tx = (*it).second;

        if (
            (-1 == depth) || 
            (tx.GetDepthInMainChain() < depth)
           )
            ListTransactions(tx, "*", 0, true, transactions, filter);
    }

    uint256 
        lastblock;

    if (1 == target_confirms)
    {
        lastblock = hashBestChain;
    }
    else
    {
        int 
            target_height = chainActive.Tip()->nHeight + 1 - target_confirms;

        CBlockIndex 
            *block;
        for (block = chainActive.Tip();
             block && block->nHeight > target_height;
             block = block->pprev
            )  
        { 
        }
        lastblock = block ? block->GetBlockHash() : 0;
    }
    Object 
        ret;
    ret.push_back(Pair("transactions", transactions));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));
    return ret;
}

Value gettransaction(const Array& params, bool fHelp)
{
    if (
        fHelp || 
        (params.size() < 1) ||
        (params.size() > 2)
       )
        throw runtime_error(
            "gettransaction <txid>\n"
            "Get detailed information about <txid>");

    uint256 hash;
    hash.SetHex(params[0].get_str());

    isminefilter 
        filter = MINE_SPENDABLE;

    if(params.size() > 1)
        if(params[1].get_bool())
            filter = filter | MINE_WATCH_ONLY;

    Object entry;

    if (pwalletMain->mapWallet.count(hash))
    {
        const CWalletTx& wtx = pwalletMain->mapWallet[hash];

        TxToJSON(wtx, 0, entry);

        int64_t nCredit = wtx.GetCredit(filter);
        int64_t nDebit = wtx.GetDebit(filter);
        int64_t nNet = nCredit - nDebit;
        int64_t nFee = (wtx.IsFromMe(filter) ? wtx.GetValueOut() - nDebit : 0);

        entry.push_back(Pair("Credit", ValueFromAmount(nCredit)));
        entry.push_back(Pair("Debit", ValueFromAmount(nDebit)));
        entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
        if (wtx.IsFromMe(filter))
            entry.push_back(Pair("fee", ValueFromAmount(nFee)));

        WalletTxToJSON(wtx, entry);

        Array details;
        Array tokenDetails;
        ListTransactions(pwalletMain->mapWallet[hash], "*", 0, false, details, tokenDetails, filter);
        entry.push_back(Pair("details", details));
        entry.push_back(Pair("token_details", tokenDetails));
    }
    else
    {
        CTransaction tx;
        uint256 hashBlock = 0;
        if (GetTransaction(hash, tx, hashBlock))
        {
            TxToJSON(tx, 0, entry);
            if (hashBlock == 0)
                entry.push_back(Pair("confirmations", 0));
            else
            {
                entry.push_back(Pair("blockhash", hashBlock.GetHex()));
                BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
                if (mi != mapBlockIndex.end() && (*mi).second)
                {
                    CBlockIndex* pindex = (*mi).second;
                    if (pindex->IsInMainChain())
                        entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                    else
                        entry.push_back(Pair("confirmations", 0));
                }
            }
        }
        else
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    }

    return entry;
}


Value backupwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "backupwallet <destination>\n"
            "Safely copies wallet.dat to destination, which can be a directory or a path with filename.");

    string strDest = params[0].get_str();
    if (!BackupWallet(*pwalletMain, strDest))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");

    return Value::null;
}


Value keypoolrefill(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "keypoolrefill [new-size]\n"
            "Fills the keypool.\n"
            "IMPORTANT: Any previous backups you have made of your wallet file "
            "should be replaced with the newly generated one."
            + HelpRequiringPassphrase());

    unsigned int nSize = max<unsigned int>(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), 0);
    if (params.size() > 0) {
        if (params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size");
        nSize = (unsigned int) params[0].get_int();
    }

    EnsureWalletIsUnlocked();

    pwalletMain->TopUpKeyPool(nSize);

    if (pwalletMain->GetKeyPoolSize() < nSize)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return Value::null;
}

Value keypoolreset(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "keypoolreset [new-size]\n"
            "Resets the keypool.\n"
            "IMPORTANT: Any previous backups you have made of your wallet file "
            "should be replaced with the newly generated one."
            + HelpRequiringPassphrase());

    unsigned int nSize = max<unsigned int>(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), 0);
    if (params.size() > 0) {
        if (params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size");
        nSize = (unsigned int) params[0].get_int();
    }

    EnsureWalletIsUnlocked();

    pwalletMain->NewKeyPool(nSize);

    if (pwalletMain->GetKeyPoolSize() < nSize)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");

    return Value::null;
}


void ThreadTopUpKeyPool(void* parg)
{
    // Make this thread recognisable as the key-topping-up thread
    RenameThread("yacoin-key-top");

    pwalletMain->TopUpKeyPool();
}

void ThreadCleanWalletPassphrase(void* parg)
{
    // Make this thread recognisable as the wallet relocking thread
    RenameThread("yacoin-lock-wa");

    int64_t nMyWakeTime = GetTimeMillis() + *((int64_t*)parg) * 1000;

    ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

    if (nWalletUnlockTime == 0)
    {
        nWalletUnlockTime = nMyWakeTime;

        do
        {
            if (nWalletUnlockTime==0)
                break;
            int64_t nToSleep = nWalletUnlockTime - GetTimeMillis();
            if (nToSleep <= 0)
                break;

            LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);
            Sleep(nToSleep);
            ENTER_CRITICAL_SECTION(cs_nWalletUnlockTime);

        } while( true );

        if (nWalletUnlockTime)
        {
            nWalletUnlockTime = 0;
            pwalletMain->Lock();
        }
    }
    else
    {
        if (nWalletUnlockTime < nMyWakeTime)
            nWalletUnlockTime = nMyWakeTime;
    }

    LEAVE_CRITICAL_SECTION(cs_nWalletUnlockTime);

    delete (int64_t*)parg;
}

Value walletpassphrase(const Array& params, bool fHelp)
{
    if (
        fHelp ||    // otherwise this doesn't showup in help!
        (
         pwalletMain->IsCrypted() && 
         (fHelp || params.size() < 2 || params.size() > 3)
        )
       )
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout> [mintonly]\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.\n"
            "mintonly is optional true/false allowing only block minting.");
    //if (fHelp)    // this is not needed now
    //    return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");

    if (!pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_ALREADY_UNLOCKED, "Error: Wallet is already unlocked, use walletlock first if need to change unlock settings.");
    // Note that the walletpassphrase is stored in params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() > 0)
    {
        if (!pwalletMain->Unlock(strWalletPass))
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }
    else
        throw runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    NewThread(ThreadTopUpKeyPool, NULL);
    int64_t* pnSleepTime = new int64_t(params[1].get_int64());
    NewThread(ThreadCleanWalletPassphrase, pnSleepTime);

    // ppcoin: if user OS account compromised prevent trivial sendmoney commands
    if (params.size() > 2)
        fWalletUnlockMintOnly = params[2].get_bool();
    else
        fWalletUnlockMintOnly = false;

    return Value::null;
}


Value walletpassphrasechange(const Array& params, bool fHelp)
{
    if (
        fHelp ||    // otherwise this doesn't showup in help!
        (
         pwalletMain->IsCrypted() && 
         (fHelp || params.size() != 2)
        )
       )
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");
    //if (fHelp)
    //    return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwalletMain->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass))
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");

    return Value::null;
}


Value walletlock(const Array& params, bool fHelp)
{
    if (
        fHelp ||    // otherwise this doesn't showup in help!
        (
         pwalletMain->IsCrypted() && 
         (fHelp || params.size() != 0)
        )
       )
        throw runtime_error(
            "walletlock\n"
            "Removes the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.");
    //if (fHelp)
    //    return true;
    if (!pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");

    {
        LOCK(cs_nWalletUnlockTime);
        pwalletMain->Lock();
        nWalletUnlockTime = 0;
    }

    return Value::null;
}


Value encryptwallet(const Array& params, bool fHelp)
{
    if (
        fHelp ||    // otherwise this doesn't showup in help!
        (
         !pwalletMain->IsCrypted() && 
         (fHelp || params.size() != 1)
        )
       )
         throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");
    //if (fHelp)
    //    return true;
    if (pwalletMain->IsCrypted())
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwalletMain->EncryptWallet(strWalletPass))
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; Yacoin server stopping, restart to run with encrypted wallet.  The keypool has been flushed, you need to make a new backup.";
}

class DescribeAddressVisitor : public boost::static_visitor<Object>
{
private:
    isminetype mine;
public:
    DescribeAddressVisitor(isminetype mineIn) : mine(mineIn) {}

    Object operator()(const CNoDestination &dest) const { return Object(); }
    Object operator()(const CKeyID &keyID) const {
        Object obj;
        CPubKey vchPubKey;
        pwalletMain->GetPubKey(keyID, vchPubKey);
        obj.push_back(Pair("isscript", false));
        if (mine == MINE_SPENDABLE) {
            pwalletMain->GetPubKey(keyID, vchPubKey);
            obj.push_back(Pair("pubkey", HexStr(vchPubKey.Raw())));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    Object operator()(const CScriptID &scriptID) const {
        Object obj;
        obj.push_back(Pair("isscript", true));
        if (mine == MINE_SPENDABLE) {
            CScript subscript;
            pwalletMain->GetCScript(scriptID, subscript);
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(Pair("script", GetTxnOutputType(whichType)));
            obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
            Array a;
            BOOST_FOREACH(const CTxDestination& addr, addresses)
                a.push_back(CBitcoinAddress(addr).ToString());
            obj.push_back(Pair("addresses", a));
            if (whichType == TX_MULTISIG)
                obj.push_back(Pair("sigsrequired", nRequired));
        }
        return obj;
    }
};

Value validateaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress <yacoinaddress>\n"
            "Return information about <yacoinaddress>.");

    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    Object ret;
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : MINE_NO;
        ret.push_back(Pair("ismine", mine != MINE_NO));
        if (mine != MINE_NO) {
            ret.push_back(Pair("watchonly", mine == MINE_WATCH_ONLY));
            Object detail = boost::apply_visitor(DescribeAddressVisitor(mine), dest);
            ret.insert(ret.end(), detail.begin(), detail.end());
        }
        if (pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest]));
    }
    return ret;
}

// ppcoin: reserve balance from being staked for network protection
Value reservebalance(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "reservebalance [<reserve> [amount]]\n"
            "<reserve> is true or false to turn balance reserve on or off.\n"
            "<amount> is a real and rounded to cent.\n"
            "Set reserve amount not participating in network protection.\n"
            "If no parameters provided current setting is printed.\n");

    if (params.size() > 0)
    {
        bool fReserve = params[0].get_bool();
        if (fReserve)
        {
            if (params.size() == 1)
                throw runtime_error("must provide amount to reserve balance.\n");
            int64_t nAmount = AmountFromValue(params[1]);
            nAmount = (nAmount / CENT) * CENT;  // round to cent
            if (nAmount < 0)
                throw runtime_error("amount cannot be negative.\n");
            gArgs.ForceSetArg("-reservebalance", FormatMoney(nAmount));
        }
        else
        {
            if (params.size() > 1)
                throw runtime_error("cannot specify amount to turn off reserve.\n");
            gArgs.ForceSetArg("-reservebalance", "0");
        }
    }

    Object result;
    int64_t nReserveBalance = 0;
    if (gArgs.IsArgSet("-reservebalance") && !ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
        throw runtime_error("invalid reserve balance amount\n");
    result.push_back(Pair("reserve", (nReserveBalance > 0)));
    result.push_back(Pair("amount", ValueFromAmount(nReserveBalance)));
    return result;
}


// ppcoin: check wallet integrity
Value checkwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "checkwallet\n"
            "Check wallet for integrity.\n");

    int nMismatchSpent;
    int64_t nBalanceInQuestion;
    pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion, true);
    Object result;
    if (nMismatchSpent == 0)
        result.push_back(Pair("wallet check passed", true));
    else
    {
        result.push_back(Pair("mismatched spent coins", nMismatchSpent));
        result.push_back(Pair("amount in question", ValueFromAmount(nBalanceInQuestion)));
    }
    return result;
}


// ppcoin: repair wallet
Value repairwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw runtime_error(
            "repairwallet\n"
            "Repair wallet if checkwallet reports any problem.\n");

    int nMismatchSpent;
    int64_t nBalanceInQuestion;
    pwalletMain->FixSpentCoins(nMismatchSpent, nBalanceInQuestion);
    Object result;
    if (nMismatchSpent == 0)
        result.push_back(Pair("wallet check passed", true));
    else
    {
        result.push_back(Pair("mismatched spent coins", nMismatchSpent));
        result.push_back(Pair("amount affected by repair", ValueFromAmount(nBalanceInQuestion)));
    }
    return result;
}

// Yacoin: resend unconfirmed wallet transactions
Value resendtx(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "resendtx\n"
            "Re-send unconfirmed transactions.\n"
        );

    ResendWalletTransactions();

    return Value::null;
}

// ppcoin: make a public-private key pair
Value makekeypair(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "makekeypair [prefix]\n"
            "Make a public/private key pair.\n"
            "[prefix] is optional preferred prefix for the public key.\n");

    string strPrefix = "";
    if (params.size() > 0)
        strPrefix = params[0].get_str();
 
    CKey key;
    key.MakeNewKey(false);

    CPrivKey vchPrivKey = key.GetPrivKey();
    Object result;
    result.push_back(Pair("PrivateKey", HexStr<CPrivKey::iterator>(vchPrivKey.begin(), vchPrivKey.end())));
    result.push_back(Pair("PublicKey", HexStr(key.GetPubKey().Raw())));
    return result;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
