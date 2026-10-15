// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Token transactions built by the wallet (CreateTokenTransaction,
// CreateReissueTokenTransaction, CreateTransferTokenTransaction), mined on a
// regtest chain, and the wallet's token balances and the token DB listings
// that follow from them.

#include "base58.h"
#include "consensus/validation.h"
#include "policy/fees.h"
#include "rpc/protocol.h"
#include "script/ismine.h"
#include "script/standard.h"
#include "tinyformat.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "validation.h"
#include "wallet/coincontrol.h"
#include "wallet/db.h"
#include "wallet/wallet.h"

#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <algorithm>
#include <functional>

#include <boost/test/unit_test.hpp>

typedef std::pair<int, std::string> RpcError;
typedef std::vector<std::pair<CTokenTransfer, std::string> > TransferList;

/** Outcome of a Create* call that is not sent */
struct CreateResult {
    bool ok;
    RpcError error;
    CAmount nFee;
};

#define CHECK_FAIL(result, code, message) do { \
    const CreateResult r_ = (result); \
    BOOST_CHECK(!r_.ok); \
    BOOST_CHECK_EQUAL(r_.error.first, (code)); \
    BOOST_CHECK_EQUAL(r_.error.second, (message)); \
} while (0)

static const std::string FEE_ERROR = "Error: This transaction requires a transaction fee of at least 0.01";

static CNewToken TokenA() { return CNewToken("TOKENA", 1000 * COIN, 2, 1, 0, ""); }
static CNewToken TokenB() { return CNewToken("TOKENB", 10 * COIN, 0, 1, 0, ""); }
static CNewToken Unique(const std::string& name) { return CNewToken(name, UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""); }

/** "name amount address" of every transfer output of tx, sorted */
static std::vector<std::string> TransfersOf(const CTransaction& tx)
{
    std::vector<std::string> result;
    for (const CTxOut& out : tx.vout) {
        CTokenTransfer transfer;
        std::string address;
        if (TransferTokenFromScript(out.scriptPubKey, transfer, address))
            result.push_back(strprintf("%s %d %s", transfer.strName, transfer.nAmount, address));
    }
    std::sort(result.begin(), result.end());
    return result;
}

static std::string TransferOut(const std::string& name, CAmount amount, const std::string& address)
{
    return strprintf("%s %d %s", name, amount, address);
}

static int CountValue(const CTransaction& tx, CAmount nValue)
{
    return std::count_if(tx.vout.begin(), tx.vout.end(), [&](const CTxOut& out) { return out.nValue == nValue; });
}

static bool Spends(const CTransaction& tx, const COutPoint& outpoint)
{
    return std::any_of(tx.vin.begin(), tx.vin.end(), [&](const CTxIn& in) { return in.prevout == outpoint; });
}

/** Index of the first output of tx that `match` accepts */
static unsigned int FindOutput(const CTransaction& tx, std::function<bool(const CScript&)> match)
{
    for (unsigned int i = 0; i < tx.vout.size(); i++)
        if (match(tx.vout[i].scriptPubKey)) return i;
    BOOST_ERROR("output not found");
    return 0;
}

static void CheckNewToken(const CScript& script, const CNewToken& expected, const std::string& expectedAddress)
{
    CNewToken token;
    std::string address;
    BOOST_REQUIRE(TokenFromScript(script, token, address));
    BOOST_CHECK_EQUAL(token.strName, expected.strName);
    BOOST_CHECK_EQUAL(token.nAmount, expected.nAmount);
    BOOST_CHECK_EQUAL((int)token.units, (int)expected.units);
    BOOST_CHECK_EQUAL((int)token.nReissuable, (int)expected.nReissuable);
    BOOST_CHECK_EQUAL((int)token.nHasIPFS, (int)expected.nHasIPFS);
    BOOST_CHECK_EQUAL(address, expectedAddress);
}

/** Restores vpwallets at the end of the scope */
struct VpWalletsGuard {
    std::vector<CWallet*> saved;
    explicit VpWalletsGuard(const std::vector<CWallet*>& wallets) : saved(vpwallets) { vpwallets = wallets; }
    ~VpWalletsGuard() { vpwallets = saved; }
};

/** Sets a token global to nullptr for the scope */
template <typename T>
struct NullGuard {
    T*& ref;
    T* saved;
    explicit NullGuard(T*& r) : ref(r), saved(r) { ref = nullptr; }
    ~NullGuard() { ref = saved; }
};

/**
 * Regtest chain with token globals (as in TokenTestingSetup) and a wallet at
 * vpwallets[0]. Wallets are funded by a mined tx that spends a coin added to
 * the UTXO set directly, which is much cheaper than mining enough coinbases
 * for the token locks. Wallets aren't registered for validation callbacks
 * (no scheduler runs in unit tests); Mine() rescans the new block instead.
 */
struct TokenWalletSetup : public TestChain100Setup {
    CTokensDB* prevTokensDb;
    CLRUCache<std::string, CDatabasedTokenData>* prevTokensCache;
    bool prevTokenIndex;
    std::vector<CWallet*> prevWallets;
    std::unique_ptr<CWallet> wallet;
    std::unique_ptr<CWallet> walletB;
    CTxDestination tokenDest, changeDest, fundDest, destB, destB2;
    std::string tokenAddress, changeAddress;
    const std::string addrX = TestTokenAddress(7);
    const std::string addrY = TestTokenAddress(8);
    const CAmount L = GetIssueTokenLockAmount();
    int nFakeCoins = 0;

    TokenWalletSetup()
    {
        prevTokensDb = ptokensdb;
        prevTokensCache = ptokensCache;
        prevTokenIndex = fTokenIndex;
        ptokensdb = new CTokensDB(1 << 20, true, true);
        ptokensCache = new CLRUCache<std::string, CDatabasedTokenData>(MAX_CACHE_TOKENS_SIZE);
        fTokenIndex = true;
        TokenTestingSetup::ClearTokenGlobals();

        bitdb.MakeMock();
        wallet = NewWallet("wallet_token_a.dat");
        prevWallets = vpwallets;
        vpwallets.insert(vpwallets.begin(), wallet.get());
        tokenDest = NewDest(*wallet);
        changeDest = NewDest(*wallet);
        fundDest = NewDest(*wallet);
        tokenAddress = EncodeDestination(tokenDest);
        changeAddress = EncodeDestination(changeDest);
    }

    ~TokenWalletSetup()
    {
        vpwallets = prevWallets;
        walletB.reset();
        wallet.reset();
        bitdb.Flush(true);
        bitdb.Reset();
        SetMockTime(0);
        mempool.clear();
        TokenTestingSetup::ClearTokenGlobals();
        delete ptokensdb;
        delete ptokensCache;
        ptokensdb = prevTokensDb;
        ptokensCache = prevTokensCache;
        fTokenIndex = prevTokenIndex;
    }

    static std::unique_ptr<CWallet> NewWallet(const std::string& file)
    {
        std::unique_ptr<CWallet> w(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, file))));
        bool fFirstRun;
        w->LoadWallet(fFirstRun);
        return w;
    }

    /** A new key of the wallet, not taken from the keypool */
    static CTxDestination NewDest(CWallet& w)
    {
        CKey key;
        key.MakeNewKey(true);
        LOCK(w.cs_wallet);
        BOOST_REQUIRE(w.AddKeyPubKey(key, key.GetPubKey()));
        return key.GetPubKey().GetID();
    }

    CWallet& WalletB()
    {
        if (!walletB) {
            walletB = NewWallet("wallet_token_b.dat");
            destB = NewDest(*walletB);
            destB2 = NewDest(*walletB);
        }
        return *walletB;
    }

    CCoinControl ChangeTo(const CTxDestination& dest)
    {
        CCoinControl cc;
        cc.destChange = dest;
        return cc;
    }

    /** Keep block times increasing (one second per block) */
    void Step()
    {
        SetMockTime(std::max(GetTime(), chainActive.Tip()->GetBlockTime()) + 1);
    }

    CBlock Mine(const std::vector<CTransaction>& txs)
    {
        Step();
        CBlock block = CreateAndProcessBlock(txs, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
        for (CWallet* w : {wallet.get(), walletB.get()})
            if (w) w->ScanForWalletTransactions(chainActive.Tip(), true);
        return block;
    }

    /** Mine a tx paying the given outputs, funded by a coin added to the UTXO set */
    CTransaction Fund(const std::vector<std::pair<CTxDestination, CAmount> >& outs)
    {
        Step();
        CAmount nTotal = COIN;
        for (const auto& out : outs)
            nTotal += out.second;
        const CScript coinScript = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
        const COutPoint fake(uint256S(strprintf("0xf00d%04x", ++nFakeCoins)), 0);
        {
            LOCK(cs_main);
            pcoinsTip->AddCoin(fake, Coin(CTxOut(nTotal, coinScript), chainActive.Height(), false, false,
                                          chainActive.Tip()->GetBlockTime()), false);
        }
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn(fake));
        for (const auto& out : outs)
            mtx.vout.push_back(CTxOut(out.second, GetScriptForDestination(out.first)));
        std::vector<unsigned char> vchSig;
        BOOST_REQUIRE(coinbaseKey.Sign(SignatureHash(coinScript, mtx, 0, SIGHASH_ALL), vchSig));
        vchSig.push_back((unsigned char)SIGHASH_ALL);
        mtx.vin[0].scriptSig = CScript() << vchSig;
        CTransaction tx(mtx);
        Mine({tx});
        return tx;
    }

    /** The fee is the only difference between inputs and outputs; small txs pay the minimum */
    static void CheckFee(const CWallet& w, const CTransaction& tx, CAmount nFee)
    {
        BOOST_REQUIRE_LT(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION), 1000U);
        BOOST_CHECK_EQUAL(nFee, MIN_TX_FEE);
        CAmount nIn = 0;
        {
            LOCK(w.cs_wallet);
            for (const CTxIn& in : tx.vin)
                nIn += w.mapWallet.at(in.prevout.hash).tx->vout[in.prevout.n].nValue;
        }
        BOOST_CHECK_EQUAL(nIn - tx.GetValueOut(), nFee);
    }

    /** Send (no broadcast: wallet only) and mine a created tx */
    CTransactionRef Commit(CWallet* w, CWalletTx& wtx, CReserveKey& reservekey, CAmount nFee)
    {
        CheckFee(*w, *wtx.tx, nFee);
        RpcError error(0, "");
        std::string txid;
        BOOST_REQUIRE(SendTokenTransaction(w, wtx, reservekey, error, txid));
        BOOST_CHECK_EQUAL(txid, wtx.GetHash().GetHex());
        BOOST_CHECK(w->GetWalletTx(wtx.GetHash()) != nullptr);
        BOOST_CHECK_EQUAL(mempool.size(), 0U);
        Mine({*wtx.tx});
        return wtx.tx;
    }

    // Create* wrappers. nFee always starts at 0: some error paths read it before it is set.

    CreateResult TryIssue(CWallet* w, const std::vector<CNewToken>& tokens, const std::string& address, CCoinControl cc)
    {
        CreateResult r{false, RpcError(0, ""), 0};
        CReserveKey reservekey(w);
        CWalletTx wtx;
        r.ok = CreateTokenTransaction(w, cc, tokens, address, r.error, wtx, reservekey, r.nFee);
        return r;
    }

    CreateResult TryReissue(CWallet* w, const CReissueToken& reissue, const std::string& address, CCoinControl cc)
    {
        CreateResult r{false, RpcError(0, ""), 0};
        CReserveKey reservekey(w);
        CWalletTx wtx;
        r.ok = CreateReissueTokenTransaction(w, cc, reissue, address, r.error, wtx, reservekey, r.nFee);
        return r;
    }

    CreateResult TryTransfer(CWallet* w, const TransferList& transfers, const CCoinControl& cc)
    {
        CreateResult r{false, RpcError(0, ""), 0};
        CReserveKey reservekey(w);
        CWalletTx wtx;
        r.ok = CreateTransferTokenTransaction(w, cc, transfers, r.error, wtx, reservekey, r.nFee);
        return r;
    }

    CTransactionRef Issue(const std::vector<CNewToken>& tokens, const std::string& address)
    {
        CCoinControl cc = ChangeTo(changeDest);
        CReserveKey reservekey(wallet.get());
        CWalletTx wtx;
        RpcError error(0, "");
        CAmount nFee = 0;
        BOOST_REQUIRE(CreateTokenTransaction(wallet.get(), cc, tokens, address, error, wtx, reservekey, nFee));
        BOOST_CHECK(error == RpcError(0, ""));
        return Commit(wallet.get(), wtx, reservekey, nFee);
    }

    CTransactionRef Reissue(const CReissueToken& reissue, const std::string& address)
    {
        CCoinControl cc = ChangeTo(changeDest);
        CReserveKey reservekey(wallet.get());
        CWalletTx wtx;
        RpcError error(0, "");
        CAmount nFee = 0;
        BOOST_REQUIRE(CreateReissueTokenTransaction(wallet.get(), cc, reissue, address, error, wtx, reservekey, nFee));
        BOOST_CHECK(error == RpcError(0, ""));
        return Commit(wallet.get(), wtx, reservekey, nFee);
    }

    CTransactionRef Transfer(const TransferList& transfers)
    {
        CReserveKey reservekey(wallet.get());
        CWalletTx wtx;
        RpcError error(0, "");
        CAmount nFee = 0;
        BOOST_REQUIRE(CreateTransferTokenTransaction(wallet.get(), ChangeTo(changeDest), transfers, error, wtx, reservekey, nFee));
        BOOST_CHECK(error == RpcError(0, ""));
        return Commit(wallet.get(), wtx, reservekey, nFee);
    }

    /** Token balance of vpwallets[0] */
    static CAmount Balance(const std::string& name, int nConf = 1)
    {
        CAmount balance = 0;
        BOOST_CHECK(GetMyTokenBalance(name, balance, nConf));
        return balance;
    }

    static std::vector<std::string> MyTokens(CWallet* w, int nMinConf, bool fIncludeAdmin, bool fOnlyAdmin)
    {
        std::vector<std::string> names;
        GetAllMyTokens(w, names, nMinConf, fIncludeAdmin, fOnlyAdmin);
        return names;
    }

    /** GetAllMyTokenBalances as "name=amount", plus the names it found outputs for */
    static std::vector<std::string> MyBalances(const std::string& prefix, int nConf, std::vector<std::string>* pOutputNames = nullptr)
    {
        std::map<std::string, std::vector<COutput> > outputs;
        std::map<std::string, CAmount> amounts;
        BOOST_CHECK(GetAllMyTokenBalances(outputs, amounts, nConf, prefix));
        if (pOutputNames) {
            pOutputNames->clear();
            for (const auto& entry : outputs)
                pOutputNames->push_back(entry.first);
        }
        return Entries(std::vector<std::pair<std::string, CAmount> >(amounts.begin(), amounts.end()));
    }
};

BOOST_FIXTURE_TEST_SUITE(token_wallet_tests, TokenWalletSetup)

BOOST_AUTO_TEST_CASE(issue_reissue_and_balances)
{
    Fund({{fundDest, 2 * L + COIN}});

    // Without a wallet the lookups fail
    {
        VpWalletsGuard noWallets(std::vector<CWallet*>{});
        CAmount balance = 42;
        BOOST_CHECK(!GetMyTokenBalance("TOKENA", balance, 1));
        BOOST_CHECK_EQUAL(balance, 42);
        std::map<std::string, std::vector<COutput> > outputs;
        std::map<std::string, CAmount> amounts;
        BOOST_CHECK(!GetAllMyTokenBalances(outputs, amounts));
        BOOST_CHECK(outputs.empty() && amounts.empty());
        RpcError error(0, "");
        BOOST_CHECK(!VerifyWalletHasToken("TOKENA", error));
        BOOST_CHECK_EQUAL(error.first, RPC_WALLET_ERROR);
        BOOST_CHECK_EQUAL(error.second, "Wallet not found. Can't verify if it contains: TOKENA");
    }

    // A wallet without tokens
    CHECK_LIST(MyTokens(wallet.get(), 1, true, false), {});
    CHECK_LIST(MyBalances("", 0), {});
    BOOST_CHECK_EQUAL(Balance("TOKENA"), 0);
    RpcError error(0, "");
    BOOST_CHECK(!VerifyWalletHasToken("TOKENA", error));
    BOOST_CHECK_EQUAL(error.first, RPC_INVALID_REQUEST);
    BOOST_CHECK_EQUAL(error.second, "Wallet doesn't have token: TOKENA");

    // Issue without a change address: a new key from the keypool gets the change
    CCoinControl cc;
    CReserveKey reservekey(wallet.get());
    CWalletTx wtx;
    CAmount nFee = 0;
    error = RpcError(0, "");
    BOOST_REQUIRE(CreateTokenTransaction(wallet.get(), cc, TokenA(), tokenAddress, error, wtx, reservekey, nFee));
    BOOST_CHECK(error == RpcError(0, ""));
    BOOST_CHECK(IsValidDestination(cc.destChange));
    BOOST_CHECK(IsMine(*wallet, cc.destChange) == ISMINE_SPENDABLE);
    const CTransaction issue = *wtx.tx;
    BOOST_CHECK(issue.IsNewToken());
    CheckNewToken(issue.vout.back().scriptPubKey, TokenA(), tokenAddress);
    std::string ownerName, ownerAddress;
    BOOST_REQUIRE(OwnerFromTransaction(issue, ownerName, ownerAddress));
    BOOST_CHECK_EQUAL(ownerName, "TOKENA!");
    BOOST_CHECK_EQUAL(ownerAddress, tokenAddress);
    BOOST_CHECK_EQUAL(CountValue(issue, GetLockAmount(ETokenType::YATOKEN)), 1);
    BOOST_CHECK(TransfersOf(issue).empty());
    // Exactly one YAC change output, paying the new change key
    int nChange = 0;
    for (const CTxOut& out : issue.vout) {
        if (!out.scriptPubKey.IsTokenScript() && out.nValue != L) {
            BOOST_CHECK(out.scriptPubKey == GetScriptForDestination(cc.destChange));
            nChange++;
        }
    }
    BOOST_CHECK_EQUAL(nChange, 1);
    Commit(wallet.get(), wtx, reservekey, nFee);

    CNewToken meta;
    BOOST_CHECK(ptokens->CheckIfTokenExists("TOKENA"));
    BOOST_CHECK_EQUAL(Balance("TOKENA"), 1000 * COIN);
    BOOST_CHECK_EQUAL(Balance("TOKENA!"), OWNER_TOKEN_AMOUNT);
    BOOST_CHECK_EQUAL(Balance("NOPE"), 0);
    BOOST_CHECK(VerifyWalletHasToken("TOKENA", error));
    BOOST_CHECK(VerifyWalletHasToken("TOKENA!", error));
    BOOST_CHECK(error == RpcError(0, ""));
    BOOST_CHECK_EQUAL(Balance("TOKENA", 2), 0);
    Mine({});
    BOOST_CHECK_EQUAL(Balance("TOKENA", 2), 1000 * COIN);

    // Reissue: owner token back to the change address, new amount to the token address
    const unsigned int ownerIndex = FindOutput(issue, [](const CScript& s) { return IsScriptOwnerToken(s); });
    const CReissueToken reissue("TOKENA", 500 * COIN, -1, 1, "");
    CTransactionRef reissueTx = Reissue(reissue, tokenAddress);
    BOOST_CHECK(reissueTx->IsReissueToken());
    CReissueToken parsed;
    std::string reissueAddress;
    BOOST_REQUIRE(ReissueTokenFromTransaction(*reissueTx, parsed, reissueAddress));
    BOOST_CHECK_EQUAL(parsed.strName, "TOKENA");
    BOOST_CHECK_EQUAL(parsed.nAmount, 500 * COIN);
    BOOST_CHECK_EQUAL((int)parsed.nUnits, -1);
    BOOST_CHECK_EQUAL((int)parsed.nReissuable, 1);
    BOOST_CHECK_EQUAL(parsed.strIPFSHash, "");
    BOOST_CHECK_EQUAL(reissueAddress, tokenAddress);
    CHECK_LIST(TransfersOf(*reissueTx), {TransferOut("TOKENA!", OWNER_TOKEN_AMOUNT, changeAddress)});
    BOOST_CHECK(Spends(*reissueTx, COutPoint(issue.GetHash(), ownerIndex)));
    BOOST_CHECK_EQUAL(CountValue(*reissueTx, GetReissueTokenLockAmount()), 1);

    BOOST_REQUIRE(ptokens->GetTokenMetaDataIfExists("TOKENA", meta));
    BOOST_CHECK_EQUAL(meta.nAmount, 1500 * COIN);
    BOOST_CHECK_EQUAL((int)meta.units, 2);
    BOOST_CHECK_EQUAL((int)meta.nReissuable, 1);

    // Two TOKENA outputs now: the issued one (depth 3) and the reissued one (depth 1)
    BOOST_CHECK_EQUAL(Balance("TOKENA"), 1500 * COIN);
    BOOST_CHECK_EQUAL(Balance("TOKENA", 2), 1000 * COIN);
    BOOST_CHECK_EQUAL(Balance("TOKENA", 3), 1000 * COIN);
    BOOST_CHECK_EQUAL(Balance("TOKENA", 4), 0);
    std::vector<std::string> outputNames;
    CHECK_LIST(MyBalances("", 0, &outputNames), {"TOKENA=1500000000", "TOKENA!=1000000"});
    CHECK_LIST(outputNames, {"TOKENA", "TOKENA!"});
    std::map<std::string, std::vector<COutput> > outputs;
    std::map<std::string, CAmount> amounts;
    BOOST_CHECK(GetAllMyTokenBalances(outputs, amounts));
    BOOST_CHECK_EQUAL(outputs["TOKENA"].size(), 2U);
}

BOOST_AUTO_TEST_CASE(sub_and_unique_issue_and_listing)
{
    Fund({{fundDest, 4 * L + COIN}});
    CTransactionRef issue = Issue({TokenA()}, tokenAddress);
    const unsigned int issueOwner = FindOutput(*issue, [](const CScript& s) { return IsScriptOwnerToken(s); });

    // Sub token: spends the parent owner token and sends it to the change address
    const CNewToken sub("TOKENA/SUB", 50 * COIN, 0, 0, 0, "");
    CTransactionRef subTx = Issue({sub}, tokenAddress);
    BOOST_CHECK(subTx->IsNewToken());
    CheckNewToken(subTx->vout.back().scriptPubKey, sub, tokenAddress);
    std::string ownerName, ownerAddress;
    BOOST_REQUIRE(OwnerFromTransaction(*subTx, ownerName, ownerAddress));
    BOOST_CHECK_EQUAL(ownerName, "TOKENA/SUB!");
    BOOST_CHECK_EQUAL(ownerAddress, tokenAddress);
    CHECK_LIST(TransfersOf(*subTx), {TransferOut("TOKENA!", OWNER_TOKEN_AMOUNT, changeAddress)});
    BOOST_CHECK(Spends(*subTx, COutPoint(issue->GetHash(), issueOwner)));
    BOOST_CHECK_EQUAL(CountValue(*subTx, GetLockAmount(ETokenType::SUB)), 1);
    BOOST_CHECK_EQUAL(Balance("TOKENA/SUB"), 50 * COIN);
    BOOST_CHECK_EQUAL(Balance("TOKENA/SUB!"), OWNER_TOKEN_AMOUNT);
    BOOST_CHECK_EQUAL(Balance("TOKENA!"), OWNER_TOKEN_AMOUNT);

    // Two unique tokens in one tx: one lock for both, no owner tokens
    const unsigned int subOwnerChange = FindOutput(*subTx, [](const CScript& s) { return IsScriptTransferToken(s); });
    CTransactionRef uniqueTx = Issue({Unique("TOKENA#TAG1"), Unique("TOKENA#TAG2")}, tokenAddress);
    BOOST_CHECK(uniqueTx->IsNewUniqueToken());
    const size_t n = uniqueTx->vout.size();
    CheckNewToken(uniqueTx->vout[n - 2].scriptPubKey, Unique("TOKENA#TAG1"), tokenAddress);
    CheckNewToken(uniqueTx->vout[n - 1].scriptPubKey, Unique("TOKENA#TAG2"), tokenAddress);
    for (const CTxOut& out : uniqueTx->vout)
        BOOST_CHECK(!IsScriptOwnerToken(out.scriptPubKey));
    BOOST_CHECK_EQUAL(CountValue(*uniqueTx, 2 * GetLockAmount(ETokenType::UNIQUE)), 1);
    CHECK_LIST(TransfersOf(*uniqueTx), {TransferOut("TOKENA!", OWNER_TOKEN_AMOUNT, changeAddress)});
    BOOST_CHECK(Spends(*uniqueTx, COutPoint(subTx->GetHash(), subOwnerChange)));
    BOOST_CHECK_EQUAL(Balance("TOKENA#TAG1"), UNIQUE_TOKEN_AMOUNT);
    BOOST_CHECK_EQUAL(Balance("TOKENA#TAG2"), UNIQUE_TOKEN_AMOUNT);

    // Name listings. Depths now: TOKENA 3, TOKENA/SUB and TOKENA/SUB! 2,
    // TOKENA! (moved by the unique tx) and the tags 1.
    CHECK_LIST(MyTokens(wallet.get(), 1, false, false), {"TOKENA", "TOKENA#TAG1", "TOKENA#TAG2", "TOKENA/SUB"});
    CHECK_LIST(MyTokens(wallet.get(), 1, true, false), {"TOKENA", "TOKENA!", "TOKENA#TAG1", "TOKENA#TAG2", "TOKENA/SUB", "TOKENA/SUB!"});
    CHECK_LIST(MyTokens(wallet.get(), 1, false, true), {"TOKENA!", "TOKENA/SUB!"});
    CHECK_LIST(MyTokens(wallet.get(), 1, true, true), {"TOKENA!", "TOKENA/SUB!"});
    CHECK_LIST(MyTokens(wallet.get(), 2, false, false), {"TOKENA", "TOKENA/SUB"});
    CHECK_LIST(MyTokens(wallet.get(), 2, true, false), {"TOKENA", "TOKENA/SUB", "TOKENA/SUB!"});
    std::vector<std::string> names;
    GetAllAdministrativeTokens(wallet.get(), names, 1);
    CHECK_LIST(names, {"TOKENA!", "TOKENA/SUB!"});
    names = {"X"};
    GetAllAdministrativeTokens(nullptr, names, 1);
    GetAllMyTokens(nullptr, names, 1, true, false);
    CHECK_LIST(names, {"X"});

    // Balances by prefix; the outputs map is never filtered
    const std::vector<std::string> allNames = {"TOKENA", "TOKENA!", "TOKENA#TAG1", "TOKENA#TAG2", "TOKENA/SUB", "TOKENA/SUB!"};
    std::vector<std::string> outputNames;
    CHECK_LIST(MyBalances("", 0, &outputNames), {"TOKENA=1000000000", "TOKENA!=1000000", "TOKENA#TAG1=1000000",
                                                 "TOKENA#TAG2=1000000", "TOKENA/SUB=50000000", "TOKENA/SUB!=1000000"});
    CHECK_LIST(outputNames, allNames);
    CHECK_LIST(MyBalances("TOKENA", 0, &outputNames), {"TOKENA=1000000000", "TOKENA!=1000000", "TOKENA#TAG1=1000000",
                                                       "TOKENA#TAG2=1000000", "TOKENA/SUB=50000000", "TOKENA/SUB!=1000000"});
    CHECK_LIST(MyBalances("TOKENA/", 0, &outputNames), {"TOKENA/SUB=50000000", "TOKENA/SUB!=1000000"});
    CHECK_LIST(outputNames, allNames);
    CHECK_LIST(MyBalances("TOKENA#", 0), {"TOKENA#TAG1=1000000", "TOKENA#TAG2=1000000"});
    CHECK_LIST(MyBalances("SUB", 0, &outputNames), {}); // must be a prefix, not anywhere in the name
    CHECK_LIST(outputNames, allNames);
    CHECK_LIST(MyBalances("NOPE", 0), {});
    CHECK_LIST(MyBalances("", 2, &outputNames), {"TOKENA=1000000000", "TOKENA/SUB=50000000", "TOKENA/SUB!=1000000"});
    CHECK_LIST(outputNames, {"TOKENA", "TOKENA/SUB", "TOKENA/SUB!"});
}

BOOST_AUTO_TEST_CASE(transfer_tokens)
{
    Fund({{fundDest, 2 * L + COIN}});
    CTransactionRef issue = Issue({TokenA()}, tokenAddress);
    Issue({CNewToken("TOKENA/SUB", 50 * COIN, 0, 0, 0, "")}, tokenAddress);

    // One transfer: the rest comes back to the change address, no lock
    CTransactionRef t1 = Transfer({{CTokenTransfer("TOKENA", 300 * COIN), addrX}});
    CHECK_LIST(TransfersOf(*t1), {TransferOut("TOKENA", 300 * COIN, addrX), TransferOut("TOKENA", 700 * COIN, changeAddress)});
    BOOST_CHECK_EQUAL(CountValue(*t1, L), 0);
    BOOST_CHECK(Spends(*t1, COutPoint(issue->GetHash(), issue->vout.size() - 1)));
    BOOST_CHECK_EQUAL(Balance("TOKENA"), 700 * COIN);

    // Several transfers in one tx, including the whole owner token
    CTransactionRef t2 = Transfer({{CTokenTransfer("TOKENA", 100 * COIN), addrX},
                                   {CTokenTransfer("TOKENA/SUB", 10 * COIN), addrY},
                                   {CTokenTransfer("TOKENA/SUB!", OWNER_TOKEN_AMOUNT), addrY}});
    CHECK_LIST(TransfersOf(*t2), {TransferOut("TOKENA", 100 * COIN, addrX), TransferOut("TOKENA", 600 * COIN, changeAddress),
                                  TransferOut("TOKENA/SUB", 10 * COIN, addrY), TransferOut("TOKENA/SUB", 40 * COIN, changeAddress),
                                  TransferOut("TOKENA/SUB!", OWNER_TOKEN_AMOUNT, addrY)});
    BOOST_CHECK_EQUAL(Balance("TOKENA"), 600 * COIN);
    BOOST_CHECK_EQUAL(Balance("TOKENA/SUB"), 40 * COIN);
    BOOST_CHECK_EQUAL(Balance("TOKENA/SUB!"), 0);
    RpcError error(0, "");
    BOOST_CHECK(!VerifyWalletHasToken("TOKENA/SUB!", error));
    BOOST_CHECK_EQUAL(error.first, RPC_INVALID_REQUEST);
    BOOST_CHECK_EQUAL(error.second, "Wallet doesn't have token: TOKENA/SUB!");

    // Errors
    const int nHeight = chainActive.Height();
    const CCoinControl cc = ChangeTo(changeDest);
    CHECK_FAIL(TryTransfer(wallet.get(), {{CTokenTransfer("TOKENA", COIN), addrX}, {CTokenTransfer("TOKENA", COIN), "notanaddress"}}, cc),
               RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address: notanaddress");
    CHECK_FAIL(TryTransfer(wallet.get(), {{CTokenTransfer("NOPE", COIN), addrX}}, cc),
               RPC_INVALID_REQUEST, "Wallet doesn't have token: NOPE");
    const std::string ownerAmountError = "When transferring an 'Ownership Token' the amount must always be 1. Please try again with the amount of 1";
    CHECK_FAIL(TryTransfer(wallet.get(), {{CTokenTransfer("TOKENA!", 2 * OWNER_TOKEN_AMOUNT), addrX}}, cc),
               RPC_INVALID_PARAMS, ownerAmountError);
    CHECK_FAIL(TryTransfer(wallet.get(), {{CTokenTransfer("TOKENA!", OWNER_TOKEN_AMOUNT / 2), addrX}}, cc),
               RPC_INVALID_PARAMS, ownerAmountError);
    {
        NullGuard<CTokensCache> noTokens(ptokens);
        CHECK_FAIL(TryTransfer(wallet.get(), {{CTokenTransfer("TOKENA", COIN), addrX}}, cc),
                   RPC_DATABASE_ERROR, "ptokens isn't initialized");
    }
    CHECK_FAIL(TryTransfer(wallet.get(), {{CTokenTransfer("TOKENA", 601 * COIN), addrX}}, cc),
               RPC_TRANSACTION_ERROR, "Insufficient token funds");
    CHECK_FAIL(TryTransfer(wallet.get(), {{CTokenTransfer("TOKENA", 0), addrX}}, cc),
               RPC_TRANSACTION_ERROR, "Token Transfer amounts must be greater than 0");
    CHECK_FAIL(TryTransfer(wallet.get(), {}, cc),
               RPC_TRANSACTION_ERROR, "Transaction must have at least one recipient");
    BOOST_CHECK_EQUAL(chainActive.Height(), nHeight);
    BOOST_CHECK_EQUAL(Balance("TOKENA"), 600 * COIN);

    // Sending everything leaves no token change
    CTransactionRef t3 = Transfer({{CTokenTransfer("TOKENA", 600 * COIN), addrX}});
    CHECK_LIST(TransfersOf(*t3), {TransferOut("TOKENA", 600 * COIN, addrX)});
    BOOST_CHECK_EQUAL(Balance("TOKENA"), 0);
}

BOOST_AUTO_TEST_CASE(second_wallet_funds_and_ownership)
{
    Fund({{fundDest, 3 * L + COIN}});
    Issue({TokenA()}, tokenAddress);
    CWallet& b = WalletB();
    const std::string addrB = EncodeDestination(destB);
    Transfer({{CTokenTransfer("TOKENA", 5 * COIN), addrB}, {CTokenTransfer("TOKENA!", OWNER_TOKEN_AMOUNT), addrB}});
    const CCoinControl ccB = ChangeTo(destB2);
    const CReissueToken reissue("TOKENA", COIN, -1, 1, "");

    // Tokens but no YAC to pay the fee
    CHECK_FAIL(TryTransfer(&b, {{CTokenTransfer("TOKENA", COIN), addrX}}, ccB),
               RPC_WALLET_INSUFFICIENT_FUNDS, "This wallet doesn't contain any YAC, transfering an token requires a network fee");

    {
        // The balance and has-token lookups (also inside the Create* functions) read
        // vpwallets[0], so the second wallet has to be first there while it acts
        VpWalletsGuard onlyB({&b});
        BOOST_CHECK_EQUAL(Balance("TOKENA"), 5 * COIN);
        BOOST_CHECK_EQUAL(Balance("TOKENA!"), OWNER_TOKEN_AMOUNT);

        // Less YAC than the fee
        Fund({{destB, 1}});
        CreateResult r = TryTransfer(&b, {{CTokenTransfer("TOKENA", COIN), addrX}}, ccB);
        CHECK_FAIL(r, RPC_WALLET_ERROR, FEE_ERROR);
        BOOST_CHECK_EQUAL(r.nFee, MIN_TX_FEE);
        CHECK_FAIL(TryIssue(&b, {TokenB()}, addrB, ccB), RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

        // One unit less than the lock
        Fund({{destB, L - 2}});
        BOOST_REQUIRE_EQUAL(b.GetBalance(), L - 1);
        CHECK_FAIL(TryIssue(&b, {TokenB()}, addrB, ccB), RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
        CHECK_FAIL(TryReissue(&b, reissue, addrB, ccB), RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

        // Exactly the lock: enough for the check, not for lock plus fee
        Fund({{destB, 1}});
        BOOST_REQUIRE_EQUAL(b.GetBalance(), L);
        r = TryIssue(&b, {TokenB()}, addrB, ccB);
        CHECK_FAIL(r, RPC_WALLET_ERROR, FEE_ERROR);
        BOOST_CHECK_EQUAL(r.nFee, MIN_TX_FEE);
        CHECK_FAIL(TryReissue(&b, reissue, addrB, ccB), RPC_WALLET_ERROR, FEE_ERROR);
    }

    // The first wallet gave its owner token away
    CHECK_FAIL(TryReissue(wallet.get(), reissue, tokenAddress, ChangeTo(changeDest)),
               RPC_INVALID_REQUEST, "Wallet doesn't have token: TOKENA!");
    CHECK_FAIL(TryIssue(wallet.get(), {CNewToken("TOKENA/SUB", COIN, 0, 0, 0, "")}, tokenAddress, ChangeTo(changeDest)),
               RPC_INVALID_REQUEST, "Wallet doesn't have token: TOKENA!");
}

BOOST_AUTO_TEST_CASE(issue_and_reissue_errors)
{
    Fund({{fundDest, 2 * L + COIN}});
    Issue({TokenA()}, tokenAddress);
    const CTxDestination smallDest = NewDest(*wallet);
    CTransaction small = Fund({{smallDest, COIN}});
    const int nHeight = chainActive.Height();
    const CCoinControl cc = ChangeTo(changeDest);
    CCoinControl ccSmall = ChangeTo(changeDest);
    ccSmall.Select(COutPoint(small.GetHash(), 0));

    // An encrypted, locked wallet with an empty keypool can't make a change address
    CWallet locked;
    CKey key;
    key.MakeNewKey(true);
    BOOST_REQUIRE(locked.LoadCryptedKey(key.GetPubKey(), {1, 2, 3}));
    BOOST_REQUIRE(locked.IsLocked());

    const std::string invalidName = "Invalid parameter: token_name must only consist of valid characters and have a size between 3 and 30 characters. See help for more details.";
    CHECK_FAIL(TryIssue(wallet.get(), {CNewToken("abc", COIN, 0, 0, 0, "")}, tokenAddress, cc), RPC_INVALID_PARAMETER, invalidName);
    CHECK_FAIL(TryIssue(wallet.get(), {TokenA()}, tokenAddress, cc),
               RPC_INVALID_PARAMETER, "Invalid parameter: token_name 'TOKENA' has already been used");
    CHECK_FAIL(TryIssue(wallet.get(), {Unique("TOKENA#T1"), CNewToken("TOKENA#T2", 2 * UNIQUE_TOKEN_AMOUNT, 0, 0, 0, "")}, tokenAddress, cc),
               RPC_INVALID_PARAMETER, "Invalid parameter: amount must be 1000000");
    CHECK_FAIL(TryIssue(wallet.get(), {TokenB(), CNewToken("TOKENC", COIN, 0, 0, 0, "")}, tokenAddress, cc),
               RPC_INVALID_PARAMETER, "Only unique tokens can be issued in bulk.");
    CHECK_FAIL(TryIssue(wallet.get(), {Unique("TOKENA#T1"), TokenB()}, tokenAddress, cc),
               RPC_INVALID_PARAMETER, "Only unique tokens can be issued in bulk.");
    CHECK_FAIL(TryIssue(wallet.get(), {Unique("TOKENA#T1"), Unique("TOKENB#T1")}, tokenAddress, cc),
               RPC_INVALID_PARAMETER, "All tokens must have the same parent.");
    CHECK_FAIL(TryIssue(wallet.get(), {CNewToken("NOPARENT/SUB", COIN, 0, 0, 0, "")}, tokenAddress, cc),
               RPC_INVALID_REQUEST, "Wallet doesn't have token: NOPARENT!");
    CHECK_FAIL(TryIssue(wallet.get(), {Unique("NOPARENT#X")}, tokenAddress, cc),
               RPC_INVALID_REQUEST, "Wallet doesn't have token: NOPARENT!");
    CHECK_FAIL(TryIssue(wallet.get(), {TokenB()}, tokenAddress, ccSmall), RPC_WALLET_ERROR, "Insufficient funds");
    CHECK_FAIL(TryIssue(&locked, {TokenB()}, tokenAddress, CCoinControl()),
               RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out, please call keypoolrefill first");
    // The destination isn't checked up front; the wallet refuses it. The error currently
    // carries no message. (TryIssue starts the fee at 0, so no fee message is added.)
    CHECK_FAIL(TryIssue(wallet.get(), {TokenB()}, "", cc), RPC_WALLET_ERROR, "");

    const CReissueToken reissue("TOKENA", COIN, -1, 1, "");
    CHECK_FAIL(TryReissue(wallet.get(), reissue, "bad", cc), RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address: bad");
    CHECK_FAIL(TryReissue(wallet.get(), reissue, "", cc), RPC_INVALID_ADDRESS_OR_KEY, "Invalid Yacoin address: ");
    CHECK_FAIL(TryReissue(&locked, reissue, tokenAddress, CCoinControl()),
               RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out, please call keypoolrefill first");
    // Without a change address (a keypool key is used) and with one
    CHECK_FAIL(TryReissue(wallet.get(), CReissueToken("TOKENA!", COIN, -1, 1, ""), tokenAddress, CCoinControl()),
               RPC_INVALID_PARAMS, "Owner Tokens are not able to be reissued");
    CHECK_FAIL(TryReissue(wallet.get(), CReissueToken("abc", COIN, -1, 1, ""), tokenAddress, cc),
               RPC_INVALID_PARAMS, "Invalid token name: abc");
    {
        NullGuard<CTokensCache> noTokens(ptokens);
        CHECK_FAIL(TryReissue(wallet.get(), reissue, tokenAddress, cc), RPC_DATABASE_ERROR, "ptokens isn't initialized");
    }
    {
        NullGuard<CLRUCache<std::string, CDatabasedTokenData> > noCache(ptokensCache);
        CHECK_FAIL(TryReissue(wallet.get(), reissue, tokenAddress, cc), RPC_DATABASE_ERROR, "ptokensCache isn't initialized");
    }
    CHECK_FAIL(TryReissue(wallet.get(), CReissueToken("NOTEXIST", COIN, -1, 1, ""), tokenAddress, cc), RPC_VERIFY_ERROR,
               "Failed to create reissue token object. Error: Unable to reissue token: token_name 'NOTEXIST' doesn't exist in the database");
    CHECK_FAIL(TryReissue(wallet.get(), reissue, tokenAddress, ccSmall), RPC_WALLET_ERROR, "Insufficient funds");

    BOOST_CHECK_EQUAL(chainActive.Height(), nHeight);
    BOOST_CHECK(!ptokens->CheckIfTokenExists("TOKENB"));
}

BOOST_AUTO_TEST_CASE(send_rejected_token_transaction)
{
    // Two issues built on the same coin: once the first is mined, the second can't be sent
    CTransaction fund = Fund({{fundDest, 3 * L}});
    CCoinControl cc = ChangeTo(changeDest);
    cc.Select(COutPoint(fund.GetHash(), 0));
    CReserveKey reserveA(wallet.get()), reserveB(wallet.get());
    CWalletTx wtxA, wtxB;
    RpcError error(0, "");
    CAmount nFeeA = 0, nFeeB = 0;
    BOOST_REQUIRE(CreateTokenTransaction(wallet.get(), cc, TokenA(), tokenAddress, error, wtxA, reserveA, nFeeA));
    BOOST_REQUIRE(CreateTokenTransaction(wallet.get(), cc, TokenB(), tokenAddress, error, wtxB, reserveB, nFeeB));
    BOOST_REQUIRE(Spends(*wtxB.tx, COutPoint(fund.GetHash(), 0)));
    Commit(wallet.get(), wtxA, reserveA, nFeeA);

    wallet->SetBroadcastTransactions(true);
    std::string txid = "unchanged";
    BOOST_CHECK(!SendTokenTransaction(wallet.get(), wtxB, reserveB, error, txid));
    BOOST_CHECK_EQUAL(error.first, RPC_WALLET_ERROR);
    BOOST_CHECK_EQUAL(error.second, strprintf("Error: The transaction %s was rejected!", wtxB.GetHash().GetHex()));
    BOOST_CHECK_EQUAL(txid, "unchanged");
    BOOST_CHECK(wallet->GetWalletTx(wtxB.GetHash())->isAbandoned());
    BOOST_CHECK_EQUAL(mempool.size(), 0U);
    BOOST_CHECK(!ptokens->CheckIfTokenExists("TOKENB"));
}

BOOST_AUTO_TEST_CASE(token_db_listings_after_issue_and_transfer)
{
    Fund({{fundDest, 2 * L + COIN}});
    Issue({TokenA()}, tokenAddress);
    const int hA = chainActive.Height();
    Issue({TokenB()}, tokenAddress);
    const int hB = chainActive.Height();
    Transfer({{CTokenTransfer("TOKENA", 300 * COIN), addrX},
              {CTokenTransfer("TOKENA", 200 * COIN), addrY},
              {CTokenTransfer("TOKENB", 1 * COIN), addrX}});

    // Token metadata, with the height and block of the issue
    std::vector<CDatabasedTokenData> tokens;
    BOOST_REQUIRE(ptokensdb->TokenDir(tokens));
    BOOST_REQUIRE_EQUAL(tokens.size(), 2U);
    const std::vector<std::pair<CNewToken, int> > expected = {{TokenA(), hA}, {TokenB(), hB}};
    for (size_t i = 0; i < 2; i++) {
        BOOST_CHECK_EQUAL(tokens[i].token.strName, expected[i].first.strName);
        BOOST_CHECK_EQUAL(tokens[i].token.nAmount, expected[i].first.nAmount);
        BOOST_CHECK_EQUAL((int)tokens[i].token.units, (int)expected[i].first.units);
        BOOST_CHECK_EQUAL((int)tokens[i].token.nReissuable, (int)expected[i].first.nReissuable);
        BOOST_CHECK_EQUAL(tokens[i].nHeight, expected[i].second);
        BOOST_CHECK(tokens[i].blockHash == chainActive[expected[i].second]->GetBlockHash());
    }
    tokens.clear();
    BOOST_CHECK(ptokensdb->TokenDir(tokens, "TOKENA", 10, 0));
    BOOST_REQUIRE_EQUAL(tokens.size(), 1U);
    BOOST_CHECK_EQUAL(tokens[0].token.strName, "TOKENA");
    tokens.clear();
    BOOST_CHECK(ptokensdb->TokenDir(tokens, "TOKEN*", 1, 1));
    BOOST_REQUIRE_EQUAL(tokens.size(), 1U);
    BOOST_CHECK_EQUAL(tokens[0].token.strName, "TOKENB");
    tokens.clear();
    BOOST_CHECK(ptokensdb->TokenDir(tokens, "*", 1, -1));
    BOOST_REQUIRE_EQUAL(tokens.size(), 1U);
    BOOST_CHECK_EQUAL(tokens[0].token.strName, "TOKENB");

    // Holders: the fully spent outputs at the token address are gone, the change is at C
    auto holders = [](const std::string& name) {
        std::vector<std::pair<std::string, CAmount> > vec;
        int nTotal = 0;
        BOOST_CHECK(ptokensdb->TokenAddressDir(vec, nTotal, false, name, 100, 0));
        return vec;
    };
    auto sorted = [](std::vector<std::pair<std::string, CAmount> > vec) {
        std::sort(vec.begin(), vec.end(), [](const std::pair<std::string, CAmount>& x, const std::pair<std::string, CAmount>& y) {
            return DbKeyLess(x.first, y.first);
        });
        return Entries(vec);
    };
    std::vector<std::pair<std::string, CAmount> > vec;
    int nTotal = 0;
    BOOST_CHECK(ptokensdb->TokenAddressDir(vec, nTotal, true, "TOKENA", 100, 0));
    BOOST_CHECK_EQUAL(nTotal, 3);
    CHECK_LIST(Entries(holders("TOKENA")), sorted({{changeAddress, 500 * COIN}, {addrX, 300 * COIN}, {addrY, 200 * COIN}}));
    CHECK_LIST(Entries(holders("TOKENB")), sorted({{changeAddress, 9 * COIN}, {addrX, 1 * COIN}}));
    CHECK_LIST(Entries(holders("TOKENA!")), {tokenAddress + "=1000000"});

    // Holdings per address
    auto holdings = [](const std::string& address, size_t count, long start) {
        std::vector<std::pair<std::string, CAmount> > v;
        int n = 0;
        BOOST_CHECK(ptokensdb->AddressDir(v, n, false, address, count, start));
        return Entries(v);
    };
    BOOST_CHECK(ptokensdb->AddressDir(vec, nTotal, true, addrX, 100, 0));
    BOOST_CHECK_EQUAL(nTotal, 2);
    CHECK_LIST(holdings(addrX, 100, 0), {"TOKENA=300000000", "TOKENB=1000000"});
    CHECK_LIST(holdings(addrY, 100, 0), {"TOKENA=200000000"});
    CHECK_LIST(holdings(changeAddress, 100, 0), {"TOKENA=500000000", "TOKENB=9000000"});
    CHECK_LIST(holdings(changeAddress, 1, 1), {"TOKENB=9000000"});
    CHECK_LIST(holdings(tokenAddress, 100, 0), {"TOKENA!=1000000", "TOKENB!=1000000"});

    // The index agrees with what the wallet holds at its own addresses
    std::map<std::string, std::map<std::string, CAmount> > walletHoldings;
    std::map<std::string, std::vector<COutput> > outputs;
    wallet->AvailableTokens(outputs);
    for (const auto& entry : outputs) {
        for (const COutput& out : entry.second) {
            CTokenOutputEntry data;
            BOOST_REQUIRE(GetTokenData(out.tx->tx->vout[out.i].scriptPubKey, data));
            walletHoldings[EncodeDestination(data.destination)][data.tokenName] += data.nAmount;
        }
    }
    BOOST_CHECK_EQUAL(walletHoldings.size(), 2U);
    for (const auto& entry : walletHoldings) {
        std::vector<std::pair<std::string, CAmount> > held(entry.second.begin(), entry.second.end());
        CHECK_LIST(holdings(entry.first, 100, 0), sorted(held));
    }
}

BOOST_AUTO_TEST_SUITE_END()
