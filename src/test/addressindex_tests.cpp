// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Address index (-addressindex): the index keys (addressindex.h), the block tree
// database functions that write and read them (txdb.cpp), and the entries
// ConnectBlock and DisconnectBlock write for each kind of output and input.
//
// Note: script checks only run above the last checkpoint (fScriptChecks), and
// the checkpoint map is mainnet's, so signatures aren't verified here.

#include "addressindex.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "miner.h"
#include "pow.h"
#include "script/sign.h"
#include "script/standard.h"
#include "streams.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "validation.h"

#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <algorithm>

#include <boost/test/unit_test.hpp>

namespace {

typedef std::pair<CAddressIndexKey, CAmount> IndexEntry;
typedef std::pair<CAddressUnspentKey, CAddressUnspentValue> UnspentEntry;

const char DB_ADDRESSINDEX = 'a';
const char DB_ADDRESSUNSPENTINDEX = 'u';

/** One readable line per entry, with every field, so collections compare field by field */
std::string Str(const CAddressIndexKey& k, CAmount amount)
{
    return strprintf("type %u %s %s height %d tx %u %s n %u %s amount %d", k.type, k.hashBytes.GetHex(), k.token,
                     k.blockHeight, k.txindex, k.txhash.GetHex(), (unsigned)k.index,
                     k.spending ? "spend" : "receive", amount);
}

std::string Str(const CAddressUnspentKey& k, const CAddressUnspentValue& v)
{
    return strprintf("type %u %s %s %s n %u = %d script %s height %d", k.type, k.hashBytes.GetHex(), k.token,
                     k.txhash.GetHex(), (unsigned)k.index, v.satoshis, HexStr(v.script), v.blockHeight);
}

template <typename K, typename V>
std::vector<std::string> Strs(const std::vector<std::pair<K, V>>& entries)
{
    std::vector<std::string> out;
    for (const auto& e : entries) out.push_back(Str(e.first, e.second));
    return out;
}

template <typename T>
std::vector<unsigned char> Bytes(const T& obj)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << obj;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

/** Entries in database order (LevelDB compares the serialized keys bytewise) */
template <typename K, typename V>
std::vector<std::string> InKeyOrder(std::vector<std::pair<K, V>> entries)
{
    std::stable_sort(entries.begin(), entries.end(), [](const std::pair<K, V>& a, const std::pair<K, V>& b) {
        return Bytes(a.first) < Bytes(b.first);
    });
    return Strs(entries);
}

/** Every record under a prefix, in database order */
template <typename K, typename V>
std::vector<std::string> Dump(CDBWrapper& db, char prefix)
{
    std::unique_ptr<CDBIterator> it(db.NewIterator());
    std::vector<std::string> out;
    for (it->Seek(prefix); it->Valid(); it->Next()) {
        std::pair<char, K> key;
        if (!it->GetKey(key) || key.first != prefix) break;
        V value;
        BOOST_REQUIRE(it->GetValue(value));
        out.push_back(Str(key.second, value));
    }
    return out;
}

std::vector<std::string> DumpIndex(CDBWrapper& db) { return Dump<CAddressIndexKey, CAmount>(db, DB_ADDRESSINDEX); }
std::vector<std::string> DumpUnspent(CDBWrapper& db) { return Dump<CAddressUnspentKey, CAddressUnspentValue>(db, DB_ADDRESSUNSPENTINDEX); }

/** Remove one expected line (it must be there) */
void Remove(std::vector<std::string>& v, const std::string& line)
{
    auto it = std::find(v.begin(), v.end(), line);
    BOOST_REQUIRE_MESSAGE(it != v.end(), "missing " + line);
    v.erase(it);
}

std::vector<std::string> Sorted(std::vector<std::string> v)
{
    std::sort(v.begin(), v.end());
    return v;
}

uint160 Hash(unsigned char n) { return uint160(std::vector<unsigned char>(20, n)); }

#define CHECK_SAME(a, b)                                                     \
    do {                                                                     \
        const std::vector<std::string> _a = (a), _b = (b);                   \
        BOOST_CHECK_EQUAL_COLLECTIONS(_a.begin(), _a.end(), _b.begin(), _b.end()); \
    } while (0)

/** Heights of an address/token's entries for a start/end range */
std::vector<int> Heights(CBlockTreeDB& db, const uint160& hash, const std::string& token, int start, int end)
{
    std::vector<IndexEntry> out;
    BOOST_CHECK(db.ReadAddressIndex(hash, 1, token, out, start, end));
    std::vector<int> heights;
    for (const IndexEntry& e : out) heights.push_back(e.first.blockHeight);
    return heights;
}

#define CHECK_HEIGHTS(actual, ...)                                             \
    do {                                                                       \
        const std::vector<int> _act = (actual), _exp = {__VA_ARGS__};          \
        BOOST_CHECK_EQUAL_COLLECTIONS(_act.begin(), _act.end(), _exp.begin(), _exp.end()); \
    } while (0)

/** The address index is a plain global: switched on before the chain below is built */
struct AddressIndexOn {
    bool prevAddressIndex;
    AddressIndexOn() : prevAddressIndex(fAddressIndex) { fAddressIndex = true; }
    ~AddressIndexOn() { fAddressIndex = prevAddressIndex; }
};

/** Regtest chain of 12 blocks, all indexed, with the token database DisconnectBlock needs */
struct AddressIndexSetup : public AddressIndexOn, public TestChain100Setup {
    CScript scriptA;                 // P2PK coinbase script of coinbaseKey
    std::vector<CTransaction> coinbases; // coinbases[h - 1] is the coinbase at height h
    CTokensDB* prevTokensDb;
    CLRUCache<std::string, CDatabasedTokenData>* prevTokensCache;
    bool prevTokenIndex;
    CKey keyB, keyC, keyU, keyF;
    uint160 idA, idB, idC, idU, idF, idS;
    CScript redeem, scriptS, opTrue;

    // Material built by BuildP / BuildX
    CTransaction tx0, tx1, tx2;
    CBlock blockP, blockX;
    CAmount u = 0;

    AddressIndexSetup()
    {
        prevTokensDb = ptokensdb;
        prevTokensCache = ptokensCache;
        prevTokenIndex = fTokenIndex;
        ptokensdb = new CTokensDB(1 << 20, true, true);
        ptokensCache = new CLRUCache<std::string, CDatabasedTokenData>(MAX_CACHE_TOKENS_SIZE);
        fTokenIndex = true;
        TokenTestingSetup::ClearTokenGlobals();

        scriptA = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        coinbases = coinbaseTxns;
        for (int i = 0; i < COINBASE_MATURITY_AFTER_HARDFORK; i++)
            coinbases.push_back(CreateAndProcessBlock({}, scriptA).vtx[0]);

        keyB.MakeNewKey(true);
        keyC.MakeNewKey(true);
        keyU.MakeNewKey(false);
        keyF.MakeNewKey(true);
        idA = coinbaseKey.GetPubKey().GetID();
        idB = keyB.GetPubKey().GetID();
        idC = keyC.GetPubKey().GetID();
        idU = keyU.GetPubKey().GetID();
        idF = keyF.GetPubKey().GetID();
        redeem = CScript() << OP_TRUE;
        idS = CScriptID(redeem);
        scriptS = GetScriptForDestination(CScriptID(redeem));
        opTrue = CScript() << OP_TRUE;
    }

    ~AddressIndexSetup()
    {
        TokenTestingSetup::ClearTokenGlobals();
        delete ptokensdb;
        delete ptokensCache;
        ptokensdb = prevTokensDb;
        ptokensCache = prevTokensCache;
        fTokenIndex = prevTokenIndex;
    }

    static CScript P2PKH(const uint160& id) { return GetScriptForDestination(CKeyID(id)); }

    /** Sign or satisfy every input: P2PK, P2PKH (also token scripts, which start with one),
     *  P2SH of OP_TRUE, bare OP_TRUE */
    CTransaction Sign(CMutableTransaction& mtx, const std::vector<CScript>& prevScripts)
    {
        const CKey* keys[] = {&coinbaseKey, &keyB, &keyF, &keyU};
        for (size_t i = 0; i < mtx.vin.size(); i++) {
            const CScript& prev = prevScripts[i];
            if (prev == scriptS) {
                mtx.vin[i].scriptSig = CScript() << ToByteVector(redeem);
                continue;
            }
            if (prev == opTrue) continue;
            bool signed_ = false;
            for (const CKey* key : keys) {
                CScript p2pk = CScript() << ToByteVector(key->GetPubKey()) << OP_CHECKSIG;
                CScript p2pkh = P2PKH(key->GetPubKey().GetID());
                bool isP2PK = prev == p2pk;
                bool isP2PKH = prev.size() >= p2pkh.size() && std::equal(p2pkh.begin(), p2pkh.end(), prev.begin());
                if (!isP2PK && !isP2PKH) continue;
                std::vector<unsigned char> vchSig;
                uint256 hash = SignatureHash(prev, mtx, i, SIGHASH_ALL);
                BOOST_CHECK(key->Sign(hash, vchSig));
                vchSig.push_back((unsigned char)SIGHASH_ALL);
                mtx.vin[i].scriptSig = CScript() << vchSig;
                if (isP2PKH) mtx.vin[i].scriptSig << ToByteVector(key->GetPubKey());
                signed_ = true;
                break;
            }
            BOOST_REQUIRE(signed_);
        }
        return CTransaction(mtx);
    }

    static void Mine(CBlock& block)
    {
        block.fChecked = false;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
    }

    /** A valid next block on the tip */
    CBlock BuildBlock(const std::vector<CTransaction>& txs, const CScript& coinbaseScript)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler().CreateNewBlock(coinbaseScript);
        CBlock block = pblocktemplate->block;
        block.vtx.resize(1);
        for (const CTransaction& tx : txs) block.vtx.push_back(tx);
        block.nTime = std::max(block.GetBlockTime(), block.GetMaxTransactionTime());
        unsigned int nExtraNonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, chainActive.Tip(), nExtraNonce);
        }
        Mine(block);
        return block;
    }

    CBlock BuildBlock(const std::vector<CTransaction>& txs) { return BuildBlock(txs, scriptA); }

    /** A valid block on any parent (side branches); coinbaseScript makes siblings differ */
    CBlock BuildOn(CBlockIndex* parent, const CScript& coinbaseScript, const std::vector<CTransaction>& txs)
    {
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler().CreateNewBlock(coinbaseScript);
        CBlock block = tmpl->block;
        block.hashPrevBlock = parent->GetBlockHash();
        block.vtx.resize(1);
        for (const CTransaction& tx : txs) block.vtx.push_back(tx);
        block.nBits = GetNextTargetRequired(parent, false);
        block.nTime = std::max({(int64_t)block.GetBlockTime(), (int64_t)block.GetMaxTransactionTime(), (int64_t)parent->GetMedianTimePast() + 1});
        unsigned int nExtraNonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, parent, nExtraNonce);
        }
        Mine(block);
        return block;
    }

    static bool Submit(const CBlock& block)
    {
        ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, nullptr);
        LOCK(cs_main);
        return chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    static CBlockIndex* Tip()
    {
        LOCK(cs_main);
        return chainActive.Tip();
    }

    static void Invalidate(const CBlock& block)
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(mapBlockIndex.count(block.GetHash()));
        BOOST_CHECK(InvalidateBlock(state, Params(), mapBlockIndex[block.GetHash()]));
    }

    static std::vector<IndexEntry> Index(const uint160& hash, int type, const std::string& token = "", int start = 0, int end = 0)
    {
        std::vector<IndexEntry> out;
        BOOST_CHECK(pblocktree->ReadAddressIndex(hash, type, token, out, start, end));
        return out;
    }

    static std::vector<UnspentEntry> Unspent(const uint160& hash, int type, const std::string& token)
    {
        std::vector<UnspentEntry> out;
        BOOST_CHECK(pblocktree->ReadAddressUnspentIndex(hash, type, token, out));
        return out;
    }

    static std::vector<UnspentEntry> UnspentTokens(const uint160& hash, int type)
    {
        std::vector<UnspentEntry> out;
        BOOST_CHECK(pblocktree->ReadAddressUnspentIndex(hash, type, out));
        return out;
    }

    static CAmount Balance(const std::vector<IndexEntry>& entries)
    {
        CAmount sum = 0;
        for (const IndexEntry& e : entries) sum += e.second;
        return sum;
    }

    static CAmount UnspentSum(const std::vector<UnspentEntry>& entries)
    {
        CAmount sum = 0;
        for (const UnspentEntry& e : entries) sum += e.second.satoshis;
        return sum;
    }

    /** Receiving entry and unspent record of output n of tx at (height, txindex) for an address */
    static IndexEntry Recv(int type, const uint160& id, const std::string& token, int h, int txi, const CTransaction& tx, int n, CAmount v)
    {
        return IndexEntry(CAddressIndexKey(type, id, token, h, txi, tx.GetHash(), n, false), v);
    }

    static IndexEntry Spend(int type, const uint160& id, const std::string& token, int h, int txi, const CTransaction& tx, int j, CAmount v)
    {
        return IndexEntry(CAddressIndexKey(type, id, token, h, txi, tx.GetHash(), j, true), -v);
    }

    static UnspentEntry Utxo(int type, const uint160& id, const std::string& token, const CTransaction& tx, int n, CAmount v, int h)
    {
        return UnspentEntry(CAddressUnspentKey(type, id, token, tx.GetHash(), n), CAddressUnspentValue(v, tx.vout[n].scriptPubKey, h));
    }

    /** Coinbase receipts (and their unspent records) of heights [from, to] for idA */
    std::vector<IndexEntry> CoinbaseRecv(int from, int to)
    {
        std::vector<IndexEntry> out;
        for (int h = from; h <= to; h++) out.push_back(Recv(1, idA, YAC, h, 0, coinbases[h - 1], 0, coinbases[h - 1].vout[0].nValue));
        return out;
    }

    /** Unspent records have no height in the key: they sort by txid, use InKeyOrder */
    std::vector<UnspentEntry> CoinbaseUtxos(int from, int to)
    {
        std::vector<UnspentEntry> out;
        for (int h = from; h <= to; h++) out.push_back(Utxo(1, idA, YAC, coinbases[h - 1], 0, coinbases[h - 1].vout[0].nValue, h));
        return out;
    }

    /** P (height 13): tx0 spends coinbase 1 into one output of each kind */
    void BuildP()
    {
        const CTransaction& cb = coinbases[0];
        u = cb.vout[0].nValue / 20;
        CMutableTransaction m;
        m.vin.emplace_back(COutPoint(cb.GetHash(), 0));
        m.vout.emplace_back(2 * u, CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG); // 0 P2PK A
        m.vout.emplace_back(2 * u, P2PKH(idB));                                                          // 1
        m.vout.emplace_back(2 * u, scriptS);                                                             // 2 P2SH
        m.vout.emplace_back(u, opTrue);                                                                  // 3
        m.vout.emplace_back(u, GetScriptForCltvP2PKH(1000, CKeyID(idC)));                                // 4
        m.vout.emplace_back(u, GetScriptForCsvP2PKH(10, CKeyID(idC)));                                   // 5
        m.vout.emplace_back(u, CScript() << ToByteVector(keyU.GetPubKey()) << OP_CHECKSIG);             // 6 uncompressed
        m.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(1, 'x'));           // 7
        m.vout.emplace_back(u, GetScriptForMultisig(1, {keyB.GetPubKey()}));                            // 8
        m.vout.emplace_back(u, P2PKH(idB));                                                              // 9 same address again
        m.vout.emplace_back(u, GetScriptForCltvP2SH(1000, keyC.GetPubKey()));                           // 10
        m.vout.emplace_back(u, GetScriptForCsvP2SH(10, keyC.GetPubKey()));                              // 11
        m.vout.emplace_back(cb.vout[0].nValue - 14 * u - u / 10, P2PKH(idA));                           // 12 change
        tx0 = Sign(m, {cb.vout[0].scriptPubKey});
        blockP = BuildBlock({tx0});
        coinbases.push_back(blockP.vtx[0]);
    }

    /** X (height 14): tx1 spends tx0's P2PK, P2SH, P2PKH and OP_TRUE outputs (input index
     *  differs from the output index for P2SH and P2PKH); tx2 spends tx1's P2SH output */
    void BuildX()
    {
        CMutableTransaction m1;
        for (int n : {0, 2, 1, 3}) m1.vin.emplace_back(COutPoint(tx0.GetHash(), n));
        m1.vout.emplace_back(u, P2PKH(idB));                                                 // 0
        m1.vout.emplace_back(2 * u, scriptS);                                                // 1
        m1.vout.emplace_back(u, opTrue);                                                     // 2
        m1.vout.emplace_back(0, CScript() << OP_RETURN << std::vector<unsigned char>(1, 'y')); // 3
        m1.vout.emplace_back(u, CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG); // 4
        m1.vout.emplace_back(u, GetScriptForCsvP2PKH(20, CKeyID(idC)));                      // 5
        tx1 = Sign(m1, {tx0.vout[0].scriptPubKey, tx0.vout[2].scriptPubKey, tx0.vout[1].scriptPubKey, tx0.vout[3].scriptPubKey});
        CMutableTransaction m2;
        m2.vin.emplace_back(COutPoint(tx1.GetHash(), 1));
        m2.vout.emplace_back(2 * u - u / 10, P2PKH(idA));
        tx2 = Sign(m2, {tx1.vout[1].scriptPubKey});
        blockX = BuildBlock({tx1, tx2});
        coinbases.push_back(blockX.vtx[0]);
    }

    // Expected entries after P (and X) per address

    std::vector<IndexEntry> ExpectA(bool withX)
    {
        std::vector<IndexEntry> e = CoinbaseRecv(1, withX ? 14 : 13);
        e.push_back(Spend(1, idA, YAC, 13, 1, tx0, 0, coinbases[0].vout[0].nValue));
        e.push_back(Recv(1, idA, YAC, 13, 1, tx0, 0, 2 * u));
        e.push_back(Recv(1, idA, YAC, 13, 1, tx0, 12, tx0.vout[12].nValue));
        if (withX) {
            e.push_back(Spend(1, idA, YAC, 14, 1, tx1, 0, 2 * u));
            e.push_back(Recv(1, idA, YAC, 14, 1, tx1, 4, u));
            e.push_back(Recv(1, idA, YAC, 14, 2, tx2, 0, tx2.vout[0].nValue));
        }
        return e;
    }

    std::vector<UnspentEntry> ExpectUtxoA(bool withX)
    {
        std::vector<UnspentEntry> e = CoinbaseUtxos(2, withX ? 14 : 13);
        if (!withX) e.push_back(Utxo(1, idA, YAC, tx0, 0, 2 * u, 13));
        e.push_back(Utxo(1, idA, YAC, tx0, 12, tx0.vout[12].nValue, 13));
        if (withX) {
            e.push_back(Utxo(1, idA, YAC, tx1, 4, u, 14));
            e.push_back(Utxo(1, idA, YAC, tx2, 0, tx2.vout[0].nValue, 14));
        }
        return e;
    }

    std::vector<IndexEntry> ExpectB(bool withX)
    {
        std::vector<IndexEntry> e{Recv(1, idB, YAC, 13, 1, tx0, 1, 2 * u), Recv(1, idB, YAC, 13, 1, tx0, 9, u)};
        if (withX) {
            e.push_back(Spend(1, idB, YAC, 14, 1, tx1, 2, 2 * u));
            e.push_back(Recv(1, idB, YAC, 14, 1, tx1, 0, u));
        }
        return e;
    }

    std::vector<UnspentEntry> ExpectUtxoB(bool withX)
    {
        std::vector<UnspentEntry> e;
        if (!withX) e.push_back(Utxo(1, idB, YAC, tx0, 1, 2 * u, 13));
        e.push_back(Utxo(1, idB, YAC, tx0, 9, u, 13));
        if (withX) e.push_back(Utxo(1, idB, YAC, tx1, 0, u, 14));
        return e;
    }

    std::vector<IndexEntry> ExpectS(bool withX)
    {
        std::vector<IndexEntry> e{Recv(2, idS, YAC, 13, 1, tx0, 2, 2 * u)};
        if (withX) {
            e.push_back(Spend(2, idS, YAC, 14, 1, tx1, 1, 2 * u));
            e.push_back(Recv(2, idS, YAC, 14, 1, tx1, 1, 2 * u));
            e.push_back(Spend(2, idS, YAC, 14, 2, tx2, 0, 2 * u));
        }
        return e;
    }

    std::vector<UnspentEntry> ExpectUtxoS(bool withX)
    {
        if (withX) return {}; // tx1's P2SH output is created and spent in the same block
        return {Utxo(2, idS, YAC, tx0, 2, 2 * u, 13)};
    }

    std::vector<IndexEntry> ExpectC(bool withX)
    {
        // The CLTV/CSV P2SH outputs (10, 11) pay keyC's public key but aren't indexed
        std::vector<IndexEntry> e{Recv(1, idC, YAC, 13, 1, tx0, 4, u), Recv(1, idC, YAC, 13, 1, tx0, 5, u)};
        if (withX) e.push_back(Recv(1, idC, YAC, 14, 1, tx1, 5, u));
        return e;
    }

    std::vector<UnspentEntry> ExpectUtxoC(bool withX)
    {
        std::vector<UnspentEntry> e{Utxo(1, idC, YAC, tx0, 4, u, 13), Utxo(1, idC, YAC, tx0, 5, u, 13)};
        if (withX) e.push_back(Utxo(1, idC, YAC, tx1, 5, u, 14));
        return e;
    }

    /** Everything that should be in the index after P (and X): nothing else is indexed */
    std::vector<std::string> ExpectAllIndex(bool withX)
    {
        std::vector<IndexEntry> all;
        for (const auto& v : {ExpectA(withX), ExpectB(withX), ExpectS(withX), ExpectC(withX)})
            all.insert(all.end(), v.begin(), v.end());
        all.push_back(Recv(1, idU, YAC, 13, 1, tx0, 6, u));
        return InKeyOrder(all);
    }

    std::vector<std::string> ExpectAllUnspent(bool withX)
    {
        std::vector<UnspentEntry> all;
        for (const auto& v : {ExpectUtxoA(withX), ExpectUtxoB(withX), ExpectUtxoS(withX), ExpectUtxoC(withX)})
            all.insert(all.end(), v.begin(), v.end());
        all.push_back(Utxo(1, idU, YAC, tx0, 6, u, 13));
        return InKeyOrder(all);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(addressindex_tests, AddressIndexSetup)

BOOST_FIXTURE_TEST_CASE(key_serialization, BasicTestingSetup)
{
    const uint160 h = Hash(0x5a);
    const uint256 txid = uint256S("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    // Index key: heights and tx positions are big-endian so LevelDB sorts them numerically
    CAddressIndexKey key(1, h, "YAC", 0x01020304, 0x0a0b0c0d, txid, 0x11223344, true);
    std::vector<unsigned char> b = Bytes(key);
    BOOST_REQUIRE_EQUAL(b.size(), 67U + 3);
    BOOST_CHECK_EQUAL(b[0], 1);
    BOOST_CHECK(std::equal(h.begin(), h.end(), b.begin() + 1));
    BOOST_CHECK_EQUAL(b[21], 3);
    BOOST_CHECK_EQUAL(std::string(b.begin() + 22, b.begin() + 25), "YAC");
    BOOST_CHECK(std::vector<unsigned char>(b.begin() + 25, b.begin() + 33) == std::vector<unsigned char>({1, 2, 3, 4, 0x0a, 0x0b, 0x0c, 0x0d}));
    BOOST_CHECK(std::equal(txid.begin(), txid.end(), b.begin() + 33));
    BOOST_CHECK(std::vector<unsigned char>(b.begin() + 65, b.begin() + 69) == std::vector<unsigned char>({0x44, 0x33, 0x22, 0x11}));
    BOOST_CHECK_EQUAL(b[69], 1);

    CAddressIndexKey back;
    CDataStream ss(b, SER_DISK, CLIENT_VERSION);
    ss >> back;
    BOOST_CHECK_EQUAL(Str(back, 0), Str(key, 0));
    // Any non-zero spending byte reads as true
    b[69] = 2;
    CDataStream ss2(b, SER_DISK, CLIENT_VERSION);
    ss2 >> back;
    BOOST_CHECK(back.spending);

    // Constructors: the one without a token name means YAC; default and SetNull clear everything
    CAddressIndexKey yac(2, h, 7, 3, txid, 5, false);
    BOOST_CHECK_EQUAL(Str(yac, 0), Str(CAddressIndexKey(2, h, YAC, 7, 3, txid, 5, false), 0));
    CAddressIndexKey null;
    BOOST_CHECK_EQUAL(Str(null, 0), strprintf("type 0 %s  height 0 tx 0 %s n 0 receive amount 0", uint160().GetHex(), uint256().GetHex()));
    key.SetNull();
    BOOST_CHECK_EQUAL(Str(key, 0), Str(null, 0));

    // Unspent key and value
    CAddressUnspentKey ukey(1, h, "TOKEN", txid, 9);
    std::vector<unsigned char> ub = Bytes(ukey);
    BOOST_REQUIRE_EQUAL(ub.size(), 58U + 5);
    BOOST_CHECK_EQUAL(ub[0], 1);
    BOOST_CHECK(std::equal(h.begin(), h.end(), ub.begin() + 1));
    BOOST_CHECK_EQUAL(ub[21], 5);
    BOOST_CHECK_EQUAL(std::string(ub.begin() + 22, ub.begin() + 27), "TOKEN");
    BOOST_CHECK(std::equal(txid.begin(), txid.end(), ub.begin() + 27));
    BOOST_CHECK(std::vector<unsigned char>(ub.begin() + 59, ub.end()) == std::vector<unsigned char>({9, 0, 0, 0}));
    CAddressUnspentValue uval(123, CScript() << OP_TRUE, 77);
    BOOST_CHECK(!uval.IsNull());
    // Value: amount (8 bytes LE), script with its length, height (4 bytes LE)
    BOOST_CHECK(Bytes(uval) == std::vector<unsigned char>({123, 0, 0, 0, 0, 0, 0, 0, 1, OP_TRUE, 77, 0, 0, 0}));
    CAddressUnspentKey uback;
    CAddressUnspentValue vback;
    CDataStream us(SER_DISK, CLIENT_VERSION);
    us << ukey << uval;
    us >> uback >> vback;
    BOOST_CHECK_EQUAL(Str(uback, vback), Str(ukey, uval));
    BOOST_CHECK_EQUAL(Str(CAddressUnspentKey(2, h, txid, 1), uval), Str(CAddressUnspentKey(2, h, YAC, txid, 1), uval));
    CAddressUnspentKey unull;
    ukey.SetNull();
    BOOST_CHECK_EQUAL(Str(ukey, uval), Str(unull, uval));
    BOOST_CHECK_EQUAL(unull.token, "");
    BOOST_CHECK(unull.hashBytes.IsNull() && unull.txhash.IsNull() && unull.type == 0 && unull.index == 0);

    // Value: satoshis -1 is the "erase" marker; an empty script round trips too
    CAddressUnspentValue vnull;
    BOOST_CHECK(vnull.IsNull());
    BOOST_CHECK_EQUAL(vnull.satoshis, -1);
    BOOST_CHECK(vnull.script.empty());
    BOOST_CHECK_EQUAL(vnull.blockHeight, 0);
    BOOST_CHECK(!CAddressUnspentValue(0, CScript(), 1).IsNull());
    BOOST_CHECK(CAddressUnspentValue(-1, CScript() << OP_TRUE, 5).IsNull());
    uval.SetNull();
    BOOST_CHECK(uval.IsNull() && uval.script.empty() && uval.blockHeight == 0);
    CAddressUnspentValue empty(0, CScript(), 3), emptyBack;
    CDataStream es(SER_DISK, CLIENT_VERSION);
    es << empty;
    es >> emptyBack;
    BOOST_CHECK(emptyBack.satoshis == 0 && emptyBack.script.empty() && emptyBack.blockHeight == 3);

    // Iterator keys are byte prefixes of the full key, which is what the reads seek to
    const std::string token(30, 'Z');
    CAddressIndexKey full(1, h, token, 500, 2, txid, 3, false);
    std::vector<unsigned char> fb = Bytes(full);
    CAddressIndexIteratorKey ik(1, h);
    CAddressIndexIteratorTokenKey tk(1, h, token);
    CAddressIndexIteratorHeightKey hk(1, h, token, 500);
    std::vector<unsigned char> ib = Bytes(ik), tb = Bytes(tk), hb = Bytes(hk);
    BOOST_CHECK_EQUAL(ib.size(), 21U);
    BOOST_CHECK_EQUAL(ik.GetSerializeSize(), ib.size());
    BOOST_CHECK_EQUAL(tb.size(), 22U + token.size());
    BOOST_CHECK_EQUAL(hb.size(), 26U + token.size());
    BOOST_CHECK(std::equal(ib.begin(), ib.end(), fb.begin()));
    BOOST_CHECK(std::equal(tb.begin(), tb.end(), fb.begin()));
    BOOST_CHECK(std::equal(hb.begin(), hb.end(), fb.begin()));
    // ... and of the unspent key (type, hash, token)
    std::vector<unsigned char> ufull = Bytes(CAddressUnspentKey(1, h, token, txid, 3));
    BOOST_CHECK(std::equal(tb.begin(), tb.end(), ufull.begin()));

    CAddressIndexIteratorKey ikBack;
    CAddressIndexIteratorTokenKey tkBack;
    CAddressIndexIteratorHeightKey hkBack;
    CDataStream is(SER_DISK, CLIENT_VERSION);
    is << ik << tk << hk;
    is >> ikBack >> tkBack >> hkBack;
    BOOST_CHECK(ikBack.type == 1 && ikBack.hashBytes == h);
    BOOST_CHECK(tkBack.type == 1 && tkBack.hashBytes == h && tkBack.token == token);
    BOOST_CHECK(hkBack.type == 1 && hkBack.hashBytes == h && hkBack.token == token && hkBack.blockHeight == 500);
    BOOST_CHECK_EQUAL(CAddressIndexIteratorTokenKey(1, h).token, YAC);
    BOOST_CHECK_EQUAL(CAddressIndexIteratorHeightKey(1, h, 9).token, YAC);
    BOOST_CHECK_EQUAL(CAddressIndexIteratorHeightKey(1, h, 9).blockHeight, 9);
    ikBack.SetNull();
    tkBack.SetNull();
    hkBack.SetNull();
    BOOST_CHECK(ikBack.type == 0 && ikBack.hashBytes.IsNull());
    BOOST_CHECK(tkBack.type == 0 && tkBack.hashBytes.IsNull() && tkBack.token.empty());
    BOOST_CHECK(hkBack.type == 0 && hkBack.hashBytes.IsNull() && hkBack.token.empty() && hkBack.blockHeight == 0);
    BOOST_CHECK(CAddressIndexIteratorKey().hashBytes.IsNull());
    BOOST_CHECK(CAddressIndexIteratorTokenKey().token.empty());
    BOOST_CHECK_EQUAL(CAddressIndexIteratorHeightKey().blockHeight, 0);
}

BOOST_FIXTURE_TEST_CASE(address_index_write_read_erase, TestingSetup)
{
    CBlockTreeDB db(1 << 20, true, true);
    const uint160 h1 = Hash(0x11), h2 = Hash(0x22), h3 = Hash(0x33);
    const uint256 txA = uint256S("0xaa"), txB = uint256S("0xbb");

    // Empty batches are no-ops
    BOOST_CHECK(db.WriteAddressIndex({}));
    BOOST_CHECK(db.EraseAddressIndex({}));
    BOOST_CHECK(DumpIndex(db).empty());

    // Written out of order; tokens sort by length first ("TOK" < "YAC" < "TOKEN")
    const IndexEntry y65536(CAddressIndexKey(1, h1, 65536, 1, txA, 0, false), 6);
    const IndexEntry y255(CAddressIndexKey(1, h1, 255, 2, txA, 1, false), 1);
    const IndexEntry y256(CAddressIndexKey(1, h1, 256, 0, txB, 3, false), 2);
    const IndexEntry tok(CAddressIndexKey(1, h1, "TOK", 256, 1, txA, 0, false), 7);
    const IndexEntry token(CAddressIndexKey(1, h1, "TOKEN", 256, 1, txA, 1, false), 8);
    const IndexEntry y300spend(CAddressIndexKey(1, h1, 300, 4, txB, 2, true), -3);
    const IndexEntry y300recv(CAddressIndexKey(1, h1, 300, 4, txB, 2, false), 3);
    const IndexEntry other(CAddressIndexKey(1, h2, 256, 0, txA, 0, false), 9);
    const IndexEntry p2sh(CAddressIndexKey(2, h3, 256, 0, txA, 0, false), 10);
    BOOST_CHECK(db.WriteAddressIndex({y65536, y255, y256, tok, token, y300spend, y300recv, other, p2sh}));

    // All tokens of the address, in key order; the overload without a token name is the same
    const std::vector<std::string> all = Strs<CAddressIndexKey, CAmount>({tok, y255, y256, y300recv, y300spend, y65536, token});
    std::vector<IndexEntry> out;
    BOOST_CHECK(db.ReadAddressIndex(h1, 1, out));
    CHECK_SAME(Strs(out), all);
    out.clear();
    BOOST_CHECK(db.ReadAddressIndex(h1, 1, "", out));
    CHECK_SAME(Strs(out), all);

    // One token: exact name only
    auto read = [&](const uint160& h, int type, const std::string& name) {
        std::vector<IndexEntry> r;
        BOOST_CHECK(db.ReadAddressIndex(h, type, name, r));
        return Strs(r);
    };
    CHECK_SAME(read(h1, 1, "YAC"), (Strs<CAddressIndexKey, CAmount>({y255, y256, y300recv, y300spend, y65536})));
    CHECK_SAME(read(h1, 1, "TOK"), (Strs<CAddressIndexKey, CAmount>({tok})));
    CHECK_SAME(read(h1, 1, "TOKEN"), (Strs<CAddressIndexKey, CAmount>({token})));
    BOOST_CHECK(read(h1, 1, "TOKE").empty());
    // Other addresses and types: the neighbour stops the scan, nothing past the end
    CHECK_SAME(read(h2, 1, ""), (Strs<CAddressIndexKey, CAmount>({other})));
    CHECK_SAME(read(h3, 2, ""), (Strs<CAddressIndexKey, CAmount>({p2sh})));
    BOOST_CHECK(read(h1, 2, "").empty());
    BOOST_CHECK(read(Hash(0x15), 1, "").empty());
    BOOST_CHECK(read(Hash(0x44), 2, "").empty());

    // Results are appended to what the caller passes in
    out = {other};
    BOOST_CHECK(db.ReadAddressIndex(h1, 1, "TOK", out));
    CHECK_SAME(Strs(out), (Strs<CAddressIndexKey, CAmount>({other, tok})));

    // Rewriting a key replaces its amount (last one in a batch wins)
    const IndexEntry y255b(y255.first, 11), y255c(y255.first, 12);
    BOOST_CHECK(db.WriteAddressIndex({y255b, y255c}));
    // Erase matches the whole key including the spending flag, not the amount
    BOOST_CHECK(db.EraseAddressIndex({y300spend, IndexEntry(y65536.first, 0)}));
    // Erasing what isn't there is fine
    BOOST_CHECK(db.EraseAddressIndex({y300spend, IndexEntry(CAddressIndexKey(1, h1, 1, 0, txA, 0, false), 0)}));
    CHECK_SAME(read(h1, 1, "YAC"), (Strs<CAddressIndexKey, CAmount>({y255c, y256, y300recv})));
    BOOST_CHECK_EQUAL(DumpIndex(db).size(), 7U);
}

BOOST_FIXTURE_TEST_CASE(address_index_height_range, TestingSetup)
{
    CBlockTreeDB db(1 << 20, true, true);
    const uint160 h1 = Hash(0x11), h2 = Hash(0x22);
    const uint256 tx = uint256S("0xaa");
    BOOST_CHECK(db.WriteAddressIndex({
        IndexEntry(CAddressIndexKey(1, h1, 65536, 0, tx, 0, false), 1),
        IndexEntry(CAddressIndexKey(1, h1, 256, 0, tx, 0, false), 1),
        IndexEntry(CAddressIndexKey(1, h1, 255, 0, tx, 0, false), 1),
        IndexEntry(CAddressIndexKey(1, h1, "TOK", 256, 0, tx, 0, false), 1),
        IndexEntry(CAddressIndexKey(1, h1, "TOKEN", 256, 0, tx, 0, false), 1),
        IndexEntry(CAddressIndexKey(1, h2, 256, 0, tx, 0, false), 1),
    }));

    // Both ends are inclusive; 255 < 256 < 65536 in key order (big-endian)
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 256, 256), 256);
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 255, 256), 255, 256);
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 256, 65536), 256, 65536);
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 257, 65535));
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 65536, 70000), 65536);
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 70000, 80000));
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 1, 254));
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 1, 255), 255);
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 300, 200));
    // start 0: from the first entry, end still applies
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 0, 256), 255, 256);
    CHECK_HEIGHTS(Heights(db, h1, "YAC", -1, 256), 255, 256);
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 256, -1), 255, 256, 65536);
    // start is only used together with end (the RPC always passes both)
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 256, 0), 255, 256, 65536);
    CHECK_HEIGHTS(Heights(db, h1, "YAC", 0, 0), 255, 256, 65536);
    // The range stays within one token and one address
    CHECK_HEIGHTS(Heights(db, h1, "TOK", 256, 256), 256);
    CHECK_HEIGHTS(Heights(db, h1, "TOKEN", 1, 255));
    CHECK_HEIGHTS(Heights(db, h1, "TOKEN", 1, 300), 256);
    CHECK_HEIGHTS(Heights(db, h2, "YAC", 1, 1000), 256);
}

BOOST_FIXTURE_TEST_CASE(address_index_corrupt_records, TestingSetup)
{
    CBlockTreeDB db(1 << 20, true, true);
    const uint160 h1 = Hash(0x11), h2 = Hash(0x22), hLast = Hash(0xee);
    const uint256 tx = uint256S("0xaa");
    const IndexEntry e1(CAddressIndexKey(1, h1, 10, 0, tx, 0, false), 5);
    const IndexEntry e2(CAddressIndexKey(1, h2, 10, 0, tx, 0, false), 6);
    const IndexEntry eLast(CAddressIndexKey(1, hLast, 10, 0, tx, 0, false), 7);
    BOOST_CHECK(db.WriteAddressIndex({e1, e2, eLast}));

    // A truncated key in front of an address's records: the scan stops there
    BOOST_CHECK(db.Write(std::make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorTokenKey(1, h1, "YAC")), CAmount(1)));
    std::vector<IndexEntry> out;
    BOOST_CHECK(db.ReadAddressIndex(h1, 1, "YAC", out));
    BOOST_CHECK(out.empty());
    BOOST_CHECK(db.ReadAddressIndex(h1, 1, out));
    BOOST_CHECK(out.empty());

    // A value that doesn't deserialize: false, with the records before it already returned
    BOOST_CHECK(db.Write(std::make_pair(DB_ADDRESSINDEX, CAddressIndexKey(1, h2, 20, 0, tx, 0, false)), (unsigned char)1));
    BOOST_CHECK(!db.ReadAddressIndex(h2, 1, "YAC", out));
    CHECK_SAME(Strs(out), (Strs<CAddressIndexKey, CAmount>({e2})));
    out.clear();
    BOOST_CHECK(!db.ReadAddressIndex(h2, 1, out));
    CHECK_SAME(Strs(out), (Strs<CAddressIndexKey, CAmount>({e2})));

    // A well-formed address key under the next prefix isn't an address index record
    BOOST_CHECK(db.Write(std::make_pair('b', CAddressIndexKey(1, hLast, 20, 0, tx, 0, false)), CAmount(8)));
    out.clear();
    BOOST_CHECK(db.ReadAddressIndex(hLast, 1, out));
    CHECK_SAME(Strs(out), (Strs<CAddressIndexKey, CAmount>({eLast})));
}

BOOST_FIXTURE_TEST_CASE(unspent_index_update_and_read, TestingSetup)
{
    CBlockTreeDB db(1 << 20, true, true);
    const uint160 h1 = Hash(0x11), h2 = Hash(0x22);
    const uint256 txA = uint256S("0xaa"), txB = uint256S("0xbb"), txC = uint256S("0xcc");
    const CScript s1 = CScript() << OP_TRUE, s2 = CScript() << OP_2 << OP_DROP;

    BOOST_CHECK(db.UpdateAddressUnspentIndex({}));
    BOOST_CHECK(DumpUnspent(db).empty());

    const UnspentEntry yA(CAddressUnspentKey(1, h1, txA, 0), CAddressUnspentValue(5, s1, 10));
    const UnspentEntry yB(CAddressUnspentKey(1, h1, txB, 1), CAddressUnspentValue(0, CScript(), 11)); // zero isn't "erase"
    const UnspentEntry tok(CAddressUnspentKey(1, h1, "TOK", txA, 2), CAddressUnspentValue(7, s2, 12));
    const UnspentEntry token(CAddressUnspentKey(1, h1, "TOKEN", txA, 3), CAddressUnspentValue(8, s1, 13));
    const UnspentEntry other(CAddressUnspentKey(1, h2, txA, 0), CAddressUnspentValue(9, s1, 14));
    BOOST_CHECK(db.UpdateAddressUnspentIndex({token, yB, other, tok, yA}));

    auto read = [&](const uint160& h, const std::string& name) {
        std::vector<UnspentEntry> r;
        BOOST_CHECK(db.ReadAddressUnspentIndex(h, 1, name, r));
        return Strs(r);
    };
    auto readTokens = [&](const uint160& h) {
        std::vector<UnspentEntry> r;
        BOOST_CHECK(db.ReadAddressUnspentIndex(h, 1, r));
        return Strs(r);
    };
    typedef CAddressUnspentKey K;
    typedef CAddressUnspentValue V;
    CHECK_SAME(read(h1, "YAC"), (Strs<K, V>({yA, yB})));
    CHECK_SAME(read(h1, "TOK"), (Strs<K, V>({tok})));
    CHECK_SAME(read(h1, ""), (Strs<K, V>({tok, yA, yB, token})));
    BOOST_CHECK(read(h1, "NOPE").empty());
    CHECK_SAME(read(h2, "YAC"), (Strs<K, V>({other})));
    BOOST_CHECK(read(Hash(0x99), "").empty());

    // Without a token name: every token but YAC (the scan goes on past the YAC records)
    CHECK_SAME(readTokens(h1), (Strs<K, V>({tok, token})));
    BOOST_CHECK(readTokens(h2).empty());
    BOOST_CHECK(readTokens(Hash(0x99)).empty());

    // Appends to the caller's vector
    std::vector<UnspentEntry> out{other};
    BOOST_CHECK(db.ReadAddressUnspentIndex(h1, 1, "TOK", out));
    BOOST_CHECK(db.ReadAddressUnspentIndex(h1, 1, out));
    CHECK_SAME(Strs(out), (Strs<K, V>({other, tok, tok, token})));

    // A null value erases; so does an explicit -1 amount; erasing a missing key is fine
    BOOST_CHECK(db.UpdateAddressUnspentIndex({UnspentEntry(yB.first, V()), UnspentEntry(tok.first, V(-1, s2, 12)),
                                              UnspentEntry(K(1, h1, txC, 9), V())}));
    CHECK_SAME(read(h1, ""), (Strs<K, V>({yA, token})));

    // Several updates of one key in a batch are applied in order
    const K k(1, h2, txC, 5);
    BOOST_CHECK(db.UpdateAddressUnspentIndex({UnspentEntry(k, V(1, s1, 1)), UnspentEntry(k, V())}));
    CHECK_SAME(read(h2, "YAC"), (Strs<K, V>({other})));
    BOOST_CHECK(db.UpdateAddressUnspentIndex({UnspentEntry(k, V()), UnspentEntry(k, V(2, s1, 2))}));
    CHECK_SAME(read(h2, "YAC"), (Strs<K, V>({other, UnspentEntry(k, V(2, s1, 2))})));
    BOOST_CHECK(db.UpdateAddressUnspentIndex({UnspentEntry(k, V(3, s1, 3)), UnspentEntry(k, V(4, s2, 4))}));
    CHECK_SAME(read(h2, "YAC"), (Strs<K, V>({other, UnspentEntry(k, V(4, s2, 4))})));
}

BOOST_FIXTURE_TEST_CASE(unspent_index_corrupt_records, TestingSetup)
{
    CBlockTreeDB db(1 << 20, true, true);
    const uint160 h1 = Hash(0x11), h2 = Hash(0x22), hLast = Hash(0xee);
    const uint256 txA = uint256S("0xaa"), txB = uint256S("0xbb");
    const CScript s = CScript() << OP_TRUE;
    typedef CAddressUnspentKey K;
    typedef CAddressUnspentValue V;
    const UnspentEntry y1(K(1, h1, txA, 0), V(1, s, 1)), t1(K(1, h1, "TOKEN", txA, 1), V(2, s, 1));
    const UnspentEntry y2(K(1, h2, txA, 0), V(3, s, 1));
    const UnspentEntry yLast(K(1, hLast, txA, 0), V(4, s, 1)), tLast(K(1, hLast, "TOK", txA, 1), V(5, s, 1));
    BOOST_CHECK(db.UpdateAddressUnspentIndex({y1, t1, y2, yLast, tLast}));

    // Truncated key in front of the address's records: both reads stop there
    BOOST_CHECK(db.Write(std::make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorTokenKey(1, h1, "TOK")), V(9, s, 9)));
    std::vector<UnspentEntry> out;
    BOOST_CHECK(db.ReadAddressUnspentIndex(h1, 1, "TOK", out));
    BOOST_CHECK(out.empty());
    BOOST_CHECK(db.ReadAddressUnspentIndex(h1, 1, out));
    BOOST_CHECK(out.empty());

    // Undecodable value: false from both reads (the YAC filter comes after decoding)
    BOOST_CHECK(db.Write(std::make_pair(DB_ADDRESSUNSPENTINDEX, K(1, h2, txB, 0)), (unsigned char)1));
    BOOST_CHECK(!db.ReadAddressUnspentIndex(h2, 1, "YAC", out));
    CHECK_SAME(Strs(out), (Strs<K, V>({y2})));
    out.clear();
    BOOST_CHECK(!db.ReadAddressUnspentIndex(h2, 1, out));
    BOOST_CHECK(out.empty());

    // A well-formed unspent key under a later prefix isn't returned
    BOOST_CHECK(db.Write(std::make_pair('v', K(1, hLast, "TOKEN", txA, 2)), V(6, s, 1)));
    BOOST_CHECK(db.ReadAddressUnspentIndex(hLast, 1, "", out));
    CHECK_SAME(Strs(out), (Strs<K, V>({tLast, yLast})));
    out.clear();
    BOOST_CHECK(db.ReadAddressUnspentIndex(hLast, 1, out));
    CHECK_SAME(Strs(out), (Strs<K, V>({tLast})));
}

/* The fixture's chain: every coinbase (P2PK) is indexed under the key's hash, genesis isn't */
BOOST_AUTO_TEST_CASE(coinbase_chain_indexed)
{
    for (const CTransaction& cb : coinbases) BOOST_REQUIRE_EQUAL(cb.vout.size(), 1U);
    CHECK_SAME(Strs(Index(idA, 1)), Strs(CoinbaseRecv(1, 12)));
    CHECK_SAME(Strs(Unspent(idA, 1, YAC)), InKeyOrder(CoinbaseUtxos(1, 12)));
    CHECK_SAME(DumpIndex(*pblocktree), Strs(CoinbaseRecv(1, 12)));
    CHECK_SAME(DumpUnspent(*pblocktree), InKeyOrder(CoinbaseUtxos(1, 12)));
    BOOST_CHECK_EQUAL(Balance(Index(idA, 1)), UnspentSum(Unspent(idA, 1, YAC)));
    BOOST_CHECK(Index(idA, 2).empty());
    BOOST_CHECK(UnspentTokens(idA, 1).empty());
}

/* Receipts and spends of each kind of output, in one block and across two */
BOOST_AUTO_TEST_CASE(outputs_and_spends_by_script_type)
{
    BuildP();
    BOOST_REQUIRE(Submit(blockP));
    CHECK_SAME(DumpIndex(*pblocktree), ExpectAllIndex(false));
    CHECK_SAME(DumpUnspent(*pblocktree), ExpectAllUnspent(false));

    BuildX();
    BOOST_REQUIRE(Submit(blockX));
    // P2PK and P2PKH outputs of one key share an address
    CHECK_SAME(Strs(Index(idA, 1, YAC)), InKeyOrder(ExpectA(true)));
    CHECK_SAME(Strs(Unspent(idA, 1, YAC)), InKeyOrder(ExpectUtxoA(true)));
    // Two outputs to one address in a tx; the bare multisig output to keyB isn't credited
    CHECK_SAME(Strs(Index(idB, 1)), InKeyOrder(ExpectB(true)));
    CHECK_SAME(Strs(Unspent(idB, 1, YAC)), InKeyOrder(ExpectUtxoB(true)));
    // P2SH (type 2): spent in the same block it was created, so no unspent record is left
    CHECK_SAME(Strs(Index(idS, 2)), InKeyOrder(ExpectS(true)));
    BOOST_CHECK(Unspent(idS, 2, YAC).empty());
    // Uncompressed P2PK: hash of the 65-byte key
    CHECK_SAME(Strs(Index(idU, 1)), (Strs<CAddressIndexKey, CAmount>({Recv(1, idU, YAC, 13, 1, tx0, 6, u)})));
    // Timelocked P2PKH outputs count for the key; the timelocked P2SH outputs don't
    CHECK_SAME(Strs(Index(idC, 1)), InKeyOrder(ExpectC(true)));
    CHECK_SAME(Strs(Unspent(idC, 1, YAC)), InKeyOrder(ExpectUtxoC(true)));

    for (const uint160& id : {idA, idB, idC, idU})
        BOOST_CHECK_EQUAL(Balance(Index(id, 1)), UnspentSum(Unspent(id, 1, YAC)));

    // Nothing else (OP_TRUE, OP_RETURN, multisig, the OP_TRUE input) is indexed
    CHECK_SAME(DumpIndex(*pblocktree), ExpectAllIndex(true));
    CHECK_SAME(DumpUnspent(*pblocktree), ExpectAllUnspent(true));
}

/* Disconnecting blocks removes their entries and restores the unspent records they spent */
BOOST_AUTO_TEST_CASE(disconnect_and_reconnect)
{
    BuildP();
    BOOST_REQUIRE(Submit(blockP));
    const std::vector<std::string> indexP = DumpIndex(*pblocktree), unspentP = DumpUnspent(*pblocktree);
    BuildX();
    BOOST_REQUIRE(Submit(blockX));
    const std::vector<std::string> indexX = DumpIndex(*pblocktree), unspentX = DumpUnspent(*pblocktree);
    CBlock blockZ = BuildBlock({});
    BOOST_REQUIRE(Submit(blockZ));
    BOOST_CHECK(DumpIndex(*pblocktree).size() == indexX.size() + 1);

    // Both X and its child are disconnected
    Invalidate(blockX);
    BOOST_REQUIRE(Tip()->GetBlockHash() == blockP.GetHash());
    CHECK_SAME(DumpIndex(*pblocktree), indexP);
    CHECK_SAME(DumpUnspent(*pblocktree), unspentP);

    // The same transactions in a sibling whose coinbase isn't indexed: X's entries but its coinbase's
    CBlock sibling = BuildBlock({tx1, tx2}, CScript() << OP_TRUE << std::vector<unsigned char>(1, 1));
    BOOST_REQUIRE(Submit(sibling));
    const CTransaction& cbX = blockX.vtx[0];
    std::vector<std::string> expIndex = indexX, expUnspent = unspentX;
    const IndexEntry cbRecv = Recv(1, idA, YAC, 14, 0, cbX, 0, cbX.vout[0].nValue);
    const UnspentEntry cbUtxo = Utxo(1, idA, YAC, cbX, 0, cbX.vout[0].nValue, 14);
    Remove(expIndex, Str(cbRecv.first, cbRecv.second));
    Remove(expUnspent, Str(cbUtxo.first, cbUtxo.second));
    CHECK_SAME(DumpIndex(*pblocktree), expIndex);
    CHECK_SAME(DumpUnspent(*pblocktree), expUnspent);
}

/* A reorg: the losing branch's entries go, the winning branch's are written */
BOOST_AUTO_TEST_CASE(reorg_replaces_entries)
{
    BuildP();
    BOOST_REQUIRE(Submit(blockP));
    CBlockIndex* pindexP = Tip();
    const std::vector<std::string> indexP = DumpIndex(*pblocktree), unspentP = DumpUnspent(*pblocktree);
    BuildX();
    BOOST_REQUIRE(Submit(blockX));
    CBlockIndex* pindexX = Tip();
    const std::vector<std::string> indexX = DumpIndex(*pblocktree), unspentX = DumpUnspent(*pblocktree);

    // Y1 spends tx0's keyB output (also spent by X) to keyC; Y2 makes that branch longer
    CMutableTransaction m;
    m.vin.emplace_back(COutPoint(tx0.GetHash(), 1));
    m.vout.emplace_back(2 * u - u / 10, P2PKH(idC));
    CTransaction ytx = Sign(m, {tx0.vout[1].scriptPubKey});
    CBlock y1 = BuildOn(pindexP, CScript() << OP_TRUE << std::vector<unsigned char>(1, 2), {ytx});
    BOOST_CHECK(!Submit(y1));
    CBlockIndex* pindexY1;
    {
        LOCK(cs_main);
        pindexY1 = mapBlockIndex.at(y1.GetHash());
    }
    CBlock y2 = BuildOn(pindexY1, CScript() << OP_TRUE << std::vector<unsigned char>(1, 3), {});
    BOOST_REQUIRE(Submit(y2));

    std::vector<std::string> expIndex = indexP, expUnspent = unspentP;
    expIndex.push_back(Str(Spend(1, idB, YAC, 14, 1, ytx, 0, 2 * u).first, -2 * u));
    expIndex.push_back(Str(Recv(1, idC, YAC, 14, 1, ytx, 0, 0).first, ytx.vout[0].nValue));
    UnspentEntry spent = Utxo(1, idB, YAC, tx0, 1, 2 * u, 13), created = Utxo(1, idC, YAC, ytx, 0, ytx.vout[0].nValue, 14);
    Remove(expUnspent, Str(spent.first, spent.second));
    expUnspent.push_back(Str(created.first, created.second));
    CHECK_SAME(Sorted(DumpIndex(*pblocktree)), Sorted(expIndex));
    CHECK_SAME(Sorted(DumpUnspent(*pblocktree)), Sorted(expUnspent));

    // Two more blocks on X (coinbases not indexed): back to exactly X's entries
    CBlock x2 = BuildOn(pindexX, CScript() << OP_TRUE << std::vector<unsigned char>(1, 4), {});
    BOOST_CHECK(!Submit(x2));
    CBlockIndex* pindexX2;
    {
        LOCK(cs_main);
        pindexX2 = mapBlockIndex.at(x2.GetHash());
    }
    BOOST_REQUIRE(Submit(BuildOn(pindexX2, CScript() << OP_TRUE << std::vector<unsigned char>(1, 5), {})));
    CHECK_SAME(DumpIndex(*pblocktree), indexX);
    CHECK_SAME(DumpUnspent(*pblocktree), unspentX);
}

/* Spending an uncompressed P2PK output, and undoing the spend */
BOOST_AUTO_TEST_CASE(uncompressed_p2pk_spend)
{
    BuildP();
    BOOST_REQUIRE(Submit(blockP));
    // A keyU output at index 0, spent by input 0 of the next block
    CMutableTransaction m1;
    m1.vin.emplace_back(COutPoint(tx0.GetHash(), 12));
    m1.vout.emplace_back(tx0.vout[12].nValue - u / 10, CScript() << ToByteVector(keyU.GetPubKey()) << OP_CHECKSIG);
    CTransaction txU = Sign(m1, {tx0.vout[12].scriptPubKey});
    BOOST_REQUIRE(Submit(BuildBlock({txU})));
    const std::vector<std::string> index1 = DumpIndex(*pblocktree), unspent1 = DumpUnspent(*pblocktree);
    CMutableTransaction m2;
    m2.vin.emplace_back(COutPoint(txU.GetHash(), 0));
    m2.vout.emplace_back(txU.vout[0].nValue - u / 10, P2PKH(idB));
    CTransaction spendU = Sign(m2, {txU.vout[0].scriptPubKey});
    CBlock block2 = BuildBlock({spendU});
    BOOST_REQUIRE(Submit(block2));

    const CAmount v = txU.vout[0].nValue;
    CHECK_SAME(Strs(Index(idU, 1)), (Strs<CAddressIndexKey, CAmount>({Recv(1, idU, YAC, 13, 1, tx0, 6, u),
        Recv(1, idU, YAC, 14, 1, txU, 0, v), Spend(1, idU, YAC, 15, 1, spendU, 0, v)})));
    CHECK_SAME(Strs(Unspent(idU, 1, YAC)), (Strs<CAddressUnspentKey, CAddressUnspentValue>({Utxo(1, idU, YAC, tx0, 6, u, 13)})));

    Invalidate(block2);
    CHECK_SAME(DumpIndex(*pblocktree), index1);
    CHECK_SAME(DumpUnspent(*pblocktree), unspent1);
}

/* Token outputs are indexed per token name (owner tokens included), and undone on disconnect */
BOOST_AUTO_TEST_CASE(token_entries)
{
    // A mature coin large enough for the issue lock, instead of mining enough coinbases.
    // It wasn't created by an indexed block, so its address only shows the spend.
    const CAmount nLock = GetLockAmount(ETokenType::YATOKEN);
    const CAmount nFund = nLock + 10 * COIN;
    const COutPoint fund(uint256S("0xf0f0f0f0"), 0);
    {
        LOCK(cs_main);
        pcoinsTip->AddCoin(fund, Coin(CTxOut(nFund, P2PKH(idF)), Tip()->nHeight, false, false, (int)coinbases[0].nTime), false);
    }
    const std::vector<std::string> index0 = DumpIndex(*pblocktree), unspent0 = DumpUnspent(*pblocktree);

    CNewToken newToken("ADDR", 1000 * COIN, 0, 1, 0, "");
    CScript ownerScript = P2PKH(idA), issueScript = P2PKH(idA);
    newToken.ConstructOwnerTransaction(ownerScript);
    newToken.ConstructTransaction(issueScript);
    CMutableTransaction mIssue;
    mIssue.vin.emplace_back(fund);
    mIssue.vout.emplace_back(10 * COIN - CENT, P2PKH(idA));
    mIssue.vout.push_back(TokenLockOutput(ETokenType::YATOKEN));
    mIssue.vout.emplace_back(0, ownerScript);
    mIssue.vout.emplace_back(0, issueScript);
    CTransaction issue = Sign(mIssue, {P2PKH(idF)});
    CBlock t1 = BuildBlock({issue});
    BOOST_REQUIRE(Submit(t1));
    coinbases.push_back(t1.vtx[0]);

    const std::vector<IndexEntry> addr1{Recv(1, idA, "ADDR", 13, 1, issue, 3, 1000 * COIN)};
    const std::vector<IndexEntry> owner{Recv(1, idA, "ADDR!", 13, 1, issue, 2, OWNER_TOKEN_AMOUNT)};
    CHECK_SAME(Strs(Index(idA, 1, "ADDR")), Strs(addr1));
    CHECK_SAME(Strs(Index(idA, 1, "ADDR!")), Strs(owner));
    CHECK_SAME(Strs(Unspent(idA, 1, "ADDR")), (Strs<CAddressUnspentKey, CAddressUnspentValue>({Utxo(1, idA, "ADDR", issue, 3, 1000 * COIN, 13)})));
    // YAC history of the address has no token records
    std::vector<IndexEntry> yac = CoinbaseRecv(1, 13);
    yac.push_back(Recv(1, idA, YAC, 13, 1, issue, 0, 10 * COIN - CENT));
    CHECK_SAME(Strs(Index(idA, 1, YAC)), Strs(yac));
    // The lock output is a YAC receipt of its key
    CTxDestination lockDest;
    BOOST_REQUIRE(ExtractDestination(TokenLockOutput(ETokenType::YATOKEN).scriptPubKey, lockDest));
    const uint160 idLock = boost::get<CKeyID>(lockDest);
    CHECK_SAME(Strs(Index(idLock, 1)), (Strs<CAddressIndexKey, CAmount>({Recv(1, idLock, YAC, 13, 1, issue, 1, nLock)})));
    CHECK_SAME(Strs(Unspent(idLock, 1, "")), (Strs<CAddressUnspentKey, CAddressUnspentValue>({Utxo(1, idLock, YAC, issue, 1, nLock, 13)})));
    // The funding coin: spend only, no unspent record
    CHECK_SAME(Strs(Index(idF, 1)), (Strs<CAddressIndexKey, CAmount>({Spend(1, idF, YAC, 13, 1, issue, 0, nFund)})));
    BOOST_CHECK(Unspent(idF, 1, "").empty());
    const std::vector<std::string> indexT1 = DumpIndex(*pblocktree), unspentT1 = DumpUnspent(*pblocktree);

    // Transfer 400 to keyB and 600 back
    CScript toB = P2PKH(idB), back = P2PKH(idA);
    CTokenTransfer("ADDR", 400 * COIN).ConstructTransaction(toB);
    CTokenTransfer("ADDR", 600 * COIN).ConstructTransaction(back);
    CMutableTransaction mT;
    mT.vin.emplace_back(COutPoint(issue.GetHash(), 3));
    mT.vin.emplace_back(COutPoint(issue.GetHash(), 0));
    mT.vout.emplace_back(10 * COIN - 2 * CENT, P2PKH(idA));
    mT.vout.emplace_back(0, toB);
    mT.vout.emplace_back(0, back);
    CTransaction transfer = Sign(mT, {issueScript, P2PKH(idA)});
    CBlock t2 = BuildBlock({transfer});
    BOOST_REQUIRE(Submit(t2));
    coinbases.push_back(t2.vtx[0]);

    CHECK_SAME(Strs(Index(idA, 1, "ADDR")), (Strs<CAddressIndexKey, CAmount>({addr1[0],
        Spend(1, idA, "ADDR", 14, 1, transfer, 0, 1000 * COIN), Recv(1, idA, "ADDR", 14, 1, transfer, 2, 600 * COIN)})));
    const UnspentEntry addr600 = Utxo(1, idA, "ADDR", transfer, 2, 600 * COIN, 14);
    const UnspentEntry owner1 = Utxo(1, idA, "ADDR!", issue, 2, OWNER_TOKEN_AMOUNT, 13);
    CHECK_SAME(Strs(Unspent(idA, 1, "ADDR")), (Strs<CAddressUnspentKey, CAddressUnspentValue>({addr600})));
    // All tokens but YAC; or with an empty name, YAC too
    CHECK_SAME(Strs(UnspentTokens(idA, 1)), (Strs<CAddressUnspentKey, CAddressUnspentValue>({addr600, owner1})));
    std::vector<UnspentEntry> allA = CoinbaseUtxos(1, 14);
    allA.push_back(Utxo(1, idA, YAC, transfer, 0, transfer.vout[0].nValue, 14));
    allA.push_back(addr600);
    allA.push_back(owner1);
    CHECK_SAME(Strs(Unspent(idA, 1, "")), InKeyOrder(allA));
    CHECK_SAME(Strs(Index(idB, 1, "ADDR")), (Strs<CAddressIndexKey, CAmount>({Recv(1, idB, "ADDR", 14, 1, transfer, 1, 400 * COIN)})));
    CHECK_SAME(Strs(Unspent(idB, 1, "ADDR")), (Strs<CAddressUnspentKey, CAddressUnspentValue>({Utxo(1, idB, "ADDR", transfer, 1, 400 * COIN, 14)})));
    BOOST_CHECK_EQUAL(Balance(Index(idA, 1, "ADDR")), 600 * COIN);
    BOOST_CHECK_EQUAL(Balance(Index(idA, 1, YAC)), UnspentSum(Unspent(idA, 1, YAC)));

    // Height ranges on a token
    CHECK_SAME(Strs(Index(idA, 1, "ADDR", 13, 13)), Strs(addr1));
    CHECK_SAME(Strs(Index(idA, 1, "ADDR", 14, 14)), (Strs<CAddressIndexKey, CAmount>({
        Spend(1, idA, "ADDR", 14, 1, transfer, 0, 1000 * COIN), Recv(1, idA, "ADDR", 14, 1, transfer, 2, 600 * COIN)})));
    BOOST_CHECK(Index(idA, 1, "ADDR", 15, 20).empty());

    // Disconnecting the transfer restores the state after the issue
    Invalidate(t2);
    BOOST_REQUIRE(Tip()->GetBlockHash() == t1.GetHash());
    CHECK_SAME(DumpIndex(*pblocktree), indexT1);
    CHECK_SAME(DumpUnspent(*pblocktree), unspentT1);

    // Disconnecting the issue too removes the token and lock records; the funding coin
    // comes back as an unspent record
    Invalidate(t1);
    BOOST_REQUIRE(Tip()->nHeight == 12);
    std::vector<std::string> expUnspent = unspent0;
    expUnspent.push_back(Str(CAddressUnspentKey(1, idF, fund.hash, 0), CAddressUnspentValue(nFund, P2PKH(idF), 12)));
    CHECK_SAME(DumpIndex(*pblocktree), index0);
    CHECK_SAME(Sorted(DumpUnspent(*pblocktree)), Sorted(expUnspent));
    BOOST_CHECK(Index(idA, 1, "ADDR").empty() && Index(idA, 1, "ADDR!").empty());
}

/* GetAddressIndex with a token name and a height range, on the chain */
BOOST_AUTO_TEST_CASE(chain_height_ranges)
{
    auto heights = [&](int start, int end) {
        std::vector<IndexEntry> out;
        BOOST_CHECK(GetAddressIndex(idA, 1, YAC, out, start, end));
        std::vector<int> h;
        for (const IndexEntry& e : out) h.push_back(e.first.blockHeight);
        return h;
    };
    CHECK_HEIGHTS(heights(3, 5), 3, 4, 5);
    CHECK_HEIGHTS(heights(7, 7), 7);
    CHECK_HEIGHTS(heights(1, 1), 1);
    CHECK_HEIGHTS(heights(12, 12), 12);
    CHECK_HEIGHTS(heights(12, 100), 12);
    CHECK_HEIGHTS(heights(13, 20));
    CHECK_HEIGHTS(heights(6, 5));
    CHECK_HEIGHTS(heights(0, 5), 1, 2, 3, 4, 5);
    CHECK_HEIGHTS(heights(5, 0), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12);
}

/* Block checks (TestBlockValidity) and VerifyDB connect and disconnect without touching the index */
BOOST_AUTO_TEST_CASE(index_untouched_by_checks)
{
    const std::vector<std::string> index0 = DumpIndex(*pblocktree), unspent0 = DumpUnspent(*pblocktree);
    BuildP();
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_CHECK(TestBlockValidity(state, Params(), blockP, chainActive.Tip(), true));
    }
    CHECK_SAME(DumpIndex(*pblocktree), index0);
    CHECK_SAME(DumpUnspent(*pblocktree), unspent0);

    BOOST_REQUIRE(Submit(blockP));
    BuildX();
    BOOST_REQUIRE(Submit(blockX));
    // Remove one record of each kind by hand: VerifyDB's reconnect mustn't write them again
    const IndexEntry recv = Recv(1, idB, YAC, 14, 1, tx1, 0, u);
    const UnspentEntry utxo = Utxo(1, idB, YAC, tx1, 0, u, 14);
    BOOST_REQUIRE(pblocktree->EraseAddressIndex({recv}));
    BOOST_REQUIRE(pblocktree->UpdateAddressUnspentIndex({UnspentEntry(utxo.first, CAddressUnspentValue())}));
    const std::vector<std::string> index1 = DumpIndex(*pblocktree), unspent1 = DumpUnspent(*pblocktree);
    BOOST_CHECK_EQUAL(index1.size() + 1, ExpectAllIndex(true).size());
    BOOST_CHECK_EQUAL(unspent1.size() + 1, ExpectAllUnspent(true).size());

    BOOST_CHECK(CVerifyDB().VerifyDB(Params(), pcoinsTip, 4, 0));
    CHECK_SAME(DumpIndex(*pblocktree), index1);
    CHECK_SAME(DumpUnspent(*pblocktree), unspent1);
}

/* With the index off nothing is written and the getters refuse; a corrupt record makes them fail */
BOOST_AUTO_TEST_CASE(index_switched_off)
{
    const std::vector<std::string> index0 = DumpIndex(*pblocktree), unspent0 = DumpUnspent(*pblocktree);
    const IndexEntry marker(CAddressIndexKey(), 1);
    const UnspentEntry umarker{CAddressUnspentKey(), CAddressUnspentValue()};
    std::vector<IndexEntry> out{marker};
    std::vector<UnspentEntry> uout{umarker};

    fAddressIndex = false;
    BOOST_CHECK(!GetAddressIndex(idA, 1, out));
    BOOST_CHECK(!GetAddressIndex(idA, 1, YAC, out));
    BOOST_CHECK(!GetAddressUnspent(idA, 1, YAC, uout));
    BOOST_CHECK(!GetAddressUnspent(idA, 1, uout));
    BOOST_CHECK_EQUAL(out.size(), 1U);
    BOOST_CHECK_EQUAL(uout.size(), 1U);
    BuildP();
    BOOST_REQUIRE(Submit(blockP));
    CHECK_SAME(DumpIndex(*pblocktree), index0);
    CHECK_SAME(DumpUnspent(*pblocktree), unspent0);
    // Switched back on without a reindex: P stays missing from the index (spent coinbase 1
    // still listed as unspent); a reindex is what rebuilds it
    fAddressIndex = true;

    // The getters pass through to the database
    out.clear();
    BOOST_CHECK(GetAddressIndex(idA, 1, out));
    CHECK_SAME(Strs(out), Strs(CoinbaseRecv(1, 12)));
    out.clear();
    BOOST_CHECK(GetAddressIndex(idA, 1, YAC, out, 3, 5));
    CHECK_SAME(Strs(out), Strs(CoinbaseRecv(3, 5)));
    uout.clear();
    BOOST_CHECK(GetAddressUnspent(idA, 1, YAC, uout));
    CHECK_SAME(Strs(uout), InKeyOrder(CoinbaseUtxos(1, 12)));
    uout.clear();
    BOOST_CHECK(GetAddressUnspent(idA, 1, uout));
    BOOST_CHECK(uout.empty());

    // Undecodable records make every getter fail
    const uint160 idZ = Hash(0x7f);
    BOOST_CHECK(pblocktree->Write(std::make_pair(DB_ADDRESSINDEX, CAddressIndexKey(1, idZ, 5, 0, uint256S("0x01"), 0, false)), (unsigned char)1));
    BOOST_CHECK(pblocktree->Write(std::make_pair(DB_ADDRESSUNSPENTINDEX, CAddressUnspentKey(1, idZ, uint256S("0x01"), 0)), (unsigned char)1));
    BOOST_CHECK(!GetAddressIndex(idZ, 1, out));
    BOOST_CHECK(!GetAddressIndex(idZ, 1, YAC, out, 1, 10));
    BOOST_CHECK(!GetAddressUnspent(idZ, 1, YAC, uout));
    BOOST_CHECK(!GetAddressUnspent(idZ, 1, uout));
}

BOOST_AUTO_TEST_SUITE_END()
