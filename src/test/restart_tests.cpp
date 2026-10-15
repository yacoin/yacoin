// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// What a node does when it restarts: loading the block index (LoadBlockIndex,
// LoadBlockIndexGuts, InsertBlockIndex), the chain tip (LoadChainTip), the
// token database (LoadTokens), the startup reward/difficulty summary
// (LoadBlockRewardAndHighestDiff), the block hash index rebuild
// (BuildMapHash, BuildBlockHashIndex), mempool persistence (DumpMempool,
// LoadMempool) and block import (LoadExternalBlockFile, for -loadblock and
// -reindex).
//
// The databases in TestingSetup are in-memory LevelDBs, so a restart here keeps
// the database objects and only throws away the in-memory state built from
// them, then runs init.cpp's load sequence again. Block and undo files are
// real files in the test's data directory.

#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "fs.h"
#include "kernel.h"
#include "miner.h"
#include "net_processing.h"
#include "pow.h"
#include "script/sign.h"
#include "streams.h"
#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "txdb.h"
#include "txmempool.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <fstream>
#include <sstream>

#include <boost/test/unit_test.hpp>

namespace {

// Database keys, as defined (file-static) in txdb.cpp and tokens/tokendb.cpp
const char DB_BLOCK_INDEX = 'b';
const char DB_TOKEN = 'A';
const char DB_TOKEN_ADDRESS_QUANTITY = 'B';

typedef CLRUCache<std::string, CDatabasedTokenData> TokenLRU;

/** A database value written as raw bytes, to store a corrupt record */
struct RawValue {
    std::vector<unsigned char> data;
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!data.empty()) s.write((const char*)data.data(), data.size());
    }
};

/** The first half of obj's disk serialization */
template <typename T>
RawValue TruncatedValue(const T& obj)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << obj;
    RawValue raw;
    raw.data.assign(ss.begin(), ss.begin() + ss.size() / 2);
    return raw;
}

/** Sends log output (LogPrintf goes to stdout with fPrintToConsole) into a file while alive */
class LogCapture
{
public:
    explicit LogCapture(const fs::path& path) : m_path(path)
    {
        fflush(stdout);
        m_saved = dup(fileno(stdout));
        int fd = open(path.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        dup2(fd, fileno(stdout));
        close(fd);
        m_prevConsole = fPrintToConsole;
        fPrintToConsole = true;
    }
    ~LogCapture() { Restore(); }

    std::string Stop()
    {
        Restore();
        std::ifstream in(m_path.string());
        std::stringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

private:
    void Restore()
    {
        if (m_saved < 0) return;
        fflush(stdout);
        dup2(m_saved, fileno(stdout));
        close(m_saved);
        m_saved = -1;
        fPrintToConsole = m_prevConsole;
    }

    fs::path m_path;
    int m_saved;
    bool m_prevConsole;
};

/** The rest of the log line that starts with prefix ("" if there is none) */
std::string LogValue(const std::string& log, const std::string& prefix)
{
    size_t pos = log.find(prefix);
    if (pos == std::string::npos) return "";
    pos += prefix.size();
    return log.substr(pos, log.find('\n', pos) - pos);
}

bool Contains(const std::string& str, const std::string& part)
{
    return str.find(part) != std::string::npos;
}

/** Everything about a block index entry that is stored or rebuilt on load */
struct IndexSnapshot {
    struct Entry {
        CBlockIndex index;
        uint256 prev;
        uint256 skip;
    };
    std::map<uint256, Entry> entries;
    std::vector<uint256> chain;
    int nLastFile = -1;
    std::vector<CBlockFileInfo> files;
};

IndexSnapshot TakeSnapshot()
{
    LOCK(cs_main);
    IndexSnapshot snap;
    for (const auto& item : mapBlockIndex) {
        const CBlockIndex* p = item.second;
        IndexSnapshot::Entry e{*p, p->pprev ? p->pprev->GetBlockHash() : uint256(), p->pskip ? p->pskip->GetBlockHash() : uint256()};
        snap.entries.emplace(item.first, e);
    }
    for (int h = 0; h <= chainActive.Height(); h++)
        snap.chain.push_back(chainActive[h]->GetBlockHash());
    pblocktree->ReadLastBlockFile(snap.nLastFile);
    try {
        for (size_t i = 0; ; i++) snap.files.push_back(*GetBlockFileInfo(i));
    } catch (const std::out_of_range&) {
    }
    return snap;
}

/** Field by field comparison. nSequenceId is 0 for every loaded block by design, and the
 *  stake modifier checksum is only computed live below the fork height, so neither is compared. */
void CheckSame(const IndexSnapshot& a, const IndexSnapshot& b)
{
    BOOST_CHECK_EQUAL(a.entries.size(), b.entries.size());
    for (const auto& item : a.entries) {
        auto it = b.entries.find(item.first);
        BOOST_CHECK_MESSAGE(it != b.entries.end(), "missing " << item.first.ToString());
        if (it == b.entries.end()) continue;
        const CBlockIndex& x = item.second.index;
        const CBlockIndex& y = it->second.index;
        const std::string name = strprintf("height %d %s", x.nHeight, item.first.ToString().substr(0, 12));
#define CHECK_FIELD(f) BOOST_CHECK_MESSAGE(x.f == y.f, name << ": " #f)
        CHECK_FIELD(nHeight);
        CHECK_FIELD(nStatus);
        CHECK_FIELD(nTx);
        CHECK_FIELD(nChainTx);
        CHECK_FIELD(nFile);
        CHECK_FIELD(nDataPos);
        CHECK_FIELD(nUndoPos);
        CHECK_FIELD(nVersion);
        CHECK_FIELD(hashMerkleRoot);
        CHECK_FIELD(nTime);
        CHECK_FIELD(nBits);
        CHECK_FIELD(nNonce);
        CHECK_FIELD(nMint);
        CHECK_FIELD(nMoneySupply);
        CHECK_FIELD(nFlags);
        CHECK_FIELD(nStakeModifier);
        CHECK_FIELD(prevoutStake);
        CHECK_FIELD(nStakeTime);
        CHECK_FIELD(hashProofOfStake);
        CHECK_FIELD(bnChainTrust);
        CHECK_FIELD(nTimeMax);
        CHECK_FIELD(blockHash);
#undef CHECK_FIELD
        BOOST_CHECK_MESSAGE(item.second.prev == it->second.prev, name << ": pprev");
        BOOST_CHECK_MESSAGE(item.second.skip == it->second.skip, name << ": pskip");
    }
    BOOST_CHECK(a.chain == b.chain);
    BOOST_CHECK_EQUAL(a.nLastFile, b.nLastFile);
    BOOST_CHECK_EQUAL(a.files.size(), b.files.size());
    for (size_t i = 0; i < std::min(a.files.size(), b.files.size()); i++) {
        BOOST_CHECK_EQUAL(a.files[i].nBlocks, b.files[i].nBlocks);
        BOOST_CHECK_EQUAL(a.files[i].nSize, b.files[i].nSize);
        BOOST_CHECK_EQUAL(a.files[i].nUndoSize, b.files[i].nUndoSize);
        BOOST_CHECK_EQUAL(a.files[i].nHeightFirst, b.files[i].nHeightFirst);
        BOOST_CHECK_EQUAL(a.files[i].nHeightLast, b.files[i].nHeightLast);
        BOOST_CHECK_EQUAL(a.files[i].nTimeFirst, b.files[i].nTimeFirst);
        BOOST_CHECK_EQUAL(a.files[i].nTimeLast, b.files[i].nTimeLast);
    }
}

/** Import file record: message start, size, block */
void AppendBlock(CAutoFile& file, const CBlock& block, unsigned int* pnDataPos = nullptr)
{
    file << FLATDATA(Params().MessageStart());
    unsigned int nSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
    file << nSize;
    if (pnDataPos) *pnDataPos = (unsigned int)ftell(file.Get());
    file << block;
}

void AppendBytes(CAutoFile& file, const std::vector<unsigned char>& bytes)
{
    file.write((const char*)bytes.data(), bytes.size());
}

/** Message start followed by a size and nothing else */
void AppendHeaderOnly(CAutoFile& file, unsigned int nSize)
{
    file << FLATDATA(Params().MessageStart());
    file << nSize;
}

/** A record whose block is cut off by the end of the file */
void AppendTruncatedBlock(CAutoFile& file, const CBlock& block)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << block;
    AppendHeaderOnly(file, ss.size());
    file.write(&ss[0], ss.size() / 2);
}

bool Import(const fs::path& path, CDiskBlockPos* dbp = nullptr)
{
    FILE* file = fsbridge::fopen(path, "rb");
    BOOST_REQUIRE(file);
    return LoadExternalBlockFile(Params(), file, dbp);
}

CBlockIndex* Index(const uint256& hash)
{
    LOCK(cs_main);
    auto it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? nullptr : it->second;
}

bool Known(const uint256& hash)
{
    return Index(hash) != nullptr;
}

/** Find a nonce for the block as it is */
void Solve(CBlock& block)
{
    block.fChecked = false;
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
}

/** Regtest chain with mature coinbases, the token databases init creates, and helpers to
 *  restart the node in-process. */
struct RestartSetup : public TestChain100Setup {
    CScript scriptPubKey;
    std::vector<CTransaction> coinbases; // coinbases[h - 1] is the coinbase of the block at height h
    CTokensDB* prevTokensDb;
    TokenLRU* prevTokensCache;
    bool prevTokenIndex, prevTxIndex, prevAddressIndex, prevBlockHashIndex, prevReindex;
    std::map<uint256, uint256> prevMapHash;

    RestartSetup()
    {
        prevTokensDb = ptokensdb;
        prevTokensCache = ptokensCache;
        prevTokenIndex = fTokenIndex;
        prevTxIndex = fTxIndex;
        prevAddressIndex = fAddressIndex;
        prevBlockHashIndex = fBlockHashIndex;
        prevReindex = fReindex;
        prevMapHash = mapHash;
        ptokensdb = new CTokensDB(1 << 20, true, true);
        ptokensCache = new TokenLRU(MAX_CACHE_TOKENS_SIZE);
        fTokenIndex = true;
        TokenTestingSetup::ClearTokenGlobals();
        scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        coinbases = coinbaseTxns;
        for (int i = 0; i < COINBASE_MATURITY_AFTER_HARDFORK; i++) Mine();
    }

    ~RestartSetup()
    {
        SetMockTime(0);
        {
            LOCK(mempool.cs);
            mempool.mapDeltas.clear(); // CTxMemPool::clear() keeps them
        }
        TokenTestingSetup::ClearTokenGlobals();
        delete ptokensdb;
        delete ptokensCache;
        ptokensdb = prevTokensDb;
        ptokensCache = prevTokensCache;
        fTokenIndex = prevTokenIndex;
        fTxIndex = prevTxIndex;
        fAddressIndex = prevAddressIndex;
        fBlockHashIndex = prevBlockHashIndex;
        fReindex = prevReindex;
        mapHash = prevMapHash;
        blockHashPos.clear();
    }

    static CBlockIndex* Tip()
    {
        LOCK(cs_main);
        return chainActive.Tip();
    }

    static CBlockIndex* AtHeight(int h)
    {
        LOCK(cs_main);
        return chainActive[h];
    }

    /** Move the (mocked) clock one second past the tip; time only ever moves forward.
     *  FlushStateToDisk's periodic flush timers and the IsInitialBlockDownload latch are
     *  process-wide statics, so when periodic flushes happen depends on the tests run before;
     *  these tests flush explicitly and don't rely on them. */
    static void AdvanceTime()
    {
        SetMockTime(std::max(GetTime(), Tip()->GetBlockTime()) + 1);
    }

    /** Mine the next block on the tip */
    CBlock Mine(const std::vector<CTransaction>& txs = {})
    {
        AdvanceTime();
        CBlock block = CreateAndProcessBlock(txs, scriptPubKey);
        BOOST_REQUIRE(Tip()->GetBlockHash() == block.GetHash());
        coinbases.push_back(block.vtx[0]);
        return block;
    }

    /** A valid block on any parent (side branches); cbScript makes siblings differ */
    CBlock BuildOn(CBlockIndex* parent, const CScript& cbScript, const std::vector<CTransaction>& txs = {})
    {
        AdvanceTime();
        std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler().CreateNewBlock(cbScript);
        CBlock block = tmpl->block;
        block.hashPrevBlock = parent->GetBlockHash();
        block.vtx.resize(1);
        for (const CTransaction& tx : txs) block.vtx.push_back(tx);
        block.nBits = GetNextTargetRequired(parent, false);
        block.nTime = std::max(block.GetBlockTime(), parent->GetMedianTimePast() + 1);
        unsigned int nExtraNonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, parent, nExtraNonce);
        }
        Solve(block);
        return block;
    }

    static bool Submit(const CBlock& block)
    {
        return ProcessNewBlock(Params(), std::make_shared<const CBlock>(block), true, nullptr);
    }

    static bool SubmitHeader(const CBlock& block)
    {
        CValidationState state;
        return ProcessNewBlockHeaders({block.GetBlockHeader()}, state, Params());
    }

    static CScript OtherScript(unsigned char n)
    {
        return CScript() << OP_TRUE << std::vector<unsigned char>(1, n);
    }

    /** Sign every input; coinbase-style outputs are P2PK, everything else P2PKH */
    CTransaction Sign(CMutableTransaction& mtx, const std::vector<CScript>& prevScripts)
    {
        for (size_t i = 0; i < mtx.vin.size(); i++) {
            uint256 hash = SignatureHash(prevScripts[i], mtx, i, SIGHASH_ALL);
            std::vector<unsigned char> vchSig;
            BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
            vchSig.push_back((unsigned char)SIGHASH_ALL);
            if (prevScripts[i] == scriptPubKey)
                mtx.vin[i].scriptSig = CScript() << vchSig;
            else
                mtx.vin[i].scriptSig = CScript() << vchSig << ToByteVector(coinbaseKey.GetPubKey());
        }
        return CTransaction(mtx);
    }

    CTransaction Spend(const CTransaction& prev, unsigned int n = 0, CAmount nFee = CENT)
    {
        CMutableTransaction mtx;
        mtx.vin.emplace_back(COutPoint(prev.GetHash(), n));
        mtx.vout.emplace_back(prev.vout[n].nValue - nFee, scriptPubKey);
        return Sign(mtx, {prev.vout[n].scriptPubKey});
    }

    static bool HaveCoin(const COutPoint& out)
    {
        LOCK(cs_main);
        return pcoinsTip->HaveCoin(out);
    }

    /** Raw block index record as stored in the database */
    static CDiskBlockIndex DiskEntry(const uint256& hash)
    {
        CDiskBlockIndex disk;
        BOOST_CHECK(pblocktree->Read(std::make_pair(DB_BLOCK_INDEX, hash), disk));
        return disk;
    }

    static bool ReadBlockHash(const CBlockIndex* pindex, uint256& hash)
    {
        return pblocktree->ReadBlockHash(pindex->nFile, pindex->nDataPos, hash);
    }

    static void EraseBlockHash(const CBlockIndex* pindex)
    {
        BOOST_CHECK(pblocktree->Erase(std::make_pair(std::string("blockhash"), std::make_pair(pindex->nFile, pindex->nDataPos)), true));
    }

    /** A well-formed key just after the block index records, so the load loops stop on the key check */
    static void WriteKeyAfterBlockIndex()
    {
        BOOST_CHECK(pblocktree->Write(std::make_pair('c', uint256S("0x01")), 1));
    }

    fs::path DataFile(const std::string& name) const { return GetDataDir() / name; }

    /** LoadBlockRewardAndHighestDiff's log output */
    std::string RewardLog() const
    {
        LogCapture capture(DataFile("reward.log"));
        {
            LOCK(cs_main);
            LoadBlockRewardAndHighestDiff();
        }
        return capture.Stop();
    }

    /** init.cpp's load sequence (AppInitMain, "Loading block index") without a flush first:
     *  whatever wasn't written to the databases is lost, as in a crash. */
    bool Reload(bool fActivate = true, std::string* pRewardLog = nullptr)
    {
        const CChainParams& params = Params();
        {
            LOCK(cs_main);
            UnloadBlockIndex();
            mapHash.clear();
            delete pcoinsTip;
            pcoinsTip = new CCoinsViewCache(pcoinsdbview);
            delete ptokens;
            ptokens = new CTokensCache();
            delete ptokensCache;
            ptokensCache = new TokenLRU(MAX_CACHE_TOKENS_SIZE);
            pblocktree->ReadFlag("tokenindex", fTokenIndex);
            if (!ptokensdb->LoadTokens()) return Failed("LoadTokens");
            ptokensdb->ReadReissuedMempoolState();
            if (!LoadBlockIndex(params)) return Failed("LoadBlockIndex");
            if (!LoadGenesisBlock(params)) return Failed("LoadGenesisBlock");
            if (!ReplayBlocks(params, pcoinsdbview)) return Failed("ReplayBlocks");
            if (!LoadChainTip(params)) return Failed("LoadChainTip");
        }
        std::string log = RewardLog();
        if (pRewardLog) *pRewardLog = log;
        if (fActivate) {
            CValidationState state;
            if (!ActivateBestChain(state, params)) return Failed("ActivateBestChain");
        }
        return true;
    }

    bool Restart(bool fActivate = true, std::string* pRewardLog = nullptr)
    {
        FlushStateToDisk();
        return Reload(fActivate, pRewardLog);
    }

    static bool Failed(const char* step)
    {
        BOOST_TEST_MESSAGE(std::string("reload failed at ") + step);
        return false;
    }

    /** UnloadBlockIndex + LoadBlockIndex only */
    static bool LoadIndexOnly()
    {
        LOCK(cs_main);
        UnloadBlockIndex();
        return LoadBlockIndex(Params());
    }

    /** Write the block index and block file info, but neither coins nor tokens: what a
     *  periodic write without a full flush leaves behind if the node then stops. Block and
     *  undo data are already in their files. */
    static void WriteIndexOnly()
    {
        LOCK(cs_main);
        std::vector<const CBlockIndex*> blocks;
        for (const auto& item : mapBlockIndex) blocks.push_back(item.second);
        std::vector<std::pair<int, const CBlockFileInfo*> > files{{0, GetBlockFileInfo(0)}};
        BOOST_REQUIRE(pblocktree->WriteBatchSync(files, 0, blocks));
    }

    /** A new data directory: empty databases and no block files, then init's steps up to the
     *  connected genesis block */
    void FreshNode(bool fRemoveBlocks = true)
    {
        {
            LOCK(cs_main);
            UnloadBlockIndex();
        }
        mapHash.clear();
        delete pcoinsTip;
        delete pcoinsdbview;
        delete pblocktree;
        pblocktree = new CBlockTreeDB(1 << 20, true, true);
        pcoinsdbview = new CCoinsViewDB(1 << 23, true, true);
        pcoinsTip = new CCoinsViewCache(pcoinsdbview);
        delete ptokens;
        ptokens = new CTokensCache();
        delete ptokensdb;
        ptokensdb = new CTokensDB(1 << 20, true, true);
        delete ptokensCache;
        ptokensCache = new TokenLRU(MAX_CACHE_TOKENS_SIZE);
        TokenTestingSetup::ClearTokenGlobals();
        if (fRemoveBlocks) {
            fs::remove_all(GetDataDir() / "blocks");
            const CChainParams& params = Params();
            LOCK(cs_main);
            BOOST_REQUIRE(LoadBlockIndex(params));
            BOOST_REQUIRE(LoadGenesisBlock(params));
            BOOST_REQUIRE(LoadChainTip(params));
        }
    }

    std::vector<CBlock> ReadChain()
    {
        std::vector<CBlock> blocks;
        for (int h = 0; h <= Tip()->nHeight; h++) {
            CBlock block;
            BOOST_REQUIRE(ReadBlockFromDisk(block, AtHeight(h), Params().GetConsensus()));
            blocks.push_back(block);
        }
        return blocks;
    }
};

/** Swaps in a token LRU cache of a given size for the duration of a scope */
struct CacheSwap {
    TokenLRU cache;
    TokenLRU* prev;
    explicit CacheSwap(size_t nSize) : cache(nSize), prev(ptokensCache) { ptokensCache = &cache; }
    ~CacheSwap() { ptokensCache = prev; }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(restart_tests, RestartSetup)

BOOST_AUTO_TEST_CASE(restart_restores_block_index)
{
    // Main chain with spends, a side branch, a header without data and a block on top of it,
    // and an invalidated block with a child.
    CBlock a13 = Mine({Spend(coinbases[0])});
    CBlock a14 = Mine();
    CBlockIndex* pa13 = Index(a13.GetHash());
    CBlockIndex* pa14 = Index(a14.GetHash());
    CBlock x15 = Mine();
    CBlock y16 = Mine();
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(InvalidateBlock(state, Params(), Index(x15.GetHash())));
    }
    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, Params()));
    BOOST_REQUIRE(Tip() == pa14);
    Mine();
    CTransaction spend2 = Spend(coinbases[1]);
    Mine({spend2});
    CBlock b17 = Mine();
    CBlock b18 = Mine();
    CBlock s14 = BuildOn(pa13, OtherScript(1));
    BOOST_REQUIRE(Submit(s14));
    BOOST_REQUIRE(Submit(BuildOn(Index(s14.GetHash()), OtherScript(2))));
    CBlock h15 = BuildOn(pa14, OtherScript(3));
    BOOST_REQUIRE(SubmitHeader(h15));
    CBlock hc16 = BuildOn(Index(h15.GetHash()), OtherScript(4));
    BOOST_REQUIRE(Submit(hc16));
    BOOST_REQUIRE(Tip()->GetBlockHash() == b18.GetHash());
    BOOST_CHECK_EQUAL(Index(hc16.GetHash())->nChainTx, 0U);
    WriteKeyAfterBlockIndex();

    FlushStateToDisk();
    IndexSnapshot before = TakeSnapshot();
    std::string rewardBefore = RewardLog();
    std::string rewardAfter;
    BOOST_REQUIRE(Restart(true, &rewardAfter));
    IndexSnapshot after = TakeSnapshot();
    CheckSame(before, after);

    {
        LOCK(cs_main);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b18.GetHash());
        BOOST_CHECK(pindexBestHeader == chainActive.Tip());
        BOOST_CHECK(mapBlockIndex[x15.GetHash()]->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(mapBlockIndex[y16.GetHash()]->nStatus & BLOCK_FAILED_CHILD);
        BOOST_CHECK_EQUAL(mapBlockIndex[h15.GetHash()]->nTx, 0U);
        BOOST_CHECK(!(mapBlockIndex[h15.GetHash()]->nStatus & BLOCK_HAVE_DATA));
        BOOST_CHECK_EQUAL(mapBlockIndex[hc16.GetHash()]->nChainTx, 0U);
        for (const auto& item : mapBlockIndex) {
            // mapHash is rebuilt from the index (it was cleared before loading)
            auto it = mapHash.find(item.second->GetSHA256Hash());
            BOOST_CHECK(it != mapHash.end() && it->second == item.first);
            BOOST_CHECK_EQUAL(item.second->nStakeModifierChecksum, GetStakeModifierChecksum(item.second));
        }
    }
    // The coins come back from the coins database
    BOOST_CHECK(!HaveCoin(COutPoint(coinbases[0].GetHash(), 0)));
    BOOST_CHECK(!HaveCoin(COutPoint(coinbases[1].GetHash(), 0)));
    BOOST_CHECK(HaveCoin(COutPoint(a13.vtx[1].GetHash(), 0)));
    BOOST_CHECK(HaveCoin(COutPoint(spend2.GetHash(), 0)));
    {
        LOCK(cs_main);
        BOOST_CHECK(pcoinsTip->GetBestBlock() == b18.GetHash());
    }

    // Same epoch reward and highest difficulty; the reward is what an empty block's coinbase pays
    const std::string strReward = "Current block reward = ";
    const std::string strTarget = "Minimum difficulty target = ";
    const std::string strEpoch = "last epoch change at block ";
    BOOST_CHECK(!LogValue(rewardBefore, strReward).empty());
    BOOST_CHECK_EQUAL(LogValue(rewardBefore, strReward), LogValue(rewardAfter, strReward));
    BOOST_CHECK_EQUAL(LogValue(rewardBefore, strTarget), LogValue(rewardAfter, strTarget));
    BOOST_CHECK_EQUAL(LogValue(rewardBefore, strEpoch), LogValue(rewardAfter, strEpoch));
    BOOST_CHECK_EQUAL(LogValue(rewardAfter, strReward), std::to_string(b17.vtx[0].vout[0].nValue));

    // LoadChainTip: nothing to do when the tip already matches the coins, otherwise it follows them
    {
        LOCK(cs_main);
        const CChainParams& params = Params();
        BOOST_CHECK(LoadChainTip(params));
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b18.GetHash());
        pcoinsTip->SetBestBlock(b17.GetHash());
        BOOST_CHECK(LoadChainTip(params));
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b17.GetHash());
        pcoinsTip->SetBestBlock(b18.GetHash());
        BOOST_CHECK(LoadChainTip(params));
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b18.GetHash());
    }
    // No block is processed after this restart: with the tip already up to date the candidate
    // set isn't pruned until a block is connected (LoadChainTip doesn't call
    // PruneBlockIndexCandidates), and CheckBlockIndex, which unit tests enable, checks it on
    // the next block. restart_reconnects_blocks_after_index_only_write processes blocks after
    // a restart that has to reconnect blocks.
}

BOOST_AUTO_TEST_CASE(restart_marks_children_of_invalid_blocks)
{
    CBlock a13 = Mine();
    CBlock x14 = Mine();
    CBlock y15 = Mine();
    CBlock y16 = Mine();
    // Z15 is stored before X14 is invalidated; InvalidateBlock only marks the blocks it
    // disconnects, so Z15 stays unmarked until the next load.
    CBlock z15 = BuildOn(Index(x14.GetHash()), OtherScript(1));
    BOOST_REQUIRE(Submit(z15));
    BOOST_REQUIRE(Tip()->GetBlockHash() == y16.GetHash());
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(InvalidateBlock(state, Params(), Index(x14.GetHash())));
    }
    BOOST_CHECK_EQUAL(Index(z15.GetHash())->nStatus & BLOCK_FAILED_MASK, 0U);
    FlushStateToDisk();
    BOOST_CHECK_EQUAL(DiskEntry(z15.GetHash()).nStatus & BLOCK_FAILED_MASK, 0U);

    BOOST_REQUIRE(Reload(false));
    BOOST_CHECK(Tip()->GetBlockHash() == a13.GetHash());
    BOOST_CHECK(Index(x14.GetHash())->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(Index(y15.GetHash())->nStatus & BLOCK_FAILED_CHILD);
    BOOST_CHECK(Index(y16.GetHash())->nStatus & BLOCK_FAILED_CHILD);
    BOOST_CHECK(Index(z15.GetHash())->nStatus & BLOCK_FAILED_CHILD);
    BOOST_CHECK(!(Index(z15.GetHash())->nStatus & BLOCK_FAILED_VALID));

    // The new flag is queued for writing and reaches the database with the next flush
    FlushStateToDisk();
    BOOST_CHECK(DiskEntry(z15.GetHash()).nStatus & BLOCK_FAILED_CHILD);
    BOOST_REQUIRE(Reload());
    BOOST_CHECK(Index(z15.GetHash())->nStatus & BLOCK_FAILED_CHILD);
    BOOST_CHECK(Tip()->GetBlockHash() == a13.GetHash());
}

BOOST_AUTO_TEST_CASE(restart_reconnects_blocks_after_index_only_write)
{
    // A header without data and a block on top of it, on a side branch
    CBlock h11 = BuildOn(AtHeight(10), OtherScript(1));
    BOOST_REQUIRE(SubmitHeader(h11));
    CBlock hc12 = BuildOn(Index(h11.GetHash()), OtherScript(2));
    BOOST_REQUIRE(Submit(hc12));
    BOOST_CHECK_EQUAL(Index(hc12.GetHash())->nChainTx, 0U);
    CBlockIndex* pT = Tip();
    const uint256 hashT = pT->GetBlockHash();
    FlushStateToDisk();

    CTransaction spend = Spend(coinbases[0]);
    CBlock t1 = Mine({spend});
    CBlock t2 = Mine();
    WriteIndexOnly();

    BOOST_REQUIRE(Reload(false));
    // The coins were written at T, so that's where the chain starts again
    BOOST_CHECK(Tip()->GetBlockHash() == hashT);
    {
        LOCK(cs_main);
        BOOST_CHECK(pcoinsTip->GetBestBlock() == hashT);
    }
    BOOST_REQUIRE(Known(t2.GetHash()));
    BOOST_CHECK(Index(t2.GetHash())->nStatus & BLOCK_HAVE_DATA);
    BOOST_CHECK(!HaveCoin(COutPoint(spend.GetHash(), 0)));
    BOOST_CHECK(HaveCoin(COutPoint(coinbases[0].GetHash(), 0)));

    // The stored blocks are connected again from disk
    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, Params()));
    BOOST_CHECK(Tip()->GetBlockHash() == t2.GetHash());
    BOOST_CHECK(HaveCoin(COutPoint(spend.GetHash(), 0)));
    BOOST_CHECK(!HaveCoin(COutPoint(coinbases[0].GetHash(), 0)));

    // The block waiting for its parent's data is linked once that data arrives
    BOOST_REQUIRE(Submit(h11));
    BOOST_CHECK(Index(h11.GetHash())->nChainTx > 0);
    BOOST_CHECK(Index(hc12.GetHash())->nChainTx > 0);
    BOOST_CHECK(Tip()->GetBlockHash() == t2.GetHash());

    // And the chain keeps growing (CheckBlockIndex runs on the reloaded state)
    CBlock t3 = Mine();
    BOOST_CHECK_EQUAL(Tip()->nHeight, 15);
}

BOOST_AUTO_TEST_CASE(restart_restores_tokens)
{
    // A mature coin large enough for the issue lock, instead of mining enough coinbases
    const CAmount nLock = GetLockAmount(ETokenType::YATOKEN);
    const COutPoint fund(uint256S("0xf0f0f0f0"), 0);
    {
        LOCK(cs_main);
        pcoinsTip->AddCoin(fund, Coin(CTxOut(nLock + 10 * COIN, scriptPubKey), 1, false, false, (int)Tip()->GetBlockTime()), false);
    }
    FlushStateToDisk();
    AdvanceTime();

    const CKeyID keyA = coinbaseKey.GetPubKey().GetID();
    const std::string addrA = EncodeDestination(keyA);
    const std::string addrB = TestTokenAddress(2);
    const std::string addrC = TestTokenAddress(3);
    CNewToken token("RELOAD", 1000 * COIN, 0, 1, 0, "");
    CScript ownerScript = GetScriptForDestination(keyA);
    token.ConstructOwnerTransaction(ownerScript);
    CScript issueScript = GetScriptForDestination(keyA);
    token.ConstructTransaction(issueScript);

    CMutableTransaction mIssue;
    mIssue.vin.emplace_back(fund);
    mIssue.vout.emplace_back(10 * COIN - CENT, scriptPubKey);
    mIssue.vout.push_back(TokenLockOutput(ETokenType::YATOKEN));
    mIssue.vout.emplace_back(0, ownerScript);
    mIssue.vout.emplace_back(0, issueScript);
    CTransaction issue = Sign(mIssue, {scriptPubKey});
    CBlock t1 = Mine({issue});

    auto transfer = [&](const CTransaction& prev, unsigned int nToken, CAmount nAway, const CScript& away, CAmount nBack) {
        CScript awayScript = away;
        CTokenTransfer("RELOAD", nAway).ConstructTransaction(awayScript);
        CScript backScript = GetScriptForDestination(keyA);
        CTokenTransfer("RELOAD", nBack).ConstructTransaction(backScript);
        CMutableTransaction mtx;
        mtx.vin.emplace_back(COutPoint(prev.GetHash(), nToken));
        mtx.vin.emplace_back(COutPoint(prev.GetHash(), 0));
        mtx.vout.emplace_back(prev.vout[0].nValue - CENT, scriptPubKey);
        mtx.vout.emplace_back(0, awayScript);
        mtx.vout.emplace_back(0, backScript);
        return Sign(mtx, {prev.vout[nToken].scriptPubKey, prev.vout[0].scriptPubKey});
    };
    CTransaction t2tx = transfer(issue, 3, 400 * COIN, TestTokenScriptBase(2), 600 * COIN);
    CBlock t2 = Mine({t2tx});
    FlushStateToDisk();

    // T3 reaches the block index but not the coins or token databases
    CTransaction t3tx = transfer(t2tx, 2, 100 * COIN, TestTokenScriptBase(3), 500 * COIN);
    CBlock t3 = Mine({t3tx});
    WriteIndexOnly();

    BOOST_REQUIRE(Reload(false));
    BOOST_CHECK(Tip()->GetBlockHash() == t2.GetHash());
    BOOST_REQUIRE(ptokensCache->Exists("RELOAD"));
    CDatabasedTokenData data = ptokensCache->Get("RELOAD");
    BOOST_CHECK_EQUAL(data.token.strName, "RELOAD");
    BOOST_CHECK_EQUAL(data.token.nAmount, 1000 * COIN);
    BOOST_CHECK_EQUAL(data.token.units, 0);
    BOOST_CHECK_EQUAL(data.token.nReissuable, 1);
    BOOST_CHECK_EQUAL(data.token.nHasIPFS, 0);
    BOOST_CHECK_EQUAL(data.nHeight, Index(t1.GetHash())->nHeight);
    BOOST_CHECK(data.blockHash == t1.GetHash());
    std::map<std::pair<std::string, std::string>, CAmount> expected{
        {{"RELOAD", addrA}, 600 * COIN}, {{"RELOAD", addrB}, 400 * COIN}, {{"RELOAD!", addrA}, OWNER_TOKEN_AMOUNT}};
    BOOST_CHECK(ptokens->mapTokensAddressAmount == expected);

    // T3's transfer is validated against the reloaded token state
    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, Params()));
    BOOST_CHECK(Tip()->GetBlockHash() == t3.GetHash());
    FlushStateToDisk();
    CAmount nQuantity = 0;
    BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("RELOAD", addrA, nQuantity));
    BOOST_CHECK_EQUAL(nQuantity, 500 * COIN);
    BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("RELOAD", addrC, nQuantity));
    BOOST_CHECK_EQUAL(nQuantity, 100 * COIN);

    // Disconnecting T3 uses its token undo data, written before the restart
    {
        LOCK(cs_main);
        BOOST_REQUIRE(InvalidateBlock(state, Params(), Index(t3.GetHash())));
    }
    BOOST_CHECK(Tip()->GetBlockHash() == t2.GetHash());
    FlushStateToDisk();
    BOOST_CHECK(ptokensdb->ReadTokenAddressQuantity("RELOAD", addrA, nQuantity));
    BOOST_CHECK_EQUAL(nQuantity, 600 * COIN);
    BOOST_CHECK(!ptokensdb->ReadTokenAddressQuantity("RELOAD", addrC, nQuantity));
}

BOOST_AUTO_TEST_CASE(load_block_index_rejects_corrupt_or_missing_data)
{
    Mine({Spend(coinbases[0])});
    CBlockIndex* pTip = Tip();
    const uint256 hashTip = pTip->GetBlockHash();
    FlushStateToDisk();

    // A block file is missing
    const fs::path blk = GetBlockPosFilename(CDiskBlockPos(0, 0), "blk");
    fs::rename(blk, blk.string() + ".bak");
    BOOST_CHECK(!LoadIndexOnly());
    fs::rename(blk.string() + ".bak", blk);
    BOOST_REQUIRE(Reload());
    BOOST_CHECK(Tip()->GetBlockHash() == hashTip);
    pTip = Tip();

    // A block index record that can't be read
    const auto badKey = std::make_pair(DB_BLOCK_INDEX, uint256S("0x01"));
    BOOST_REQUIRE(pblocktree->Write(badKey, TruncatedValue(CDiskBlockIndex(pTip))));
    BOOST_CHECK(!LoadIndexOnly());
    BOOST_REQUIRE(pblocktree->Erase(badKey, true));
    BOOST_REQUIRE(Reload());
    pTip = Tip();

    // A header on top of the tip whose stored hash doesn't meet its target
    CDiskBlockIndex crafted(pTip);
    crafted.hashPrev = hashTip;
    crafted.nHeight = pTip->nHeight + 1;
    crafted.nStatus = BLOCK_VALID_TREE;
    crafted.nTx = 0;
    crafted.nFlags = 0;
    crafted.blockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const auto craftedKey = std::make_pair(DB_BLOCK_INDEX, crafted.blockHash);
    BOOST_REQUIRE(pblocktree->Write(craftedKey, crafted));
    BOOST_CHECK(!LoadIndexOnly());

    // The same header as proof of stake isn't checked against a work target
    crafted.nFlags = CBlockIndex::BLOCK_PROOF_OF_STAKE;
    crafted.prevoutStake = COutPoint(uint256S("0xabc"), 1);
    crafted.nStakeTime = 1234;
    crafted.hashProofOfStake = uint256S("0x99");
    // and as a pre-1.0 header, whose time is stored in 32 bits
    crafted.nVersion = VERSION_of_block_for_yac_05x_new - 1;
    BOOST_REQUIRE(pblocktree->Write(craftedKey, crafted));
    {
        LOCK(cs_main);
        UnloadBlockIndex();
        BOOST_CHECK(LoadBlockIndex(Params()));
        BOOST_REQUIRE(mapBlockIndex.count(crafted.blockHash));
        const CBlockIndex* p = mapBlockIndex[crafted.blockHash];
        BOOST_CHECK(p->pprev && p->pprev->GetBlockHash() == hashTip);
        BOOST_CHECK_EQUAL(p->nHeight, crafted.nHeight);
        BOOST_CHECK(p->IsProofOfStake());
        BOOST_CHECK(p->prevoutStake == crafted.prevoutStake);
        BOOST_CHECK_EQUAL(p->nStakeTime, 1234U);
        BOOST_CHECK(p->hashProofOfStake == crafted.hashProofOfStake);
        BOOST_CHECK_EQUAL(p->nVersion, crafted.nVersion);
        BOOST_CHECK_EQUAL(p->nTime, crafted.nTime);
        BOOST_CHECK(LoadChainTip(Params()));
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == hashTip);
    }
    BOOST_REQUIRE(pblocktree->Erase(craftedKey, true));
    BOOST_REQUIRE(Reload());
    BOOST_CHECK(!Known(crafted.blockHash));

    // The coins' best block isn't in the index
    {
        LOCK(cs_main);
        pcoinsTip->SetBestBlock(uint256S("0xbad"));
        BOOST_CHECK(!LoadChainTip(Params()));
        pcoinsTip->SetBestBlock(hashTip);
        BOOST_CHECK(LoadChainTip(Params()));
    }

    // Empty coins with a full index. (init doesn't call LoadChainTip when the coins
    // database is empty, init.cpp "is_coinsview_empty", so this only tests the guard.)
    {
        LOCK(cs_main);
        CCoinsView empty;
        CCoinsViewCache* saved = pcoinsTip;
        pcoinsTip = new CCoinsViewCache(&empty);
        BOOST_CHECK(!LoadChainTip(Params()));
        delete pcoinsTip;
        pcoinsTip = saved;
        BOOST_CHECK(LoadChainTip(Params()));
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == hashTip);
    }
}

BOOST_AUTO_TEST_CASE(load_block_index_reads_flags_and_block_hash_index)
{
    BOOST_REQUIRE(Restart());

    // Flags stored in the block tree database win over the globals
    for (bool fValue : {false, true}) {
        BOOST_REQUIRE(pblocktree->WriteFlag("txindex", fValue));
        BOOST_REQUIRE(pblocktree->WriteFlag("tokenindex", fValue));
        BOOST_REQUIRE(pblocktree->WriteFlag("addressindex", fValue));
        fTxIndex = fTokenIndex = fAddressIndex = !fValue;
        BOOST_REQUIRE(Reload(false));
        BOOST_CHECK_EQUAL(fTxIndex, fValue);
        BOOST_CHECK_EQUAL(fTokenIndex, fValue);
        BOOST_CHECK_EQUAL(fAddressIndex, fValue);
    }
    fAddressIndex = false;

    // An interrupted reindex continues
    BOOST_REQUIRE(pblocktree->WriteReindexing(true));
    BOOST_CHECK(LoadIndexOnly());
    BOOST_CHECK(fReindex);
    BOOST_REQUIRE(pblocktree->WriteReindexing(false));
    fReindex = false;
    BOOST_REQUIRE(Reload(false));
    BOOST_CHECK(!fReindex);

    // File info records after the last block file are loaded too
    CBlockFileInfo extra;
    extra.nBlocks = 3;
    extra.nSize = 1234;
    extra.nUndoSize = 56;
    extra.nHeightFirst = 7;
    extra.nHeightLast = 9;
    extra.nTimeFirst = 1000;
    extra.nTimeLast = 2000;
    BOOST_REQUIRE(pblocktree->WriteBatchSync({{1, &extra}}, 0, {}));
    BOOST_REQUIRE(Reload(false));
    {
        LOCK(cs_main);
        const CBlockFileInfo* info = GetBlockFileInfo(1);
        BOOST_CHECK_EQUAL(info->nBlocks, 3U);
        BOOST_CHECK_EQUAL(info->nSize, 1234U);
        BOOST_CHECK_EQUAL(info->nUndoSize, 56U);
        BOOST_CHECK_EQUAL(info->nHeightFirst, 7U);
        BOOST_CHECK_EQUAL(info->nHeightLast, 9U);
        BOOST_CHECK_EQUAL(info->nTimeFirst, 1000U);
        BOOST_CHECK_EQUAL(info->nTimeLast, 2000U);
        BOOST_CHECK_THROW(GetBlockFileInfo(2), std::out_of_range);
    }

    // A missing block hash index entry is written while loading, unless the index is off
    CBlockIndex* p5 = AtHeight(5);
    const uint256 hash5 = p5->GetBlockHash();
    uint256 stored;
    EraseBlockHash(p5);
    BOOST_CHECK(!ReadBlockHash(p5, stored));
    BOOST_REQUIRE(Reload(false));
    p5 = Index(hash5);
    BOOST_CHECK(ReadBlockHash(p5, stored));
    BOOST_CHECK(stored == hash5);

    EraseBlockHash(p5);
    fBlockHashIndex = false;
    BOOST_REQUIRE(Reload(false));
    p5 = Index(hash5);
    BOOST_CHECK(!ReadBlockHash(p5, stored));
}

BOOST_AUTO_TEST_CASE(build_map_hash_and_block_hash_index)
{
    Mine();
    CBlock h = BuildOn(AtHeight(11), OtherScript(1));
    BOOST_REQUIRE(SubmitHeader(h));
    WriteKeyAfterBlockIndex();
    FlushStateToDisk();

    std::vector<const CBlockIndex*> withData;
    size_t nEntries;
    {
        LOCK(cs_main);
        nEntries = mapBlockIndex.size();
        for (const auto& item : mapBlockIndex)
            if (item.second->nStatus & BLOCK_HAVE_DATA) withData.push_back(item.second);
    }
    BOOST_CHECK_EQUAL(withData.size(), nEntries - 1);

    mapHash.clear();
    blockHashPos.clear();
    BOOST_CHECK(pblocktree->BuildMapHash());
    BOOST_CHECK_EQUAL(mapHash.size(), nEntries);
    {
        LOCK(cs_main);
        for (const auto& item : mapBlockIndex) {
            auto it = mapHash.find(item.second->GetSHA256Hash());
            BOOST_CHECK(it != mapHash.end() && it->second == item.first);
        }
    }
    // Positions only for blocks with data (not for the header)
    BOOST_CHECK_EQUAL(blockHashPos.size(), withData.size());
    std::set<std::tuple<int, unsigned int, uint256> > positions;
    for (const CBlockHashPos& pos : blockHashPos) positions.insert(std::make_tuple(pos.nFile, pos.nPos, pos.hash));
    for (const CBlockIndex* p : withData)
        BOOST_CHECK(positions.count(std::make_tuple(p->nFile, p->nDataPos, p->GetBlockHash())));

    // BuildBlockHashIndex writes them all back
    for (const CBlockIndex* p : withData) EraseBlockHash(p);
    BOOST_CHECK(pblocktree->BuildBlockHashIndex());
    BOOST_CHECK(blockHashPos.empty());
    uint256 stored;
    for (const CBlockIndex* p : withData) {
        BOOST_CHECK(ReadBlockHash(p, stored));
        BOOST_CHECK(stored == p->GetBlockHash());
    }

    // With -blockhashindex=0 nothing is written and the positions are kept
    fBlockHashIndex = false;
    BOOST_CHECK(pblocktree->BuildMapHash());
    EraseBlockHash(withData[0]);
    BOOST_CHECK(pblocktree->BuildBlockHashIndex());
    BOOST_CHECK_EQUAL(blockHashPos.size(), withData.size());
    BOOST_CHECK(!ReadBlockHash(withData[0], stored));
    blockHashPos.clear();
    fBlockHashIndex = true;

    // An unreadable record fails the scan
    const auto badKey = std::make_pair(DB_BLOCK_INDEX, uint256S("0x01"));
    BOOST_REQUIRE(pblocktree->Write(badKey, TruncatedValue(CDiskBlockIndex(withData[0]))));
    BOOST_CHECK(!pblocktree->BuildMapHash());
    BOOST_REQUIRE(pblocktree->Erase(badKey, true));
    blockHashPos.clear();

    // An empty database adds nothing
    CBlockTreeDB emptyDb(1 << 20, true, true);
    mapHash.clear();
    BOOST_CHECK(emptyDb.BuildMapHash());
    BOOST_CHECK(mapHash.empty());
    BOOST_CHECK(blockHashPos.empty());
}

BOOST_AUTO_TEST_CASE(import_blocks_into_fresh_datadir)
{
    Mine({Spend(coinbases[0])});
    Mine();
    std::vector<CBlock> b = ReadChain(); // b[h] is the block at height h; tip is 14
    BOOST_REQUIRE_EQUAL(b.size(), 15U);
    const uint256 hashTip = b[14].GetHash();

    CBlock badMerkle = b[4];
    badMerkle.hashMerkleRoot = uint256S("0x1234");
    Solve(badMerkle);

    const fs::path file1 = DataFile("bootstrap1.dat");
    {
        CAutoFile out(fsbridge::fopen(file1, "wb"), SER_DISK, CLIENT_VERSION);
        AppendBytes(out, std::vector<unsigned char>(10, 'x'));
        AppendBytes(out, {Params().MessageStart()[0], 0, 0, 0}); // not a message start
        AppendHeaderOnly(out, 79); // too small for a block
        AppendHeaderOnly(out, MAX_BLOCK_SERIALIZED_SIZE + 1); // too large
        for (int h = 0; h <= 3; h++) AppendBlock(out, b[h]);
        AppendHeaderOnly(out, 80);
        AppendBytes(out, std::vector<unsigned char>(80, 0)); // a header and no transactions
        AppendBlock(out, badMerkle);
        AppendBlock(out, b[5]); // before its parent: dropped without a block position
        AppendBlock(out, b[4]);
        AppendBlock(out, b[6]); // its parent was dropped
        AppendTruncatedBlock(out, b[7]);
    }
    const fs::path file2 = DataFile("bootstrap2.dat");
    {
        CAutoFile out(fsbridge::fopen(file2, "wb"), SER_DISK, CLIENT_VERSION);
        for (int h = 5; h <= 14; h++) AppendBlock(out, b[h]);
    }

    FreshNode();
    BOOST_CHECK(Tip()->GetBlockHash() == b[0].GetHash());
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(mapBlockIndex.size(), 1U);
        bool fFlag = false;
        BOOST_CHECK(pblocktree->ReadFlag("txindex", fFlag) && fFlag && fTxIndex);
        BOOST_CHECK(pblocktree->ReadFlag("tokenindex", fFlag) && fFlag == DEFAULT_TOKENINDEX && fTokenIndex == DEFAULT_TOKENINDEX);
        BOOST_CHECK(pblocktree->ReadFlag("addressindex", fFlag) && fFlag == DEFAULT_ADDRESSINDEX && fAddressIndex == DEFAULT_ADDRESSINDEX);
    }
    // B1's header is already known; its data comes from the file
    BOOST_REQUIRE(SubmitHeader(b[1]));

    BOOST_CHECK(Import(file1));
    BOOST_CHECK(Tip()->GetBlockHash() == b[4].GetHash());
    for (int h = 1; h <= 4; h++) BOOST_CHECK(AtHeight(h)->GetBlockHash() == b[h].GetHash());
    BOOST_CHECK(!Known(b[5].GetHash()));
    BOOST_CHECK(!Known(b[6].GetHash()));
    BOOST_CHECK(!Known(badMerkle.GetHash()));
    BOOST_CHECK(mapHash.count(b[2].GetSHA256Hash()) && mapHash[b[2].GetSHA256Hash()] == b[2].GetHash());

    BOOST_CHECK(Import(file2));
    BOOST_CHECK(Tip()->GetBlockHash() == hashTip);

    // Everything known now: nothing loaded
    BOOST_CHECK(!Import(file1));
    BOOST_CHECK(!Import(file2));
    BOOST_CHECK(Tip()->GetBlockHash() == hashTip);

    const fs::path empty = DataFile("empty.dat");
    { CAutoFile out(fsbridge::fopen(empty, "wb"), SER_DISK, CLIENT_VERSION); }
    BOOST_CHECK(!Import(empty));
    const fs::path junk = DataFile("junk.dat");
    {
        CAutoFile out(fsbridge::fopen(junk, "wb"), SER_DISK, CLIENT_VERSION);
        AppendBytes(out, std::vector<unsigned char>(1000, 'x'));
    }
    BOOST_CHECK(!Import(junk));
}

BOOST_AUTO_TEST_CASE(reindex_rebuilds_index_from_block_files)
{
    Mine({Spend(coinbases[0])});
    Mine();
    Mine();
    const int nHeight0 = Tip()->nHeight; // 15, all in blk00000.dat
    unsigned int nSize0;
    {
        LOCK(cs_main);
        nSize0 = GetBlockFileInfo(0)->nSize;
    }
    // Five more blocks; they're cut off blk00000.dat below and written out of order into
    // blk00001.dat instead
    for (int i = 0; i < 5; i++) Mine();
    std::vector<CBlock> b = ReadChain();
    const uint256 hashTip = b.back().GetHash();
    FlushStateToDisk();
    IndexSnapshot original = TakeSnapshot();
    fs::resize_file(GetBlockPosFilename(CDiskBlockPos(0, 0), "blk"), nSize0);

    CBlock badPow = b[nHeight0 + 3]; // child of C17
    do {
        ++badPow.nNonce;
    } while (CheckProofOfWork(badPow.GetHash(), badPow.nBits, Params().GetConsensus()));
    CBlock badMerkle = b[nHeight0 + 5]; // child of C19
    badMerkle.hashMerkleRoot = uint256S("0x1234");
    Solve(badMerkle);

    // Index, coins and token databases wiped, block files kept (-reindex)
    FreshNode(false);
    std::map<uint256, unsigned int> offsets;
    {
        const int c = nHeight0;
        CAutoFile out(fsbridge::fopen(GetBlockPosFilename(CDiskBlockPos(1, 0), "blk"), "wb"), SER_DISK, CLIENT_VERSION);
        std::vector<CBlock> order{b[c + 1], b[c + 4], b[c + 3], badPow, badMerkle, b[c + 2], b[c + 5]};
        for (const CBlock& block : order) AppendBlock(out, block, &offsets[block.GetHash()]);
    }
    // The reindex re-accepts the genesis block through ProcessNewBlock. With the fork at height 0
    // (the unit test default) ContextualCheckBlock rejects genesis' version 1 transaction, so the
    // fork is moved to height 1 for the reindex, as feature_reindex.py does.
    ConsensusGlobalsGuard guard;
    guard.Set(1, nEpochInterval);
    fReindex = true;
    BOOST_REQUIRE(pblocktree->WriteReindexing(true));
    {
        LOCK(cs_main);
        BOOST_CHECK(LoadBlockIndex(Params()));
        BOOST_CHECK(mapBlockIndex.empty());
    }
    // ThreadImport's reindex loop
    int nFiles = 0;
    for (int nFile = 0; ; nFile++) {
        CDiskBlockPos pos(nFile, 0);
        FILE* file = OpenBlockFile(pos, true);
        if (!file) break;
        BOOST_CHECK(LoadExternalBlockFile(Params(), file, &pos));
        nFiles++;
    }
    BOOST_CHECK_EQUAL(nFiles, 2);
    BOOST_REQUIRE(pblocktree->WriteReindexing(false));
    fReindex = false;
    {
        LOCK(cs_main);
        BOOST_CHECK(LoadGenesisBlock(Params()));
    }
    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, Params()));

    BOOST_CHECK(Tip()->GetBlockHash() == hashTip);
    BOOST_CHECK(!Known(badPow.GetHash()));
    BOOST_CHECK(!Known(badMerkle.GetHash()));
    {
        LOCK(cs_main);
        BOOST_CHECK(pcoinsTip->GetBestBlock() == hashTip);
        for (int h = 0; h <= chainActive.Height(); h++) {
            const CBlockIndex* p = chainActive[h];
            BOOST_CHECK(p->GetBlockHash() == b[h].GetHash());
            BOOST_CHECK(p->nStatus & BLOCK_HAVE_DATA);
            BOOST_CHECK(h == 0 || (p->nStatus & BLOCK_HAVE_UNDO));
            BOOST_CHECK_MESSAGE(h == 0 || p->IsValid(BLOCK_VALID_SCRIPTS), "height " << h); // ConnectBlock returns early for genesis
            const CBlockIndex& o = original.entries.at(p->GetBlockHash()).index;
            BOOST_CHECK_EQUAL(p->nTx, o.nTx);
            if (h <= nHeight0) {
                BOOST_CHECK_EQUAL(p->nFile, 0);
                BOOST_CHECK_EQUAL(p->nDataPos, o.nDataPos);
            } else {
                BOOST_CHECK_EQUAL(p->nFile, 1);
                BOOST_CHECK_EQUAL(p->nDataPos, offsets[p->GetBlockHash()]);
            }
        }
    }

    // Blocks imported from a known position never had a block hash index entry; the next
    // load writes them
    std::vector<uint256> hashes;
    for (int h = nHeight0 + 1; h <= nHeight0 + 5; h++) hashes.push_back(b[h].GetHash());
    uint256 stored;
    for (const uint256& hash : hashes) BOOST_CHECK(!ReadBlockHash(Index(hash), stored));
    FlushStateToDisk();
    IndexSnapshot before = TakeSnapshot();
    BOOST_REQUIRE(Restart());
    CheckSame(before, TakeSnapshot());
    BOOST_CHECK_EQUAL(before.nLastFile, 1);
    for (const uint256& hash : hashes) {
        BOOST_CHECK(ReadBlockHash(Index(hash), stored));
        BOOST_CHECK(stored == hash);
    }
}

BOOST_AUTO_TEST_CASE(mempool_dump_and_load_round_trip)
{
    AdvanceTime();
    CTransaction tx1 = Spend(coinbases[0]);
    CTransaction tx2 = Spend(tx1);
    CTransaction tx3 = Spend(coinbases[1]);
    for (const CTransaction& tx : {tx1, tx2, tx3}) {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), nullptr));
    }
    mempool.PrioritiseTransaction(tx3.GetHash(), 5 * CENT);
    mempool.PrioritiseTransaction(uint256S("0xdead"), 7);

    std::map<uint256, std::pair<int64_t, int64_t> > info;
    for (const TxMempoolInfo& i : mempool.infoAll()) info[i.tx->GetHash()] = std::make_pair(i.nTime, i.nFeeDelta);
    std::map<uint256, CAmount> deltas = mempool.mapDeltas;
    BOOST_CHECK_EQUAL(info.size(), 3U);
    BOOST_CHECK_EQUAL(deltas.size(), 2U);

    DumpMempool();
    BOOST_CHECK(fs::exists(DataFile("mempool.dat")));
    BOOST_CHECK(!fs::exists(DataFile("mempool.dat.new")));
    mempool.clear();
    {
        LOCK(mempool.cs);
        mempool.mapDeltas.clear();
    }

    BOOST_CHECK(LoadMempool());
    BOOST_CHECK_EQUAL(mempool.size(), 3U);
    for (const auto& item : info) {
        BOOST_REQUIRE(mempool.exists(item.first));
        TxMempoolInfo i = mempool.info(item.first);
        BOOST_CHECK_EQUAL(i.nTime, item.second.first);
        BOOST_CHECK_EQUAL(i.nFeeDelta, item.second.second);
    }
    {
        LOCK(mempool.cs);
        auto it = mempool.mapTx.find(tx3.GetHash());
        BOOST_CHECK_EQUAL(it->GetModifiedFee(), it->GetFee() + 5 * CENT);
        BOOST_CHECK(mempool.mapDeltas == deltas);
    }
}

namespace {
struct MempoolRecord {
    CTransaction tx;
    int64_t nTime;
    int64_t nFeeDelta;
};

/** A mempool.dat in DumpMempool's format; nRecordsToWrite < records.size() truncates the file */
void WriteMempoolFile(const fs::path& path, uint64_t nVersion, const std::vector<MempoolRecord>& records,
                      bool fWriteDeltas = true, size_t nRecordsToWrite = std::numeric_limits<size_t>::max())
{
    CAutoFile file(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    file << nVersion;
    file << (uint64_t)records.size();
    for (size_t i = 0; i < records.size() && i < nRecordsToWrite; i++)
        file << records[i].tx << records[i].nTime << records[i].nFeeDelta;
    if (fWriteDeltas && nRecordsToWrite >= records.size()) file << std::map<uint256, CAmount>();
}

void ResetMempool()
{
    mempool.clear();
    LOCK(mempool.cs);
    mempool.mapDeltas.clear();
}
} // namespace

BOOST_AUTO_TEST_CASE(load_mempool_edge_cases)
{
    AdvanceTime();
    const int64_t nNow = GetTime();
    const int64_t nExpiry = DEFAULT_MEMPOOL_EXPIRY * 60 * 60;
    CTransaction tx1 = Spend(coinbases[0]);
    CTransaction tx2 = Spend(tx1);
    CTransaction tx3 = Spend(coinbases[1]);
    const fs::path path = DataFile("mempool.dat");

    // No file yet
    BOOST_CHECK(!LoadMempool());
    BOOST_CHECK_EQUAL(mempool.size(), 0U);

    // Unknown versions
    for (uint64_t nVersion : {0, 2}) {
        WriteMempoolFile(path, nVersion, {{tx1, nNow, 0}});
        BOOST_CHECK(!LoadMempool());
        BOOST_CHECK_EQUAL(mempool.size(), 0U);
    }

    // No records
    WriteMempoolFile(path, 1, {});
    BOOST_CHECK(LoadMempool());
    BOOST_CHECK_EQUAL(mempool.size(), 0U);

    // Expired (entry time exactly the expiry age), loaded (one second younger), a duplicate
    // (fails), and another tx. Fee deltas are applied even for records that aren't loaded.
    WriteMempoolFile(path, 1, {{tx1, nNow - nExpiry, 3}, {tx1, nNow - nExpiry + 1, 0}, {tx1, nNow, 5}, {tx3, nNow, 4 * CENT}});
    {
        LogCapture capture(DataFile("mempool.log"));
        BOOST_CHECK(LoadMempool());
        std::string log = capture.Stop();
        BOOST_CHECK(Contains(log, "Imported mempool transactions from disk: 2 successes, 1 failed, 1 expired"));
    }
    BOOST_CHECK_EQUAL(mempool.size(), 2U);
    BOOST_CHECK(mempool.exists(tx1.GetHash()));
    BOOST_CHECK(mempool.exists(tx3.GetHash()));
    BOOST_CHECK_EQUAL(mempool.info(tx1.GetHash()).nTime, nNow - nExpiry + 1);
    BOOST_CHECK_EQUAL(mempool.info(tx1.GetHash()).nFeeDelta, 8);
    {
        LOCK(mempool.cs);
        BOOST_CHECK_EQUAL(mempool.mapDeltas[tx1.GetHash()], 8);
        BOOST_CHECK_EQUAL(mempool.mapDeltas[tx3.GetHash()], 4 * CENT);
    }
    ResetMempool();

    // A child before its parent can't be accepted
    WriteMempoolFile(path, 1, {{tx2, nNow, 0}, {tx1, nNow, 0}});
    BOOST_CHECK(LoadMempool());
    BOOST_CHECK(mempool.exists(tx1.GetHash()));
    BOOST_CHECK(!mempool.exists(tx2.GetHash()));
    ResetMempool();

    // Truncated after the first record, or before the deltas: fails, but keeps what was loaded
    WriteMempoolFile(path, 1, {{tx1, nNow, 0}, {tx3, nNow, 0}}, true, 1);
    BOOST_CHECK(!LoadMempool());
    BOOST_CHECK(mempool.exists(tx1.GetHash()));
    BOOST_CHECK(!mempool.exists(tx3.GetHash()));
    ResetMempool();
    WriteMempoolFile(path, 1, {{tx1, nNow, 0}}, false);
    BOOST_CHECK(!LoadMempool());
    BOOST_CHECK(mempool.exists(tx1.GetHash()));
    ResetMempool();

    // Dumping an empty mempool: version, count and an empty delta map
    DumpMempool();
    BOOST_CHECK_EQUAL(fs::file_size(path), 17U);
    BOOST_CHECK(LoadMempool());
    BOOST_CHECK_EQUAL(mempool.size(), 0U);

    // The temporary file can't be created: nothing is written
    fs::remove(path);
    fs::create_directory(DataFile("mempool.dat.new"));
    {
        LOCK(cs_main);
        CValidationState state;
        BOOST_REQUIRE(AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx1), nullptr));
    }
    DumpMempool();
    BOOST_CHECK(!fs::exists(path));
    fs::remove(DataFile("mempool.dat.new"));
    ResetMempool();
}

// LoadBlockRewardAndHighestDiff only logs what it computes, so the log is checked.
BOOST_FIXTURE_TEST_CASE(load_block_reward_and_highest_diff, TestingSetup)
{
    ConsensusGlobalsGuard guard;
    SyntheticChain chain;
    CBlockIndex* genesis = chain.Genesis();
    const ::int64_t nGenesisSupply = genesis->nMoneySupply;
    genesis->nMoneySupply = 7000 * COIN;
    const unsigned int nLimitBits = Params().GetConsensus().powLimit.GetCompact();
    CBlockIndex* tip = genesis;
    std::vector<CBlockIndex*> blocks{genesis};
    for (int h = 1; h <= 12; h++) {
        tip = chain.Add(tip, genesis->GetBlockTime() + 60 * h, h == 7 ? 0x1d00ffff : nLimitBits, h * 1000 * COIN);
        chain.Register(tip);
        tip->blockHash = tip->GetBlockHash(); // the function looks blocks up by this member
        blocks.push_back(tip);
    }
    chain.SetActiveTip(tip);
    const fs::path path = GetDataDir() / "reward.log";
    auto run = [&]() {
        LogCapture capture(path);
        {
            LOCK(cs_main);
            LoadBlockRewardAndHighestDiff();
        }
        return capture.Stop();
    };
    auto target = [](unsigned int nBits) {
        return (CBigNum().SetCompact(nBits) * 3).getuint256().ToString().substr(0, 16);
    };
    const std::string strHard = "00000002fffd0000"; // 3 x 0x00000000ffff0000...

    // Epochs every 5 blocks: the newest epoch block (10) counts, its parent's supply sets the
    // reward (9000 COIN / 525960 blocks per year = 17111, x 2% = 342), and the harder block 7
    // sets the target.
    guard.Set(0, 5);
    std::string log = run();
    BOOST_CHECK_EQUAL(LogValue(log, "last epoch change at block "), "10 (" + blocks[10]->GetBlockHash().GetHex() + ")");
    BOOST_CHECK_EQUAL(LogValue(log, "Minimum difficulty target = "), strHard);
    BOOST_CHECK_EQUAL(LogValue(log, "Current block reward = "), "342");

    // Only genesis starts an epoch: its own supply sets the reward (7000 COIN -> 13309 x 2% = 266)
    guard.Set(0, 21000);
    log = run();
    BOOST_CHECK_EQUAL(LogValue(log, "last epoch change at block "), "0 (" + genesis->GetBlockHash().GetHex() + ")");
    BOOST_CHECK_EQUAL(LogValue(log, "Current block reward = "), "266");

    // From fork height 3 on there's no epoch block
    guard.Set(3, 1000);
    log = run();
    BOOST_CHECK(Contains(log, "There is something wrong, can't find last epoch change block"));
    BOOST_CHECK_EQUAL(LogValue(log, "Current block reward = "), "0");
    BOOST_CHECK_EQUAL(LogValue(log, "Minimum difficulty target = "), strHard);

    // No tip
    guard.Set(0, 21000);
    {
        LOCK(cs_main);
        chainActive.SetTip(nullptr);
    }
    log = run();
    chain.SetActiveTip(tip);
    BOOST_CHECK_EQUAL(LogValue(log, "last epoch change at block "), "0 (" + uint256().GetHex() + ")");
    BOOST_CHECK_EQUAL(LogValue(log, "Current block reward = "), "0");
    BOOST_CHECK_EQUAL(LogValue(log, "Minimum difficulty target = "), target(nLimitBits));

    genesis->nMoneySupply = nGenesisSupply;
}

BOOST_FIXTURE_TEST_CASE(load_tokens_from_database, TokenTestingSetup)
{
    // Empty database
    BOOST_CHECK(ptokensdb->LoadTokens());
    BOOST_CHECK_EQUAL(ptokensCache->Size(), 0U);
    BOOST_CHECK(ptokens->mapTokensAddressAmount.empty());

    const std::string addr1 = TestTokenAddress(1), addr2 = TestTokenAddress(2);
    const CNewToken aaa("AAA", 100 * COIN, 2, 1, 0, "");
    const CNewToken bb("BB", 200 * COIN, 0, 0, 1, TestIpfsHash());
    const CNewToken cccc("CCCC", 300 * COIN, 6, 1, 0, "");
    BOOST_REQUIRE(ptokensdb->WriteTokenData(aaa, 10, uint256S("0xa1")));
    BOOST_REQUIRE(ptokensdb->WriteTokenData(bb, 20, uint256S("0xb2")));
    BOOST_REQUIRE(ptokensdb->WriteTokenData(cccc, 30, uint256S("0xc3")));
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("AAA", addr1, 5 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("BB", addr2, 7 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteAddressTokenQuantity(addr1, "AAA", 5 * COIN)); // the next key range

    BOOST_CHECK(ptokensdb->LoadTokens());
    BOOST_CHECK_EQUAL(ptokensCache->Size(), 3U);
    BOOST_REQUIRE(ptokensCache->Exists("BB"));
    CDatabasedTokenData data = ptokensCache->Get("BB");
    BOOST_CHECK_EQUAL(data.token.strName, "BB");
    BOOST_CHECK_EQUAL(data.token.nAmount, 200 * COIN);
    BOOST_CHECK_EQUAL(data.token.units, 0);
    BOOST_CHECK_EQUAL(data.token.nReissuable, 0);
    BOOST_CHECK_EQUAL(data.token.nHasIPFS, 1);
    BOOST_CHECK(data.token.strIPFSHash == TestIpfsHash());
    BOOST_CHECK_EQUAL(data.nHeight, 20);
    BOOST_CHECK(data.blockHash == uint256S("0xb2"));
    std::map<std::pair<std::string, std::string>, CAmount> expected{{{"AAA", addr1}, 5 * COIN}, {{"BB", addr2}, 7 * COIN}};
    BOOST_CHECK(ptokens->mapTokensAddressAmount == expected);

    // An entry already in memory isn't replaced
    ptokens->mapTokensAddressAmount.clear();
    ptokens->mapTokensAddressAmount[std::make_pair("AAA", addr1)] = 1;
    BOOST_CHECK(ptokensdb->LoadTokens());
    BOOST_CHECK_EQUAL(ptokens->mapTokensAddressAmount[std::make_pair("AAA", addr1)], 1);

    // Without the token index no balances are loaded
    ptokens->mapTokensAddressAmount.clear();
    fTokenIndex = false;
    BOOST_CHECK(ptokensdb->LoadTokens());
    BOOST_CHECK(ptokens->mapTokensAddressAmount.empty());
    fTokenIndex = true;

    // Loading stops once the cache is half full. Names sort by length first: BB, AAA, CCCC.
    {
        CacheSwap swap(4);
        BOOST_CHECK(ptokensdb->LoadTokens());
        BOOST_CHECK_EQUAL(ptokensCache->Size(), 2U);
        BOOST_CHECK(ptokensCache->Exists("BB"));
        BOOST_CHECK(ptokensCache->Exists("AAA"));
        BOOST_CHECK(!ptokensCache->Exists("CCCC"));
    }
    {
        // Half of 1 is 0, so a one-entry cache never stops the loop; the last one put stays
        CacheSwap swap(1);
        BOOST_CHECK(ptokensdb->LoadTokens());
        BOOST_CHECK_EQUAL(ptokensCache->Size(), 1U);
        BOOST_CHECK(ptokensCache->Exists("CCCC"));
    }

    // Unreadable token record
    ptokens->mapTokensAddressAmount.clear();
    const auto badToken = std::make_pair(DB_TOKEN, std::string("BAD"));
    BOOST_REQUIRE(ptokensdb->Write(badToken, TruncatedValue(CDatabasedTokenData(aaa, 1, uint256()))));
    BOOST_CHECK(!ptokensdb->LoadTokens());
    BOOST_REQUIRE(ptokensdb->Erase(badToken, true));

    // Unreadable balance record
    const auto badQuantity = std::make_pair(DB_TOKEN_ADDRESS_QUANTITY, std::make_pair(std::string("ZZZ"), addr1));
    RawValue oneByte;
    oneByte.data.push_back(1);
    BOOST_REQUIRE(ptokensdb->Write(badQuantity, oneByte));
    BOOST_CHECK(!ptokensdb->LoadTokens());
    BOOST_REQUIRE(ptokensdb->Erase(badQuantity, true));

    // At most MAX_CACHE_TOKENS_SIZE + 1 balances (the limit is checked after the insert)
    ptokens->mapTokensAddressAmount.clear();
    for (int i = 0; i < MAX_CACHE_TOKENS_SIZE + 2; i++)
        BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("LIM", strprintf("addr%05d", i), i + 1));
    BOOST_CHECK(ptokensdb->LoadTokens());
    BOOST_CHECK_EQUAL(ptokens->mapTokensAddressAmount.size(), (size_t)MAX_CACHE_TOKENS_SIZE + 1);
    ptokens->mapTokensAddressAmount.clear();

    // Reissue mempool state: missing, then written and read back
    mapReissuedTx[uint256S("0x5")] = "OLD";
    BOOST_CHECK(!ptokensdb->ReadReissuedMempoolState());
    BOOST_CHECK(mapReissuedTx.empty());
    mapReissuedTokens["AAA"] = uint256S("0x77");
    BOOST_REQUIRE(ptokensdb->WriteReissuedMempoolState());
    mapReissuedTokens.clear();
    BOOST_CHECK(ptokensdb->ReadReissuedMempoolState());
    BOOST_CHECK_EQUAL(mapReissuedTokens.size(), 1U);
    BOOST_CHECK(mapReissuedTokens["AAA"] == uint256S("0x77"));
    BOOST_CHECK_EQUAL(mapReissuedTx.size(), 1U);
    BOOST_CHECK_EQUAL(mapReissuedTx[uint256S("0x77")], "AAA");
}

BOOST_AUTO_TEST_SUITE_END()
