// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifdef USE_LEVELDB
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "kernel.h"
#include "checkpoints.h"
#include "txdb.h"

#include <map>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <memenv/memenv.h>

using namespace boost;

//using namespace std;
using std::string;
using std::runtime_error;
using std::make_pair;
using std::map;
using std::pair;
using std::vector;

leveldb::DB *txdb; // global pointer for LevelDB object instance

static leveldb::Options GetOptions() {
    leveldb::Options options;
    int nCacheSizeMB = GetArg("-dbcache", 25);
    options.block_cache = leveldb::NewLRUCache(nCacheSizeMB * 1048576);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    return options;
}

void init_blockindex(leveldb::Options& options, bool fRemoveOld = false) {
    // First time init.
    filesystem::path directory = GetDataDir() / "txleveldb";

    if (fRemoveOld) {
        filesystem::remove_all(directory); // remove directory
        unsigned int nFile = 1;

        while (true)
        {
            filesystem::path strBlockFile = GetDataDir() / strprintf("blk%04u.dat", nFile);

            // Break if no such file
            if( !filesystem::exists( strBlockFile ) )
                break;

            filesystem::remove(strBlockFile);

            nFile++;
        }
    }

    filesystem::create_directory(directory);
    printf("Opening LevelDB in %s\n", directory.string().c_str());
    leveldb::Status status = leveldb::DB::Open(options, directory.string(), &txdb);
    if (!status.ok()) {
        throw runtime_error(strprintf("init_blockindex(): error opening database environment %s", status.ToString().c_str()));
    }
}

// CDB subclasses are created and destroyed VERY OFTEN. That's why
// we shouldn't treat this as a free operations.
CTxDB::CTxDB(const char* pszMode)
{
#ifdef _MSC_VER
    bool
        fTest = (pszMode);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(pszMode);
#endif
    activeBatch = NULL;
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));

    if (txdb) {
        pdb = txdb;
        return;
    }

    bool fCreate = strchr(pszMode, 'c');

    options = GetOptions();
    options.create_if_missing = fCreate;
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    init_blockindex(options); // Init directory
    pdb = txdb;

    if (Exists(string("version")))
    {
        ReadVersion(nVersion);
        printf("Transaction index version is %d\n", nVersion);

        if (nVersion < DATABASE_VERSION)
        {
            printf("Required index version is %d, removing old database\n", DATABASE_VERSION);

            // Leveldb instance destruction
            delete txdb;
            txdb = pdb = NULL;
            delete activeBatch;
            activeBatch = NULL;

            init_blockindex(options, true); // Remove directory and create new database
            pdb = txdb;

            bool fTmp = fReadOnly;
            fReadOnly = false;
            WriteVersion(DATABASE_VERSION); // Save transaction index version
            fReadOnly = fTmp;
        }
    }
    else if (fCreate)
    {
        bool fTmp = fReadOnly;
        fReadOnly = false;
        WriteVersion(DATABASE_VERSION);
        fReadOnly = fTmp;
    }

    printf("Opened LevelDB successfully\n");
}

void CTxDB::Close()
{
    delete txdb;
    txdb = pdb = NULL;
    delete options.filter_policy;
    options.filter_policy = NULL;
    delete options.block_cache;
    options.block_cache = NULL;
    delete activeBatch;
    activeBatch = NULL;
}

bool CTxDB::TxnBegin()
{
#ifdef _MSC_VER
    bool
        fTest = (!activeBatch);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(!activeBatch);
#endif
    activeBatch = new leveldb::WriteBatch();
    return true;
}

bool CTxDB::TxnCommit()
{
#ifdef _MSC_VER
    bool
        fTest = (activeBatch);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(activeBatch);
#endif
    leveldb::Status status = pdb->Write(leveldb::WriteOptions(), activeBatch);
    delete activeBatch;
    activeBatch = NULL;
    if (!status.ok()) {
        printf("LevelDB batch commit failure: %s\n", status.ToString().c_str());
        return false;
    }
    return true;
}

class CBatchScanner : public leveldb::WriteBatch::Handler {
public:
    std::string needle;
    bool *deleted;
    std::string *foundValue;
    bool foundEntry;

    CBatchScanner() : foundEntry(false) {}

    virtual void Put(const leveldb::Slice& key, const leveldb::Slice& value) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = false;
            *foundValue = value.ToString();
        }
    }

    virtual void Delete(const leveldb::Slice& key) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = true;
        }
    }
};

// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
bool CTxDB::ScanBatch(const CDataStream &key, string *value, bool *deleted) const {
#ifdef _MSC_VER
    bool
        fTest = (activeBatch);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(activeBatch);
#endif
    *deleted = false;
    CBatchScanner scanner;
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    leveldb::Status status = activeBatch->Iterate(&scanner);
    if (!status.ok()) {
        throw runtime_error(status.ToString());
    }
    return scanner.foundEntry;
}

bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex& txindex)
{
#ifdef _MSC_VER
    bool
        fTest = (!fClient);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(!fClient);
#endif
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
#ifdef _MSC_VER
    bool
        fTest = (!fClient);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(!fClient);
#endif
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
#ifdef _MSC_VER
    bool
        fTest = (!fClient);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(!fClient);
#endif
    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
#ifdef _MSC_VER
    bool
        fTest = (!fClient);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(!fClient);
#endif
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
#ifdef _MSC_VER
    bool
        fTest = (!fClient);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(!fClient);
#endif
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
#ifdef _MSC_VER
    bool
        fTest = (!fClient);
    #ifdef _DEBUG
    assert(fTest);
    #else
    if( !fTest )
        releaseModeAssertionfailure( __FILE__, __LINE__, __PRETTY_FUNCTION__ );
    #endif
#else
    assert(!fClient);
#endif
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

bool CTxDB::ReadBestInvalidTrust(CBigNum& bnBestInvalidTrust)
{
    return Read(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::WriteBestInvalidTrust(CBigNum bnBestInvalidTrust)
{
    return Write(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::ReadSyncCheckpoint(uint256& hashCheckpoint)
{
    return Read(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::WriteSyncCheckpoint(uint256 hashCheckpoint)
{
    return Write(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::ReadCheckpointPubKey(string& strPubKey)
{
    return Read(string("strCheckpointPubKey"), strPubKey);
}

bool CTxDB::WriteCheckpointPubKey(const string& strPubKey)
{
    return Write(string("strCheckpointPubKey"), strPubKey);
}

bool CTxDB::ReadModifierUpgradeTime(unsigned int& nUpgradeTime)
{
    return Read(string("nUpgradeTime"), nUpgradeTime);
}

bool CTxDB::WriteModifierUpgradeTime(const unsigned int& nUpgradeTime)
{
    return Write(string("nUpgradeTime"), nUpgradeTime);
}

static CBlockIndex *InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CTxDB::LoadBlockIndex()
{
    if (mapBlockIndex.size() > 0) 
    {
        // Already loaded once in this session. It can happen during migration
        // from BDB.
        return true;
    }
#ifdef WIN32
    int
        nMaxHeightGuess = 0,
        nCounter = 0,
    #ifdef _DEBUG
        nRefresh = 2000;    // generally resfresh rates are chosen to give ~1 update/sec
    #else
        // seems to be slowing down??
        #ifdef QT_GUI
        nRefresh = 4000;
        #else
        nRefresh = 5000;    // 15000;    //10000;
        #endif
    #endif
    ::int64_t
        n64MsStartTime = GetTimeMillis();
#endif
    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into mapBlockIndex.
    leveldb::Iterator 
        *iterator = pdb->NewIterator(leveldb::ReadOptions());
    // Seek to start key.

    CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
    ssStartKey << make_pair(string("blockindex"), uint256(0));
    iterator->Seek(ssStartKey.str());
    // Now read each entry.
    while (iterator->Valid())
    {
        // Unpack keys and values.
        CDataStream 
            ssKey(SER_DISK, CLIENT_VERSION);

        ssKey.write(iterator->key().data(), iterator->key().size());
        
        CDataStream 
            ssValue(SER_DISK, CLIENT_VERSION);

        ssValue.write(iterator->value().data(), iterator->value().size());
        
        string 
            strType;

        ssKey >> strType;
        // Did we reach the end of the data to read?
        if (fRequestShutdown || strType != "blockindex")
            break;
        
        CDiskBlockIndex 
            diskindex;

        ssValue >> diskindex;

        uint256 
            blockHash = diskindex.GetBlockHash();

        if ( 0 == blockHash )
        {
            if (fPrintToConsole)
                (void)printf( 
                            "Error? at nHeight=%d"
                            "\n"
                            "",
                            diskindex.nHeight
                            );
            continue;   //?

        }
        // Construct block index object
        CBlockIndex
            * pindexNew    = InsertBlockIndex(blockHash);
        // what if null? Can't be, since blockhash is known to be != 0
        //if( NULL == pindexNew ) // ???
        //{
        //    iterator->Next();        
        //    continue;
        //}
        pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
        pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);

        pindexNew->nFile          = diskindex.nFile;
        pindexNew->nBlockPos      = diskindex.nBlockPos;
        pindexNew->nHeight        = diskindex.nHeight;
        pindexNew->nMint          = diskindex.nMint;
        pindexNew->nMoneySupply   = diskindex.nMoneySupply;
        pindexNew->nFlags         = diskindex.nFlags;
        pindexNew->nStakeModifier = diskindex.nStakeModifier;
        pindexNew->prevoutStake   = diskindex.prevoutStake;
        pindexNew->nStakeTime     = diskindex.nStakeTime;
        pindexNew->hashProofOfStake = diskindex.hashProofOfStake;
        pindexNew->nVersion       = diskindex.nVersion;
        pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
        pindexNew->nTime          = diskindex.nTime;
        pindexNew->nBits          = diskindex.nBits;
        pindexNew->nNonce         = diskindex.nNonce;

        // Watch for genesis block
#ifdef WIN32
        if( 
            (NULL != pindexGenesisBlock) &&
            (0 == diskindex.nHeight)
           )
        {
            if (fPrintToConsole)
                (void)printf( 
                        "Error? an extra null block???"
                        "\n"
                        ""
                            );
        }
        if (
            (NULL == pindexGenesisBlock) && 
            (0 == diskindex.nHeight)      // ought to be faster than a hash check!?
           )
        {
            if (blockHash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))// check anyway, but only if block 0
#else
        if (pindexGenesisBlock == NULL && blockHash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
#endif
            {
                pindexGenesisBlock = pindexNew;
                /*************
#ifdef WIN32
                if (fPrintToConsole)
                    (void)printf( 
                            "Found block 0 at nCounter=%d"
                            "\n"
                            "",
                            nCounter
                                );
#endif
                *************/
            }
            else
            {
#ifdef WIN32
                if (fPrintToConsole)
                    (void)printf( 
                            "Error? a extra genesis block with the wrong hash???"
                            "\n"
                            ""
                                );
#endif
            }
        }
        // there seem to be 2 errant blocks?
        else
        {
            if(
                (NULL != pindexGenesisBlock) && 
                (0 == diskindex.nHeight) 
              )
            {
#ifdef WIN32
                if (fPrintToConsole)
                    (void)printf( 
                            "Error? a extra genesis null block???"
                            "\n"
                            ""
                                );
#endif
            }
        }
        //if (!pindexNew->CheckIndex()) // as it stands, this never fails??? So why bother?????
        //{
        //    delete iterator;
        //    return error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->nHeight);
        //}

        // NovaCoin: build setStakeSeen
        if (pindexNew->IsProofOfStake())
            setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
#ifdef WIN32
        ++nCounter;
        // could "guess at the max nHeight & %age against the loop count
        // to "hone in on" the %age done.  
        // Towards the end it ought to be pretty accurate.
        if( nMaxHeightGuess < pindexNew->nHeight )
            nMaxHeightGuess = pindexNew->nHeight;
        if( 0 == ( nCounter % nRefresh ) )  // every nRefresh-th time through the loop
        {
            float                   // these #s are just to slosh the . around
                dEstimate = float( ( 100.0 * nCounter ) / nMaxHeightGuess );
            std::string 
                sGutsNoise = strprintf(
                            "%7d (%3.2f%%)"
                            "",
                            pindexNew->nHeight,
                            dEstimate > 100.0? 100.0: dEstimate
                                      );
            if (fPrintToConsole)
            {
                (void)printf( 
                            "%s"
                            "   "
                            "",
                            sGutsNoise.c_str()
                            );
                DoProgress( nCounter, nMaxHeightGuess, n64MsStartTime );
                (void)printf( 
                            "\r"
                            );
            }
    #ifdef QT_GUI
            uiInterface.InitMessage( sGutsNoise.c_str() );
    #endif
        }
#endif
        iterator->Next();
    }
    delete iterator;

    if (fRequestShutdown)
        return true;
#ifdef WIN32
    if (fPrintToConsole)
        (void)printf( "\n" );

    #ifdef QT_GUI
    uiInterface.InitMessage(_("<b>...done.</b>"));
    #endif
#endif

#ifdef WIN32
    if (fPrintToConsole) 
        (void)printf( "Sorting by height...\n" );        
    #ifdef QT_GUI
    uiInterface.InitMessage(
                            _("Sorting by height...")
                           );
    #endif
    nCounter = 0;
#endif
    // Calculate bnChainTrust
    {
        LOCK(cs_main);

        vector< pair< int, CBlockIndex*> > vSortedByHeight;

        vSortedByHeight.reserve(mapBlockIndex.size());
        //vSortedByHeight.resize( mapBlockIndex.size() );

        int
            nUpdatePeriod = 10000;
        BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex)
        {
            CBlockIndex
                * pindex = item.second;

            vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
#ifdef WIN32
            ++nCounter;
            if( 0 == (nCounter % nUpdatePeriod) )
            {
    #ifdef QT_GUI
                uiInterface.InitMessage( strprintf( _("%7d"), nCounter ) );
    #else
                if (fPrintToConsole) 
                    printf( "%7d\r", nCounter );
    #endif
            }
#endif        
        }
        sort(vSortedByHeight.begin(), vSortedByHeight.end());
 #ifdef WIN32
        if (fPrintToConsole) 
            (void)printf( "\ndone\nChecking stake checksums...\n" );
    #ifdef _DEBUG
        nUpdatePeriod /= 4; // speed up update for debug mode
    #endif
    #ifdef QT_GUI
        uiInterface.InitMessage( _("done") );
        uiInterface.InitMessage( _("Checking stake checksums...") );
    #endif
        nCounter = 0;
#endif
        BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
        {
            CBlockIndex* pindex = item.second;
            pindex->nPosBlockCount = ( pindex->pprev ? pindex->pprev->nPosBlockCount : 0 ) + ( pindex->IsProofOfStake() ? 1 : 0 );
            pindex->nBitsMA = pindex->IsProofOfStake() ? GetProofOfWorkMA(pindex->pprev) : 0;
            pindex->bnChainTrust = (pindex->pprev ? pindex->pprev->bnChainTrust : CBigNum(0)) + pindex->GetBlockTrust();
            // NovaCoin: calculate stake modifier checksum
            pindex->nStakeModifierChecksum = GetStakeModifierChecksum(pindex);
            if (!CheckStakeModifierCheckpoints(pindex->nHeight, pindex->nStakeModifierChecksum))
                return error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016" PRIx64, pindex->nHeight, pindex->nStakeModifier);
#ifdef WIN32
            ++nCounter;
            if( 0 == (nCounter % nUpdatePeriod) )
            {
    #ifdef QT_GUI
                uiInterface.InitMessage( strprintf( _("%7d"), nCounter ) );
    #else
                if (fPrintToConsole) 
                    printf( "%7d\r", nCounter );
    #endif
            }
#endif        
        }
    }

#ifdef WIN32
    if (fPrintToConsole) 
        (void)printf( "\ndone\n"
                      "Read best chain\n" 
                    );        
    #ifdef QT_GUI
    uiInterface.InitMessage( _("...done") );
    uiInterface.InitMessage( _("Read best chain") );
    #endif
#endif        

    // Load hashBestChain pointer to end of best chain
    if (!ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == NULL)
            return true;
        return error("CTxDB::LoadBlockIndex() : hashBestChain not loaded");
    }
    if (!mapBlockIndex.count(hashBestChain))
        return error("CTxDB::LoadBlockIndex() : hashBestChain not found in the block index");
    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->nHeight;
    bnBestChainTrust = pindexBest->bnChainTrust;

    printf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight, bnBestChainTrust.ToString().c_str(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    // NovaCoin: load hashSyncCheckpoint
    if( !fTestNet )
    {
        if (!ReadSyncCheckpoint(Checkpoints::hashSyncCheckpoint))
            return error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
        printf("LoadBlockIndex(): synchronized checkpoint %s\n", 
               Checkpoints::hashSyncCheckpoint.ToString().c_str()
              );
    }
    // Load bnBestInvalidTrust, OK if it doesn't exist
    ReadBestInvalidTrust(bnBestInvalidTrust);

    // Verify blocks in the best chain
    int nCheckLevel = GetArg("-checklevel", 1);
    int nCheckDepth = GetArg( "-checkblocks", 750);
    if (nCheckDepth == 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > nBestHeight)
        nCheckDepth = nBestHeight;

#ifdef WIN32
    nCounter = 0;
    //#ifdef _MSC_VER
        #ifdef _DEBUG
        /****************
        const int
            nMINUTESperBLOCK = 1,   // or whatever you want to do in this *coin
            nMINUTESperHOUR = 60,
            nBLOCKSperHOUR = nMINUTESperHOUR / nMINUTESperBLOCK,
            nHOURStoCHECK = 1,   //12,     // this could be a variable
            nBLOCKSinLASTwhateverHOURS = nBLOCKSperHOUR * nHOURStoCHECK;

        nCheckDepth = nBLOCKSinLASTwhateverHOURS;
        ****************/
        #endif
    //#endif
    #ifdef QT_GUI
    std::string
        sX;
    uiInterface.InitMessage(
                            strprintf( _("Verifying the last %i blocks at level %i"), 
                                        nCheckDepth, nCheckLevel
                                     ).c_str()
                           );
    #endif
#endif
    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex* pindexFork = NULL;
    map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (fRequestShutdown || pindex->nHeight < nBestHeight-nCheckDepth)
            break;
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        // check level 1: verify block validity
        // check level 7: verify block signature too
        if (nCheckLevel>0 && !block.CheckBlock(true, true, (nCheckLevel>6)))
        {
            printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pindex->pprev;
        }
        // check level 2: verify transaction index validity
        if (nCheckLevel>1)
        {
            pair<unsigned int, unsigned int> pos = make_pair(pindex->nFile, pindex->nBlockPos);
            mapBlockPos[pos] = pindex;
            BOOST_FOREACH(const CTransaction &tx, block.vtx)
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                if (ReadTxIndex(hashTx, txindex))
                {
                    // check level 3: checker transaction hashes
                    if (nCheckLevel>2 || pindex->nFile != txindex.pos.nFile || pindex->nBlockPos != txindex.pos.nBlockPos)
                    {
                        // either an error or a duplicate transaction
                        CTransaction txFound;
                        if (!txFound.ReadFromDisk(txindex.pos))
                        {
                            printf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->pprev;
                        }
                        else
                            if (txFound.GetHash() != hashTx) // not a duplicate tx
                            {
                                printf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
                                pindexFork = pindex->pprev;
                            }
                    }
                    // check level 4: check whether spent txouts were spent within the main chain
                    unsigned int 
                        nOutput = 0;
                    if (nCheckLevel>3)
                    {
                        BOOST_FOREACH(const CDiskTxPos &txpos, txindex.vSpent)
                        {
                            if (!txpos.IsNull())
                            {
                                pair<unsigned int, unsigned int> posFind = make_pair(txpos.nFile, txpos.nBlockPos);
                                if (!mapBlockPos.count(posFind))
                                {
                                    printf("LoadBlockIndex(): *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str(), hashTx.ToString().c_str());
                                    pindexFork = pindex->pprev;
                                }
                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                if (nCheckLevel>5)
                                {
                                    CTransaction txSpend;
                                    if (!txSpend.ReadFromDisk(txpos))
                                    {
                                        printf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else if (!txSpend.CheckTransaction())
                                    {
                                        printf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else
                                    {
                                        bool fFound = false;
                                        BOOST_FOREACH(const CTxIn &txin, txSpend.vin)
                                            if (txin.prevout.hash == hashTx && txin.prevout.n == nOutput)
                                                fFound = true;
                                        if (!fFound)
                                        {
                                            printf("LoadBlockIndex(): *** spending transaction of %s:%i does not spend it\n", hashTx.ToString().c_str(), nOutput);
                                            pindexFork = pindex->pprev;
                                        }
                                    }
                                }
                            }
                            ++nOutput;
                        }
                    }
                }
                // check level 5: check whether all prevouts are marked spent
                if (nCheckLevel>4)
                {
                     BOOST_FOREACH(const CTxIn &txin, tx.vin)
                     {
                          CTxIndex txindex;
                          if (ReadTxIndex(txin.prevout.hash, txindex))
                              if (txindex.vSpent.size()-1 < txin.prevout.n || txindex.vSpent[txin.prevout.n].IsNull())
                              {
                                  printf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.prevout.hash.ToString().c_str(), txin.prevout.n, hashTx.ToString().c_str());
                                  pindexFork = pindex->pprev;
                              }
                     }
                }
            }
        }
#ifdef WIN32
    #ifdef _MSC_VER
        if (fPrintToConsole) 
        {
            (void)printf( "\b\b\b" );       // , 1
         // (void)printf( "Verifying %7d at 0",
            (void)printf(// V e r i f y i n g   n n n n n n n   a t   t
                          "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b"
                        );
        }
    #endif        
        ++nCounter;                
#endif        
#ifdef WIN32
    #ifdef _MSC_VER
        if (fPrintToConsole) 
            (void)printf( "Verifying %7d",
                          nCheckDepth - nCounter  
                        );        
    #endif        
    #ifdef QT_GUI
        uiInterface.InitMessage( strprintf( "Verifying %7d", nCheckDepth - nCounter ).c_str() );
    #endif
#endif
    }
    if (pindexFork && !fRequestShutdown)
    {
        // Reorg back to the fork
        printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
        CBlock block;
        if (!block.ReadFromDisk(pindexFork))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        CTxDB txdb;
        block.SetBestChain(txdb, pindexFork);
    }

    return true;
}
#endif