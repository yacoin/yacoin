// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifdef USE_LEVELDB
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_CHECKPOINT_H
 #include "checkpoints.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb.h"
#endif

#ifndef PPCOIN_KERNEL_H
 #include "kernel.h"
#endif

#include <map>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <memenv/memenv.h>

using namespace boost;

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
    Yassert(pszMode);
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
    Yassert(!activeBatch);
    activeBatch = new leveldb::WriteBatch();
    return true;
}

bool CTxDB::TxnCommit()
{
    Yassert(activeBatch);
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
    Yassert(activeBatch);
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
    Yassert(!fClient);
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
    Yassert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    Yassert(!fClient);
    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    Yassert(!fClient);
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    Yassert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
    Yassert(!fClient);
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
    return ReadDiskTx(outpoint.COutPointGetHash(), tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.COutPointGetHash(), tx, txindex);
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
{   // this is the slow poke in start up load block index
    if (hash == 0)
        return NULL;

    // Return existing, presume this is slow?
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
    if (
        !(mapBlockIndex.empty())
       ) 
    {   // Already loaded. But, it can happen during migration from BDB.
        return true;
    }
    // need a RAII class to fiddle fPrintToConsole to true if QT_GUI is defined
    // saving it and restoring it at function exit
     #ifdef QT_GUI
     class QCtFiddlefPTC
     {
     public:
        QCtFiddlefPTC() : fSaved( fPrintToConsole ) { fPrintToConsole = true;}
        ~QCtFiddlefPTC(){ fPrintToConsole = fSaved; }
     private:
        bool fSaved;
     } Junk;
     #endif
#ifdef WIN32
    const int
#ifdef Yac1dot0
  #ifdef _DEBUG
        nREFRESH = 10;    // generally resfresh rates are chosen to give ~1 update/sec
  #else
        // seems to be slowing down??
        nREFRESH = 20;
  #endif
#else
  #ifdef _DEBUG
        nREFRESH = 2000;    // generally resfresh rates are chosen to give ~1 update/sec
  #else
        // seems to be slowing down??
        nREFRESH = 12000;
  #endif
#endif
    int
        nMaxHeightGuess = 1,
        nCounter = 0,
        nRefresh = nREFRESH;
    ::int64_t
        n64timeStart, 
        nDelta1 = 0,
        n64timeStart1, 
        nDelta2 = 0,
        n64timeStart2, 
        nDelta3 = 0,
        n64timeStart3, 
        nDelta4 = 0,
        n64timeStart4, 
        nDelta5 = 0,
        n64timeStart5, 
        nDelta6 = 0,
        n64timeStart6, 
        nDelta7 = 0,
        n64timeStart7, 
        nDelta8 = 0,
        n64timeStart8, 
        nDelta9 = 0,
        n64timeStart9, 
        nDelta10 = 0,
        n64timeStart10, 
        nDelta11 = 0,
        n64timeStart11, 
        n64timeEnd, 
        n64deltaT = 0,
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
    ::int32_t bestEpochIntervalHeight = 0;
    uint256 bestEpochIntervalHash;
    // Now read each entry.
    while (iterator->Valid())   //what is so slow in this loop of all PoW blocks?
    {                           // 5 minutes for 1400 blocks, ~300 blocks/min or ~5/sec
#ifdef WIN32
        n64timeStart = GetTimeMillis();
#endif

        // Unpack keys and values.
        CDataStream 
            ssKey(SER_DISK, CLIENT_VERSION);

#ifdef WIN32
        n64timeStart1 = GetTimeMillis(); 
        nDelta1 += (n64timeStart1 - n64timeStart);
#endif
        ssKey.write(iterator->key().data(), iterator->key().size());

#ifdef WIN32
        n64timeStart2 = GetTimeMillis(); 
        nDelta2 += (n64timeStart2 - n64timeStart1);
#endif
        CDataStream 
            ssValue(SER_DISK, CLIENT_VERSION);

#ifdef WIN32
        n64timeStart3 = GetTimeMillis(); 
        nDelta3 += (n64timeStart3 - n64timeStart2);
#endif
        ssValue.write(iterator->value().data(), iterator->value().size());

#ifdef WIN32
        n64timeStart4 = GetTimeMillis(); 
        nDelta4 += (n64timeStart4 - n64timeStart3);
#endif
        string 
            strType;

        ssKey >> strType;
        // Did we reach the end of the data to read?
        if (fRequestShutdown || strType != "blockindex")
            break;
        
#ifdef WIN32
        n64timeStart5 = GetTimeMillis(); 
        nDelta5 += (n64timeStart5 - n64timeStart4);
#endif
        CDiskBlockIndex 
            diskindex;

#ifdef WIN32
        n64timeStart6 = GetTimeMillis(); 
        nDelta6 += (n64timeStart6 - n64timeStart5);
#endif
        ssValue >> diskindex;

#ifdef WIN32
        n64timeStart7 = GetTimeMillis(); 
        nDelta7 += (n64timeStart7 - n64timeStart6);
#endif
        uint256 
            blockHash = diskindex.GetBlockHash();   // the slow poke!

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

#ifdef WIN32
        n64timeStart8 = GetTimeMillis(); 
        nDelta8 += (n64timeStart8 - n64timeStart7);
#endif
        // Construct block index object
        CBlockIndex
            * pindexNew    = InsertBlockIndex(blockHash);
        // what if null? Can't be, since blockhash is known to be != 0
        if( NULL == pindexNew ) // ???
        {
            if (fPrintToConsole)
                (void)printf( 
                            "Error? InsertBlockIndex(...) failed"
                            "\n"
                            ""
                            );
            iterator->Next();        
            continue;
        }
        pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);

#ifdef WIN32
        n64timeStart9 = GetTimeMillis(); 
        nDelta9 += (n64timeStart9 - n64timeStart8);
#endif
        pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);

#ifdef WIN32
        n64timeStart10 = GetTimeMillis(); 
        nDelta10 += (n64timeStart10 - n64timeStart9);
#endif
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

        if (pindexNew->nHeight >= bestEpochIntervalHeight &&
            ((pindexNew->nHeight % nEpochInterval == 0) || (pindexNew->nHeight == nMainnetNewLogicBlockNumber)))
        {
            bestEpochIntervalHeight = pindexNew->nHeight;
            bestEpochIntervalHash = blockHash;
        }
        // Find the minimum ease (highest difficulty) when starting node
        // It will be used to calculate min difficulty (maximum ease)
        if ((pindexNew->nHeight >= nMainnetNewLogicBlockNumber) && (nMinEase > pindexNew->nBits))
        {
            nMinEase = pindexNew->nBits;
        }

#ifdef WIN32
        n64timeStart11 = GetTimeMillis(); 
        nDelta11 += (n64timeStart11 - n64timeStart10);

        n64deltaT += n64timeStart11 - n64timeStart;
#endif
        // Watch for genesis block
        if( 
            (0 == diskindex.nHeight) &&
            (NULL != pindexGenesisBlock)
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
            (0 == diskindex.nHeight) &&     // ought to be faster than a hash check!?
            (NULL == pindexGenesisBlock)
           )
        {
            if (blockHash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))// check anyway, but only if block 0
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
                if (fPrintToConsole)
                    (void)printf( 
                            "Error? a extra genesis block with the wrong hash???"
                            "\n"
                            ""
                                );
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
                if (fPrintToConsole)
                    (void)printf( 
                            "Error? a extra genesis null block???"
                            "\n"
                            ""
                                );
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
        {
            nMaxHeightGuess = pindexNew->nHeight;
        }
        if( 0 == ( nCounter % nRefresh ) )  // every nRefresh-th time through the loop
        {
            float                   // these #s are just to slosh the . around
                dEstimate = float( ( 100.0 * nCounter ) / nMaxHeightGuess );
            std::string 
                sGutsNoise = strprintf(
                            "%7d (%3.2f%%)"
                            "",
                            nCounter, //pindexNew->nHeight,
                            dEstimate >= 100.0? 100.0: dEstimate
                                      );
            if (fPrintToConsole)
            {
                /****************
                (void)printf( 
                            "%s"
                            "   "
                            "",
                            sGutsNoise.c_str()
                            );
                ****************/
                DoProgress( nCounter, nMaxHeightGuess, n64MsStartTime );
                //(void)printf( 
                //            "\r"
                //            );
            }
    #ifdef QT_GUI
        //    uiInterface.InitMessage( sGutsNoise.c_str() );
    #endif
        }
#endif
        iterator->Next();
    }
    delete iterator;

    // Calculate current block reward
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(bestEpochIntervalHash);
    if (mi != mapBlockIndex.end())
    {
        CBlockIndex* pBestEpochIntervalIndex = (*mi).second;
        nBlockRewardPrev =
            (::int64_t)((pBestEpochIntervalIndex->pprev ? pBestEpochIntervalIndex->pprev->nMoneySupply : pBestEpochIntervalIndex->nMoneySupply) /
                        nNumberOfBlocksPerYear) * nInflation;
    }
    else
    {
       printf("There is something wrong, can't find best epoch interval block\n");
    }


    if (fRequestShutdown)
        return true;
#ifdef WIN32
    if (fPrintToConsole)
    {
        DoProgress( nCounter, nCounter, n64MsStartTime );
        (void)printf( "\n" );
    }
    #ifdef QT_GUI
    uiInterface.InitMessage(_("<b>...done.</b>"));
    #endif
#endif

#ifdef WIN32
    if (fPrintToConsole) 
    {
        (void)printf(
            "delta times"
            "\n1 %" 
            PRId64 
            "\n2 %" 
            PRId64 
            "\n3 %" 
            PRId64 
            "\n4 %" 
            PRId64 
            "\n5 %" 
            PRId64 
            "\n6 %" 
            PRId64 
            "\n7 %" 
            PRId64  
            "\n8 %" 
            PRId64 
            "\n9 %" 
            PRId64 
            "\n10 %" 
            PRId64 
            "\n11 %" 
            PRId64 
            "\nt %" 
            PRId64 
            "\n",
        nDelta1,
        nDelta2,
        nDelta3,
        nDelta4,
        nDelta5,
        nDelta6,
        nDelta7,
        nDelta8,
        nDelta9,
        nDelta10,
        nDelta11,
        n64deltaT 
                   );
    }
#endif
// <<<<<<<<<

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
    #else
        nUpdatePeriod *= 5; // slow down update for release mode
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
            if (pindex->nHeight >= nMainnetNewLogicBlockNumber)
				break;
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
                    if (nCheckLevel>2 || pindex->nFile != txindex.pos.Get_CDiskTxPos_nFile() || pindex->nBlockPos != txindex.pos.Get_CDiskTxPos_nBlockPos())
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
                                pair<unsigned int, unsigned int> posFind = make_pair(txpos.Get_CDiskTxPos_nFile(), txpos.Get_CDiskTxPos_nBlockPos());
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
                                            if (txin.prevout.COutPointGetHash() == hashTx && txin.prevout.COutPointGet_n() == nOutput)
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
                          if (ReadTxIndex(txin.prevout.COutPointGetHash(), txindex))
                              if (txindex.vSpent.size()-1 < txin.prevout.COutPointGet_n() || txindex.vSpent[txin.prevout.COutPointGet_n()].IsNull())
                              {
                                  printf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.prevout.COutPointGetHash().ToString().c_str(), txin.prevout.COutPointGet_n(), hashTx.ToString().c_str());
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
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
#endif
