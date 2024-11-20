// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
#include <stdint.h>

#include "msvc_warnings.push.h"
#endif

#include "addressindex.h"
#include "checkpoints.h"
#include "txdb.h"
#include "kernel.h"

#include <map>
#include <string>
#include <vector>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <memenv/memenv.h>

using std::make_pair;
using std::map;
using std::pair;
using std::runtime_error;
using std::string;
using std::vector;

static const char DB_ADDRESSINDEX = 'a';
static const char DB_ADDRESSUNSPENTINDEX = 'u';

// CDB subclasses are created and destroyed VERY OFTEN. That's why
// we shouldn't treat this as a free operations.
CTxDB::CTxDB(const char *pszMode, bool fWipe) :
		CDBWrapper(BLOCK_INDEX, pszMode, fWipe) {
}

bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex &txindex)
{
    Yassert(!fClient);
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex &txindex)
{
    Yassert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction &tx, const CDiskTxPos &pos, int nHeight)
{
    Yassert(!fClient);
    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction &tx)
{
    Yassert(!fClient);
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::UpdateAddressUnspentIndex(const std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue > >&vect) {
    bool result = true;
    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        if (it->second.IsNull()) {
            result = Erase(std::make_pair(DB_ADDRESSUNSPENTINDEX, it->first));
        } else {
            result = Write(std::make_pair(DB_ADDRESSUNSPENTINDEX, it->first), it->second);
        }

        if (!result)
        {
            break;
        }
    }
    return result;
}

bool CTxDB::ReadAddressUnspentIndex(uint160 addressHash, int type, std::string tokenName,
                                           std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorTokenKey(type, addressHash, tokenName)));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressUnspentKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSUNSPENTINDEX && key.second.hashBytes == addressHash
                && (tokenName.empty() || key.second.token == tokenName)) {
            CAddressUnspentValue nValue;
            if (pcursor->GetValue(nValue)) {
                unspentOutputs.push_back(std::make_pair(key.second, nValue));
                pcursor->Next();
            } else {
                return error("failed to get address unspent value");
            }
        } else {
            break;
        }
    }

    return true;
}

bool CTxDB::ReadAddressUnspentIndex(uint160 addressHash, int type,
                                           std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorKey(type, addressHash)));

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressUnspentKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSUNSPENTINDEX && key.second.hashBytes == addressHash) {
            CAddressUnspentValue nValue;
            if (pcursor->GetValue(nValue)) {
                if (key.second.token != "YAC") {
                    unspentOutputs.push_back(std::make_pair(key.second, nValue));
                }
                pcursor->Next();
            } else {
                return error("failed to get address unspent value");
            }
        } else {
            break;
        }
    }

    return true;
}

bool CTxDB::WriteAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount > >&vect) {
    bool result = true;
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
    {
        result = Write(std::make_pair(DB_ADDRESSINDEX, it->first), it->second);
        if (!result)
        {
            break;
        }
    }
    return result;
}

bool CTxDB::EraseAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount > >&vect) {
    bool result = true;
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
    {
        result = Erase(std::make_pair(DB_ADDRESSINDEX, it->first));
        if (!result)
        {
            break;
        }
    }

    return result;
}

bool CTxDB::ReadAddressIndex(uint160 addressHash, int type, std::string tokenName,
                                    std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                                    int start, int end) {

    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    if (!tokenName.empty() && start > 0 && end > 0) {
        pcursor->Seek(std::make_pair(DB_ADDRESSINDEX,
                                     CAddressIndexIteratorHeightKey(type, addressHash, tokenName, start)));
    } else if (!tokenName.empty()) {
        pcursor->Seek(std::make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorTokenKey(type, addressHash, tokenName)));
    } else {
        pcursor->Seek(std::make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorKey(type, addressHash)));
    }

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressIndexKey> key;
        if (pcursor->GetKey(key) && key.first == DB_ADDRESSINDEX && key.second.hashBytes == addressHash
                && (tokenName.empty() || key.second.token == tokenName)) {
            if (end > 0 && key.second.blockHeight > end) {
                break;
            }
            CAmount nValue;
            if (pcursor->GetValue(nValue)) {
                addressIndex.push_back(std::make_pair(key.second, nValue));
                pcursor->Next();
            } else {
                return error("failed to get address index value");
            }
        } else {
            break;
        }
    }

    return true;
}

bool CTxDB::ReadAddressIndex(uint160 addressHash, int type,
                                    std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                                    int start, int end) {

    return CTxDB::ReadAddressIndex(addressHash, type, "", addressIndex, start, end);
}

bool CTxDB::ContainsTx(uint256 hash)
{
    Yassert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction &tx, CTxIndex &txindex)
{
    Yassert(!fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction &tx, CTxIndex &txindex)
{
    return ReadDiskTx(outpoint.COutPointGetHash(), tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction &tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.COutPointGetHash(), tx, txindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex &blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::WriteBlockHash(const CDiskBlockIndex &blockindex)
{
    return Write(make_pair(string("blockhash"), make_pair(blockindex.nFile, blockindex.nBlockPos)), blockindex.GetBlockHash());
}

bool CTxDB::ReadBlockHash(const unsigned int nFile, const unsigned int nBlockPos, uint256 &blockhash)
{
    return Read(make_pair(string("blockhash"), make_pair(nFile, nBlockPos)), blockhash);
}

bool CTxDB::ReadHashBestChain(uint256 &hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

bool CTxDB::ReadBestInvalidTrust(CBigNum &bnBestInvalidTrust)
{
    return Read(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::WriteBestInvalidTrust(CBigNum bnBestInvalidTrust)
{
    return Write(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::ReadSyncCheckpoint(uint256 &hashCheckpoint)
{
    return Read(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::WriteSyncCheckpoint(uint256 hashCheckpoint)
{
    return Write(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::ReadCheckpointPubKey(string &strPubKey)
{
    return Read(string("strCheckpointPubKey"), strPubKey);
}

bool CTxDB::WriteCheckpointPubKey(const string &strPubKey)
{
    return Write(string("strCheckpointPubKey"), strPubKey);
}

bool CTxDB::ReadModifierUpgradeTime(unsigned int &nUpgradeTime)
{
    return Read(string("nUpgradeTime"), nUpgradeTime);
}

bool CTxDB::WriteModifierUpgradeTime(const unsigned int &nUpgradeTime)
{
    return Write(string("nUpgradeTime"), nUpgradeTime);
}

static CBlockIndex *InsertBlockIndex(uint256 hash)
{ // this is the slow poke in start up load block index
    if (hash == 0)
        return NULL;

    // Return existing, presume this is slow?
    map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex *pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");

    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CTxDB::BuildMapHash()
{
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
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(iterator->key().data(), iterator->key().size());

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.write(iterator->value().data(), iterator->value().size());

        string strType;
        ssKey >> strType;

        // Did we reach the end of the data to read?
        if (fRequestShutdown || strType != "blockindex")
            break;

        CDiskBlockIndex diskindex;
        ssValue >> diskindex;

        uint256 blockHash = diskindex.GetBlockHash();  // the slow poke!
        if (0 == blockHash)
        {
            if (fPrintToConsole)
                (void)printf(
                    "Error? at nHeight=%d"
                    "\n"
                    "",
                    diskindex.nHeight);
            continue; //?
        }
        mapHash.insert(make_pair( diskindex.GetSHA256Hash(), blockHash));
        iterator->Next();
    }
    delete iterator;
}

bool CTxDB::LoadBlockIndex()
{
    if (
        !(mapBlockIndex.empty()))
    { // Already loaded. But, it can happen during migration from BDB.
        return true;
    }
    // need a RAII class to fiddle fPrintToConsole to true if QT_GUI is defined
    // saving it and restoring it at function exit
#ifdef QT_GUI
    class QCtFiddlefPTC
    {
    public:
        QCtFiddlefPTC() : fSaved(fPrintToConsole) { fPrintToConsole = true; }
        ~QCtFiddlefPTC() { fPrintToConsole = fSaved; }

    private:
        bool fSaved;
    } Junk;
#endif
#ifdef WIN32
    const int
#ifdef Yac1dot0
#ifdef _DEBUG
        nREFRESH = 10; // generally resfresh rates are chosen to give ~1 update/sec
#else
        // seems to be slowing down??
        nREFRESH = 20;
#endif
#else
#ifdef _DEBUG
        nREFRESH = 2000; // generally resfresh rates are chosen to give ~1 update/sec
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
    int newStoredBlock = 0;
    int alreadyStoredBlock = 0;
    // Now read each entry.
    while (iterator->Valid()) //what is so slow in this loop of all PoW blocks?
    {                         // 5 minutes for 1400 blocks, ~300 blocks/min or ~5/sec
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
            blockHash = diskindex.GetBlockHash(); // the slow poke!

        if (0 == blockHash)
        {
            if (fPrintToConsole)
                (void)printf(
                    "Error? at nHeight=%d"
                    "\n"
                    "",
                    diskindex.nHeight);
            continue; //?
        }

#ifdef WIN32
        n64timeStart8 = GetTimeMillis();
        nDelta8 += (n64timeStart8 - n64timeStart7);
#endif
        // Construct block index object
        CBlockIndex
            *pindexNew = InsertBlockIndex(blockHash);
        // what if null? Can't be, since blockhash is known to be != 0
        if (NULL == pindexNew) // ???
        {
            if (fPrintToConsole)
                (void)printf(
                    "Error? InsertBlockIndex(...) failed"
                    "\n"
                    "");
            iterator->Next();
            continue;
        }
        pindexNew->pprev = InsertBlockIndex(diskindex.hashPrev);

#ifdef WIN32
        n64timeStart9 = GetTimeMillis();
        nDelta9 += (n64timeStart9 - n64timeStart8);
#endif
        pindexNew->pnext = InsertBlockIndex(diskindex.hashNext);

#ifdef WIN32
        n64timeStart10 = GetTimeMillis();
        nDelta10 += (n64timeStart10 - n64timeStart9);
#endif
        pindexNew->nFile = diskindex.nFile;
        pindexNew->nBlockPos = diskindex.nBlockPos;
        pindexNew->nHeight = diskindex.nHeight;
        pindexNew->nMint = diskindex.nMint;
        pindexNew->nMoneySupply = diskindex.nMoneySupply;
        pindexNew->nFlags = diskindex.nFlags;
        pindexNew->nStakeModifier = diskindex.nStakeModifier;
        pindexNew->prevoutStake = diskindex.prevoutStake;
        pindexNew->nStakeTime = diskindex.nStakeTime;
        pindexNew->hashProofOfStake = diskindex.hashProofOfStake;
        pindexNew->nVersion = diskindex.nVersion;
        pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
        pindexNew->nTime = diskindex.nTime;
        pindexNew->nBits = diskindex.nBits;
        pindexNew->nNonce = diskindex.nNonce;
        pindexNew->nStatus = diskindex.nStatus;
        pindexNew->blockHash = blockHash;

        if (fReindexOnlyHeaderSync)
        {
            if ((pindexNew->nHeight == 0) || (pindexNew->nFile != 0 && pindexNew->nBlockPos != 0))
            {
                pindexNew->nStatus |= BLOCK_HAVE_DATA;
                pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
            }
            else
            {
                printf("block height = %d has no block data, nFile = %u, nBlockPost = %u\n", pindexNew->nHeight, pindexNew->nFile, pindexNew->nBlockPos);
            }
        }

        uint256 tmpBlockhash;
        if (fStoreBlockHashToDb && !ReadBlockHash(diskindex.nFile, diskindex.nBlockPos, tmpBlockhash))
        {
            newStoredBlock++;
            WriteBlockHash(diskindex);
        }
        else
        {
            alreadyStoredBlock++;
        }

#ifdef WIN32
        n64timeStart11 = GetTimeMillis();
        nDelta11 += (n64timeStart11 - n64timeStart10);

        n64deltaT += n64timeStart11 - n64timeStart;
#endif
        // Watch for genesis block
        if (
            (0 == diskindex.nHeight) &&
            (NULL != chainActive.Genesis()))
        {
            if (fPrintToConsole)
                (void)printf(
                    "Error? an extra null block???"
                    "\n"
                    "");
        }
        if (
            (0 == diskindex.nHeight) && // ought to be faster than a hash check!?
            (NULL == chainActive.Genesis()))
        {
            if (blockHash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)) // check anyway, but only if block 0
            {
                chainActive.SetTip(pindexNew);
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
                        "");
            }
        }
        // there seem to be 2 errant blocks?
        else
        {
            if (
                (NULL != chainActive.Genesis()) &&
                (0 == diskindex.nHeight))
            {
                if (fPrintToConsole)
                    (void)printf(
                        "Error? a extra genesis null block???"
                        "\n"
                        "");
            }
        }
        //if (!pindexNew->CheckIndex()) // as it stands, this never fails??? So why bother?????
        //{
        //    delete iterator;
        //    return error("LoadBlockIndex() : CheckIndex failed at %d", pindexNew->nHeight);
        //}

#ifdef WIN32
        ++nCounter;
        // could "guess at the max nHeight & %age against the loop count
        // to "hone in on" the %age done.
        // Towards the end it ought to be pretty accurate.
        if (nMaxHeightGuess < pindexNew->nHeight)
        {
            nMaxHeightGuess = pindexNew->nHeight;
        }
        if (0 == (nCounter % nRefresh)) // every nRefresh-th time through the loop
        {
            float // these #s are just to slosh the . around
                dEstimate = float((100.0 * nCounter) / nMaxHeightGuess);
            std::string
                sGutsNoise = strprintf(
                    "%7d (%3.2f%%)"
                    "",
                    nCounter, //pindexNew->nHeight,
                    dEstimate >= 100.0 ? 100.0 : dEstimate);
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
                DoProgress(nCounter, nMaxHeightGuess, n64MsStartTime);
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

    printf("CTxDB::LoadBlockIndex(), fStoreBlockHashToDb = %d, "
           "newStoredBlock = %d, "
           "alreadyStoredBlock = %d\n",
           fStoreBlockHashToDb,
           newStoredBlock,
           alreadyStoredBlock);

    // Load hashBestChain pointer to end of best chain
    if (!ReadHashBestChain(hashBestChain))
    {
        if (chainActive.Genesis() == NULL)
            return true;
        return error("CTxDB::LoadBlockIndex() : hashBestChain not loaded");
    }
    if (!mapBlockIndex.count(hashBestChain))
        return error("CTxDB::LoadBlockIndex() : hashBestChain not found in the block index");
    chainActive.SetTip(mapBlockIndex[hashBestChain]);

    // Recalculate block reward and minimum ease (highest difficulty) when starting node
    CBlockIndex* tmpBlockIndex = chainActive[nMainnetNewLogicBlockNumber];
    while (tmpBlockIndex != NULL)
    {
        if (tmpBlockIndex->nHeight >= bestEpochIntervalHeight &&
            ((tmpBlockIndex->nHeight % nEpochInterval == 0) || (tmpBlockIndex->nHeight == nMainnetNewLogicBlockNumber)))
        {
            bestEpochIntervalHeight = tmpBlockIndex->nHeight;
            bestEpochIntervalHash = tmpBlockIndex->blockHash;
        }
        // Find the minimum ease (highest difficulty) when starting node
        // It will be used to calculate min difficulty (maximum ease)
        if ((tmpBlockIndex->nHeight >= nMainnetNewLogicBlockNumber) && (nMinEase > tmpBlockIndex->nBits))
        {
            nMinEase = tmpBlockIndex->nBits;
        }
        tmpBlockIndex = tmpBlockIndex->pnext;
    }
    // Calculate maximum target of all blocks, it corresponds to 1/3 highest difficulty (or 3 minimum ease)
    uint256 bnMaximum = CBigNum().SetCompact(nMinEase).getuint256();
    CBigNum bnMaximumTarget;
    bnMaximumTarget.setuint256(bnMaximum);
    bnMaximumTarget *= 3;

    (void)printf(
                 "Minimum difficulty target %s\n"
                 ""
                 , CBigNum( bnMaximumTarget ).getuint256().ToString().substr(0,16).c_str()
                );

    if (fReindexOnlyHeaderSync)
    {
        fReindexOnlyHeaderSync = false;
        CBlockIndex* chainTip = chainActive.Tip();
        while (chainTip != NULL)
        {
            chainTip->RaiseValidity(BLOCK_VALID_SCRIPTS);
            chainTip = chainTip->pprev;
        }

        map<uint256, CBlockIndex *>::iterator it;
        int numberOfReindexOnlyHeaderSyncBlock = 0;
        for (it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++)
        {
            CBlockIndex* pindexCurrent = (*it).second;
            WriteBlockIndex(CDiskBlockIndex(pindexCurrent));
            mapHash.insert(make_pair(pindexCurrent->GetSHA256Hash(), (*it).first));
            numberOfReindexOnlyHeaderSyncBlock++;
        }
        printf("CTxDB::LoadBlockIndex(), fReindexOnlyHeaderSync = 1, "
               "numberOfReindexOnlyHeaderSyncBlock = %d\n",
               fReindexOnlyHeaderSync,
               numberOfReindexOnlyHeaderSyncBlock);
    }
    else
    {
        map<uint256, CBlockIndex *>::iterator it;
        for (it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++)
        {
            CBlockIndex* pindexCurrent = (*it).second;
            mapHash.insert(make_pair(pindexCurrent->GetSHA256Hash(), (*it).first)).first;
        }
    }

    // Calculate current block reward
    map<uint256, CBlockIndex *>::iterator mi = mapBlockIndex.find(bestEpochIntervalHash);
    if (mi != mapBlockIndex.end())
    {
        CBlockIndex *pBestEpochIntervalIndex = (*mi).second;
        nBlockRewardPrev =
            (::int64_t)((pBestEpochIntervalIndex->pprev ? pBestEpochIntervalIndex->pprev->nMoneySupply : pBestEpochIntervalIndex->nMoneySupply) /
                        nNumberOfBlocksPerYear) *
            nInflation;
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
        DoProgress(nCounter, nCounter, n64MsStartTime);
        (void)printf("\n");
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
            "\n1 %" PRId64
            "\n2 %" PRId64
            "\n3 %" PRId64
            "\n4 %" PRId64
            "\n5 %" PRId64
            "\n6 %" PRId64
            "\n7 %" PRId64
            "\n8 %" PRId64
            "\n9 %" PRId64
            "\n10 %" PRId64
            "\n11 %" PRId64
            "\nt %" PRId64
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
            n64deltaT);
    }
#endif
    // <<<<<<<<<

#ifdef WIN32
    if (fPrintToConsole)
        (void)printf("Sorting by height...");
#ifdef QT_GUI
    uiInterface.InitMessage(
        _("Sorting by height..."));
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
        BOOST_FOREACH (const PAIRTYPE(uint256, CBlockIndex *) & item, mapBlockIndex)
        {
            CBlockIndex
                *pindex = item.second;

            vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
#ifdef WIN32
            ++nCounter;
            if (0 == (nCounter % nUpdatePeriod))
            {
#ifdef QT_GUI
                uiInterface.InitMessage(strprintf(_("%7d"), nCounter));
#else
                if (fPrintToConsole)
                    printf("%7d\r", nCounter);
#endif
            }
#endif
        }
        sort(vSortedByHeight.begin(), vSortedByHeight.end());
#ifdef WIN32
        if (fPrintToConsole)
            (void)printf("\ndone\nChecking stake checksums...\n");
#ifdef _DEBUG
        nUpdatePeriod /= 20; // speed up update for debug mode
#else
        nUpdatePeriod /= 2; // slow down update for release mode
#endif
#ifdef QT_GUI
        uiInterface.InitMessage(_("done"));
        uiInterface.InitMessage(_("Checking stake checksums..."));
#endif
        nCounter = 0;
#endif

        BOOST_FOREACH (const PAIRTYPE(int, CBlockIndex *) & item, vSortedByHeight)
        {
            CBlockIndex *pindex = item.second;
            pindex->bnChainTrust = (pindex->pprev ? pindex->pprev->bnChainTrust : CBigNum(0)) + pindex->GetBlockTrust();
            // NovaCoin: calculate stake modifier checksum
            pindex->nStakeModifierChecksum = GetStakeModifierChecksum(pindex);
            if (!CheckStakeModifierCheckpoints(pindex->nHeight, pindex->nStakeModifierChecksum))
                printf("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, modifier=0x%016\n" PRIx64, pindex->nHeight, pindex->nStakeModifier);
            if (pindex->nStatus & BLOCK_HAVE_DATA) {
                if (pindex->pprev) {
                    if (pindex->pprev->validTx) {
                        pindex->validTx = true;
                    } else {
                        pindex->validTx = false;
                        mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                    }
                } else {
                    pindex->validTx = true;
                }
            }
            if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->validTx || pindex->pprev == NULL))
                setBlockIndexCandidates.insert(pindex);
            if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->bnChainTrust > pindexBestInvalid->bnChainTrust))
                pindexBestInvalid = pindex;
            if (pindex->pprev)
                pindex->BuildSkip();
            if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == NULL || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
                pindexBestHeader = pindex;
#ifdef WIN32
            ++nCounter;
            if (0 == (nCounter % nUpdatePeriod))
            {
#ifdef QT_GUI
                uiInterface.InitMessage(strprintf(_("%7d"), nCounter));
#else
                if (fPrintToConsole)
                    printf("%7d\r", nCounter);
#endif
            }
#endif
        }
    }

#ifdef WIN32
    if (fPrintToConsole)
        (void)printf("\ndone\n"
                     "Read best chain\n");
#ifdef QT_GUI
    uiInterface.InitMessage(_("...done"));
    uiInterface.InitMessage(_("Read best chain"));
#endif
#endif

    bnBestChainTrust = chainActive.Tip()->bnChainTrust;

    printf("LoadBlockIndex(): hashBestChain=%s  height=%d  trust=%s  date=%s\n",
           hashBestChain.ToString().substr(0, 20).c_str(), chainActive.Height(), bnBestChainTrust.ToString().c_str(),
           DateTimeStrFormat("%x %H:%M:%S", chainActive.Tip()->GetBlockTime()).c_str());

    // NovaCoin: load hashSyncCheckpoint
    if (!fTestNet)
    {
        if (!ReadSyncCheckpoint(Checkpoints::hashSyncCheckpoint))
            return error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
        printf("LoadBlockIndex(): synchronized checkpoint %s\n",
               Checkpoints::hashSyncCheckpoint.ToString().c_str());
    }
    // Load bnBestInvalidTrust, OK if it doesn't exist
    //    ReadBestInvalidTrust(bnBestInvalidTrust);

    // Verify blocks in the best chain
    int nCheckLevel = gArgs.GetArg("-checklevel", 1);
    int nCheckDepth = gArgs.GetArg("-checkblocks", 750);
    if (nCheckDepth == 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();

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
        strprintf(_("Verifying the last %i blocks at level %i"),
                  nCheckDepth, nCheckLevel)
            .c_str());
#endif
#endif
    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex *pindexFork = NULL;
    map<pair<unsigned int, unsigned int>, CBlockIndex *> mapBlockPos;
    for (CBlockIndex *pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (fRequestShutdown || pindex->nHeight < chainActive.Height() - nCheckDepth)
            break;
        CBlock block;
        CValidationState stateDummy;
        if (!block.ReadFromDisk(pindex))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        // check level 1: verify block validity
        // check level 7: verify block signature too
        if (nCheckLevel > 0 && !block.CheckBlock(stateDummy, true, true, (nCheckLevel > 6)))
        {
            printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pindex->pprev;
        }
        // check level 2: verify transaction index validity
        if (nCheckLevel > 1)
        {
            pair<unsigned int, unsigned int> pos = make_pair(pindex->nFile, pindex->nBlockPos);
            mapBlockPos[pos] = pindex;
            BOOST_FOREACH (const CTransaction &tx, block.vtx)
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                if (ReadTxIndex(hashTx, txindex))
                {
                    // check level 3: checker transaction hashes
                    if (nCheckLevel > 2 || pindex->nFile != txindex.pos.Get_CDiskTxPos_nFile() || pindex->nBlockPos != txindex.pos.Get_CDiskTxPos_nBlockPos())
                    {
                        // either an error or a duplicate transaction
                        CTransaction txFound;
                        if (!txFound.ReadFromDisk(txindex.pos))
                        {
                            printf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->pprev;
                        }
                        else if (txFound.GetHash() != hashTx) // not a duplicate tx
                        {
                            printf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->pprev;
                        }
                    }
                    // check level 4: check whether spent txouts were spent within the main chain
                    unsigned int
                        nOutput = 0;
                    if (nCheckLevel > 3)
                    {
                        BOOST_FOREACH (const CDiskTxPos &txpos, txindex.vSpent)
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
                                if (nCheckLevel > 5)
                                {
                                    CTransaction txSpend;
                                    if (!txSpend.ReadFromDisk(txpos))
                                    {
                                        printf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else if (!txSpend.CheckTransaction(stateDummy))
                                    {
                                        printf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else
                                    {
                                        bool fFound = false;
                                        BOOST_FOREACH (const CTxIn &txin, txSpend.vin)
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
                if (nCheckLevel > 4)
                {
                    BOOST_FOREACH (const CTxIn &txin, tx.vin)
                    {
                        CTxIndex txindex;
                        if (ReadTxIndex(txin.prevout.COutPointGetHash(), txindex))
                            if (txindex.vSpent.size() - 1 < txin.prevout.COutPointGet_n() || txindex.vSpent[txin.prevout.COutPointGet_n()].IsNull())
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
            (void)printf("\b\b\b"); // , 1
                                    // (void)printf( "Verifying %7d at 0",
            (void)printf(           // V e r i f y i n g   n n n n n n n   a t   t
                "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        }
#endif
        ++nCounter;
#endif
#ifdef WIN32
#ifdef _MSC_VER
        if (fPrintToConsole)
            (void)printf("Verifying %7d",
                         nCheckDepth - nCounter);
#endif
#ifdef QT_GUI
        uiInterface.InitMessage(strprintf("Verifying %7d", nCheckDepth - nCounter).c_str());
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
        setBlockIndexCandidates.insert(pindexFork);
        CTxDB txdb;
        CValidationState state;
        ActivateBestChain(state, txdb);
    }

    return true;
}
#ifdef _MSC_VER
#include "msvc_warnings.pop.h"
#endif
