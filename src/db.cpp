// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_DB_H
 #include "db.h"
#endif

#ifndef BITCOIN_UI_INTERFACE_H
 #include "ui_interface.h"
#endif

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <openssl/rand.h>

#ifndef WIN32
#include "sys/stat.h"
#endif

using namespace boost;

using std::runtime_error;
using std::stringstream;
using std::string;
using std::map;
using std::vector;

unsigned int nWalletDBUpdated;
extern bool fUseMemoryLog;


//
// CDB
//

CDBEnv bitdb;

void CDBEnv::EnvShutdown()
{
    if (!fDbEnvInit)
        return;

    fDbEnvInit = false;
    int ret = dbenv.close(0);
    if (ret != 0)
        LogPrintf("EnvShutdown exception: %s (%d)\n", DbEnv::strerror(ret), ret);
    if (!fMockDb)
        DbEnv(0).remove(strPath.c_str(), 0);
}

CDBEnv::CDBEnv() : dbenv(DB_CXX_NO_EXCEPTIONS)
{
    fDbEnvInit = false;
    fMockDb = false;
}

CDBEnv::~CDBEnv()
{
    EnvShutdown();
}

void CDBEnv::Close()
{
    EnvShutdown();
}

bool CDBEnv::Open(boost::filesystem::path pathEnv_)
{
    if (fDbEnvInit)
        return true;

    if (fShutdown)
        return false;

    pathEnv = pathEnv_;

    filesystem::path 
        pathDataDir = pathEnv;

    strPath = pathDataDir.string();

    filesystem::path 
        pathLogDir = pathDataDir / "database";

    filesystem::create_directory(pathLogDir);

#ifdef _MSC_VER
    filesystem::path 
        pathErrorFile = pathDataDir / "BerkeleyDB_wallet_ErrorFile.log";   // call it what it is
#else
    filesystem::path pathErrorFile = pathDataDir / "db.log";
    LogPrintf(
            "dbenv.open\n"
            "LogDir=%s\n"
            "ErrorFile=%s\n"
            , pathLogDir.string()
            , pathErrorFile.string()
          );
#endif

    unsigned int nEnvFlags = 0;
    if (gArgs.GetBoolArg("-privdb", true))
        nEnvFlags |= DB_PRIVATE;

    int nDbCache = gArgs.GetArg("-dbcache", 25);
    dbenv.set_lg_dir(pathLogDir.string().c_str());
    dbenv.set_cachesize(nDbCache / 1024, (nDbCache % 1024)*1048576, 1);
    dbenv.set_lg_bsize(1048576);
    dbenv.set_lg_max(10485760);

    // Bugfix: Bump lk_max_locks default to 537000, to safely handle reorgs with up to 5 blocks reversed
    // dbenv.set_lk_max_locks(10000);
    dbenv.set_lk_max_locks(537000);

    dbenv.set_lk_max_objects(10000);
    dbenv.set_errfile(fopen(pathErrorFile.string().c_str(), "a")); /// debug
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
    dbenv.set_flags(DB_TXN_WRITE_NOSYNC, 1);
#ifdef DB_LOG_AUTO_REMOVE
    dbenv.log_set_config(DB_LOG_AUTO_REMOVE, 1);
#endif
    int ret = dbenv.open(strPath.c_str(),
                     DB_CREATE     |
                     DB_INIT_LOCK  |
                     DB_INIT_LOG   |
                     DB_INIT_MPOOL |
                     DB_INIT_TXN   |
                     DB_THREAD     |
                     DB_RECOVER    |
                     nEnvFlags,
                     S_IRUSR | S_IWUSR);
    if (ret != 0)
        return error("CDB() : error %s (%d) opening database environment", DbEnv::strerror(ret), ret);
#ifdef _MSC_VER
    LogPrintf(
        "\n"                // kind of important, so give it its own space
        "CDBEnv::Open()'ed successfully) on dbenv.open() the BerkeleyDB DbEnv wallet code"
        "\n"
        "MainDir  =%s"
        "\n"
        "LogDir   =[MainDir]/%s"
        "\n"
        "ErrorFile=[MainDir]/%s"  // was kind of a misnomer (maybe it was never fixed?)
        "\n"
        "",
        pathEnv.string(),
        pathLogDir.filename().string(),     // a bit tricky since it's a directory!
        pathErrorFile.filename().string()
                );
#endif
    fDbEnvInit = true;
    fMockDb = false;

    return true;
}

void CDBEnv::MakeMock()
{
    if (fDbEnvInit)
        throw runtime_error("CDBEnv::MakeMock(): already initialized");

    if (fShutdown)
        throw runtime_error("CDBEnv::MakeMock(): during shutdown");

    LogPrintf("CDBEnv::MakeMock()\n");

    dbenv.set_cachesize(1, 0, 1);
    dbenv.set_lg_bsize(10485760*4);
    dbenv.set_lg_max(10485760);
    dbenv.set_lk_max_locks(10000);
    dbenv.set_lk_max_objects(10000);
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
#ifdef DB_LOG_IN_MEMORY
    dbenv.log_set_config(DB_LOG_IN_MEMORY, fUseMemoryLog ? 1 : 0);
#endif
    int ret = dbenv.open(NULL,
                     DB_CREATE     |
                     DB_INIT_LOCK  |
                     DB_INIT_LOG   |
                     DB_INIT_MPOOL |
                     DB_INIT_TXN   |
                     DB_THREAD     |
                     DB_PRIVATE,
                     S_IRUSR | S_IWUSR);
    if (ret > 0)
        throw runtime_error(strprintf("CDBEnv::MakeMock(): error %d opening database environment", ret));

    fDbEnvInit = true;
    fMockDb = true;
}

CDBEnv::VerifyResult CDBEnv::Verify(std::string strFile, bool (*recoverFunc)(CDBEnv& dbenv, std::string strFile))
{
    LOCK(cs_db);
    Yassert(mapFileUseCount.count(strFile) == 0);
    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, NULL, 0);
    if (result == 0)
        return VERIFY_OK;
    else if (recoverFunc == NULL)
        return RECOVER_FAIL;

    // Try to recover:
    bool fRecovered = (*recoverFunc)(*this, strFile);
    return (fRecovered ? RECOVER_OK : RECOVER_FAIL);
}

bool CDBEnv::Salvage(std::string strFile, bool fAggressive,
                     std::vector<CDBEnv::KeyValPair >& vResult)
{
    LOCK(cs_db);
    Yassert(mapFileUseCount.count(strFile) == 0);
    u_int32_t flags = DB_SALVAGE;
    if (fAggressive) flags |= DB_AGGRESSIVE;

    stringstream strDump;

    Db db(&dbenv, 0);
    int result = db.verify(strFile.c_str(), NULL, &strDump, flags);
    if (result != 0)
    {
        LogPrintf("ERROR: db salvage failed\n");
        return false;
    }

    // Format of bdb dump is ascii lines:
    // header lines...
    // HEADER=END
    // hexadecimal key
    // hexadecimal value
    // ... repeated
    // DATA=END

    string strLine;
    while (!strDump.eof() && strLine != "HEADER=END")
        getline(strDump, strLine); // Skip past header

    std::string keyHex, valueHex;
    while (!strDump.eof() && keyHex != "DATA=END")
    {
        getline(strDump, keyHex);
        if (keyHex != "DATA_END")
        {
            getline(strDump, valueHex);
            vResult.push_back(make_pair(ParseHex(keyHex),ParseHex(valueHex)));
        }
    }

    return (result == 0);
}


void CDBEnv::CheckpointLSN(std::string strFile)
{
    dbenv.txn_checkpoint(0, 0, 0);
    if (fMockDb)
        return;
    dbenv.lsn_reset(strFile.c_str(), 0);
}


CDB::CDB(const char *pszFile, const char* pszMode) :
    pdb(NULL), activeTxn(NULL)
{
    int ret;
    if (pszFile == NULL)
        return;

    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    bool fCreate = strchr(pszMode, 'c');
    unsigned int nFlags = DB_THREAD;
    if (fCreate)
        nFlags |= DB_CREATE;

    {
        LOCK(bitdb.cs_db);
        if (!bitdb.Open(GetDataDir()))
            throw runtime_error("env open failed");

        strFile = pszFile;
        ++bitdb.mapFileUseCount[strFile];
        pdb = bitdb.mapDb[strFile];
        if (pdb == NULL)
        {
            pdb = new Db(&bitdb.dbenv, 0);

            bool fMockDb = bitdb.IsMock();
            if (fMockDb)
            {
                DbMpoolFile*mpf = pdb->get_mpf();
                ret = mpf->set_flags(DB_MPOOL_NOFILE, 1);
                if (ret != 0)
                    throw runtime_error(strprintf("CDB() : failed to configure for no temp file backing for database %s", pszFile));
            }

            ret = pdb->open(NULL,      // Txn pointer
                            fMockDb ? NULL : pszFile,   // Filename
                            "main",    // Logical db name
                            DB_BTREE,  // Database type
                            nFlags,    // Flags
                            0);

            if (ret != 0)
            {
                delete pdb;
                pdb = NULL;
                --bitdb.mapFileUseCount[strFile];
                strFile = "";
                throw runtime_error(strprintf("CDB() : can't open database file %s, error %d", pszFile, ret));
            }

            if (fCreate && !Exists(string("version")))
            {
                bool fTmp = fReadOnly;
                fReadOnly = false;
                WriteVersion(CLIENT_VERSION);
                fReadOnly = fTmp;
            }

            bitdb.mapDb[strFile] = pdb;
        }
    }
}

static bool IsChainFile(std::string strFile)
{
    if (strFile == "blkindex.dat")
        return true;

    return false;
}

void CDB::Close()
{
    if (!pdb)
        return;
    if (activeTxn)
        activeTxn->abort();
    activeTxn = NULL;
    pdb = NULL;

    // Flush database activity from memory pool to disk log
    unsigned int nMinutes = 0;
    if (fReadOnly)
        nMinutes = 1;
    if (IsChainFile(strFile))
        nMinutes = 2;
    if (IsChainFile(strFile) && IsInitialBlockDownload())
        nMinutes = 5;

    bitdb.dbenv.txn_checkpoint(nMinutes ? gArgs.GetArg("-dblogsize", 100)*1024 : 0, nMinutes, 0);

    {
        LOCK(bitdb.cs_db);
        --bitdb.mapFileUseCount[strFile];
    }
}

void CDBEnv::CloseDb(const string& strFile)
{
    {
        LOCK(cs_db);
        if (mapDb[strFile] != NULL)
        {
            // Close the database handle
            Db* pdb = mapDb[strFile];
            pdb->close(0);
            delete pdb;
            mapDb[strFile] = NULL;
        }
    }
}

bool CDBEnv::RemoveDb(const string& strFile)
{
    this->CloseDb(strFile);

    LOCK(cs_db);
    int rc = dbenv.dbremove(NULL, strFile.c_str(), NULL, DB_AUTO_COMMIT);
    return (rc == 0);
}

bool CDB::Rewrite(const string& strFile, const char* pszSkip)
{
    while (!fShutdown)
    {
        {
            LOCK(bitdb.cs_db);
            if (!bitdb.mapFileUseCount.count(strFile) || bitdb.mapFileUseCount[strFile] == 0)
            {
                // Flush log data to the dat file
                bitdb.CloseDb(strFile);
                bitdb.CheckpointLSN(strFile);
                bitdb.mapFileUseCount.erase(strFile);

                bool fSuccess = true;
                LogPrintf("Rewriting %s...\n", strFile);
                string strFileRes = strFile + ".rewrite";
                { // surround usage of db with extra {}
                    CDB db(strFile.c_str(), "r");
                    Db* pdbCopy = new Db(&bitdb.dbenv, 0);

                    int ret = pdbCopy->open(NULL,                 // Txn pointer
                                            strFileRes.c_str(),   // Filename
                                            "main",    // Logical db name
                                            DB_BTREE,  // Database type
                                            DB_CREATE,    // Flags
                                            0);
                    if (ret > 0)
                    {
                        LogPrintf("Cannot create database file %s\n", strFileRes);
                        fSuccess = false;
                    }

                    Dbc* pcursor = db.GetCursor();
                    if (pcursor)
                        while (fSuccess)
                        {
                            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
                            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                            int ret = db.ReadAtCursor(pcursor, ssKey, ssValue, DB_NEXT);
                            if (ret == DB_NOTFOUND)
                            {
                                pcursor->close();
                                break;
                            }
                            else if (ret != 0)
                            {
                                pcursor->close();
                                fSuccess = false;
                                break;
                            }
                            if (pszSkip &&
                                strncmp(&ssKey[0], pszSkip, std::min(ssKey.size(), strlen(pszSkip))) == 0)
                                continue;
                            if (strncmp(&ssKey[0], "\x07version", 8) == 0)
                            {
                                // Update version:
                                ssValue.clear();
                                ssValue << CLIENT_VERSION;
                            }
                            Dbt datKey(&ssKey[0], ssKey.size());
                            Dbt datValue(&ssValue[0], ssValue.size());
                            int ret2 = pdbCopy->put(NULL, &datKey, &datValue, DB_NOOVERWRITE);
                            if (ret2 > 0)
                                fSuccess = false;
                        }
                    if (fSuccess)
                    {
                        db.Close();
                        bitdb.CloseDb(strFile);
                        if (pdbCopy->close(0))
                            fSuccess = false;
                        delete pdbCopy;
                    }
                }
                if (fSuccess)
                {
                    Db dbA(&bitdb.dbenv, 0);
                    if (dbA.remove(strFile.c_str(), NULL, 0))
                        fSuccess = false;
                    Db dbB(&bitdb.dbenv, 0);
                    if (dbB.rename(strFileRes.c_str(), NULL, strFile.c_str(), 0))
                        fSuccess = false;
                }
                if (!fSuccess)
                    LogPrintf("Rewriting of %s FAILED!\n", strFileRes);
                return fSuccess;
            }
        }
        Sleep(100);
    }
    return false;
}


void CDBEnv::Flush(bool fShutdown)
{
    ::int64_t nStart = GetTimeMillis();
    // Flush log data to the actual data file
    //  on all files that are not in use
    if (fDebug)
        LogPrintf("Flush(%s)%s\n", fShutdown ? "true" : "false", fDbEnvInit ? "" : " db not started");
    if (!fDbEnvInit)
        return;
    {
        LOCK(cs_db);
        map<string, int>::iterator mi = mapFileUseCount.begin();
        while (mi != mapFileUseCount.end())
        {
            string strFile = (*mi).first;
            int nRefCount = (*mi).second;
            LogPrintf("%s refcount=%d\n", strFile, nRefCount);
            if (nRefCount == 0)
            {
                // Move log data to the dat file
                CloseDb(strFile);
                LogPrintf("%s checkpoint\n", strFile);
                dbenv.txn_checkpoint(0, 0, 0);
                if (!IsChainFile(strFile) || fDetachDB) {
                    LogPrintf("%s detach\n", strFile);
                    if (!fMockDb)
                        dbenv.lsn_reset(strFile.c_str(), 0);
                }
                LogPrintf("%s closed\n", strFile);
                mapFileUseCount.erase(mi++);
            }
            else
                mi++;
        }
        LogPrintf(
                "DBFlush(%s)%s ended %15" PRId64 "ms\n", 
                fShutdown ? "true" : "false", 
                fDbEnvInit ? "" : " db not started", 
                GetTimeMillis() - nStart
              );
        if (fShutdown)
        {
            char** listp;
            if (mapFileUseCount.empty())
            {
                dbenv.log_archive(&listp, DB_ARCH_REMOVE);
                Close();
                if (!fMockDb)
#ifdef _MSC_VER
                {
                    try
                    {
                        boost::filesystem::remove_all(pathEnv / "database");     
                    }
                    catch (std::exception& e) 
                    //catch(boost::filesystem::filesystem_error &error) 
                    {
                        PrintExceptionContinue(&e, 
                                                "shutdown berkeley DB log "
                                                "directory delete failure, best to reboot? And run again."
                                              );
                    }
                }
#else
                    boost::filesystem::remove_all(pathEnv / "database");     
#endif
            }
        }
    }
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
