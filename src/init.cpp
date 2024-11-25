// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include <stdio.h>
    #include "msvc_warnings.push.h"
#else
    #ifndef BITCOIN_UTIL_H
        #include "util.h"
    #endif
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb-leveldb.h"
#endif

#ifndef _BITCOINRPC_H_
 #include "bitcoinrpc.h"
#endif

#ifndef BITCOIN_INIT_H
 #include "init.h"
#endif

#include <boost/format.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include "random.h"

#ifndef WIN32
#include <signal.h>
#endif
#include "scheduler.h"
#include "validationinterface.h"
#include "torcontrol.h"
#include "net_processing.h"

static const bool DEFAULT_PROXYRANDOMIZE = true;
::int64_t
    nUpTimeStart = 0;
bool fNewerOpenSSL = false; // for key.cpp's benefit
static const ::uint32_t mainnetNewLogicBlockNumber = 1890000;
static const ::uint32_t testnetNewLogicBlockNumber = 0;
static const ::uint32_t tokenSupportBlockNumber = 1911210;

using namespace boost;

using std::string;
using std::max;
using std::map;

CWallet* pwalletMain;
CClientUIInterface uiInterface;
std::string strWalletFileName;
bool fConfChange;
unsigned int nNodeLifespan;
unsigned int nMinerSleep;
bool fUseFastIndex;
bool fStoreBlockHashToDb;
bool fReindexOnlyHeaderSync;
bool fReindexBlockIndex;
bool fReindexToken;
bool fUseFastStakeMiner;
bool fUseMemoryLog;
enum Checkpoints::CPMode CheckpointsMode;

// Ping and address broadcast intervals
extern ::int64_t nPingInterval;
extern ::int64_t nBroadcastInterval;

std::unique_ptr<CConnman> g_connman;
std::unique_ptr<PeerLogicValidation> peerLogic;

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_CORE_FILEDESCRIPTORS 0
#else
#define MIN_CORE_FILEDESCRIPTORS 150
#endif

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

void ExitTimeout(void* parg)
{
#ifdef WIN32
    if (fDebug)
        if (fPrintToConsole)
            LogPrintf("2 sec timeout for unknown reason!?\n");
    Sleep(2 * 1000);
#endif
}

#ifndef TESTS_ENABLED
void StartShutdown()
{
#ifdef QT_GUI
    // ensure we leave the Qt main loop for a clean GUI exit (Shutdown() is called in bitcoin.cpp afterwards)
    uiInterface.QueueShutdown();
#else
    // Without UI, Shutdown() can simply be started in a new thread
    NewThread(Shutdown, NULL);
#endif
}
static bool
    fExit;

void Shutdown(void* parg)
{
    if (fDebug)
        LogPrintf("Shutdown : In progress...\n");
    
    static CCriticalSection 
        cs_Shutdown;

    static bool 
        fTaken;

    // Make this thread recognisable as the shutdown thread
    RenameThread("yacoin-shutoff");

    bool 
        fFirstThread = false;
    {
        TRY_LOCK(cs_Shutdown, lockShutdown);
        if (lockShutdown)
        {
            fFirstThread = !fTaken;
            fTaken = true;
        }
    }
    if (fFirstThread)
    {
        fShutdown = true;
        fRequestShutdown = true;
//        CTxDB().Close();
        bitdb.Flush(false);
        StopNode();
        {
            LOCK(cs_main);
            if (pwalletMain)
                pwalletMain->SetBestChain(chainActive.GetLocator());
        }
        bitdb.Flush(true);
#if !defined(WIN32) && !defined(QT_GUI)
    if (fDaemon)
    {
        boost::filesystem::remove(GetPidFile());
    }
#endif
        CloseWallets();
        if (fDebug)
            if (fPrintToConsole)
                LogPrintf("wallet unregistered\n");
        NewThread(ExitTimeout, NULL);
        if (fDebug)
            if (fPrintToConsole)
                LogPrintf("exit thread started\n");
        Sleep(50);
        if (fDebug)
            LogPrintf("Yacoin exited\n\n");
        fExit = true;
#ifndef QT_GUI
        // ensure non-UI client gets exited here, but let yacoin-qt reach 'return 0;' in bitcoin.cpp
    #ifdef _MSC_VER
        return;
    #else
        exit(0);
    #endif        
#endif
    }
    else
    {
        while (!fExit)
            Sleep(500);
        Sleep(100);
        ExitThread(0);
    }
}
#endif

void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}
#ifdef WIN32
//_____________________________________________________________________________
// this works for Windows gcc & MSVC++
static int WindowsHandleSigterm( unsigned long the_signal )
    {
    bool
        fIWillHandleIt = false;

    switch( the_signal )
        {
        case CTRL_C_EVENT:          //A CTRL+c signal was received,
            //either from keyboard input
            //or from a signal generated by the GenerateConsoleCtrlEvent function

        case CTRL_BREAK_EVENT:      //A CTRL+BREAK signal was received,
            //either from keyboard input
            //or from a signal generated by the GenerateConsoleCtrlEvent function

        case CTRL_LOGOFF_EVENT:     //A signal that the system sends to all console
            // processes when a user is logging off. This signal does not 
            // indicate which user is logging off, so no assumptions can be made.

        case CTRL_SHUTDOWN_EVENT:   // a system shutdown has occured
            HandleSIGTERM( ( int )the_signal );
            fIWillHandleIt = true;  // tell Windows we will take care of this
            break;      // It may not listen, but we will shutdown in any event

        case CTRL_CLOSE_EVENT:      // A signal that the system sends to all processes
            // attached to a console when the user closes
            // the console (either by choosing the Close
            // command from the console window's System menu,
            // or by choosing the End Task command from the Task List).
            HandleSIGTERM( ( int )the_signal );
            fIWillHandleIt = true;  // tell Windows we will take care of this
            // not on WIndows > XP :(
            // so can we hang here? Perhaps
            while( true )
            {
                Sleep( 1000 );
            }
            break;      // It may not listen, but we will shutdown in any event

        default:                    // any other (strange) signal we pass on
            break;                  // and just let it happen?
        }
    return fIWillHandleIt;
    }
//_____________________________________________________________________________
#endif
void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}



void Interrupt(boost::thread_group& threadGroup)
{
    if (g_connman)
        g_connman->Interrupt();
    threadGroup.interrupt_all();
}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
#if !defined(QT_GUI) && !defined(TESTS_ENABLED)
bool AppInit(int argc, char* argv[])
{
    boost::thread_group threadGroup;
    CScheduler scheduler;

    bool fRet = false;
    try
    {
        //
        // Parameters
        //
        // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
        gArgs.ParseParameters(argc, argv);
        bool 
            fTest_or_Main_Net_is_decided = false;

        if (!boost::filesystem::is_directory(GetDataDir(fTest_or_Main_Net_is_decided)))
        {
            fprintf(stderr, "Error: Specified directory does not exist\n");
            Shutdown(NULL);
        }
        try
        {
            gArgs.ReadConfigFile(gArgs.GetArg("-conf", YACOIN_CONF_FILENAME));
        } catch (const std::exception& e) {
            fprintf(stderr,"Error reading configuration file: %s\n", e.what());
            return false;
        }

        if(gArgs.IsArgSet("-version") || gArgs.IsArgSet("-v"))
        {
            std::string msg = "Yacoin version: " + FormatFullVersion() + "\n\n";
            fprintf(stdout, "%s", msg.c_str());
            exit(0);
        } else if (gArgs.IsArgSet("-?") || gArgs.IsArgSet("-h") || gArgs.IsArgSet("-help"))
        {
            // First part of help message is specific to yacoind / RPC client
            std::string strUsage = _("Yacoin version") + " " + FormatFullVersion() + "\n\n" +
                _("Usage:") + "\n" +
                  "  yacoind [options]                     " + "\n" +
                  "  yacoind [options] <command> [params]  " + _("Send command to -server or yacoind") + "\n" +
                  "  yacoind [options] help                " + _("List commands") + "\n" +
                  "  yacoind [options] help <command>      " + _("Get help for a command") + "\n";

            strUsage += "\n" + HelpMessage();

            fprintf(stdout, "%s", strUsage.c_str());
#ifdef _MSC_VER
            fRet = false;
            //Shutdown(NULL);
#else            
            exit(0);
#endif
        }
        else
        {
            bool 
                fCommandLine = false;
            // Command-line RPC
            for (int i = 1; i < argc; ++i)
            {
                if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "yacoin:"))
                {
                    fCommandLine = true;
                }
            }
            if (fCommandLine)
            {
                int ret = CommandLineRPC(argc, argv);
#ifdef _MSC_VER
                if( 0 == ret )  // signifies a successful RPC call
                {
                    fRet = false;
                }
#else
                exit(ret);
#endif
            }
            else
                fRet = AppInit2(threadGroup, scheduler);
        }
    }
    catch(std::exception& e) 
    {
        PrintException(&e, "AppInit()");
    } 
    catch(...)
    {
        PrintException(NULL, "AppInit()");
    }
    if (!fRet)
    {
        Interrupt(threadGroup);
        threadGroup.join_all();
        Shutdown(NULL);
    }
    return fRet;
}

extern void noui_connect();
int main(int argc, char* argv[])
{
    bool fRet = false;

    nUpTimeStart = GetTime();
    // Connect yacoind signal handlers
    noui_connect();

    fRet = AppInit(argc, argv);

    if (fRet)
        return 0;

    return 1;
}
#endif

bool static InitError(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("Yacoin"), CClientUIInterface::OK | CClientUIInterface::MODAL);
    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("Yacoin"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
    return true;
}


bool static Bind(const CService &addr, bool fError = true) 
{
    if (IsLimited(addr))
        return false;

    std::string 
        strError;

    if (!BindListenPort(addr, strError)) 
    {
        if (fError)
            return InitError(strError);
        return false;
    }
    return true;
}

// Core-specific options shared between UI and daemon
std::string HelpMessage()
{
    string strUsage = _("Options:") + "\n" +
        "  -?                     " + _("This help message") + "\n" +
        "  -v                     " + _("Yacoin version") + "\n" +
        "  -conf=<file>           " + _("Specify configuration file (default: yacoin.conf)") + "\n" +
        "  -pid=<file>            " + _("Specify pid file (default: yacoind.pid)") + "\n" +
        "  -datadir=<dir>         " + _("Specify data directory") + "\n" +
        "  -wallet=<file>         " + _("Specify wallet file (within data directory)") + "\n" +
        "  -dbcache=<n>           " + _("Set database cache size in megabytes (default: 25)") + "\n" +
        "  -dblogsize=<n>         " + _("Set database disk log size in megabytes (default: 100)") + "\n" +
        "  -timeout=<n>           " + _("Specify connection timeout in milliseconds (default: 5000)") + "\n" +
        "  -proxy=<ip:port>       " + _("Connect through socks proxy") + "\n" +
        "  -socks=<n>             " + _("Select the version of socks proxy to use (4-5, default: 5)") + "\n" +
        "  -tor=<ip:port>         " + _("Use proxy to reach tor hidden services (default: same as -proxy)") + "\n"
        "  -torname=<host.onion>  " + _("Send the specified hidden service name when connecting to Tor nodes (default: none)") + "\n"
        "  -dns                   " + _("Allow DNS lookups for -addnode, -seednode and -connect") + "\n" +
        "  -maxconnections=<n>    " + _("Maintain at most <n> connections to peers (default: 125)") + "\n" +
        "  -addnode=<ip>          " + _("Add a node to connect to and attempt to keep the connection open") + "\n" +
        "  -tokenindex            " + _("Keep an index of tokens. Requires a -reindex-token.") + "\n" +
        "  -addressindex          " + _("Maintain a full address index, used to query for the balance, txids and unspent outputs for addresses. Require a -reindex-token or -reindex-blockindex") + "\n" +
        "  -connect=<ip>          " + _("Connect only to the specified node(s)") + "\n" +
        "  -seednode=<ip>         " + _("Connect to a node to retrieve peer addresses, and disconnect") + "\n" +
        "  -externalip=<ip>       " + _("Specify your own public address") + "\n" +
        "  -onlynet=<net>         " + _("Only connect to nodes in network <net> (IPv4, IPv6 or Tor)") + "\n" +
        "  -discover              " + _("Discover own IP address (default: 1 when listening and no -externalip)") + "\n" +
        "  -listen                " + _("Accept connections from outside (default: 1 if no -proxy or -connect)") + "\n" +
        "  -bind=<addr>           " + _("Bind to given address. Use [host]:port notation for IPv6") + "\n" +
        "  -dnsseed               " + _("Find peers using DNS lookup (default: 1)") + "\n" +
        "  -cppolicy              " + _("Sync checkpoints policy (default: strict)") + "\n" +
        "  -banscore=<n>          " + _("Threshold for disconnecting misbehaving peers (default: 100)") + "\n" +
        "  -bantime=<n>           " + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)") + "\n" +
        "  -maxreceivebuffer=<n>  " + _("Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)") + "\n" +
        "  -maxsendbuffer=<n>     " + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)") + "\n" +
        "  -reindex-onlyheadersync          " + _("Upgrade block index to have new field `nstatus`, it just takes a few minutes") + "\n" +
        "  -reindex-blockindex              " + _("Rebuild block index and transaction index from the blk*.dat files on disk, it takes very long time (around 24->48 hours)") + "\n" +
        "  -reindex-token                   " + _("Rebuild token index from the blk*.dat files on disk, it takes around 6->9 hours") + "\n" +
        "  -initSyncDownloadTimeout=<n>     " + _("Headers/block download timeout in seconds (default: 600)") + "\n" +
        "  -initSyncMaximumBlocksInDownloadPerPeer=<n>     " + _("Maximum number of blocks being downloaded at a time from one peer (default: 500)") + "\n" +
        "  -initSyncBlockDownloadWindow=<n>     " + _("Block download windows (default: initSyncMaximumBlocksInDownloadPerPeer * 64)") + "\n" +
        "  -initSyncTriggerGetBlocks=<n>     " + _("When number of synced headers - number of synced blocks, send getblocks message to all peers to download block (default: 10000)") + "\n" +
#ifdef USE_UPNP
#if USE_UPNP
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 1 when listening)") + "\n" +
#else
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 0)") + "\n" +
#endif
#endif
        "  -detachdb              " + _("Detach block and address databases. Increases shutdown time (default: 0)") + "\n" +

#ifdef DB_LOG_IN_MEMORY
        "  -memorylog             " + _("Use in-memory logging for block index database (default: 1)") + "\n" +
#endif

        "  -paytxfee=<amt>        " + _("Fee per KB to add to transactions you send") + "\n" +
        "  -mininput=<amt>        " + str(boost::format(_("When creating transactions, ignore inputs with value less than this (default: %s)")) % FormatMoney(MIN_TXOUT_AMOUNT)) + "\n" +
#ifdef QT_GUI
        "  -server                " + _("Accept command line and JSON-RPC commands") + "\n" +
#endif
#if !defined(WIN32) && !defined(QT_GUI)
        "  -daemon                " + _("Run in the background as a daemon and accept commands") + "\n" +
#endif
        "  -testnet               " + _("Use the test network") + "\n" +
        "  -testnetNewLogic       " + _("Use the test network New Logic") + "\n" +
        "  -testnetnewlogicblocknumber=<number> " + _("New Logic starting at block = <number>") + "\n" +
        "  -debug                 " + _("Output extra debugging information. Implies all other -debug* options") + "\n" +
        "  -debugnet              " + _("Output extra network debugging information") + "\n" +
        "  -logtimestamps         " + _("Prepend debug output with timestamp") + "\n" +
        "  -shrinkdebugfile       " + _("Shrink debug.log file on client startup (default: 1 when no -debug)") + "\n" +
        "  -printtoconsole        " + _("Send trace/debug info to console instead of debug.log file") + "\n" +
#ifdef WIN32
        "  -printtodebugger       " + _("Send trace/debug info to debugger") + "\n" +
#endif
        "  -btcyacprovider        " + _("Add a BTC to YAC price provider, entered as") + "\n" +
        "                         domain,key,argument,offset,port" + "\n" 
        "                         For example: where the url is" + "\n"
        "                         http://pubapi2.cryptsy.com/api.php?method=singlemarketdata&marketid=11" + "\n"
        "                         one would enter" + "\n"
        "                         pubapi2.cryptsy.com,lasttradeprice,/api.php?method=singlemarketdata&marketid=11,3,80" + "\n"
        "                         see https://www.cryptsy.com/pages/publicapi" + "\n" +
        "  -usdbtcprovider        " + _("Add a USD to BTC price provider, entered as") + "\n" +
        "                         domain,key,argument,offset" + "\n" +
        "                         For example: where the url is" + "\n" +
        "                         http://pubapi2.cryptsy.com/api.php?method=singlemarketdata&marketid=2" + "\n" +
        "                         one would enter" + "\n" +
        "                         pubapi2.cryptsy.com,lastdata,/api.php?method=singlemarketdata&marketid=2,3,80" + "\n" +
        "                         see https://www.cryptsy.com/pages/publicapi" + "\n" +
        "  -rpcuser=<user>        " + _("Username for JSON-RPC connections") + "\n" +
        "  -rpcpassword=<pw>      " + _("Password for JSON-RPC connections") + "\n" +
        "  -port=<port>           " + _("Listen for connections on <port> (default: 7688 or testnet: 17688)") + "\n" +
        "  -rpcport=<port>        " + _("Listen for JSON-RPC connections on <port> (default: 7687 or testnet: 17687)") + "\n" +
        "  -rpcallowip=<ip>       " + _("Allow JSON-RPC connections from specified IP address") + "\n" +
        "  -rpcconnect=<ip>       " + _("Send commands to node running on <ip> (default: 127.0.0.1)") + "\n" +
        "  -blocknotify=<cmd>     " + _("Execute command when the best block changes (%s in cmd is replaced by block hash)") + "\n" +
        "  -walletnotify=<cmd>    " + _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)") + "\n" +
        "  -confchange            " + _("Require a confirmations for change (default: 0)") + "\n" +
        "  -upgradewallet         " + _("Upgrade wallet to latest format") + "\n" +
        "  -keypool=<n>           " + _("Set key pool size to <n> (default: 100)") + "\n" +
        "  -rescan                " + _("Rescan the block chain for missing wallet transactions") + "\n" +
        "  -salvagewallet         " + _("Attempt to recover private keys from a corrupt wallet.dat") + "\n" +
        "  -checkblocks=<n>       " + _("How many blocks to check at startup (default: 750, 0 = all)") + "\n" +
        "  -checklevel=<n>        " + _("How thorough the block verification is (0-6, default: 1)") + "\n" +
        "  -par=N                 " + _("Set the number of script verification threads (1-16, 0=auto, default: 0)") + "\n" +
        "  -hashcalcthreads=N     " + _("Set the number of threads which calculate hash (maximum threads = number of cpu cores, default: 1)") + "\n" +
        "  -loadblock=<file>      " + _("Imports blocks from external blk000?.dat file") + "\n" +
                                        "\n" + _("SSL options: (see the Bitcoin Wiki for SSL setup instructions)") + "\n" +
        "  -rpcssl                                  " + _("Use OpenSSL (https) for JSON-RPC connections") + "\n" +
        "  -rpcsslcertificatechainfile=<file.cert>  " + _("Server certificate file (default: server.cert)") + "\n" +
        "  -rpcsslprivatekeyfile=<file.pem>         " + _("Server private key (default: server.pem)") + "\n" +
        "  -rpcsslciphers=<ciphers>                 " + _("Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)") + "\n";

    return strUsage;
}

static std::string ResolveErrMsg(const char * const optname, const std::string& strBind)
{
    return strprintf(_("Cannot resolve -%s address: '%s'"), optname, strBind);
}

namespace { // Variables internal to initialization process only

ServiceFlags nRelevantServices = NODE_NETWORK;
int nMaxConnections;
int nUserMaxConnections;
int nFD;
ServiceFlags nLocalServices = NODE_NETWORK;

} // namespace

bool AppInitParameterInteraction()
{
    // -bind and -whitebind can't be set when not listening
    size_t nUserBind = gArgs.GetArgs("-bind").size() + gArgs.GetArgs("-whitebind").size();
    if (nUserBind != 0 && !gArgs.GetBoolArg("-listen", DEFAULT_LISTEN)) {
        return InitError("Cannot set -bind or -whitebind together with -listen=0");
    }

    // Make sure enough file descriptors are available
    int nBind = std::max(nUserBind, size_t(1));
    nUserMaxConnections = gArgs.GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS);
    nMaxConnections = std::max(nUserMaxConnections, 0);

    // Trim requested connection counts, to fit into system limitations
    nMaxConnections = std::max(std::min(nMaxConnections, (int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS - MAX_ADDNODE_CONNECTIONS)), 0);
    nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS + MAX_ADDNODE_CONNECTIONS);
    if (nFD < MIN_CORE_FILEDESCRIPTORS)
        return InitError(_("Not enough file descriptors available."));
    nMaxConnections = std::min(nFD - MIN_CORE_FILEDESCRIPTORS - MAX_ADDNODE_CONNECTIONS, nMaxConnections);

    if (nMaxConnections < nUserMaxConnections)
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), nUserMaxConnections, nMaxConnections));

    nNodeLifespan = (unsigned int)(gArgs.GetArg("-addrlifespan", 7));
    fUseFastIndex = gArgs.GetBoolArg("-fastindex", true);
    fStoreBlockHashToDb = gArgs.GetBoolArg("-storeblockhash", true);
    fUseMemoryLog = gArgs.GetBoolArg("-memorylog", true);
    // YAC_TOKEN START
    fTokenIndex = gArgs.GetBoolArg("-tokenindex", false);
    fAddressIndex = gArgs.GetBoolArg("-addressindex", false);
    // YAC_TOKEN END
    nMinerSleep = (unsigned int)(gArgs.GetArg("-minersleep", nOneHundredMilliseconds));

    HEADERS_DOWNLOAD_TIMEOUT_BASE = gArgs.GetArg("-initSyncDownloadTimeout", 15 * 60) * 1000000;
    BLOCK_DOWNLOAD_TIMEOUT_BASE = HEADERS_DOWNLOAD_TIMEOUT_BASE;
    MAX_BLOCKS_IN_TRANSIT_PER_PEER = gArgs.GetArg("-initSyncMaximumBlocksInDownloadPerPeer", 500);
    BLOCK_DOWNLOAD_WINDOW = gArgs.GetArg("-initSyncBlockDownloadWindow", MAX_BLOCKS_IN_TRANSIT_PER_PEER * 64);
    HEADER_BLOCK_DIFFERENCES_TRIGGER_GETBLOCKS = gArgs.GetArg("-initSyncTriggerGetBlocks", 10000);

    int maximumHashCalcThread = boost::thread::hardware_concurrency();
    nHashCalcThreads = (int)(gArgs.GetArg("-hashcalcthreads", 1));
    if (nHashCalcThreads <= 0)
        nHashCalcThreads = 1;
    else if (nHashCalcThreads > maximumHashCalcThread)
        nHashCalcThreads = maximumHashCalcThread;

    // Ping and address broadcast intervals
    nPingInterval = max< ::int64_t>(10, gArgs.GetArg("-keepalive", 10 * 60));
    nBroadcastInterval = max< ::int64_t>(6 * 60 * 60, gArgs.GetArg("-addrsetlifetime", 24 * 60 * 60));

    CheckpointsMode = Checkpoints::STRICT_;
    std::string strCpMode = gArgs.GetArg("-cppolicy", "strict");

    if(strCpMode == "strict") {
        CheckpointsMode = Checkpoints::STRICT_;
    }

    if(strCpMode == "advisory") {
        CheckpointsMode = Checkpoints::ADVISORY;
    }

    if(strCpMode == "permissive") {
        CheckpointsMode = Checkpoints::PERMISSIVE;
    }

    // Good that testnet is tested here, but closer to AppInit() => ReadConfigFile() would be better
    fTestNet = gArgs.GetBoolArg("-testnet");

    // -par=0 means autodetect, but nScriptCheckThreads==0 means no concurrency
    nScriptCheckThreads = (int)(gArgs.GetArg("-par", 0));
    if (nScriptCheckThreads == 0)
        nScriptCheckThreads = boost::thread::hardware_concurrency();
    if (nScriptCheckThreads <= 1)
        nScriptCheckThreads = 0;
    else if (nScriptCheckThreads > MAX_SCRIPTCHECK_THREADS)
        nScriptCheckThreads = MAX_SCRIPTCHECK_THREADS;

    fDebug = gArgs.GetBoolArg("-debug");

    // -debug implies fDebug*
    if (fDebug)
        fDebugNet = true;
    else
        fDebugNet = gArgs.GetBoolArg("-debugnet");

    bitdb.SetDetach(gArgs.GetBoolArg("-detachdb", false));

#if !defined(WIN32) && !defined(QT_GUI)
    fDaemon = gArgs.GetBoolArg("-daemon");
#else
    fDaemon = false;
#endif

    if (fDaemon)
        fServer = true;
    else
        fServer = gArgs.GetBoolArg("-server");

    /* force fServer when running without GUI */
#if !defined(QT_GUI)
    fServer = true;
#endif

    nEpochInterval = (::uint32_t)(gArgs.GetArg("-epochinterval", 21000));
    nDifficultyInterval = nEpochInterval;

    nConnectTimeout = gArgs.GetArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0)
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    // Continue to put "/P2SH/" in the coinbase to monitor
    // BIP16 support.
    // This can be removed eventually...
    const char* pszP2SH = "/P2SH/";
    COINBASE_FLAGS << std::vector<unsigned char>(pszP2SH, pszP2SH+strlen(pszP2SH));


    if (gArgs.IsArgSet("-paytxfee"))
    {
        if (!ParseMoney(gArgs.GetArg("-paytxfee", ""), nTransactionFee))
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s'"), gArgs.GetArg("-paytxfee", "").c_str()));
        if (nTransactionFee > 0.25 * COIN)
            InitWarning(_("Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
    }

    fConfChange = gArgs.GetBoolArg("-confchange", false);

    if (gArgs.IsArgSet("-mininput"))
    {
        if (!ParseMoney(gArgs.GetArg("-mininput", ""), nMinimumInputValue))
            return InitError(strprintf(_("Invalid amount for -mininput=<amount>: '%s'"), gArgs.GetArg("-mininput", "").c_str()));
    }

    nMaxTipAge = gArgs.GetArg("-maxtipage", DEFAULT_MAX_TIP_AGE);

    return true;
}

// Parameter interaction based on rules
void InitParameterInteraction()
{
    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (gArgs.IsArgSet("-bind")) {
        if (gArgs.SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }

    if (gArgs.IsArgSet("-whitebind")) {
        if (gArgs.SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    if (gArgs.IsArgSet("-connect") &&  gArgs.GetArgs("-connect").size() > 0) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (gArgs.SoftSetBoolArg("-dnsseed", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }

    if (gArgs.IsArgSet("-proxy")) {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (gArgs.SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not use UPNP when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (gArgs.SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -upnp=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!gArgs.GetBoolArg("-listen", DEFAULT_LISTEN)) {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (gArgs.SoftSetBoolArg("-upnp", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -upnp=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (gArgs.SoftSetBoolArg("-listenonion", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    if (gArgs.IsArgSet("-externalip")) {
        // if an explicit public IP is specified, do not try to find others
        if (gArgs.SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    if (gArgs.GetBoolArg("-salvagewallet")) {
        // Rewrite just private keys: rescan to find transactions
        gArgs.SoftSetBoolArg("-rescan", true);
    }
}

void InitLogging()
{
#if !defined(QT_GUI)
    fPrintToConsole = gArgs.GetBoolArg("-printtoconsole");
#else
    fPrintToConsole = false;
#endif
    fPrintToDebugLog = gArgs.GetBoolArg("-printtodebugger", true);
    fLogTimestamps = gArgs.GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
    fLogTimeMicros = gArgs.GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);
    fLogIPs = gArgs.GetBoolArg("-logips", DEFAULT_LOGIPS);
    LogPrintf("fPrintToConsole = %d, fPrintToDebugLog = %d\n", fPrintToConsole, fPrintToDebugLog);
}

//_____________________________________________________________________________

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    // ********************************************************* Step 1: setup
    // Set this early so that parameter interactions go to console
    InitLogging();

#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
// We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
// which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif
#ifndef WIN32
    umask(077);

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);
#else
    // what do we do for windows aborts or Ctl-Cs, etc.?
    bool
        fWeShouldBeConcerned = true;
        
    if( SetConsoleCtrlHandler( ( PHANDLER_ROUTINE )&WindowsHandleSigterm, true ) )
        fWeShouldBeConcerned = false;    // success
    else                        //exigency of wincon.h
    {    //    // we failed!
        LogPrintf(
                    "\n"
                    "Windows CCH failed?"
                    "\n"
                    ""
                    );
    }
#endif

    // ********************************************************* Step 2: parameter interactions
    InitParameterInteraction();

    // ********************************************************* Step 3: parameter-to-internal-flags
    if (!AppInitParameterInteraction())
    {
        // InitError will have been called with detailed error, which ends up on console
        exit(EXIT_FAILURE);
    }

    if (fPrintToDebugLog)
        OpenDebugLog();

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    std::string // note fTestNet has been set and finally we 'discover' the 'data directory'!
        strDataDir = GetDataDir().string();

    strWalletFileName = gArgs.GetArg("-wallet", "wallet.dat");

    // strWalletFileName must be a plain filename without a directory
    if (
        strWalletFileName != 
        boost::filesystem::basename(strWalletFileName) + 
        boost::filesystem::extension(strWalletFileName)
       )
        return InitError(
                         strprintf(
                            _("Wallet %s resides outside data directory %s."), 
                            strWalletFileName.c_str(), 
                            strDataDir.c_str()
                                  )
                        );

    // Make sure only a single Bitcoin process is using the data directory.
    boost::filesystem::path 
        pathLockFile = GetDataDir() / ".lock";

    FILE
        * file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.

    if (file)         
        fclose(file);

    static boost::interprocess::file_lock 
        lock(pathLockFile.string().c_str());

    if (!lock.try_lock())
        return InitError(
                         strprintf(
                            _("Cannot obtain a lock on data directory %s.  Yacoin is probably already running."), 
                            strDataDir.c_str()
                                  )
                        );

#if !defined(WIN32) && !defined(QT_GUI)
    if (fDaemon)
    {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0)
        {
            fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
            return false;
        }
        if (pid > 0)
        {
            CreatePidFile(GetPidFile(), pid);
            return true;
        }

        pid_t sid = setsid();
        if (sid < 0)
            fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
    }
#endif

    if (gArgs.GetBoolArg("-shrinkdebugfile", !fDebug))
        ShrinkDebugFile();
    LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    LogPrintf("Yacoin version %s (%s)\n", FormatFullVersion(), CLIENT_DATE);
    LogPrintf("\n" );

#if defined( USE_IPV6 )
        LogPrintf( "USE_IPV6 is defined\n" );
#endif
#if defined( USE_ASM )
        LogPrintf( "USE_ASM is defined\n" );
#endif
#if defined( USE_UPNP )
        LogPrintf( "USE_UPNP is defined\n" );
#endif
    LogPrintf("Using Boost version %1d.%d.%d\n", BOOST_VERSION / 100000, (BOOST_VERSION / 100) % 1000, BOOST_VERSION % 100);
    LogPrintf("Boost is using the %s compiler\n", BOOST_COMPILER );
    LogPrintf("Boost is using the %s standard library\n", BOOST_STDLIB );
    LogPrintf("Boost is using the %s platform\n\n", BOOST_PLATFORM );

    LogPrintf("Using levelDB version %d.%d\n", leveldb::kMajorVersion, leveldb::kMinorVersion);
    LogPrintf("\n");

    int
        nBdbMajor,
        nBdbMinor,
        nBdbPatch;

    (void)db_version( &nBdbMajor, &nBdbMinor, &nBdbPatch );
    LogPrintf("Using BerkeleyDB version %d.%d.%d\n\n", nBdbMajor, nBdbMinor, nBdbPatch);
    LogPrintf("Using OpenSSL version %s\n\n", SSLeay_version(SSLEAY_VERSION));
    LogPrintf("Wallet is %s\n", strDataDir + "/" + strWalletFileName);

    unsigned int
        nCutoffVersion = (unsigned int)((int)'j' - (int)'`'),
        nV = SSLEAY_VERSION_NUMBER;
    nV &= 0x000000f0;
    nV >>= 4;
    if( nV > nCutoffVersion )
        fNewerOpenSSL = true;

    if (!fLogTimestamps)
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%x %H:%M:%S", GetTime()));
    LogPrintf("The Default data directory is %s\n", GetDefaultDataDir().string());
    LogPrintf("Using data directory %s\n", strDataDir);
    std::ostringstream 
        strErrors;

    if (fDaemon)
        fprintf(stdout, "Yacoin server starting\n");

    if (nScriptCheckThreads) 
    {
        LogPrintf("Using %u threads for script verification\n", nScriptCheckThreads);
        for (int i=0; i<nScriptCheckThreads-1; ++i)
            NewThread(ThreadScriptCheck, NULL);
    }

    if (nHashCalcThreads)
    {
        LogPrintf("Using %u threads for hash calculation\n", nHashCalcThreads);
        for (int i=0; i<nHashCalcThreads-1; ++i)
            NewThread(ThreadHashCalculation, NULL);
    }

    // Start the lightweight task scheduler thread
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler);
    threadGroup.create_thread(boost::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop));

    GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);

    ::int64_t nStart;

    // ********************************************************* Step 5: verify database integrity

    uiInterface.InitMessage(_("<b>Verifying database integrity...</b>"));

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }

    if (gArgs.GetBoolArg("-salvagewallet"))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, strWalletFileName, true))
            return false;
    }

    if (filesystem::exists(GetDataDir() / strWalletFileName))
    {
        CDBEnv::VerifyResult r = bitdb.Verify(strWalletFileName, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK)
        {
            string msg = strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
                                     " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                     " your balance or transactions are incorrect you should"
                                     " restore from a backup."), strDataDir.c_str());
            uiInterface.ThreadSafeMessageBox(msg, _("Yacoin"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        }
        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(_("wallet.dat corrupt, salvage failed"));
    }

    // ********************************************************* Step 6: network initialization
    // Note that we absolutely cannot open any actual connections
    // until the very end ("start node") as the UTXO/block state
    // is not yet setup and may end up being set up twice if we
    // need to reindex later.

    assert(!g_connman);
    g_connman = std::unique_ptr<CConnman>(new CConnman(GetRand(std::numeric_limits<uint64_t>::max()), GetRand(std::numeric_limits<uint64_t>::max())));
    CConnman& connman = *g_connman;
    peerLogic.reset(new PeerLogicValidation(&connman, scheduler));
    RegisterValidationInterface(peerLogic.get());

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector<std::string> uacomments;
    for (const std::string& cmt : gArgs.GetArgs("-uacomment")) {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(cmt);
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return InitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    // Check for -socks - as this is a privacy risk to continue, exit here
    if (gArgs.IsArgSet("-socks"))
        return InitError(_("Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."));

#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA 
        wsadata;

    int 
        ret = WSAStartup(MAKEWORD(2,2), &wsadata);

    if (ret != NO_ERROR)
    {
        string
            strError = strprintf(
                                 "Error: TCP/IP socket library failed to start "
                                 "(WSAStartup returned error %d)", 
                                 ret
                                );
        LogPrintf("%s\n", strError);
    }
    if (
        (2 != LOBYTE( wsadata.wVersion )) ||
        (2 != HIBYTE( wsadata.wVersion ))
       ) 
    {
    /* Tell the user that we could not find a usable */
    /* WinSock DLL.                                  */
    WSACleanup( );
    string
        strError = "Error: TCP/IP socket library isn't 2.2 or greater?";
    LogPrintf("%s\n", strError);
    return InitError(_("Error: TCP/IP socket library isn't 2.2 or greater?"));
    }

#endif

    if (gArgs.IsArgSet("-onlynet")) {
        std::set<enum Network> nets;
        for (const std::string& snet : gArgs.GetArgs("-onlynet")) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++) {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }

    // Check for host lookup allowed before parsing any network related parameters
    fNameLookup = gArgs.GetBoolArg("-dns", DEFAULT_NAME_LOOKUP);

    bool proxyRandomize = gArgs.GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = gArgs.GetArg("-proxy", "");
    SetLimited(NET_TOR);
    if (proxyArg != "" && proxyArg != "0") {
        CService proxyAddr;
        if (!Lookup(proxyArg.c_str(), proxyAddr, 9050, fNameLookup)) {
            return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));
        }

        proxyType addrProxy = proxyType(proxyAddr, proxyRandomize);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_TOR, addrProxy);
        SetNameProxy(addrProxy);
        SetLimited(NET_TOR, false); // by default, -proxy sets onion as reachable, unless -noonion later
    }

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses
    // -noonion (or -onion=0) disables connecting to .onion entirely
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none)
    std::string onionArg = gArgs.GetArg("-onion", "");
    if (onionArg != "") {
        if (onionArg == "0") { // Handle -noonion/-onion=0
            SetLimited(NET_TOR); // set onions as unreachable
        } else {
            CService onionProxy;
            if (!Lookup(onionArg.c_str(), onionProxy, 9050, fNameLookup)) {
                return InitError(strprintf(_("Invalid -onion address or hostname: '%s'"), onionArg));
            }
            proxyType addrOnion = proxyType(onionProxy, proxyRandomize);
            if (!addrOnion.IsValid())
                return InitError(strprintf(_("Invalid -onion address or hostname: '%s'"), onionArg));
            SetProxy(NET_TOR, addrOnion);
            SetLimited(NET_TOR, false);
        }
    }

    // Check for -tor - as this is a privacy risk to continue, exit here
    if (gArgs.GetBoolArg("-tor", false))
        return InitError(_("Unsupported argument -tor found, use -onion."));

    // see Step 2: parameter interactions for more information about these
    fListen = gArgs.GetBoolArg("-listen", DEFAULT_LISTEN);
    fDiscover = gArgs.GetBoolArg("-discover", true);
    fRelayTxes = !gArgs.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY);

    for (const std::string& strAddr : gArgs.GetArgs("-externalip")) {
        CService addrLocal;
        if (Lookup(strAddr.c_str(), addrLocal, GetListenPort(), fNameLookup) && addrLocal.IsValid())
            AddLocal(addrLocal, LOCAL_MANUAL);
        else
            return InitError(ResolveErrMsg("externalip", strAddr));
    }

#if ENABLE_ZMQ
    pzmqNotificationInterface = CZMQNotificationInterface::Create();

    if (pzmqNotificationInterface) {
        RegisterValidationInterface(pzmqNotificationInterface);
    }
#endif
    uint64_t nMaxOutboundLimit = 0; //unlimited unless -maxuploadtarget is set
    uint64_t nMaxOutboundTimeframe = MAX_UPLOAD_TIMEFRAME;

    if (gArgs.IsArgSet("-maxuploadtarget")) {
        nMaxOutboundLimit = gArgs.GetArg("-maxuploadtarget", DEFAULT_MAX_UPLOAD_TARGET)*1024*1024;
    }

    if (gArgs.IsArgSet("-reservebalance")) // ppcoin: reserve balance amount
    {
        ::int64_t nReserveBalance = 0;
        if (!ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
        {
            InitError(_("Invalid amount for -reservebalance=<amount>"));
            return false;
        }
    }

    if (gArgs.IsArgSet("-checkpointkey")) // ppcoin: checkpoint master priv key
    {
        if (!Checkpoints::SetCheckpointPrivKey(gArgs.GetArg("-checkpointkey", "")))
            InitError(_("Unable to sign checkpoint, wrong checkpointkey?\n"));
    }

    // ********************************************************* Step 7 was Step 8: load wallet

    uiInterface.InitMessage(_("<b>Loading wallet...</b>"));
    LogPrintf("Loading wallet...\n");
    nStart = GetTimeMillis();
    bool fFirstRun = true;
    pwalletMain = new CWallet(strWalletFileName);
    DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)
            strErrors << _("Error loading wallet.dat: Wallet corrupted") << "\n";
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            string msg(_("Warning: error reading wallet.dat! All keys read correctly, but transaction data"
                         " or address book entries might be missing or incorrect."));
            uiInterface.ThreadSafeMessageBox(msg, _("Yacoin"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        }
        else if (nLoadWalletRet == DB_TOO_NEW)
            strErrors << _("Error loading wallet.dat: Wallet requires newer version of Yacoin") << "\n";
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            strErrors << _("Wallet needed to be rewritten: restart Yacoin to complete") << "\n";
            LogPrintf("%s\n", strErrors.str());
            return InitError(strErrors.str());
        }
        else
            strErrors << _("Error loading wallet.dat") << "\n";
    }

    if (gArgs.GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = (int)(gArgs.GetArg("-upgradewallet", 0));
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < pwalletMain->GetVersion())
            strErrors << _("Cannot downgrade wallet") << "\n";
        pwalletMain->SetMaxVersion(nMaxVersion);
    }
    // ********************************************************* Step 8 was Step 7: load blockchain

    fReindexOnlyHeaderSync = gArgs.GetBoolArg("-reindex-onlyheadersync", false);
    fReindexBlockIndex = gArgs.GetBoolArg("-reindex-blockindex", false);
    if (!fReindexBlockIndex)
    {
        fReindexToken = gArgs.GetBoolArg("-reindex-token", false);
    }
    LogPrintf("Param fReindexOnlyHeaderSync = %d, fReindexBlockIndex = %d, fReindexToken = %d\n", fReindexOnlyHeaderSync, fReindexBlockIndex, fReindexToken);

    nMainnetNewLogicBlockNumber = gArgs.GetArg("-testnetNewLogicBlockNumber", mainnetNewLogicBlockNumber);
    nTokenSupportBlockNumber = gArgs.GetArg("-tokenSupportBlockNumber", tokenSupportBlockNumber);
    LogPrintf("Param nMainnetNewLogicBlockNumber = %d\n",nMainnetNewLogicBlockNumber);

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }

    if (gArgs.GetBoolArg("-loadblockindextest"))
    {
        CTxDB txdb("r");
        txdb.LoadBlockIndex();
        PrintBlockTree();
        return false;
    }

    MAXIMUM_YAC1DOT0_N_FACTOR = gArgs.GetArg("-nFactorAtHardfork", 21);
    LogPrintf("Param nFactorAtHardfork = %d\n", MAXIMUM_YAC1DOT0_N_FACTOR);

    std::string additionalInfo = fReindexBlockIndex ? "(reindex block index)" : fReindexToken ? "(reindex token)" : "";
    LogPrintf("Loading block index %s ...\n", additionalInfo);
    bool fLoaded = false;
    bool fReindex = fReindexBlockIndex || fReindexToken;
    while (!fLoaded) 
    {
        std::string 
            strLoadError;
        // YACOIN TODO ADD SPINNER OR PROGRESS BAR
        uiInterface.InitMessage(_("<b>Loading block index, this may take several minutes...</b>"));

        nStart = GetTimeMillis();
        do 
        {
            try 
            {
                UnloadBlockIndex();

                /** YAC_TOKEN START */
                {
                    // Basic tokens
                    delete ptokens;
                    delete ptokensdb;
                    delete ptokensCache;

                    // Basic tokens
                    ptokensdb = new CTokensDB("cr+", fReindex);
                    ptokens = new CTokensCache();
                    ptokensCache = new CLRUCache<std::string, CDatabasedTokenData>(MAX_CACHE_TOKENS_SIZE);

                    // Need to load tokens before we verify the database
                    if (!ptokensdb->LoadTokens()) {
                        return InitError("Failed to load Tokens Database");
                    }

                    if (!ptokensdb->ReadReissuedMempoolState())
                        LogPrintf("Database failed to load last Reissued Mempool State. Will have to start from empty state\n");

                    LogPrintf("Successfully loaded tokens from database.\nCache of tokens size: %d\n",
                              ptokensCache->Size());
                }
                /** YAC_TOKEN END */

                // Don't build map hash for fReindexBlockIndex
                if (fReindexToken)
                {
                    {
                        CTxDB txdb;
                        txdb.BuildMapHash();
                        txdb.Close();
                    }

                }
                if (fReindex)
                {
                    // Wipe the database
                    CTxDB txdb("cr+", fReindex);
                    fReindexToken = false;
                    fReindexBlockIndex = false;
                }

                if (!LoadBlockIndex())
                {
                    strLoadError = _("Error loading block database");
                    break;
                }
            }
            catch(std::exception &e) 
            {
                (void)e;
                strLoadError = _("Error opening block database");
                break;
            }
            fLoaded = true;
        }
        while(false);

        if (!fLoaded) 
        {   // TODO: suggest reindex here
            strLoadError += ".\nPlease restart with -reindex-onlyheadersync (takes a few minutes) or -reindex-token (takes around 6->9 hours) or -reindex-blockindex (takes very long time, around 24->48 hours) to recover.";
            return InitError(strLoadError);
        }
    }

    // as LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill bitcoin-qt during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    LogPrintf(" block index %15" PRId64 "ms\n", GetTimeMillis() - nStart);

    if (gArgs.GetBoolArg("-printblockindex") || gArgs.GetBoolArg("-printblocktree"))
    {
        PrintBlockTree();
        return false;
    }

    if (gArgs.IsArgSet("-printblock"))
    {
        string strMatch = gArgs.GetArg("-printblock", "");
        int nFound = 0;
        for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        {
            uint256 hash = (*mi).first;
            if (strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0)
            {
                CBlockIndex* pindex = (*mi).second;
                CBlock block;
                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();
                block.print();
                LogPrintf("\n");
                nFound++;
            }
        }
        if (nFound == 0)
            LogPrintf("No blocks matching %s were found\n", strMatch);
        return false;
    }


    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        RandAddSeedPerfmon();

        CPubKey newDefaultKey;
        if (!pwalletMain->GetKeyFromPool(newDefaultKey, false))
            strErrors << _("Cannot initialize keypool") << "\n";
        pwalletMain->SetDefaultKey(newDefaultKey);
        if (!pwalletMain->SetAddressBookName(pwalletMain->vchDefaultKey.GetID(), ""))
            strErrors << _("Cannot write default address") << "\n";
    }

    LogPrintf("%s\n", strErrors.str());
    LogPrintf(" wallet      %15" PRId64 "ms\n", GetTimeMillis() - nStart);

    RegisterWallet(pwalletMain);

    CBlockIndex *pindexRescan = chainActive.Tip();
    if (gArgs.GetBoolArg("-rescan"))
        pindexRescan = chainActive.Genesis();
    else
    {
        CWalletDB walletdb(strWalletFileName);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = chainActive.FindFork(locator);
        else
            pindexRescan = chainActive.Genesis();
    }
    if (chainActive.Tip() != pindexRescan && chainActive.Tip() && pindexRescan && chainActive.Tip()->nHeight > pindexRescan->nHeight)
    {
        uiInterface.InitMessage(_("<b>Please wait, rescanning blocks...</b>"));
        LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Tip()->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
#ifdef WIN32
        pwalletMain->ScanForWalletTransactions(pindexRescan, true, chainActive.Tip()->nHeight - pindexRescan->nHeight);
#else
        pwalletMain->ScanForWalletTransactions(pindexRescan, true);
#endif
        LogPrintf(" rescan      %15" PRId64 "ms\n", GetTimeMillis() - nStart);
    }

    // ********************************************************* Step 9: import blocks

    // Reindex
    if (fReindex) {
        int nFile = 1;
        while (true) {
            CDiskBlockPos pos(nFile, 0);
            if (!boost::filesystem::exists(GetBlockPosFilename(pos, "blk")))
                break; // No block files left to reindex
            FILE *file = OpenBlockFile(pos.nFile, pos.nPos, "rb");
            if (!file)
                break; // This error is logged in OpenBlockFile
            LogPrintf("Reindexing block file blk%04u.dat...\n", (unsigned int)nFile);
            LoadExternalBlockFile(file, &pos);
            nFile++;
        }
        fReindex = false;
        LogPrintf("Reindexing finished\n");
    }

    if (gArgs.IsArgSet("-loadblock"))
    {
        uiInterface.InitMessage(_("<b>Importing blockchain data file.</b>"));

        for (const std::string& strFile : gArgs.GetArgs("-loadblock")) {
            FILE *file = fopen(strFile.c_str(), "rb");
            if (file)
                LoadExternalBlockFile(file);
        }
        StartShutdown();
    }

    filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (filesystem::exists(pathBootstrap)) {
        uiInterface.InitMessage(_("<b>Importing bootstrap blockchain data file.</b>"));

        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LoadExternalBlockFile(file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        }
    }

    // ********************************************************* Step 11: start node

    RandAddSeedPerfmon();

    // debug print
    LogPrintf("mapBlockIndex.size() = %" PRIszu "\n",   mapBlockIndex.size());
    LogPrintf("chainActive.Height() = %d\n",                     chainActive.Height());
    LogPrintf("setKeyPool.size() = %" PRIszu "\n",      pwalletMain->setKeyPool.size());
    LogPrintf("mapWallet.size() = %" PRIszu " transactions\n",       pwalletMain->mapWallet.size());
    LogPrintf("mapAddressBook.size() = %" PRIszu "\n",  pwalletMain->mapAddressBook.size());

    if (!CheckDiskSpace())
        return false;

    if (gArgs.GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION))
        StartTorControl(threadGroup, scheduler);

    Discover(threadGroup);

    // Map ports with UPnP
    MapPort(gArgs.GetBoolArg("-upnp", DEFAULT_UPNP));

    CConnman::Options connOptions;
    connOptions.nLocalServices = nLocalServices;
    connOptions.nRelevantServices = nRelevantServices;
    connOptions.nMaxConnections = nMaxConnections;
    connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);
    connOptions.nMaxAddnode = MAX_ADDNODE_CONNECTIONS;
    connOptions.nMaxFeeler = 1;
    connOptions.nBestHeight = chainActive.Height();
    connOptions.uiInterface = &uiInterface;
    connOptions.m_msgproc = peerLogic.get();
    connOptions.nSendBufferMaxSize = 1000*gArgs.GetArg("-maxsendbuffer", DEFAULT_MAXSENDBUFFER);
    connOptions.nReceiveFloodSize = 1000*gArgs.GetArg("-maxreceivebuffer", DEFAULT_MAXRECEIVEBUFFER);

    connOptions.nMaxOutboundTimeframe = nMaxOutboundTimeframe;
    connOptions.nMaxOutboundLimit = nMaxOutboundLimit;

    LogPrintf("Max connection = %d\n", connOptions.nMaxConnections);
    LogPrintf("Max outbound connection = %d\n", connOptions.nMaxOutbound);

    for (const std::string& strBind : gArgs.GetArgs("-bind")) {
        CService addrBind;
        if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false)) {
            return InitError(ResolveErrMsg("bind", strBind));
        }
        connOptions.vBinds.push_back(addrBind);
    }
    for (const std::string& strBind : gArgs.GetArgs("-whitebind")) {
        CService addrBind;
        if (!Lookup(strBind.c_str(), addrBind, 0, false)) {
            return InitError(ResolveErrMsg("whitebind", strBind));
        }
        if (addrBind.GetPort() == 0) {
            return InitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
        }
        connOptions.vWhiteBinds.push_back(addrBind);
    }

    for (const auto& net : gArgs.GetArgs("-whitelist")) {
        CSubNet subnet;
        LookupSubNet(net.c_str(), subnet);
        if (!subnet.IsValid())
            return InitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
        connOptions.vWhitelistedRange.push_back(subnet);
    }

    if (gArgs.IsArgSet("-seednode")) {
        connOptions.vSeedNodes = gArgs.GetArgs("-seednode");
    }

    if (!connman.Start(scheduler, connOptions)) {
        return false;
    }

    if (!NewThread(StartNode, NULL))
        InitError(_("Error: could not start node"));

    if (fServer)
        NewThread(ThreadRPCServer, NULL);

    // ********************************************************* Step 12: finished

    uiInterface.InitMessage(_("<b>Done loading</b>"));
    LogPrintf("Done loading\n");

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

    //Yassert( false );   //test
#ifdef _MSC_VER
    #ifdef _DEBUG
        LogPrintf("\a\n" );    // just to call me back after a long debug startup!
    #endif
#endif
     // Add wallet transactions that aren't already in a block to mapTransactions
    pwalletMain->ReacceptWalletTransactions();

#if !defined(QT_GUI)
    // Loop until process is exit()ed from shutdown() function,
    // called from ThreadRPCServer thread when a "stop" command is received.
    while (1)
    {
        Sleep(5 * 1000);
        if(fExit)
            break;
    }
#endif
    return true;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
