// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_IRC_H
 #include "irc.h"
#endif

#ifndef BITCOIN_DB_H
 #include "db.h"
#endif

#ifndef BITCOIN_NET_H
 #include "net.h"
#endif

#ifndef BITCOIN_INIT_H
 #include "init.h"
#endif

#ifndef BITCOIN_STRLCPY_H
 #include "strlcpy.h"
#endif

#ifndef NOVACOIN_MINER_H
 #include "miner.h"
#endif

#include <vector>
#ifdef WIN32
#include <string.h>
#endif

#ifdef USE_UPNP
#include <miniupnpc/miniupnpc.h>
//#include <miniwget.h> 
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

using namespace boost;

using std::map;
using std::string;
using std::runtime_error;
using std::vector;
using std::deque;
using std::max;
using std::min;
using std::pair;
using std::list;
using std::set;

const unsigned int 
    nStakeMaxAge = 90 * nSecondsPerDay,             //60 * 60 * 24 * 90; // 90 days as full weight
    nOnedayOfAverageBlocks = (nSecondsPerDay / nStakeTargetSpacing)/10;  // the old 144
    //nOnedayOfAverageBlocks = nSecondsPerDay / nStakeTargetSpacing;  // should be 144 if it's BTC!
unsigned int 
    nStakeMinAge = 30 * nSecondsPerDay,             //60 * 60 * 24 * 30; // 30 days as zero time weight
    nStakeTargetSpacing = 1 * nSecondsperMinute,    //1 * 60; // 1-minute stake spacing
// MODIFIER_INTERVAL: time to elapse before new modifier is computed
//extern unsigned int nModifierInterval;
    nModifierInterval = 6 * nSecondsPerHour;        //6 * 60 * 60; 
                        // time (in seconds????)to elapse before new modifier is computed
                        // i.e 6 hours?????
                        // or is the INTENT 360 blocks??????????????????
                        // another way to put it is, WHAT ARE THE UNITS, seconds or blocks??????????
                        // so I guess it IS seconds, actually 6 hours.

static const int 
#ifdef WIN32
    nDEFAULT_BAN_SCORE = 1000,
    nDEFAULT_BAN_TIME_in_seconds = 3 * nSecondsperMinute;
#else
    nDEFAULT_BAN_SCORE = 100,
    nDEFAULT_BAN_TIME_in_seconds = nHoursPerDay * nSecondsPerHour;  // one day
#endif

// WM - static const int MAX_OUTBOUND_CONNECTIONS = 8;
static const int DEFAULT_MAX_CONNECTIONS        = 125;    // WM - Default value for -maxconnections= parameter.
static const int MIN_CONNECTIONS                = 8;      // WM - Lowest value we allow for -maxconnections= (never ever set less than 2!).
static const int MAX_CONNECTIONS                = 1000;   // WM - Max allowed value for -maxconnections= parameter.  Getting kinda excessive, eh?

static const int DEFAULT_OUTBOUND_CONNECTIONS   = 8;      // WM - Reasonable default of 8 outbound connections for -maxoutbound= parameter.
static const int MIN_OUTBOUND_CONNECTIONS       = 4;      // WM - Lowest we allow for -maxoutbound= parameter shall be 4 connections (never ever set below 2).
static const int MAX_OUTBOUND_CONNECTIONS       = 100;    // WM - This no longer means what it used to.  Outbound conn count now runtime configurable.
//static const int MAX_OUTBOUND_CONNECTIONS = 16;

void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);
void ThreadOpenConnections2(void* parg);
void ThreadOpenAddedConnections2(void* parg);
#ifdef USE_UPNP
//void ThreadMapPort2(void* parg);
#endif
void ThreadDNSAddressSeed2(void* parg);

struct LocalServiceInfo {
    int nScore;
    int nPort;
};

//
// Global state variables
//
bool fClient = false;
bool fDiscover = true;
bool fUseUPnP = false;
::uint64_t nLocalServices = (fClient ? 0 : NODE_NETWORK);
static CCriticalSection cs_mapLocalHost;
static map<CNetAddr, LocalServiceInfo> mapLocalHost;
static bool vfReachable[NET_MAX] = {};
static bool vfLimited[NET_MAX] = {};
static CNode* pnodeLocalHost = NULL;
static CNode* pnodeSync = NULL;
CAddress addrSeenByPeer(CService("0.0.0.0", 0), nLocalServices);
::uint64_t nLocalHostNonce = 0;
boost::array<int, THREAD_MAX> vnThreadsRunning;
static std::vector<SOCKET> vhListenSocket;
CAddrMan addrman;

vector<CNode*> vNodes;
vector<std::string> vAddedNodes;
map<CInv, CDataStream> mapRelay;
map<CInv, ::int64_t> mapAlreadyAskedFor;
deque<pair< ::int64_t, CInv> > vRelayExpiration;
static deque<string> vOneShots;
set<CNetAddr> setservAddNodeAddresses;

CCriticalSection cs_vNodes;
CCriticalSection cs_mapRelay;
CCriticalSection cs_vOneShots;
CCriticalSection cs_setservAddNodeAddresses;
CCriticalSection cs_vAddedNodes;

static CSemaphore *semOutbound = NULL;

void AddOneShot(string strDest)
{
    LOCK(cs_vOneShots);
    vOneShots.push_back(strDest);
}

unsigned short GetListenPort()
{
    return (unsigned short)(GetArg("-port", GetDefaultPort()));
}

int GetMaxConnections()
{
    int count;

    // Config'eth away..
    count = GetArg( "-maxconnections", DEFAULT_MAX_CONNECTIONS );
    
    // Ensure some level of sanity amount the max connection count.
    count = max( count, MIN_CONNECTIONS );
    count = min( count, MAX_CONNECTIONS );
    
    //printf( "GetMaxConnections() = %d\n", count );

    return count;
}

static int GetMaxOutboundConnections()
{
    int count;

    // What sayeth the config parameters?
    count = GetArg( "-maxoutbound", DEFAULT_OUTBOUND_CONNECTIONS );
    
    // Did someone set it too low or too high?  Shame, shame..
    count = max( count, MIN_OUTBOUND_CONNECTIONS );
    count = min( count, MAX_OUTBOUND_CONNECTIONS );
    count = min( count, GetMaxConnections() );

    //printf( "GetMaxOutboundConnections() = %d\n", count );
    
    return count;
}

void CNode::PushGetBlocks(CBlockIndex* pindexBegin, uint256 hashEnd)
{
    // Filter out duplicate requests
    if (pindexBegin == pindexLastGetBlocksBegin && hashEnd == hashLastGetBlocksEnd)
        return;
    pindexLastGetBlocksBegin = pindexBegin;
    hashLastGetBlocksEnd = hashEnd;

    PushMessage("getblocks", CBlockLocator(pindexBegin), hashEnd);
}

// find 'best' local address for a particular peer
bool GetLocal(CService& addr, const CNetAddr *paddrPeer)
{
    if (fNoListen)
        return false;

    int nBestScore = -1;
    int nBestReachability = -1;
    {
        LOCK(cs_mapLocalHost);
        for (
            map<CNetAddr, LocalServiceInfo>::iterator it = mapLocalHost.begin(); 
            it != mapLocalHost.end(); 
            ++it
            )
        {
            int nScore = (*it).second.nScore;
            int nReachability = (*it).first.GetReachabilityFrom(paddrPeer);
            if (
                (nReachability > nBestReachability) || 
                ((nReachability == nBestReachability) && (nScore > nBestScore))
               )
            {
                addr = CService((*it).first, (*it).second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return nBestScore >= 0;
}

// get best local address for a particular peer as a CAddress
CAddress GetLocalAddress(const CNetAddr *paddrPeer)
{
    CAddress ret(CService("0.0.0.0",0),0);
    CService addr;
    if (GetLocal(addr, paddrPeer))
    {
        ret = CAddress(addr);
        ret.nServices = nLocalServices;
        ret.nTime = GetAdjustedTime();
    }
    return ret;
}

void
    clearLocalSocketError( SOCKET hSocket )
{
#ifdef WIN32
    int
        nRet,
        nRetSize = sizeof( nRet );
    if ( SOCKET_ERROR == getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (char*)(&nRet), &nRetSize) )
    {
        printf(
                "getsockopt( SO_ERROR ) failed with error code = %i\n",
                WSAGetLastError()
              );
    }
#else
    // now all the clearLocalSocketError can be unguarded
#endif
}

bool RecvLine(SOCKET hSocket, string& strLine)
{
    strLine = "";
    while (true)
    {
        char c;
        int nBytes = recv(hSocket, &c, 1, 0);
        if (nBytes > 0)
        {
            if (c == '\n')
                continue;
            if (c == '\r')
                return true;
            strLine += c;
            if (strLine.size() >= 9000)
                return true;
        }
        else if (nBytes <= 0)
        {
            if (fShutdown)
                return false;
            if (nBytes < 0)
            {
                int 
                    nErr = WSAGetLastError();

                if (nErr == WSAEMSGSIZE)
                {
                    continue;
                }
                if (
                    (nErr == WSAEWOULDBLOCK) || 
                    (nErr == WSAEINTR) || 
                    (nErr == WSAEINPROGRESS)
                   )
                {
                    Sleep( nTenMilliseconds );      // needed? Or not? Why? How much? Calculated how? Guess?
                    continue;
                }
            }
            if (!strLine.empty())
                return true;
            if (nBytes == 0)
            {
                // socket closed
                printf("socket closed\n");
                return false;
            }
            else
            {
                // socket error
                int 
                    nErr = WSAGetLastError();

                printf("recv failed: %d\n", nErr);
                clearLocalSocketError( hSocket );
                return false;
            }
        }
    }
}

// used when scores of local addresses may have changed
// pushes better local address to peers
void static AdvertizeLocal()
{
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if (pnode->fSuccessfullyConnected)
        {
            CAddress addrLocal = GetLocalAddress(&pnode->addr);
            if (
                addrLocal.IsRoutable() && 
                ((CService)addrLocal != (CService)pnode->addrLocal)
               )
            {
                pnode->PushAddress(addrLocal);
                pnode->addrLocal = addrLocal;
            }
        }
    }
}

void SetReachable(enum Network net, bool fFlag)
{
    LOCK(cs_mapLocalHost);
    vfReachable[net] = fFlag;
    if (net == NET_IPV6 && fFlag)
        vfReachable[NET_IPV4] = true;
}

// learn a new local address
bool AddLocal(const CService& addr, int nScore)
{
    if (!addr.IsRoutable())
        return false;

    if (
        !fDiscover && 
        (nScore < LOCAL_MANUAL)
       )
        return false;

    if (IsLimited(addr))
        return false;

    printf("AddLocal(%s,%i)\n", addr.ToString().c_str(), nScore);

    {
        LOCK(cs_mapLocalHost);

        bool 
            fAlready = (mapLocalHost.count(addr) > 0);

        LocalServiceInfo 
            &info = mapLocalHost[addr];

        if (
            (!fAlready) || 
            (nScore >= info.nScore)
           ) 
        {
            info.nScore = nScore + (fAlready ? 1 : 0);
            info.nPort = addr.GetPort();
        }
        SetReachable(addr.GetNetwork());
    }

    AdvertizeLocal();

    return true;
}

bool AddLocal(const CNetAddr &addr, int nScore)
{
    return AddLocal(CService(addr, GetListenPort()), nScore);
}

/** Make a particular network entirely off-limits (no automatic connects to it) */
void SetLimited(enum Network net, bool fLimited)
{
    if (net == NET_UNROUTABLE)
        return;
    LOCK(cs_mapLocalHost);
    vfLimited[net] = fLimited;
}

bool IsLimited(enum Network net)
{
    LOCK(cs_mapLocalHost);
    return vfLimited[net];
}

bool IsLimited(const CNetAddr &addr)
{
    return IsLimited(addr.GetNetwork());
}

/** vote for a local address */
bool SeenLocal(const CService& addr)
{
    {
        LOCK(cs_mapLocalHost);
        if (mapLocalHost.count(addr) == 0)
            return false;
        mapLocalHost[addr].nScore++;
    }

    AdvertizeLocal();

    return true;
}

/** check whether a given address is potentially local */
bool IsLocal(const CService& addr)
{
    LOCK(cs_mapLocalHost);
    return (mapLocalHost.count(addr) > 0);
}

/** check whether a given address is in a network we can probably connect to */
bool IsReachable(const CNetAddr& addr)
{
    LOCK(cs_mapLocalHost);

    enum Network 
        net = addr.GetNetwork();

    return (vfReachable[net] && !vfLimited[net]);
}

extern int GetExternalIPbySTUN(::uint64_t rnd, struct sockaddr_in *mapped, const char **srv);

// We now get our external IP from the IRC server first and only use this as a backup
bool GetMyExternalIP(CNetAddr& ipRet)
{
    struct sockaddr_in 
        mapped;

    ::uint64_t 
        rnd = GetRand(~0LL);

    const char 
        *srv;

    int 
        rc = GetExternalIPbySTUN(rnd, &mapped, &srv);

    if(rc >= 0) 
    {
        ipRet = CNetAddr(mapped.sin_addr);
        printf("GetExternalIPbySTUN(%" PRIu64 ") returned %s in attempt %d; Server=%s\n", 
                rnd, 
                ipRet.ToStringIP().c_str(), 
                rc, 
                srv
              );
        return true;
    }
    return false;
}

void ThreadGetMyExternalIP(void* parg)
{
    // Make this thread recognisable as the external IP detection thread
    RenameThread("yacoin-ext-ip");

    CNetAddr 
        addrLocalHost;

    if (GetMyExternalIP(addrLocalHost))
    {
        printf("GetMyExternalIP() returned %s\n", addrLocalHost.ToStringIP().c_str());
        AddLocal(addrLocalHost, LOCAL_HTTP);
    }
}





void AddressCurrentlyConnected(const CService& addr)
{
    addrman.Connected(addr);
}




::uint64_t 
    CNode::nTotalBytesRecv = 0;
::uint64_t 
    CNode::nTotalBytesSent = 0;
CCriticalSection 
    CNode::cs_totalBytesRecv;
CCriticalSection 
    CNode::cs_totalBytesSent;

static CNode* FindNode(const CNetAddr& ip)
{
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if ((CNetAddr)pnode->addr == ip)
            return (pnode);
    }
    return NULL;
}

static CNode* FindNode(std::string addrName)
{
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if (pnode->addrName == addrName)
            return (pnode);
    }
    return NULL;
}

static CNode* FindNode(const CService& addr)
{
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if ((CService)pnode->addr == addr)
            return (pnode);
    }
    return NULL;
}

CNode* ConnectNode(CAddress addrConnect, const char *pszDest, ::int64_t nTimeout)
{
    if (pszDest == NULL) 
    {
        if (IsLocal(addrConnect))
            return NULL;

        // Look for an existing connection
        CNode
            * pnode = FindNode((CService)addrConnect);

        if (pnode)
        {
            if (nTimeout != 0)
                pnode->AddRef(nTimeout);
            else
                pnode->AddRef();
            return pnode;
        }
    }


    /// debug print
    if (fDebug)
    {
        printf( "trying connection " );
        if( pszDest )
        {
            printf( "%s\n", pszDest );
        }
        else
        {
            printf( "%s\n", 
                strprintf( " %s, last seen = %s",
                           addrConnect.ToString().c_str(),
                           ((double)(GetAdjustedTime() - addrConnect.nTime)/3600.0 > 24)?
                           "days":
                           strprintf( "%.1lfhrs", 
                                      (double)(GetAdjustedTime() - addrConnect.nTime)/3600.0
                                    ).c_str()
                         ).c_str()
                  );
            //printf( "%s lastseen=%.1fhrs\n", addrConnect.ToString().c_str(), (double)(GetAdjustedTime() - addrConnect.nTime)/3600.0 > 24 );
        }
    }
    // Connect
    SOCKET hSocket;
    if (
        pszDest ? ConnectSocketByName(
                                      addrConnect, 
                                      hSocket, 
                                      pszDest, 
                                      GetDefaultPort()
                                     ) : ConnectSocket(addrConnect, hSocket)
       )
    {
        addrman.Attempt(addrConnect);

        /// debug print
        printf("connected %s\n", pszDest ? pszDest : addrConnect.ToString().c_str());

        // Set to non-blocking
#ifdef WIN32
        u_long nOne = 1;
        if (SOCKET_ERROR == ioctlsocket(hSocket, FIONBIO, &nOne) )
        {
            printf("ConnectSocket() : ioctlsocket non-blocking setting failed, error %d\n", 
                    WSAGetLastError()
                  );
            clearLocalSocketError( hSocket );
        }
#else
        if (fcntl(hSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
            printf("ConnectSocket() : fcntl non-blocking setting failed, error %d\n", errno);
#endif

        // Add node
        CNode
            * pnode = new CNode(hSocket, addrConnect, pszDest ? pszDest : "", false);

        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();

        {{
            LOCK(cs_vNodes);
            vNodes.push_back(pnode);
        }}

        pnode->nTimeConnected = GetTime();
        return pnode;
    }
    else
    {
        return NULL;
    }
}

#ifdef WIN32
//_____________________________________________________________________________
char* iGetLastErrorText(DWORD nErrorCode)
{
    char* msg;
    // Ask Windows to prepare a standard message for a GetLastError() code:
    if( 
        FormatMessageA(
                       FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                        FORMAT_MESSAGE_FROM_SYSTEM | 
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, 
                        nErrorCode, 
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
                        (LPSTR)&msg, 
                        0, 
                        NULL
                      )
      ) // OK
    {
        return(msg);
    }
    else
    {
        return(char *)("Error failed to deliver text????\n");
    }
}
//_____________________________________________________________________________
#endif
void CNode::CloseSocketDisconnect()
{
    fDisconnect = true;
    if (hSocket != INVALID_SOCKET)
    {
        int
            nErr = closesocket(hSocket);

        printf( 
                "disconnecting node %s", 
                addrName.c_str()
              );
        if( nErr )
        {   // close socket errored!
            nErr = WSAGetLastError();
#ifdef WIN32
            char
                *pc = iGetLastErrorText( nErr );

            switch( nErr )
            {
                case WSANOTINITIALISED:
                    //A successful WSAStartup call must occur before using this function.

                case WSAENETDOWN:
                    //The network subsystem has failed.

                case WSAENOTSOCK:   //<<<<<<<<<<
                    //The descriptor is not a socket.

                case WSAEINPROGRESS:
                    //A blocking Windows Sockets 1.1 call is in progress, or 
                    //the service provider is still processing a callback function.

                case WSAEINTR:
                    //The (blocking) Windows Socket 1.1 call was canceled through WSACancelBlockingCall.

                case WSAEWOULDBLOCK:
                    //The socket is marked as nonblocking, but the l_onoff
                    //member of the linger structure is                     :

                    printf( "(%s)", pc );
                    break;
                default:
                    break;
            }
#endif
        }
        printf( "\n" );
        clearLocalSocketError( hSocket );
        hSocket = INVALID_SOCKET;
        vRecv.clear();
    }

    // in case this fails, we'll empty the recv buffer when the CNode is deleted
    TRY_LOCK(cs_vRecv, lockRecv);
    if (lockRecv)
        vRecv.clear();

    // if this was the sync node, we'll need a new one
    if (this == pnodeSync)
        pnodeSync = NULL;
}

void CNode::Cleanup()
{
}


void CNode::PushVersion()
{
    /// when NTP implemented, change to just nTime = GetAdjustedTime()
    ::int64_t 
        nTime = (fInbound ? GetAdjustedTime() : GetTime());

    CAddress 
        addrYou, 
        addrMe;

    bool 
        fHidden = false;

    if (addr.IsTor()) 
    {
        if (mapArgs.count("-torname")) 
        {
            // Our hidden service address
            CService addrTorName(mapArgs["-torname"], GetListenPort());

            if (addrTorName.IsValid()) 
            {
                addrYou = addr;
                addrMe = CAddress(addrTorName);
                fHidden = true;
            }
        }
    }

    if (!fHidden) 
    {
        addrYou = (
                    addr.IsRoutable() && !IsProxy(addr) ? 
                    addr : 
                    CAddress( CService("0.0.0.0",0) )
                  );
        addrMe = GetLocalAddress( &addr );
    }

    RAND_bytes((unsigned char*)&nLocalHostNonce, sizeof(nLocalHostNonce));
    printf(
            "send version message: "
            "version %d, blocks=%d, us=%s, them=%s, peer=%s\n", 
            PROTOCOL_VERSION, 
            nBestHeight, 
            addrMe.ToString().c_str(), 
            addrYou.ToString().c_str(), 
            addr.ToString().c_str()
          );
    PushMessage(
                "version", 
                PROTOCOL_VERSION, 
                nLocalServices, 
                nTime, addrYou, 
                addrMe,
                nLocalHostNonce, 
                FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, std::vector<string>()), 
                nBestHeight
               );
}





std::map<CNetAddr, ::int64_t> 
    CNode::setBanned;

CCriticalSection 
    CNode::cs_setBanned;

void CNode::ClearBanned()
{
    setBanned.clear();
}

bool CNode::IsBanned(CNetAddr ip)
{
    bool fResult = false;
    {
        LOCK(cs_setBanned);

        std::map<CNetAddr, ::int64_t>::iterator 
            i = setBanned.find(ip);

        if (i != setBanned.end())
        {
            ::int64_t t = (*i).second;
            if (GetTime() < t)
                fResult = true;
        }
    }
    return fResult;
}

bool CNode::Misbehaving(int howmuch)    // banned if banscore  exceeeded
{
    if (addr.IsLocal())
    {
        printf("Warning: Local node %s misbehaving (delta: %d)!\n", addrName.c_str(), howmuch);
        return false;
    }

    nMisbehavior += howmuch;
    printf("Misbehaving: %s (%d -> %d)",
            addr.ToString().c_str(), 
            nMisbehavior-howmuch, 
            nMisbehavior
           );
    if (nMisbehavior >= GetArg("-banscore", nDEFAULT_BAN_SCORE))
    {
      //::int64_t banTime = GetTime()+GetArg("-bantime", 60*60*24);  // Default 24-hour ban
                                        //YOU CAN MAKE THIS CLEAR WITHOUT A COMMENT!!

        ::int64_t banTime = GetTime()+GetArg("-bantime", nDEFAULT_BAN_TIME_in_seconds);

        printf( " DISCONNECTING" );
        {
            LOCK(cs_setBanned);
            if (setBanned[addr] < banTime)
                setBanned[addr] = banTime;
        }
        CloseSocketDisconnect();
        return true;
    }
    printf( "\n" );
    return false;
}

#undef X
#define X(name) stats.name = name
void CNode::copyStats(CNodeStats &stats)
{
    X(nServices);
    X(nLastSend);
    X(nLastRecv);
    X(nTimeConnected);
    X(addrName);
    X(nVersion);
    X(strSubVer);
    X(fInbound);
    X(nReleaseTime);
    X(nStartingHeight);
    X(nMisbehavior);
    X(nSendBytes);
    X(nRecvBytes);
    stats.fSyncNode = (this == pnodeSync);
}
#undef X










void ThreadSocketHandler(void* parg)
{
    // Make this thread recognisable as the networking thread
    RenameThread("yacoin-net");

    try
    {
        ++vnThreadsRunning[THREAD_SOCKETHANDLER];
        ThreadSocketHandler2(parg);
        --vnThreadsRunning[THREAD_SOCKETHANDLER];
    }
    catch (std::exception& e) 
    {
        --vnThreadsRunning[THREAD_SOCKETHANDLER];
        PrintException(&e, "ThreadSocketHandler()");
    } 
    catch (...) 
    {
        --vnThreadsRunning[THREAD_SOCKETHANDLER];
        throw; // support pthread_cancel()
    }
    printf("ThreadSocketHandler exited\n");
}

static void updatePreviousNodecountIf( 
                                      vector<CNode*> & vNodes, 
                                      unsigned int & nPrevNodeCount
                                     )
{
    if (vNodes.size() != nPrevNodeCount)
    {
        unsigned int
            nNewSize = (unsigned int)vNodes.size();
        string
            sWhichWay = "";
        if( nPrevNodeCount > nNewSize ) // going down
            sWhichWay = "down";
        if( nPrevNodeCount < nNewSize ) // going up
            sWhichWay = "up";

#ifdef _MSC_VER
        (void)printf(
                    "\n"
                    "connection count %s from %d to %d"
                    "\n"
                    "\n"
                    "", 
                    sWhichWay.c_str(),
                    nPrevNodeCount, 
                    nNewSize
                   );
#endif
        nPrevNodeCount = nNewSize;
        uiInterface.NotifyNumConnectionsChanged(nNewSize);
//MB_OK                 0x00000000L The sound specified as the Windows Default Beep sound.
//MB_ICONSTOP           0x00000010L See MB_ICONERROR.
//MB_ICONERROR          0x00000010L The sound specified as the Windows Critical Stop sound.
//MB_ICONHAND           0x00000010L See MB_ICONERROR.
//MB_ICONQUESTION       0x00000020L The sound specified as the Windows Question sound.
//MB_ICONWARNING        0x00000030L The sound specified as the Windows Exclamation sound.
//MB_ICONEXCLAMATION    0x00000030L See MB_ICONWARNING.
//MB_ICONINFORMATION    0x00000040L The sound specified as the Windows Asterisk sound.
//MB_ICONASTERISK       0x00000040L See MB_ICONINFORMATION.
//                      0xFFFFFFFF  A simple beep. If the sound card is not available, the sound is generated using the speaker.
        // unsigned int
            // nUpSound = MB_ICONINFORMATION,
            // nDownSound = MB_ICONERROR;
        if( "down" == sWhichWay )
        {
            //(void)MessageBeep( nDownSound );
        }
        else
        {
            //(void)MessageBeep( nUpSound );
        }
        if( "down" == sWhichWay )
        {
            if(
               (0 == nNewSize) 
               //|| 
               //(1 == nNewSize) 
              )
            {   // things are pretty bleak, so we could shut down and restart?
                // just while we are testing
#ifdef _MSC_VER
    #ifdef _DEBUG
                //StartShutdown();
    #else
                //StartShutdown();
    #endif
#endif
            }
        }
    }
}


void ThreadSocketHandler2(void* parg)
{
    printf("ThreadSocketHandler2 started\n");

    list<CNode*> 
        vNodesDisconnected;

    unsigned int 
        nPrevNodeCount = 0;
    //const int
        //nOneMinuteInSeconds = 60,  //nSecondsperMinute
        //nOneMillisecond = 1,    //
        //nTenMilliseconds = 10,
        //nOneHundredMilliseconds = 100;
    while (true)
    {
        if( fDebug )
            (void)printf( "ThreadSocketHandler2 is looping"
                          "\n"
                        );
        //
        // Disconnect nodes
        //
        {{
            LOCK(cs_vNodes);    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<  seems OK
            // Disconnect unused nodes
            vector<CNode*> 
                vNodesCopy = vNodes;

            BOOST_FOREACH(CNode* pnode, vNodesCopy)
            {
                if (
                    pnode->fDisconnect ||
                    (
                     pnode->GetRefCount() <= 0 && 
                     pnode->vRecv.empty() && 
                     pnode->vSend.empty()
                    )
                   )
                {   // remove from vNodes using the standard C++ idiom          
                    vNodes.erase(                 
                                 remove(  
                                        vNodes.begin(), 
                                        vNodes.end(), 
                                        pnode
                                       )
                                       , 
                                 vNodes.end()
                                )
                                  ;

                    // release outbound grant (if any)
                    pnode->grantOutbound.Release();

                    pnode->CloseSocketDisconnect();
                    pnode->Cleanup();

                    // hold in disconnected pool until all refs are released
                    pnode->nReleaseTime = max(
                                              pnode->nReleaseTime, 
                                              GetTime() + (15 * nOneMinuteInSeconds)   // Is it 15 minutes???
                                                                    // If so, WHY?????????
                                             );

                    if (                        // what is this testing for, and WHY????
                        pnode->fNetworkNode || 
                        pnode->fInbound
                       )
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
            //Sleep( nOneMillisecond ); //Sleep( nOneHundredMilliseconds );
            }

            // Delete disconnected nodes
            list<CNode*> vNodesDisconnectedCopy = vNodesDisconnected;
            BOOST_FOREACH(CNode* pnode, vNodesDisconnectedCopy)
            {
                // wait until threads are done using it
                if (pnode->GetRefCount() <= 0)
                {
                    bool fDelete = false;
                    {
                        TRY_LOCK(pnode->cs_vSend, lockSend);
                        if (lockSend)
                        {
                            TRY_LOCK(pnode->cs_vRecv, lockRecv);
                            if (lockRecv)
                            {
                                TRY_LOCK(pnode->cs_mapRequests, lockReq);
                                if (lockReq)
                                {
                                    TRY_LOCK(pnode->cs_inventory, lockInv);
                                    if (lockInv)
                                        fDelete = true;
                                }
                            }
                        }
                    }
                    if (fDelete)
                    {
                        vNodesDisconnected.remove(pnode);
                        delete pnode;
                    }
                }
            //Sleep( nOneMillisecond ); //Sleep( nOneHundredMilliseconds );
            }
            updatePreviousNodecountIf( vNodes, nPrevNodeCount );
        }}   // end of LOCK(cs_vNodes)

        //
        // Find which sockets have data to receive
        //
        const int
            n50msInMicroseconds = 50000;
        struct timeval 
            timeout;

        timeout.tv_sec  = 0;
        timeout.tv_usec = n50msInMicroseconds; // frequency to poll pnode->vSend
                        // Isn't this the period, not the frequency?
                        // and why 50,000

        fd_set fdsetRecv;   // an array of 64 sockets!
        fd_set fdsetSend;
        fd_set fdsetError;

        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        SOCKET 
            hSocketMax = 0;
        bool 
            have_fds = false;

        BOOST_FOREACH(SOCKET hListenSocket, vhListenSocket) 
        {
            FD_SET(hListenSocket, &fdsetRecv);
            hSocketMax = max(hSocketMax, hListenSocket);
            have_fds = true;
        }
        {
            LOCK(cs_vNodes);    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
            BOOST_FOREACH(CNode* pnode, vNodes)
            {
                if (pnode->hSocket == INVALID_SOCKET)
                    continue;
                FD_SET(pnode->hSocket, &fdsetRecv);
                FD_SET(pnode->hSocket, &fdsetError);
                hSocketMax = max(hSocketMax, pnode->hSocket);
                have_fds = true;
                {
                    TRY_LOCK(pnode->cs_vSend, lockSend);
                    if (lockSend && !pnode->vSend.empty())
                        FD_SET(pnode->hSocket, &fdsetSend);
                }
            Sleep( nOneMillisecond ); //nTenMilliseconds );  // try this instead of //Sleep( nOneHundredMilliseconds );
            }
        }

        --vnThreadsRunning[THREAD_SOCKETHANDLER];
        int 
            nSelect = select(
                             have_fds ? hSocketMax + 1 : 0,
                             &fdsetRecv, 
                             &fdsetSend, 
                             &fdsetError, 
                             &timeout
                            );
        ++vnThreadsRunning[THREAD_SOCKETHANDLER];
        if (fShutdown)
            return;
        if (nSelect == SOCKET_ERROR)
        {
            if (have_fds)
            {
                int 
                    nErr = WSAGetLastError();
                printf("socket select error %d\n", nErr);

                for (unsigned int i = 0; i <= hSocketMax; ++i)
                    FD_SET(i, &fdsetRecv);
            }
            FD_ZERO(&fdsetSend);
            FD_ZERO(&fdsetError);
            Sleep(timeout.tv_usec/nMillisecondsPerSecond);    // what is this sleep amount & what is it for??????
        }

        //
        // Accept new connections
        //
        BOOST_FOREACH(SOCKET hListenSocket, vhListenSocket)
        {
            if (hListenSocket != INVALID_SOCKET && FD_ISSET(hListenSocket, &fdsetRecv))
            {
#ifdef USE_IPV6
                struct sockaddr_storage sockaddr;
#else
                struct sockaddr sockaddr;
#endif
                socklen_t 
                    len = sizeof(sockaddr);

                SOCKET 
                    hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);

                CAddress 
                    addr;

                if (hSocket != INVALID_SOCKET)
                {
                    if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr))
                        printf("Warning: Unknown socket family\n");
                }

                int 
                    nInbound = 0;       // does this mean false? Or something else??

                {
                    LOCK(cs_vNodes);    //this one seems OK <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        if (pnode->fInbound)
                            ++nInbound;
                }

                if (hSocket == INVALID_SOCKET)
                {
                    int 
                        nErr = WSAGetLastError();

                    if (nErr != WSAEWOULDBLOCK)
                    {
                        printf("socket error accept failed: %d\n", nErr);
                        clearLocalSocketError( hSocket );
                    }
                }
                else
                {
                  //if (nInbound >= GetArg("-maxconnections", 125) - MAX_OUTBOUND_CONNECTIONS)
                    if ( nInbound >= GetMaxConnections() - GetMaxOutboundConnections() )
                    {
                        {
                            LOCK(cs_setservAddNodeAddresses);
                            if (!setservAddNodeAddresses.count(addr))
                                closesocket(hSocket);
                        }
                    }
                    else
                    {
                        if (CNode::IsBanned(addr))
                        {
                            printf("connection from %s dropped (banned)\n", addr.ToString().c_str());
                            closesocket(hSocket);
                        }
                        else
                        {
                            printf("accepted connection %s\n", addr.ToString().c_str());
                            CNode* pnode = new CNode(hSocket, addr, "", true);
                            pnode->AddRef();
                            {
                                LOCK(cs_vNodes);    //this one seems OK <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                                vNodes.push_back(pnode);
                                updatePreviousNodecountIf( vNodes, nPrevNodeCount );
                            }
                        }
                    }
                }
            }
        }
        //
        // Service each socket
        //
        vector<CNode*> 
            vNodesCopy;
        {{
            LOCK(cs_vNodes);    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
            vNodesCopy = vNodes;
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
            {
                pnode->AddRef();
                //Sleep( nOneMillisecond );   //nOneHundredMilliseconds );
            }
        }}
        BOOST_FOREACH(CNode* pnode, vNodesCopy)
        {
            if (fShutdown)
                return;

            //
            // Receive
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (
                FD_ISSET(pnode->hSocket, &fdsetRecv) || 
                FD_ISSET(pnode->hSocket, &fdsetError)
               )
            {
                TRY_LOCK(pnode->cs_vRecv, lockRecv);
                if (lockRecv)
                {
                    LOCK(cs_vNodes);
        
                    CDataStream
                        & vRecv = pnode->vRecv;

                    ::uint64_t 
                        nPos = vRecv.size();

                    if (nPos > ReceiveBufferSize()) 
                    {
                        if (!pnode->fDisconnect)
                            printf("socket recv flood control disconnect (%" PRIszu " bytes)\n", 
                                    vRecv.size()
                                  );
                        pnode->CloseSocketDisconnect();
                    }
                    else 
                    {
                        // typical socket buffer is 8K-64K
                        char 
                            pchBuf[0x10000];   // so what is this, 64K??? WHY??

                        int 
                            nBytes = recv(pnode->hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);

                        if (nBytes > 0)
                        {
                            vRecv.resize(nPos + nBytes);
                            memcpy(&vRecv[nPos], pchBuf, nBytes);
                            pnode->nLastRecv = GetTime();
                            pnode->nRecvBytes += nBytes;
                            pnode->RecordBytesRecv(nBytes);
                        }
                        else
                        {
                            if (nBytes == 0)
                            {   // socket closed gracefully
                                if (!pnode->fDisconnect)
                                    printf("socket closed\n");
                                pnode->CloseSocketDisconnect();
                            }
                            else
                            {
                                if (nBytes < 0) // MUST THIS BE THE CASE????
                                {   // error
                                    if( SOCKET_ERROR != nBytes )
                                    {
                                        // now here we have something really interesting!
                                        printf("socket recv return error code %d\n", nBytes);
                                    }
                                    int 
                                        nErr = WSAGetLastError();

                                    if (
                                        nErr != WSAEWOULDBLOCK && 
                                                    //The socket is marked as nonblocking and the 
                                                    //receive operation would block.

                                        nErr != WSAEMSGSIZE && 
                                                    //The message was too large to fit into the 
                                                    //specified buffer and was truncated.

                                        nErr != WSAEINTR && 
                                                    //The (blocking) call was canceled through 
                                                    //WSACancelBlockingCall.

                                        nErr != WSAEINPROGRESS
                                                    //A blocking Windows Sockets 1.1 call 
                                                    //is in progress, or the service provider 
                                                    //is still processing a callback function.
                                       )
                                    {
                                        if (!pnode->fDisconnect)    //socket recv error 10054
                                        {
#ifdef WIN32
                                            printf(
                                                    "socket recv error %d (%s)\n", 
                                                    nErr
                                                    , iGetLastErrorText( nErr )
                                                  ); //<<<<<<<<<<<<<<<<<< this was the only unguarded
                                            // these are the error codes that cause a disconnect
                                            switch( nErr )
                                            {
                                                case WSANOTINITIALISED:
                                                    //A successful WSAStartup call must occur 
                                                    //before using this function.

                                                case WSAENETDOWN:
                                                    //The network subsystem has failed.

                                                case WSAEFAULT:
                                                    //The buf parameter is not completely contained in a 
                                                    //valid part of the user address space.

                                                case WSAENOTCONN:
                                                    //The socket is not connected.

                                                case WSAENETRESET:
                                                    //For a connection-oriented socket, 
                                                    //this error indicates that the connection 
                                                    //has been broken due to keep-alive activity 
                                                    //that detected a failure while the operation 
                                                    //was in progress. For a datagram socket, 
                                                    //this error indicates that the time to live 
                                                    //has expired.

                                                case WSAENOTSOCK:   //<<<<<<<<
                                                    //The descriptor is not a socket.

                                                case WSAEOPNOTSUPP:
                                                    //MSG_OOB was specified, but the socket 
                                                    //is not stream-style such as type SOCK_STREAM, 
                                                    //OOB data is not supported in the communication 
                                                    //domain associated with this socket, 
                                                    //or the socket is unidirectional and supports 
                                                    //only send operations.

                                                case WSAESHUTDOWN:
                                                    //The socket has been shut down; it is not 
                                                    //possible to receive on a socket after shutdown 
                                                    //has been invoked with how set to SD_RECEIVE 
                                                    //or SD_BOTH.

                                                case WSAEINVAL:
                                                    //The socket has not been bound with bind, 
                                                    //or an unknown flag was specified, 
                                                    //or MSG_OOB was specified for a socket 
                                                    //with SO_OOBINLINE enabled or (for byte 
                                                    //stream sockets only) len was zero or negative.

                                                case WSAECONNABORTED:
                                                    //The virtual circuit was terminated due to 
                                                    //a time-out or other failure. The application 
                                                    //should close the socket as it is no longer usable.

                                                case WSAETIMEDOUT:
                                                    //The connection has been dropped because of a 
                                                    //network failure or because the peer system 
                                                    //failed to respond.

                                                case WSAECONNRESET:
                                                    //The virtual circuit was reset by 
                                                    //the remote side executing a hard or 
                                                    //abortive close. The application should 
                                                    //close the socket as it is no longer usable. 
                                                    //On a UDP-datagram socket, this error would 
                                                    //indicate that a previous send operation 
                                                    //resulted in an ICMP "Port Unreachable" message.

                                                    // this is an error that does happen

                                                    break;
                                                default:
                                                    break;
                                            }
#endif
                                        }
                                        pnode->CloseSocketDisconnect();
                                    }
                                    // the implication here is
                                    //else
                                    //{
                                    //    continue as if nothing happened?

                                    // these are the error codes that cause a disconnect
                                    /***************************
                                    WSANOTINITIALISED //A successful WSAStartup call must occur 
                                                      //before using this function.
                                    
                                    WSAENETDOWN //The network subsystem has failed.

                                    WSAEFAULT   //The buf parameter is not completely contained in a 
                                                //valid part of the user address space.

                                    WSAENOTCONN //The socket is not connected.


                                    WSAENETRESET    //For a connection-oriented socket, 
                                                    //this error indicates that the connection 
                                                    //has been broken due to keep-alive activity 
                                                    //that detected a failure while the operation 
                                                    //was in progress. For a datagram socket, 
                                                    //this error indicates that the time to live 
                                                    //has expired.

                                    WSAENOTSOCK     //The descriptor is not a socket. <<<<<<<<<<<

                                    WSAEOPNOTSUPP   //MSG_OOB was specified, but the socket 
                                                    //is not stream-style such as type SOCK_STREAM, 
                                                    //OOB data is not supported in the communication 
                                                    //domain associated with this socket, 
                                                    //or the socket is unidirectional and supports 
                                                    //only send operations.

                                    WSAESHUTDOWN    //The socket has been shut down; it is not 
                                                    //possible to receive on a socket after shutdown 
                                                    //has been invoked with how set to SD_RECEIVE 
                                                    //or SD_BOTH.

                                    WSAEINVAL       //The socket has not been bound with bind, 
                                                    //or an unknown flag was specified, 
                                                    //or MSG_OOB was specified for a socket 
                                                    //with SO_OOBINLINE enabled or (for byte 
                                                    //stream sockets only) len was zero or negative.

                                    WSAECONNABORTED //The virtual circuit was terminated due to 
                                                    //a time-out or other failure. The application 
                                                    //should close the socket as it is no longer usable.

                                    WSAETIMEDOUT    //The connection has been dropped because of a 
                                                    //network failure or because the peer system 
                                                    //failed to respond.

                                    WSAECONNRESET   //The virtual circuit was reset by 
                                                    //the remote side executing a hard or 
                                                    //abortive close. The application should 
                                                    //close the socket as it is no longer usable. 
                                                    //On a UDP-datagram socket, this error would 
                                                    //indicate that a previous send operation 
                                                    //resulted in an ICMP "Port Unreachable" message.
                                    ***************************/
                                    //}
                                }
                            }
                        }
                    }
                }
            }

            //
            // Send
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(pnode->hSocket, &fdsetSend))
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                {
                    LOCK(cs_vNodes);

                    CDataStream& vSend = pnode->vSend;
                    if (!vSend.empty())
                    {
                        int nBytes = send(pnode->hSocket, &vSend[0], vSend.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
                        if (nBytes > 0)
                        {
                            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                            pnode->nLastSend = GetTime();
                            pnode->nSendBytes += nBytes;
                            pnode->RecordBytesSent(nBytes);
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();
                            if (
                                (nErr != WSAEWOULDBLOCK) && 
                                (nErr != WSAEMSGSIZE) && 
                                (nErr != WSAEINTR) && 
                                (nErr != WSAEINPROGRESS)
                               )
                            {
                                printf("socket send error %d\n", nErr);
                                clearLocalSocketError( pnode->hSocket );
                                pnode->CloseSocketDisconnect();
                            }
                        }
                    }
                }
            }

            //
            // Inactivity checking
            //
            {
                LOCK(cs_vNodes);

                if (pnode->vSend.empty())
                    pnode->nLastSendEmpty = GetTime();
              //if ((GetTime() - pnode->nTimeConnected) > 60) // what is this here? Seconds??  Why???
                if ((GetTime() - pnode->nTimeConnected) > 3 * nOneMinuteInSeconds) // test<<<<<<<<<<< try 3 minutes
                {
                    if (pnode->nLastRecv == 0 || pnode->nLastSend == 0)
                    {
                        printf("socket no message in first 60 seconds, %d %d\n", 
                               pnode->nLastRecv != 0, 
                               pnode->nLastSend != 0
                              );
                        pnode->fDisconnect = true;
                    }
                    else
                    {
                        if (
                            GetTime() - pnode->nLastSend > (90 * 60) &&     // OK, what are these magic #s???
                            GetTime() - pnode->nLastSendEmpty > (90 * 60)   // "
                            )
                        {
                            printf("socket not sending\n");
                            pnode->fDisconnect = true;
                        }
                        else 
                        {
                            if (GetTime() - pnode->nLastRecv > (90 * 60))  // is this 90 minutes?
                            {
                                printf("socket inactivity timeout\n");
                                pnode->fDisconnect = true;
                            }
                        }
                    }
                }
            }
        }
        {{
            LOCK(cs_vNodes);    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
            {
                pnode->Release();
                //Sleep( nOneMillisecond );   //nOneHundredMilliseconds );
            }
        }}

      //Sleep( nOneMillisecond );  // let's try some other value? 
      //Sleep( nTenMilliseconds );  // is this 10 ms required? A guess? 
                    // Related to some other constant? Or variable?...???
        Sleep( 2* nMillisecondsPerSecond ); 
    }
}

#ifdef USE_UPNP
void ThreadMapPort2(void* parg)
{
    printf("ThreadMapPort started\n");

    std::string port = strprintf("%u", GetListenPort());
    const char * multicastif = 0;
    const char * minissdpdpath = 0;
    struct UPNPDev * devlist = 0;
    char lanaddr[64];

#ifndef UPNPDISCOVER_SUCCESS
    /* miniupnpc 1.5 */
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0);
#else
    /* miniupnpc 1.6 */
    int error = 0;
    devlist = upnpDiscover(2000, multicastif, minissdpdpath, 0, 0, &error);
#endif

    struct UPNPUrls urls;
    struct IGDdatas data;
    int r;

    r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if (r == 1)
    {
        if (fDiscover) {
            char externalIPAddress[40];
            r = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, externalIPAddress);
            if(r != UPNPCOMMAND_SUCCESS)
                printf("UPnP: GetExternalIPAddress() returned %d\n", r);
            else
            {
                if(externalIPAddress[0])
                {
                    printf("UPnP: ExternalIPAddress = %s\n", externalIPAddress);
                    AddLocal(CNetAddr(externalIPAddress), LOCAL_UPNP);
                }
                else
                    printf("UPnP: GetExternalIPAddress failed.\n");
            }
        }

        string strDesc = "Yacoin " + FormatFullVersion();
#ifndef UPNPDISCOVER_SUCCESS
        /* miniupnpc 1.5 */
        r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                            port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0);
#else
        /* miniupnpc 1.6 */
        r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                            port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0, "0");
#endif

        if(r!=UPNPCOMMAND_SUCCESS)
            printf("AddPortMapping(%s, %s, %s) failed with code %d (%s)\n",
                port.c_str(), port.c_str(), lanaddr, r, strupnperror(r));
        else
            printf("UPnP Port Mapping successful.\n");
        int i = 1;
        while (true)
        {
            if (fShutdown || !fUseUPnP)
            {
                r = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port.c_str(), "TCP", 0);
                printf("UPNP_DeletePortMapping() returned : %d\n", r);
                freeUPNPDevlist(devlist); devlist = 0;
                FreeUPNPUrls(&urls);
                return;
            }
            if (i % 600 == 0) // Refresh every 20 minutes
            {
#ifndef UPNPDISCOVER_SUCCESS
                /* miniupnpc 1.5 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0);
#else
                /* miniupnpc 1.6 */
                r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
                                    port.c_str(), port.c_str(), lanaddr, strDesc.c_str(), "TCP", 0, "0");
#endif

                if(r!=UPNPCOMMAND_SUCCESS)
                    printf("AddPortMapping(%s, %s, %s) failed with code %d (%s)\n",
                        port.c_str(), port.c_str(), lanaddr, r, strupnperror(r));
                else
                    printf("UPnP Port Mapping successful.\n");;
            }
            Sleep(2000);
            i++;
        }
    } else {
        printf("No valid UPnP IGDs found\n");
        freeUPNPDevlist(devlist); devlist = 0;
        if (r != 0)
            FreeUPNPUrls(&urls);
        while (true)
        {
            if (fShutdown || !fUseUPnP)
                return;
            Sleep(2000);
        }
    }
}

void ThreadMapPort(void* parg)
{
    // Make this thread recognisable as the UPnP thread
    RenameThread("yacoin-UPnP");

    try
    {
        vnThreadsRunning[THREAD_UPNP]++;
        ThreadMapPort2(parg);
        vnThreadsRunning[THREAD_UPNP]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_UPNP]--;
        PrintException(&e, "ThreadMapPort()");
    } catch (...) {
        vnThreadsRunning[THREAD_UPNP]--;
        PrintException(NULL, "ThreadMapPort()");
    }
    printf("ThreadMapPort exited\n");
}


void MapPort()
{
    if (fUseUPnP && vnThreadsRunning[THREAD_UPNP] < 1)
    {
        if (!NewThread(ThreadMapPort, NULL))
            printf("Error: ThreadMapPort(ThreadMapPort) failed\n");
    }
}
#else
void MapPort()
{
    // Intentionally left blank.
}
#endif

// DNS seeds
// Each pair gives a source name and a seed name.
// The first name is used as information source for addrman.
// The second name should resolve to a list of seed addresses.

// YACOIN TODO NEED TO IMPLEMENT
static const char *strDNSSeed[][2] = {
#ifdef _MSC_VER
    "", ""
#else
    //{"yacoin.org", "seed.yacoin.org"},
#endif    //{"yacoin.org", "seed.yacoin.org"},
};

void ThreadDNSAddressSeed(void* parg)
{
    // Make this thread recognisable as the DNS seeding thread
    RenameThread("yacoin-dnsseed");

    try
    {
        ++vnThreadsRunning[THREAD_DNSSEED];
        ThreadDNSAddressSeed2(parg);
        --vnThreadsRunning[THREAD_DNSSEED];
    }
    catch (std::exception& e) 
    {
        --vnThreadsRunning[THREAD_DNSSEED];
        PrintException(&e, "ThreadDNSAddressSeed()");
    } 
    catch (...) 
    {
        --vnThreadsRunning[THREAD_DNSSEED];
        throw; // support pthread_cancel()
    }
    printf("ThreadDNSAddressSeed exited\n");
}

void ThreadDNSAddressSeed2(void* parg)
{
    printf("ThreadDNSAddressSeed2 started\n");
    int found = 0;

    if (!fTestNet)
    {
        printf("Loading addresses from DNS seeds (could take a while)\n");
        
        size_t
            Length = ARRAYLEN(strDNSSeed);

      //for (unsigned int seed_idx = 0; seed_idx < ARRAYLEN(strDNSSeed); seed_idx++) 
        for (unsigned int seed_idx = 0; seed_idx < Length; ++seed_idx) 
        {
            if (HaveNameProxy()) 
            {
                AddOneShot(strDNSSeed[seed_idx][1]);
            } 
            else 
            {
                vector<CNetAddr> vaddr;
                vector<CAddress> vAdd;
                if (LookupHost(strDNSSeed[seed_idx][1], vaddr))
                {
                    BOOST_FOREACH(CNetAddr& ip, vaddr)
                    {
                        int nOneDay = 24*3600;
                        CAddress addr = CAddress(CService(ip, GetDefaultPort()));
                        addr.nTime = GetTime() - 3*nOneDay - GetRand(4*nOneDay); // use a random age between 3 and 7 days old
                        vAdd.push_back(addr);
                        ++found;
                    }
                }
                addrman.Add(vAdd, CNetAddr(strDNSSeed[seed_idx][0], true));
            }
        }
    }

    printf("%d addresses found from DNS seeds\n", found);
}











//YACOIN TODO update seeds
::uint32_t pnSeed[] =
{
    0x555b7158, 0x8ef3dfdd, 0x276a5248, 0xcda67076, 0x36c4515f, 0x4ad54bb8, 0x913e884f, 0x3829c6c3,
    0x78fda1d8, 0xc0d97550, 0x1cd138b7, 0xb9e18377, 0x18407076, 0x028b77b6, 0xb2e3344e, 0xc0fd6605,
    0xa42a7d0e, 0x666e8e71, 0xbddf4bda, 0xe7d1d3d5, 0x228f02af, 0x36485e71, 0x132a1418, 0x30375665,
    0x72c0e662, 0x31542551, 0x9ed1dd0e, 0xb285f355, 0x75815e31, 0x555b21be, 0x376b045e, 0x0f04a4cd,
    0x7cc4a17b, 0x1b82e5c5, 0x77037b70, 0xadeb856c, 0x64e1fdb2, 0x360460d0, 0x363c03da, 0x357de072,
    0x6519d25b, 0xd894437a, 0x33f1c851, 0x0c3c0a2e, 0x475a565d, 0xb163526e, 0xd3857247, 0x93b3fa76,
    0x0c267977, 0xd640bccf, 0x15b057cb, 0x6f782942, 0x15e4d4de, 0x03720205, 0xbcd1048e, 0x0242d80c,
    0xc2f25a75, 0x09e13aad, 0x5b8c587a, 0x6851995a, 0x9deaf7de, 0x93508bae, 0x71cd32c3, 0xe9eb856c,
    0x6783223b, 0x4aba54c6, 0xe4abbfde, 0x4c4e03b7, 0x1ee0fd74, 0x2b382753, 0x63218977, 0x9ab8cd71,
    0x2a8703b9, 0xfa75ae52, 0xcefe4771, 0x026ea2dc, 0x02754e4d, 0x6a2dd53a, 0x5dabf2de, 0x0cb08dca,
    0x99798459, 0x1d2e597c, 0xa430203b, 0x64c34b25, 0x237ab751, 0x2616a371, 0x4a41a17b, 0x7f954d5c,
    0x85d62678, 0x519659ba, 0x22d2aa43, 0x256b7277, 0x97d8f1c0, 0xa487e15f, 0xcd4dbb25, 0xfda65b71,
    0xe04f303a, 0xbd14e559, 0x2e99940e, 0xf8b7f805, 0x155baf43, 0x6aede65e, 0xcc5620c4, 0xc830c373,
    0x663ede0e, 0x483f2c4f, 0x5c1ebd71, 0x542cdc5d, 0xfb959a0e, 0xbcab5a75, 0x5eff3956, 0xfaee8951,
    0x550689db, 0x994986b6, 0x568710b2, 0x2e6d3f73, 0x6ef9f8b7, 0x21bf1a75, 0x5ce0304e, 0x25774ebc,
    0x50adb6d4, 0x207d565d, 0x5862af89, 0xd2934a5c, 0x98fc1bae, 0x3f544e58, 0x6552d85e, 0x059bcbda,
    0x4175d972, 0x34d4c875, 0x2b0ae662, 0x7e9aa971, 0x8d63a570, 0xe070543e, 0x5489cc62, 0x3a63bbc0,
    0x82ab8ddb, 0x6557cf79, 0xa67a2444, 0x804cf16e, 0x225b865d, 0x8c5f56be, 0x7f1a6f57, 0xc8064f5f,
    0xf22f347a, 0x9f212477, 0xa371fe96, 0x4686f9ad, 0x98ad4f5f, 0x899dafaf, 0x019acdbb, 0x235c48de,
    0xb71ee044, 0xc2e76456, 0x534ba171, 0x8e0b7a7d, 0x856f1c79, 0x20f1ca01, 0x452ce08c, 0x028987d1,
    0xc41de563, 0xd148657b, 0x532a412e, 0x0fe0036c, 0xe933d773, 0x99e7507d, 0x3611f170, 0x74a77076,
    0x48d8566a, 0xb7d8fa76, 0x18fc4771, 0xe84ef27a, 0x305a8177, 0x2bfbae6f, 0xf5c1e854, 0xc31060b7,
    0x8f06974f, 0x7b466817, 0xdd81f371, 0x9a0ca7b7, 0xaecfa405, 0x7715bd1b, 0x2206e42e, 0x13089b6e,
    0x803bbc71, 0x5cef293b, 0xe46ecb45, 0xde215771, 0xa6ed3fda, 0x692d65b6, 0x85c27254, 0x6ee32e53,
    0xd4b121b2, 0xb4004ea6, 0xba67c454, 0x42779a42, 0xe58e19bc, 0x9bb8216e, 0x6eb54105, 0x1184e079,
    0x759610b7, 0x8918597b, 0x2b6cadb4, 0x464717c6, 0xf6caa8b4, 0x54e4b2de, 0xbfe9b8b2, 0x5da925b7,
    0xe34699bb, 0xde171fbc, 0xd6643074, 0x49a6b777, 0x4ec50ec3, 0x61704cde, 0xd09ffa76, 0x897f8932,
    0xc5ac9b6e, 0x0207d8ab, 0x9428dfb2, 0xdc7c47b7, 0x6450357b, 0x8ce677b0, 0xa769a75d, 0xa64a02b7,
    0x03dfd85e, 0xdc60a6df, 0x98167c40, 0x1cdbe77a, 0xcfd0a52e, 0xf4a2f17a, 0x9c1981b6, 0xc1cb10b7,
    0xa078a6dc, 0x05353705, 0xca1df4dc, 0x1dc982b6, 0xe4cfbd41, 0xf18f6bbc, 0x31a9d074, 0x442c5d71,
    0xa63a4d6f, 0x6a353677, 0xddbe4205, 0x4234135f, 0xcc84aac1, 0x53a55cb7, 0x58791779, 0x7b77557d,
    0xfef6147b, 0xea7f4abe, 0x67ef07dd, 0xef63554d, 0x780bf37a, 0xe93a1c75, 0x0415203b, 0x570f3e54,
    0x7105b03c, 0x5bf45ec3, 0xa6e250b7, 0x469938da, 0x5962293b, 0xab16e47c, 0x08c0835d, 0xd37fe97a,
    0x462b7857, 0xbb46f37a, 0x7747e55c, 0xea01da0e, 0xd115d03a, 0xbb9ab777, 0xeb2f6b0e, 0xea53b64d,
    0xa2cf11da, 0xd2888ab6, 0xe83a624e, 0xa7208c3d, 0xcacbbc56, 0x92275bdf, 0xfee3c07a, 0xbc934558,
    0xe5ce8777, 0x05d75971, 0x6edc512a, 0xc5070165, 0x26083905, 0x0ebd9f6e, 0x44a956d9, 0x7f5f930e,
    0x6ba694af, 0x7cf29773, 0x9b545378, 0x2a36b977, 0x24202477, 0x0151014d, 0x18534b3d, 0x5a54047a,
    0x414ab776, 0x9619345c, 0x92065e71, 0x8e4ad5ab, 0xa95c735d, 0xabe4a93e, 0x04644e48, 0x2372a9b4,
    0x4d81a84f, 0xc5d76672, 0x88eaa6cb, 0xe052e774, 0x172fca78, 0x3cfe9d9f, 0xebb40b53, 0x169c557d,
    0xab7a1f50, 0x3f21ac42, 0x51d8ec97, 0x2c51e662, 0xc43602bc, 0x91e7be71, 0xaf88f402, 0x5222b03c,
    0x67939d4f, 0x35f09562, 0xb986e45c, 0x98752f3b, 0xa3b3143c, 0x6c04ff62, 0x48902db7, 0xa83659c7,
    0x75378529, 0x33be5971, 0xf9c2304e, 0x80ee8472, 0x5fb30db7, 0xba55b2dc, 0x7af86bb6, 0x378b0b6c,
    0x71c0fcde, 0xc8609cd5, 0x1068ed8d, 0xa3ee517a, 0x3ab213b2, 0x47c7eb7a, 0xd652f460, 0x696994b6,
    0x79b0c373, 0x21e40d5e, 0xb4756171, 0xca4aed8d, 0x2ac04959, 0x21fc2e24, 0xe7bc7f3b, 0xd5f70b79,
    0xa82b77d9, 0xee2219bc, 0xbe26d36e, 0xae43aa7c, 0x80237da3, 0xbd505224, 0xfcbde570, 0x5e35ec02,
    0x54f564bc, 0xc1a6026a, 0x6ec0255b, 0xc7e91c41, 0x6a09314e, 0x3785f7be, 0x7b044565, 0x50ce51bc,
    0x37c48c3d, 0x51a30fb7, 0x91ed273a, 0x8f4a5302, 0xe3692d05, 0xbc431274, 0xbdecc3be, 0x3d3e1dc2,
    0x6754d85e, 0xb39ff42e, 0xc2d64bb8, 0xfe78ce73, 0xc0c5f9b7, 0x8fee5d7b, 0xe7fa715c, 0x948017b2,
    0x2a6c8ade, 0x98dfe062, 0x657aa17b, 0xee61fc5e, 0xeb3e754a, 0x3af33f6c, 0x56684b5c, 0x159d50b7,
    0xee389b3d, 0x3511be6d, 0xecd3147b, 0x22c6515f, 0xc766a23d, 0x5c731732, 0x50ff3365, 0x8eca7552,
    0xe5aa40b6, 0x3effe37a, 0x152e9673, 0x9ff2c36e, 0x5cb1d41b, 0x255d7777, 0xb786df80, 0xbceba971,
    0x6602acd5, 0x5738ff77, 0x0ec805d4, 0x0b340070, 0x2dda0356, 0xc394a555, 0x1dbf0a70, 0x1acc5361,
    0xef93bf58, 0x916fd90e, 0x68303bb7, 0x667c7fce, 0x08c39e4e, 0xa18f5d71, 0x19b12a1f, 0xe6a42d4e,
    0x291c9b0e, 0x296a366c, 0x62a8fe3a, 0x6f8e5ebc, 0x171c5e17, 0x9cf5cbbe, 0x9d28ce59, 0x12d572d9,
    0xe62bc573, 0xdac86bca, 0x1434b2b4, 0x9256cb51, 0x6d476870, 0xda10e27a, 0x07d00477, 0xbe5f6176,
    0x021f67bc, 0xc9a90cb7, 0x1006a84b, 0x7d24ce5c, 0x82543cbe, 0x1083b0c9, 0x3c73705e, 0x51348dd1,
    0x27beba3d, 0x1373373b, 0xd94f51bc, 0x2f180070, 0xea36d33a, 0x901b27ab, 0xc3294fb2, 0x20764e5b,
    0x25640353, 0x149f495c, 0x9164d550, 0x4a33767d, 0x7890d31b, 0x2bf12a4e, 0xe5aa69b8, 0x70731732,
    0x5687fe05, 0x9a3dda47, 0x6964e87a, 0xa2368d29, 0xf1932845, 0xd0f0ce79, 0x5e0a5e70, 0x462b0574,
    0x8f2839da, 0xa25c8753, 0x869f92db, 0xe47d15af, 0xe2324c71, 0x3e133501, 0x19f69e7b, 0xeedda048,
    0xc251da0e, 0xc3565545, 0x5d94e152, 0x1ecfd43e, 0xc84543d5, 0x321c5e70, 0xa2b5f74d, 0x28469473,
    0x9b2a5201, 0x81c6e977, 0x8c76724f, 0x05f5ec69, 0xce6fea7c, 0x6b7c39da, 0x09fdaa7b, 0xb006d080,
    0xb22cc2dd, 0xa032fb6e, 0xa7173805, 0x078b1654, 0xa260e26d, 0x10d5a57c, 0xdc260774, 0xc30d993d,
    0x7b104dde, 0x2fe4f972, 0x46e65dde, 0x8f18a07b, 0x3835bb57, 0x422c5e70, 0x2adf4bb8, 0xa56ad076,
    0xa31fd254, 0xccdee77a, 0x932cd073, 0xf6a74476, 0xa7a50558, 0xb8cadfb2, 0x9be19a5e, 0x44cc487c,
    0x8380187d, 0x09aae659, 0xd02bc136, 0x652c717d, 0x9f9dff6d, 0x618ced72, 0x047eb5dc, 0x82f0f071,
    0x37fed7de, 0xd4c4e273, 0x8fd1048e, 0x38810c7b, 0x916691c9, 0x8c3b3492, 0x0736b84f, 0x0d3f8dd1,
    0xb5e4d373, 0xfb02a277, 0x4d46a23c, 0x85883c01, 0xa2beea7a, 0xb8cda952, 0xfa6d4b5c, 0xf8a0df72,
    0xa799f0df, 0xee5e45de, 0xb7cb70ab, 0xd99a53bc, 0x7d8e684a, 0x0ded517a, 0xbb0c5e70, 0x5aa78cdb,
};

//YACOIN TODO 
const char* pchTorSeed[] = 
{
#ifdef _MSC_VER
    ""
#else
   // "needtoimplement.onion",
#endif
};

static void DumpAddresses()
{
    ::int64_t nStart = GetTimeMillis();

    CAddrDB adb;    // does a GetDataDir() in ctor for "peers.dat"
    adb.Write(addrman);

    if (fDebug)
        printf("Flushed %d addresses to peers.dat  %" PRId64 "ms\n",
               addrman.size(), 
               GetTimeMillis() - nStart
              );
}

void ThreadDumpAddress2(void* parg)
{
    ++vnThreadsRunning[THREAD_DUMPADDRESS];
    while (!fShutdown)
    {
        if( fDebug )
            (void)printf( "ThreadDumpAddress2 is looping"
                         "\n"
                        );
        DumpAddresses();
        --vnThreadsRunning[THREAD_DUMPADDRESS];
        Sleep(1 * nSecondsperMinute * nMillisecondsPerSecond);  // try this arbitrary value
        ++vnThreadsRunning[THREAD_DUMPADDRESS];
    }
    --vnThreadsRunning[THREAD_DUMPADDRESS];
}

void ThreadDumpAddress(void* parg)
{
    // Make this thread recognisable as the address dumping thread
    RenameThread("yacoin-adrdump");

    try
    {
        ThreadDumpAddress2(parg);
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadDumpAddress()");
    }
    printf("ThreadDumpAddress exited\n");
}

void ThreadOpenConnections(void* parg)
{
    // Make this thread recognisable as the connection opening thread
    RenameThread("yacoin-opencon");

    try
    {
        ++vnThreadsRunning[THREAD_OPENCONNECTIONS];
        ThreadOpenConnections2(parg);
        --vnThreadsRunning[THREAD_OPENCONNECTIONS];
    }
    catch (std::exception& e) 
    {
        --vnThreadsRunning[THREAD_OPENCONNECTIONS];
        PrintException(&e, "ThreadOpenConnections()");
    } 
    catch (...) 
    {
        --vnThreadsRunning[THREAD_OPENCONNECTIONS];
        PrintException(NULL, "ThreadOpenConnections()");
    }
    printf("ThreadOpenConnections exited\n");
}

void static ProcessOneShot()
{
    string strDest;
    {
        LOCK(cs_vOneShots);
        if (vOneShots.empty())
            return;
        strDest = vOneShots.front();
        vOneShots.pop_front();
    }
    CAddress 
        addr;
    CSemaphoreGrant 
        grant(*semOutbound, true);
    if (grant) 
    {
        if (!OpenNetworkConnection(addr, &grant, strDest.c_str(), true))
            AddOneShot(strDest);
    }
}

// ppcoin: stake minter thread
void static ThreadStakeMinter(void* parg)
{
    printf("ThreadStakeMinter started\n");
    CWallet* pwallet = (CWallet*)parg;
    try
    {
        ++vnThreadsRunning[THREAD_MINTER];
        StakeMinter(pwallet);
        --vnThreadsRunning[THREAD_MINTER];
    }
    catch (std::exception& e) 
    {
        --vnThreadsRunning[THREAD_MINTER];
        PrintException(&e, "ThreadStakeMinter()");
    } 
    catch (...) 
    {
        --vnThreadsRunning[THREAD_MINTER];
        PrintException(NULL, "ThreadStakeMinter()");
    }
    printf("ThreadStakeMinter exiting, %d threads remaining\n", vnThreadsRunning[THREAD_MINTER]);
}

void ThreadOpenConnections2(void* parg)
{
    printf("ThreadOpenConnections started\n");

    // Connect to specific addresses  How???

    // what does this do with this weird unbounded for loop, I wonder?
    // what did it intend to do???????????
    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0)
    {
        for (::int64_t nLoop = 0;; ++nLoop) // can overflow??
        {
            ProcessOneShot();
            BOOST_FOREACH(string strAddr, mapMultiArgs["-connect"])
            {
                CAddress 
                    addr;
              //OpenNetworkConnection(addr, NULL, strAddr.c_str());
                bool
                    fConnected;
                fConnected = OpenNetworkConnection(addr, NULL, strAddr.c_str());
                if( fConnected )
                {
                    printf(" connected\n");
                }
                else
                {
                    printf(" not connected\n");
                }
                for (int i = 0; (i < 10) && (i < nLoop); ++i)
                {
                    Sleep( 0 );
                  //Sleep( nOneMillisecond );
                  //Sleep(500);     // Again, what is the intent and requirement here, if any?
                  //Sleep(5 * nOneHundredMilliseconds);

                    if (fShutdown)
                        return;
                }
            }
          //Sleep(500);             // ditto
            //Sleep(5 * nOneHundredMilliseconds);
        }
    }

    // Initiate network connections
    ::int64_t nStart = GetTime();
    int
        nLoopCounter = 0;
    while (true)
    {
        if( fDebug )
        {
            if( 0== (++nLoopCounter % 10) )
                (void)printf(
                             "ThreadOpenConnections2 is looping"
                             "\n"
                            );
        }
        ProcessOneShot();

        --vnThreadsRunning[THREAD_OPENCONNECTIONS];
      //Sleep(500);                 // Is this by any chance(???) related to the above??? Or not????
        Sleep( nOneMillisecond );
      //Sleep(5 * nOneHundredMilliseconds);
        ++vnThreadsRunning[THREAD_OPENCONNECTIONS];
        if (fShutdown)
            return;


        --vnThreadsRunning[THREAD_OPENCONNECTIONS];
        CSemaphoreGrant grant(*semOutbound);
        ++vnThreadsRunning[THREAD_OPENCONNECTIONS];
        if (fShutdown)
            return;

        // Add seed nodes if IRC isn't working
        if (
            !IsLimited(NET_IPV4) && 
            addrman.size()==0 && 
            (GetTime() - nStart > 60) &&    // why 60? 60 what?
            !fTestNet
           )
        {
            std::vector<CAddress> vAdd;
            for (unsigned int i = 0; i < ARRAYLEN(pnSeed); ++i)
            {
                // It'll only connect to one or two seed nodes because once it connects,
                // it'll get a pile of addresses with newer timestamps.
                // Seed nodes are given a random 'last seen time' of between one and two
                // weeks ago.
                const 
                    ::int64_t nOneWeek = 7*24*60*60;    // in seconds I presume?????????????????????

                struct in_addr 
                    ip;

                memcpy(&ip, &pnSeed[i], sizeof(ip));

                CAddress addr(CService(ip, GetDefaultPort()));

                addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
                vAdd.push_back(addr);
            }
            addrman.Add(vAdd, CNetAddr("127.0.0.1"));
        }

        // Add Tor nodes if we have connection with onion router
        if (mapArgs.count("-tor"))
        {
            size_t
                Length = ARRAYLEN(pchTorSeed);

            std::vector<CAddress> vAdd;
         // for (unsigned int i = 0; i < ARRAYLEN(pchTorSeed); ++i)
            for (unsigned int i = 0; i < Length; ++i)
            {
                const ::int64_t nOneWeek = 7*24*60*60;
                CAddress addr(CService(pchTorSeed[i], GetDefaultPort()));
                addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
                vAdd.push_back(addr);
            }
            addrman.Add(vAdd, CNetAddr("dummyaddress.onion"));
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per network group (/16 for IPv4).
        // Do this here so we don't have to critsect vNodes inside mapAddresses critsect.
        int 
            nOutbound = 0;

        set<vector<unsigned char> > setConnected;
        {{
            LOCK(cs_vNodes);    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
            BOOST_FOREACH(CNode* pnode, vNodes) 
            {
                if (!pnode->fInbound) 
                {
                    setConnected.insert(pnode->addr.GetGroup());
                    ++nOutbound;
                }
            }
        }}

        ::int64_t 
            nANow = GetAdjustedTime();

        int 
            nTries = 0;

        while (true)
        {
            // use an nUnkBias between 10 (no outgoing connections) and 90 (8 outgoing connections)
            // meaning what exactly?????????????????????????????????????????????????

            CAddress addr = addrman.Select(10 + min(nOutbound,8)*10);   // meaning what?????

            // if we selected an invalid address, restart
            // restart what exactly, by breaking here?????????????????????????????????????????

            if (
                !addr.IsValid() || 
                setConnected.count(addr.GetGroup()) || 
                IsLocal(addr)
               )
                break;

            // If we didn't find an appropriate destination after trying 
            // 100 addresses fetched from addrman, stop this loop, 
            // and let the outer loop run again (which sleeps, adds 
            // seed nodes, recalculates already-connected network ranges, 
            // ...) before trying new addrman addresses.
            ++nTries;
            Sleep( nOneHundredMilliseconds );   //<<<<<<<<<<< test
            if (nTries > 100)
                break;  // can this leave addrConnect uninitialized??????

            if (IsLimited(addr))
                continue;

            // only consider very recently tried nodes after 30 failed attempts
            // define very recently????????????? 
            // what is the magic # 600????????????????????????
            // Is it ten minutes?????????????????????????
            // If so, why?????????????????????????????????

            if (
                nANow - addr.nLastTry < 600 && 
                nTries < 30
               )
                continue;

            // do not allow non-default ports, unless after 50 invalid addresses selected already
            // Better English, please?????????????????????????
            if (
                addr.GetPort() != GetDefaultPort() && 
                nTries < 50
               )
                continue;

            addrConnect = addr;
            break;
        }
        if (addrConnect.IsValid())
        {
            bool
                fConnected;
          //OpenNetworkConnection(addrConnect, &grant);
            fConnected = OpenNetworkConnection(addrConnect, &grant);
        }
        Sleep( 5 * nOneHundredMilliseconds );   //<<<<<<<<<<< test 1/2 second
    }
}

void ThreadOpenAddedConnections(void* parg)
{
    // Make this thread recognisable as the connection opening thread
    RenameThread("yacoin-open added connections started");

    try
    {
        ++vnThreadsRunning[THREAD_ADDEDCONNECTIONS];
        ThreadOpenAddedConnections2(parg);
        --vnThreadsRunning[THREAD_ADDEDCONNECTIONS];
    }
    catch (std::exception& e) 
    {
        --vnThreadsRunning[THREAD_ADDEDCONNECTIONS];
        PrintException(&e, "ThreadOpenAddedConnections()");
    } 
    catch (...) 
    {
        --vnThreadsRunning[THREAD_ADDEDCONNECTIONS];
        PrintException(NULL, "ThreadOpenAddedConnections()");
    }
    printf("ThreadOpenAddedConnections exited\n");
}

void ThreadOpenAddedConnections2(void* parg)
{
    printf("ThreadOpenAddedConnections2 started\n");

    {
        LOCK(cs_vAddedNodes);
        vAddedNodes = mapMultiArgs["-addnode"];
    }

    if (HaveNameProxy()) 
    {
        while(!fShutdown) 
        {
            list<string> lAddresses(0);
            {
                LOCK(cs_vAddedNodes);
                BOOST_FOREACH(string& strAddNode, vAddedNodes)
                    lAddresses.push_back(strAddNode);
            }
            BOOST_FOREACH(string& strAddNode, lAddresses) 
            {
                CAddress addr;
                CSemaphoreGrant grant(*semOutbound);
                bool
                    fConnected;
                fConnected = OpenNetworkConnection(addr, &grant, strAddNode.c_str());
              //Sleep(500);     // again, what, why, etc....?
                Sleep(5 * nOneHundredMilliseconds);
            }
            --vnThreadsRunning[THREAD_ADDEDCONNECTIONS];
          //Sleep(120000); // Retry every 2 minutes
                            // why??? Is this related to any other magic #?????????????????????????
            Sleep(2 * nSecondsperMinute * nMillisecondsPerSecond);
            ++vnThreadsRunning[THREAD_ADDEDCONNECTIONS];
        }
        return;
    }

    for (::uint32_t i = 0; true; ++i)   // for ever
    {
        if( fDebug )
            (void)printf(
                         "ThreadOpenAddedConnections2 is looping"
                         "\n"
                        );
        list<string> lAddresses(0);
        {
            LOCK(cs_vAddedNodes);
            BOOST_FOREACH(string& strAddNode, vAddedNodes)
                lAddresses.push_back(strAddNode);
        }

        list<vector<CService> > lservAddressesToAdd(0);
        BOOST_FOREACH(string& strAddNode, lAddresses)
        {
            vector<CService> vservNode(0);
            if (Lookup(strAddNode.c_str(), vservNode, GetDefaultPort(), fNameLookup, 0))
            {
                lservAddressesToAdd.push_back(vservNode);
                {
                    LOCK(cs_setservAddNodeAddresses);
                    BOOST_FOREACH(CService& serv, vservNode)
                        setservAddNodeAddresses.insert(serv);
                }
            }
        }
        // Attempt to connect to each IP for each addnode entry until at least one 
        // is successful per addnode entry (keeping in mind that addnode entries 
        // can have many IPs if fNameLookup)
        {{
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
            {
                for (list<vector<CService> >::iterator it = lservAddressesToAdd.begin(); 
                     it != lservAddressesToAdd.end(); 
                     //it++
                     ++it
                    )
                {
                    BOOST_FOREACH(CService& addrNode, *(it))
                    {
#ifndef _MSC_VER
                        if (pnode->addr == addrNode)
                        {
                            it = lservAddressesToAdd.erase(it);
                            if(it != lservAddressesToAdd.begin())
                                it--;
                            break;
                        }
                    }
#else
                        if (pnode->addr == addrNode)
                        {
                            it = lservAddressesToAdd.erase(it);
                            // now it gets tricky!
                            if( lservAddressesToAdd.empty() )
                                break;          // can't --it, nor ++it
                            // else it's not empty, so
                            if (it == lservAddressesToAdd.begin())
                                break;          // can't --it
                            --it;               // finally, a legal place!!    
                            break;
                        }
                        // else we stay in the inner BOOST_FOREACH() loop
                    }
                    if( lservAddressesToAdd.empty() )
                        break;      // can't do a ++it
#endif
                    if (it == lservAddressesToAdd.end())
                        break;
                }
            }
        }}
        BOOST_FOREACH(vector<CService>& vserv, lservAddressesToAdd)
        {
            if (vserv.size() == 0)
                continue;
            CSemaphoreGrant grant(*semOutbound);
            bool
                fConnected;

            fConnected = OpenNetworkConnection(CAddress(vserv[i % vserv.size()]), &grant);
            if (!fShutdown)
            {
              //Sleep(6 * nMillisecondsPerSecond);  // is this related to nConnectTimeout?
                Sleep( nConnectTimeout );  // just trying to get rid of these magic #s
            }
            else
            {
                return;
            }
        }
        if (fShutdown)
            return;
        else
        {
            --vnThreadsRunning[THREAD_ADDEDCONNECTIONS];
            if ( !fShutdown)
            {
                //Sleep(120000); // Retry every 2 minutes
                //Sleep(30 * nMillisecondsPerSecond); // let's try every 30 seconds
                Sleep( 2* nSecondsperMinute * nMillisecondsPerSecond);
            }
            ++vnThreadsRunning[THREAD_ADDEDCONNECTIONS];
        }
        if (fShutdown)
        {
            return;
        }
    }
}

// if successful, this moves the passed grant to the constructed node
bool OpenNetworkConnection(
                           const CAddress& addrConnect, 
                           CSemaphoreGrant *grantOutbound, 
                           const char *strDest, 
                           bool fOneShot
                          )
{
    //
    // Initiate outbound network connection
    //
    if (fShutdown)
        return false;
    if (!strDest)
    {
        if (IsLocal(addrConnect) ||
            FindNode((CNetAddr)addrConnect) || 
            CNode::IsBanned(addrConnect) ||
            FindNode(addrConnect.ToStringIPPort().c_str())
           )
            return false;
    }
    if (strDest && FindNode(strDest))
        return false;

    --vnThreadsRunning[THREAD_OPENCONNECTIONS];

    CNode
        * pnode = ConnectNode(addrConnect, strDest);

    ++vnThreadsRunning[THREAD_OPENCONNECTIONS];

    Sleep(5 * nOneHundredMilliseconds); //<<<<<<<<<<<<<<< test
    if (fShutdown)
        return false;
    if (!pnode)
        return false;
    if (grantOutbound)
        grantOutbound->MoveTo(pnode->grantOutbound);
    pnode->fNetworkNode = true;
    if (fOneShot)
        pnode->fOneShot = true;

    return true;
}

// for now, use a very simple selection metric: the node from which we received
// most recently
double static NodeSyncScore(const CNode *pnode) 
{
    return -pnode->nLastRecv;
}

void static StartSync(const vector<CNode*> &vNodes) 
{
    CNode *pnodeNewSync = NULL;
    double dBestScore = 0;

    {
        LOCK(cs_vNodes);    //this seems OK<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
        // Iterate over all nodes
        BOOST_FOREACH(CNode* pnode, vNodes) 
        {
            // check preconditions for allowing a sync
            if (!pnode->fClient && 
                !pnode->fOneShot &&
                !pnode->fDisconnect && 
                pnode->fSuccessfullyConnected &&
              //(pnode->nStartingHeight > (nBestHeight - 144)) &&   // within one day if BTC !!!???
                (pnode->nStartingHeight > (nBestHeight - (int)nOnedayOfAverageBlocks)) &&   // perhaps
                (
                 (pnode->nVersion < NOBLKS_VERSION_START) || // why <60002 || >= 60005
                 (pnode->nVersion >= NOBLKS_VERSION_END)    // why are 60002, 3, 4 taboo?
                )
               ) 
            {   // if ok, compare node's score with the best so far
                double dScore = NodeSyncScore(pnode);
                if (
                    pnodeNewSync == NULL || 
                    (dScore > dBestScore) 
                   )
                {
                    pnodeNewSync = pnode;
                    dBestScore = dScore;
                }
            }
        }
        // if a new sync candidate was found, start sync!
        if (pnodeNewSync) 
        {
            pnodeNewSync->fStartSync = true;
            pnodeSync = pnodeNewSync;
        }
    }
}

void ThreadMessageHandler(void* parg)
{
    // Make this thread recognisable as the message handling thread
    RenameThread("yacoin-msghand");

    try
    {
        ++vnThreadsRunning[THREAD_MESSAGEHANDLER];
        ThreadMessageHandler2(parg);
        --vnThreadsRunning[THREAD_MESSAGEHANDLER];
    }
    catch (std::exception& e) 
    {
        --vnThreadsRunning[THREAD_MESSAGEHANDLER];
        PrintException(&e, "ThreadMessageHandler()");
    } catch (...) 
    {
        --vnThreadsRunning[THREAD_MESSAGEHANDLER];
        PrintException(NULL, "ThreadMessageHandler()");
    }
    printf("ThreadMessageHandler exited\n");
}

void ThreadMessageHandler2(void* parg)
{
    printf("ThreadMessageHandler2 started\n");
    SetThreadPriority(THREAD_PRIORITY_BELOW_NORMAL);
    int
        nLoopCounter = 0;
    while (!fShutdown)
    {
        if( fDebug )
        {
               (void)printf(
                             "ThreadMessageHandler2 is looping"
                             "\n"
                            );
        }
        bool fHaveSyncNode = false;
        vector<CNode*> vNodesCopy;
        {
            {
            LOCK(cs_vNodes);    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                vNodesCopy = vNodes;
                BOOST_FOREACH(CNode* pnode, vNodesCopy) 
                {
                    pnode->AddRef();
                    if (pnode == pnodeSync)
                        fHaveSyncNode = true;
                }
            }
        }
/*******************
        if (!fHaveSyncNode)
            StartSync(vNodesCopy);
*******************/
        // Poll the connected nodes for messages
        CNode
            * pnodeTrickle = NULL;

        if (!vNodesCopy.empty())
            pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];

        BOOST_FOREACH(CNode* pnode, vNodesCopy)
        {   // Receive messages
            {
                TRY_LOCK(pnode->cs_vRecv, lockRecv);
                if (lockRecv)
                    ProcessMessages(pnode);
            }
            if (fShutdown)
            {
                if( fDebug )
                {
                    (void)printf(
                                 "ThreadMessageHandler2 is exiting(at 1)"
                                 "\n"
                                );
                }
                return;
            }
            // Send messages
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                    SendMessages(pnode, pnode == pnodeTrickle);
            }
            if (fShutdown)
            {
                if( fDebug )
                {
                    (void)printf(
                                 "ThreadMessageHandler2 is exiting(at 2)"
                                 "\n"
                                );
                }
                return;
            }
        }

        {
            {
            LOCK(cs_vNodes);    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
                BOOST_FOREACH(CNode* pnode, vNodesCopy)
                    pnode->Release();
            }
        }

        // Wait and allow messages to bunch up.
        // Reduce vnThreadsRunning so StopNode has permission to exit while
        // we're sleeping, but we must always check fShutdown after doing this.
        --vnThreadsRunning[THREAD_MESSAGEHANDLER];
        if (fRequestShutdown)
            StartShutdown();
        //Sleep( nOneHundredMilliseconds );         // again, ????
        ++vnThreadsRunning[THREAD_MESSAGEHANDLER];
        if (fShutdown)
        {
            if( fDebug )
            {
                (void)printf(
                             "ThreadMessageHandler2 is exiting(at 3)"
                             "\n"
                            );
            }
            return;
        }
        Sleep( 100 * nMillisecondsPerSecond );
    }
    if( fDebug )
    {
        (void)printf(
                     "ThreadMessageHandler2 is exiting"
                     "\n"
                    );
    }
}


bool BindListenPort(const CService &addrBind, string& strError)
{
    LOCK(cs_net);
    {
    strError = "";
    u_long
        nOne = 1;

#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA 
        wsadata;

    int 
        ret = WSAStartup(MAKEWORD(2,2), &wsadata);

    if (ret != NO_ERROR)
    {
        strError = strprintf("Error: TCP/IP socket library failed to start (WSAStartup returned error %d)", ret);
        printf("%s\n", strError.c_str());
        return false;
    }
#endif

    // Create socket for listening for incoming connections
#ifdef USE_IPV6
    struct sockaddr_storage sockaddr;
#else
    struct sockaddr sockaddr;
#endif
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr*)&sockaddr, &len))
    {
        strError = strprintf("Error: bind address family for %s not supported", 
                            addrBind.ToString().c_str()
                            );
        printf("%s\n", strError.c_str());
        return false;
    }

    SOCKET hListenSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %d)", 
                             WSAGetLastError()
                            );
        printf("%s\n", strError.c_str());
        clearLocalSocketError( hListenSocket );
        return false;
    }

#ifdef SO_NOSIGPIPE
    // Different way of disabling SIGPIPE on BSD
    setsockopt(hListenSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&nOne, sizeof(int));
#endif

#ifndef WIN32
    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.  Not an issue on windows.
    setsockopt(hListenSocket, SOL_SOCKET, SO_REUSEADDR, (void*)&nOne, sizeof(int));
#endif


#ifdef WIN32
    // Set to non-blocking, incoming connections will also inherit this
    if (ioctlsocket(hListenSocket, FIONBIO, &nOne) == SOCKET_ERROR)
#else
    if (fcntl(hListenSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
#endif
    {
        strError = strprintf("Error: Couldn't set properties on socket for incoming connections (error %d)", 
                            WSAGetLastError()
                            );
        printf("%s\n", strError.c_str());
        clearLocalSocketError( hListenSocket );
        return false;
    }

#ifdef USE_IPV6
    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (addrBind.IsIPv6()) 
    {
#ifdef IPV6_V6ONLY
#ifdef WIN32
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&nOne, sizeof(int));
#else
        setsockopt(hListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&nOne, sizeof(int));
#endif
#endif
#ifdef WIN32
        int nProtLevel = 10 /* PROTECTION_LEVEL_UNRESTRICTED */;
        int nParameterId = 23 /* IPV6_PROTECTION_LEVEl */;
        // this call is allowed to fail
        setsockopt(hListenSocket, IPPROTO_IPV6, nParameterId, (const char*)&nProtLevel, sizeof(int));
#endif
    }
#endif

    if (::bind(hListenSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf(
                                _("Unable to bind to %s on this computer. Yacoin is probably already running."), 
                                addrBind.ToString().c_str()
                                );
        else
            strError = strprintf(
                                _("Unable to bind to %s on this computer (bind returned error %d, %s)"), 
                                addrBind.ToString().c_str(), nErr, strerror(nErr)
                                );
        printf("%s\n", strError.c_str());
        clearLocalSocketError( hListenSocket );
        return false;
    }
    printf("Bound to %s\n", addrBind.ToString().c_str());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf(
                            "Error: Listening for incoming connections failed (listen returned error %d)", 
                            WSAGetLastError()
                            );
        printf("%s\n", strError.c_str());
        clearLocalSocketError( hListenSocket );
        return false;
    }

    vhListenSocket.push_back(hListenSocket);

    if (addrBind.IsRoutable() && fDiscover)
        AddLocal(addrBind, LOCAL_BIND);

    printf("Socket %s initialized\n",  addrBind.ToString().c_str());
    return true;
    }
}

void static Discover()
{
    if (!fDiscover)
        return;

#ifdef WIN32
    // Get local host IP
    char pszHostName[1000] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        vector<CNetAddr> vaddr;
        if (LookupHost(pszHostName, vaddr))
        {
            BOOST_FOREACH (const CNetAddr &addr, vaddr)
            {
                AddLocal(addr, LOCAL_IF);
            }
        }
    }
#else
    // Get local host ip
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if (strcmp(ifa->ifa_name, "lo") == 0) continue;
            if (strcmp(ifa->ifa_name, "lo0") == 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                CNetAddr addr(s4->sin_addr);
                if (AddLocal(addr, LOCAL_IF))
                    printf("IPv4 %s: %s\n", ifa->ifa_name, addr.ToString().c_str());
            }
#ifdef USE_IPV6
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                CNetAddr addr(s6->sin6_addr);
                if (AddLocal(addr, LOCAL_IF))
                    printf("IPv6 %s: %s\n", ifa->ifa_name, addr.ToString().c_str());
            }
#endif
        }
        freeifaddrs(myaddrs);
    }
#endif

    // Don't use external IPv4 discovery, when -onlynet="IPv6"
    if (!IsLimited(NET_IPV4))
        NewThread(ThreadGetMyExternalIP, NULL);
}

void StartNode(void* parg)
{
    // Make this thread recognisable as the startup thread
    RenameThread("yacoin-start");

#ifdef WIN32
    // Enable away mode and prevent the sleep idle time-out.
    SetThreadExecutionState(
                            ES_CONTINUOUS 
                            | ES_SYSTEM_REQUIRED
    #ifdef _MSC_VER
                            | ES_AWAYMODE_REQUIRED
    #endif
                           );
#endif

    if (semOutbound == NULL) 
    {
        // initialize semaphore
      //int nMaxOutbound = min(MAX_OUTBOUND_CONNECTIONS, (int)GetArg("-maxconnections", 125));
        int nMaxOutbound = min( GetMaxOutboundConnections(), GetMaxConnections() );
        semOutbound = new CSemaphore(nMaxOutbound);
    }

    if (pnodeLocalHost == NULL)
        pnodeLocalHost = new CNode(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0), nLocalServices));

    Discover();

    //
    // Start threads
    //

    if (!GetBoolArg("-dnsseed", true))
        printf("DNS seeding disabled\n");
    else
        if (!NewThread(ThreadDNSAddressSeed, NULL))
            printf("Error: NewThread(ThreadDNSAddressSeed) failed\n");

    // Map ports with UPnP
    if (!fUseUPnP)
        printf("UPNP port mapping is disabled\n");
    else
        MapPort();

    // Get addresses from IRC and advertise ours
    if (!GetBoolArg("-irc", true))
        printf("IRC seeding disabled\n");
    else
        if (!NewThread(ThreadIRCSeed, NULL))
            printf("Error: NewThread(ThreadIRCSeed) failed\n");

    // Send and receive from sockets, accept connections
    if (!NewThread(ThreadSocketHandler, NULL))
        printf("Error: NewThread(ThreadSocketHandler) failed\n");

    // Initiate outbound connections from -addnode
    if (!NewThread(ThreadOpenAddedConnections, NULL))
        printf("Error: NewThread(ThreadOpenAddedConnections) failed\n");

    // Initiate outbound connections
    if (!NewThread(ThreadOpenConnections, NULL))
        printf("Error: NewThread(ThreadOpenConnections) failed\n");

    // Process messages
    if (!NewThread(ThreadMessageHandler, NULL))
        printf("Error: NewThread(ThreadMessageHandler) failed\n");

    // Dump network addresses
    if (!NewThread(ThreadDumpAddress, NULL))
        printf("Error; NewThread(ThreadDumpAddress) failed\n");

#if !defined(Yac1dot0)
    // ppcoin: mint proof-of-stake blocks in the background
    if (!NewThread(ThreadStakeMinter, pwalletMain))
        printf("Error: NewThread(ThreadStakeMinter) failed\n");
#endif

    // Generate coins in the background
    GenerateYacoins(GetBoolArg("-gen", false), pwalletMain);
}

bool StopNode()
{
    if (fDebug)
        printf("StopNode()\n");
    fShutdown = true;

#ifdef WIN32
    // Clear EXECUTION_STATE flags to disable away mode and allow the system to idle to sleep normally.
    SetThreadExecutionState(ES_CONTINUOUS);
#endif

    ++nTransactionsUpdated;
    ::int64_t 
        nStart = GetTime();
    {{
        LOCK(cs_main);  //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< seems OK
        ThreadScriptCheckQuit();
    }}
    if (semOutbound)
    {
        for (int i = 0; i < GetMaxOutboundConnections(); ++i)
        {
            semOutbound->post();
        }
    }
    do
    {
        int 
            nThreadsRunning = 0;

        for (int n = 0; n < THREAD_MAX; ++n)
            nThreadsRunning += vnThreadsRunning[n];
        if (nThreadsRunning == 0)
            break;
        if (GetTime() - nStart > 20) // if it takes more than 20 seconds then break?  Why
            break;
      //Sleep(20);                   // wait 20ms, then break, why?
        Sleep(2 * nTenMilliseconds);
    } while(true);

    if (vnThreadsRunning[THREAD_SOCKETHANDLER] > 0) 
        printf("ThreadSocketHandler still running\n");

    if (vnThreadsRunning[THREAD_OPENCONNECTIONS] > 0) 
        printf("ThreadOpenConnections still running\n");

    if (vnThreadsRunning[THREAD_MESSAGEHANDLER] > 0) 
        printf("ThreadMessageHandler still running\n");

    if (vnThreadsRunning[THREAD_RPCLISTENER] > 0) 
        printf("ThreadRPCListener still running\n");

    if (vnThreadsRunning[THREAD_RPCHANDLER] > 0) 
        printf("ThreadsRPCServer still running\n");
#ifdef USE_UPNP
    if (vnThreadsRunning[THREAD_UPNP] > 0) 
        printf("ThreadMapPort still running\n");
#endif

    if (vnThreadsRunning[THREAD_DNSSEED] > 0) 
        printf("ThreadDNSAddressSeed still running\n");

    if (vnThreadsRunning[THREAD_ADDEDCONNECTIONS] > 0) 
        printf("ThreadOpenAddedConnections still running\n");

    if (vnThreadsRunning[THREAD_DUMPADDRESS] > 0) 
        printf("ThreadDumpAddresses still running\n");

    if (vnThreadsRunning[THREAD_MINTER] > 0) 
        printf("ThreadStakeMinter still running\n");

    if (vnThreadsRunning[THREAD_SCRIPTCHECK] > 0) 
        printf("ThreadScriptCheck still running\n");

    while (
        (vnThreadsRunning[THREAD_MESSAGEHANDLER] > 0) || 
        (vnThreadsRunning[THREAD_RPCHANDLER] > 0) || 
        (vnThreadsRunning[THREAD_SCRIPTCHECK] > 0)
          )
      //Sleep(20);      // again, related to above?  Or not? Or ...???
        Sleep(2 * nTenMilliseconds);      // again, related to above?  Or not? Or ...???

  //Sleep(50);
    Sleep(5 * nTenMilliseconds);
    DumpAddresses();
    return true;    // it seems it can only return true, so why not void!?
}

class CNetCleanup
{
public:
    CNetCleanup()
    {
    }
    ~CNetCleanup()
    {
        if (fDebug)
        {
#ifdef _MSC_VER
            (void)printf(
                        "~CNetCleanup() destructor called..."
                       );
#endif
        }
        // Close sockets
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            if (pnode->hSocket != INVALID_SOCKET)
            {
                closesocket(pnode->hSocket);
            }
        }
        BOOST_FOREACH(SOCKET hListenSocket, vhListenSocket)
        {
            if (hListenSocket != INVALID_SOCKET)
            {
                if (closesocket(hListenSocket) == SOCKET_ERROR)
                {
                    printf("closesocket(hListenSocket) failed with error %d\n", WSAGetLastError());
                    clearLocalSocketError( hListenSocket ); //<<<<<<<<<<<<<only unguarded
                }
            }
        }
#ifdef WIN32
        // Shutdown Windows Sockets
        if( 
            (0 != vhListenSocket.size()) ||
            (0 != vNodes.size())
          )
        {
            WSACleanup();
        }
#endif
        if (fDebug)
        {
#ifdef _MSC_VER
            (void)printf( " done\n" );
#endif
            Sleep( 2 * nMillisecondsPerSecond );    // 2 seconds just to see the 
                                                    //message of who is the slowest to close
        }
    }
} instance_of_cnetcleanup;

void RelayTransaction(const CTransaction& tx, const uint256& hash)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss.reserve(10000);
    ss << tx;
    RelayTransaction(tx, hash, ss);
}

void RelayTransaction(const CTransaction& tx, const uint256& hash, const CDataStream& ss)
{
    CInv inv(MSG_TX, hash);
    {
        LOCK(cs_mapRelay);
        // Expire old relay messages
        while (
               !vRelayExpiration.empty() && 
               (vRelayExpiration.front().first < GetTime())
              )
        {
            mapRelay.erase(vRelayExpiration.front().second);
            vRelayExpiration.pop_front();
        }

        // Save original serialized message so newer versions are preserved
        mapRelay.insert(std::make_pair(inv, ss));
        vRelayExpiration.push_back(std::make_pair(GetTime() + 15 * 60, inv));
    }

    RelayInventory(inv);
}

void CNode::RecordBytesRecv(::uint64_t bytes)
{
    LOCK(cs_totalBytesRecv);
    nTotalBytesRecv += bytes;
}

void CNode::RecordBytesSent(::uint64_t bytes)
{
    LOCK(cs_totalBytesSent);
    nTotalBytesSent += bytes;
}

::uint64_t CNode::GetTotalBytesRecv()
{
    LOCK(cs_totalBytesRecv);
    return nTotalBytesRecv;
}

::uint64_t CNode::GetTotalBytesSent()
{
    LOCK(cs_totalBytesSent);
    return nTotalBytesSent;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
