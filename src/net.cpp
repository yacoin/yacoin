// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 YACoin developers and contributors
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef _MSC_VER
    #include "msvc_warnings.push.h"
#endif

#include "irc.h"
#include "db.h"
#include "net.h"
#include "init.h"
#include "strlcpy.h"
#include "addrman.h"
#include "ui_interface.h"

#ifdef WIN32
#include <string.h>
#endif

#ifdef USE_UPNP
#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

using namespace std;
using namespace boost;


// WM - static const int MAX_OUTBOUND_CONNECTIONS = 8;
#define DEFAULT_MAX_CONNECTIONS         125    // WM - Default value for -maxconnections= parameter.
#define MIN_CONNECTIONS                 8      // WM - Lowest value we allow for -maxconnections= (never ever set less than 2!).
#define MAX_CONNECTIONS                 1000   // WM - Max allowed value for -maxconnections= parameter.  Getting kinda excessive, eh?

#define DEFAULT_OUTBOUND_CONNECTIONS    8      // WM - Reasonable default of 8 outbound connections for -maxoutbound= parameter.
#define MIN_OUTBOUND_CONNECTIONS        4      // WM - Lowest we allow for -maxoutbound= parameter shall be 4 connections (never ever set below 2).
#define MAX_OUTBOUND_CONNECTIONS        100    // WM - This no longer means what it used to.  Outbound conn count now runtime configurable.


void ThreadMessageHandler2(void* parg);
void ThreadSocketHandler2(void* parg);
void ThreadOpenConnections2(void* parg);
void ThreadOpenAddedConnections2(void* parg);
#ifdef USE_UPNP
void ThreadMapPort2(void* parg);
#endif
void ThreadDNSAddressSeed2(void* parg);
bool OpenNetworkConnection(const CAddress& addrConnect, CSemaphoreGrant *grantOutbound = NULL, const char *strDest = NULL, bool fOneShot = false);


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
uint64 nLocalServices = (fClient ? 0 : NODE_NETWORK);
static CCriticalSection cs_mapLocalHost;
static map<CNetAddr, LocalServiceInfo> mapLocalHost;
static bool vfReachable[NET_MAX] = {};
static bool vfLimited[NET_MAX] = {};
static CNode* pnodeLocalHost = NULL;
CAddress addrSeenByPeer(CService("0.0.0.0", 0), nLocalServices);
uint64 nLocalHostNonce = 0;
boost::array<int, THREAD_MAX> vnThreadsRunning;
static std::vector<SOCKET> vhListenSocket;
CAddrMan addrman;

vector<CNode*> vNodes;
CCriticalSection cs_vNodes;
map<CInv, CDataStream> mapRelay;
deque<pair<int64, CInv> > vRelayExpiration;
CCriticalSection cs_mapRelay;
map<CInv, int64> mapAlreadyAskedFor;

static deque<string> vOneShots;
CCriticalSection cs_vOneShots;

set<CNetAddr> setservAddNodeAddresses;
CCriticalSection cs_setservAddNodeAddresses;

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



//
// int GetMaxConnections( void )
//
//    WM - Function to determine maximum allowed in+out connections.
//
//    Parameters: None
//    Returns: Maximum connections allowed (int)
//

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



//
// int GetMaxOutboundConnections( void )
//
//    WM - Function to determine maximum allowed outbound connections.
//
//    Parameters: None
//    Returns: Maximum outbound connections allowed (int)
//

int GetMaxOutboundConnections()
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
        for (map<CNetAddr, LocalServiceInfo>::iterator it = mapLocalHost.begin(); it != mapLocalHost.end(); it++)
        {
            int nScore = (*it).second.nScore;
            int nReachability = (*it).first.GetReachabilityFrom(paddrPeer);
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore))
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

bool ReceiveALine(SOCKET hSocket, string& strLine)
{
    size_t
        nArbitrarySize = 9000; // 9000?  Why?????????

    strLine = "";
    loop
    {
        char 
            c;

        int 
            nBytes = recv(hSocket, &c, 1, 0);

        if (nBytes > 0)
        {
            if (c == '\n')
                continue;
            if (c == '\r')
                return true;
            strLine += c;
            if (strLine.size() >= nArbitrarySize)   // why limit to 9,000 characters?
                return true;
        }
        else if (nBytes <= 0)
        {
            if (fShutdown)
                return false;
            if (nBytes < 0)
            {
                int nErr = WSAGetLastError();
                if (nErr == WSAEMSGSIZE)
                    continue;
                if (nErr == WSAEWOULDBLOCK || nErr == WSAEINTR || nErr == WSAEINPROGRESS)
                {
                    Sleep(10);
                    continue;
                }
                // else some other error happened
            }
            if (!strLine.empty()) // maybe we should continue?
                return true;
                //continue;

            if (nBytes == 0)
            {   // socket closed (maybe?)
                printf("socket closed\n");
                return false;
            }
            else
            {   // socket error
                int 
                    nErr = WSAGetLastError();
                printf("recv failed: %d\n", nErr);
                return false;
            }
        }
    }
}

bool RecvLine(SOCKET hSocket, string& strLine)
{
    size_t
        nArbitrarySize = 9000;      //Is this arbitray? Required? Wild ass guess? What?

    strLine = "";
    loop
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
            if (strLine.size() >= nArbitrarySize)   // why limit to 9,000 characters?
                return true;
        }
        else if (nBytes <= 0)
        {
            if (fShutdown)
                return false;
            if (nBytes < 0)
            {
                int nErr = WSAGetLastError();
                if (nErr == WSAEMSGSIZE)
                    continue;
                if (nErr == WSAEWOULDBLOCK || nErr == WSAEINTR || nErr == WSAEINPROGRESS)
                {
                    Sleep(10);
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
                int nErr = WSAGetLastError();
                printf("recv failed: %d\n", nErr);
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
            if (addrLocal.IsRoutable() && (CService)addrLocal != (CService)pnode->addrLocal)
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

    if (!fDiscover && nScore < LOCAL_MANUAL)
        return false;

    if (IsLimited(addr))
        return false;

    printf("AddLocal(%s,%i)\n", addr.ToString().c_str(), nScore);

    {
        LOCK(cs_mapLocalHost);
        bool fAlready = mapLocalHost.count(addr) > 0;
        LocalServiceInfo &info = mapLocalHost[addr];
        if (!fAlready || nScore >= info.nScore) {
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
    return mapLocalHost.count(addr) > 0;
}

/** check whether a given address is in a network we can probably connect to */
bool IsReachable(const CNetAddr& addr)
{
    LOCK(cs_mapLocalHost);
    enum Network net = addr.GetNetwork();
    return vfReachable[net] && !vfLimited[net];
}

#ifdef WIN32

bool recvAline( SOCKET &hSocket, string & strLine )
{
    char 
        c;
    int
        nBytes;

    do
    {
        nBytes = recv(hSocket, &c, 1, 0);   // better be one or zero!

        if (1 == nBytes)
        {   // OK
            strLine += c;
            if( '\n' == c )  // the signal for a line received
                break;
        }
        else
        {
            if (SOCKET_ERROR == nBytes) // error, which error? Some aren't
            {
                int 
                    nErr = WSAGetLastError();

                if (nErr == WSAEMSGSIZE)
                    continue;
                if (
                    nErr == WSAEWOULDBLOCK || 
                    nErr == WSAEINTR || 
                    nErr == WSAEINPROGRESS
                   )
                {
                   Sleep(10);
                    continue;
                }
            }
            if (0 == nBytes)
            {   // done
                return false;
            }
            else
            {
                // socket error
                int 
                    nErr = WSAGetLastError();
                printf("recv failed: error %d\n", nErr);
                return false;
            }
        }
    }while( true );
    return true;
}

class CdoSocket
{
    private:
    struct hostent 
        *host;
    SOCKET 
        SocketCopy;

    public:
    explicit CdoSocket( SOCKET & Socket, const string & sDomain )
    {
        Socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        
        host = gethostbyname( sDomain.c_str() );

        SOCKADDR_IN 
            SockAddr;

        SockAddr.sin_port = htons(80);
        SockAddr.sin_family = AF_INET;
        SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

        //cout << "Connecting...\n";

        int
            nResult = connect(Socket,(SOCKADDR*)(&SockAddr),sizeof(SockAddr) );

        if ( SOCKET_ERROR == nResult )
        {
            std::string
                sS = strprintf(
                    "Could not connect"
                    "connect function failed with error: %ld\n", WSAGetLastError()
                              );
            nResult = closesocket(Socket);
            if (nResult == SOCKET_ERROR)
                wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            throw runtime_error(
                    "getYACprice\n"
                    "Could not connect?"
                               );
        }
        SocketCopy = Socket;
    }

    ~CdoSocket()
    {
        closesocket( SocketCopy );
    }    
};

bool GetMyExternalWebPage(const string & sDomain, const char* pszGet, string & strBuffer, double &dPrice)
{
    SOCKET 
        hSocket = NULL;

    CdoSocket CthisSocketConnection( hSocket, sDomain );    //RAII attempt on the socket!?
    if (hSocket)    // then it's OK
    {
        int
            nBytesSent = send(hSocket, pszGet, strlen(pszGet), MSG_NOSIGNAL);

        if (nBytesSent != strlen(pszGet) )
        {
            printf(
                    "send() error: only sent %d of %d?"
                    "\n", 
                    nBytesSent,
                    strlen(pszGet)
                  );
        }
        string
            strLine = "";
        bool 
            fLineOK = false;
        do
        {
            fLineOK = recvAline(hSocket, strLine);
            if (fShutdown)
            {
                return false;
            }
            if (fLineOK)
            {
                strBuffer += strLine;
                if( string::npos != strLine.find( "volume", 0 ) ) // search 11, YAC/BTC & 2, BTC/USD
                {
                    string
                        skey = "lasttradeprice";
                    // it looks like this
                    //"YAC\/BTC","lasttradeprice":"0.00000535","volume":
                    if( string::npos != strLine.find( skey, 0 ) ) // search 11, YAC/BTC & 2, BTC/USD
                    {   // pickup the price
                        string
                            sTemp = strLine.substr( strLine.find( skey, 0 ) + skey.size() + 3);
                                  //           strtod( .cstr(), NULL
                                  //  dPrice = stod( const string & sTemp, NULL )
                        double 
                            dTemp;

                        if (1 == sscanf( sTemp.c_str(), "%lf", &dTemp ) )
                        {
                           dPrice = dTemp;  // just so I can debug.  A good compiler 
                                            // can optimize this dTemp out!
                        }
                    }
                    // read rest of result
                    strLine = "";            
                    do
                    {
                        fLineOK = recvAline(hSocket, strLine);
                        Sleep( 10 );
                        strLine = "";            
                    }while( fLineOK );
                    break;
                }
            }
            strLine = "";            
        }while( fLineOK );

        if ( 0 < strBuffer.size() )
        {
            printf(
                    "GetMyExternalWebPage() received:\n"
                    "%s"
                    "\n", 
                    strBuffer.c_str()
                  );
            return true;
        }
        else
        {
            return error("error in recv() : connection closed?");
        }
    }
    else
    {
        return false;
    }
}
#endif

bool GetMyExternalIP2(const CService& addrConnect, const char* pszGet, const char* pszKeyword, CNetAddr& ipRet)
{
    SOCKET 
        hSocket;

    if (!ConnectSocket(addrConnect, hSocket))
        return error("GetMyExternalIP() : connection to %s failed", addrConnect.ToString().c_str());

    send(hSocket, pszGet, strlen(pszGet), MSG_NOSIGNAL);

    string 
        strLine;

    while (RecvLine(hSocket, strLine))
    {
        if (strLine.empty()) // HTTP response is separated from headers by blank line
        {
            loop
            {
                if (!RecvLine(hSocket, strLine))
                {
                    closesocket(hSocket);
                    return false;
                }
                if (pszKeyword == NULL)
                    break;
                if (strLine.find(pszKeyword) != string::npos)
                {
                    strLine = strLine.substr(strLine.find(pszKeyword) + strlen(pszKeyword));
                    break;
                }
            }
            closesocket(hSocket);

            if (strLine.find("<") != string::npos)
                strLine = strLine.substr(0, strLine.find("<"));
            strLine = strLine.substr(strspn(strLine.c_str(), " \t\n\r"));
            while (strLine.size() > 0 && isspace(strLine[strLine.size()-1]))
                strLine.resize(strLine.size()-1);

            CService 
                addr(strLine,0,true);

            printf("GetMyExternalIP() received [%s] %s\n", strLine.c_str(), addr.ToString().c_str());
            if (!addr.IsValid() || !addr.IsRoutable())
                return false;
            ipRet.SetIP(addr);
            return true;
        }
    }
    closesocket(hSocket);
    return error("GetMyExternalIP() : connection closed");
}

// We now get our external IP from the IRC server first and only use this as a backup
bool GetMyExternalIP(CNetAddr& ipRet)
{
    CService addrConnect;
    const char* pszGet;
    const char* pszKeyword;

    for (int nLookup = 0; nLookup <= 1; ++nLookup)
    {
        for (int nHost = 1; nHost <= 2; ++nHost)
        {
            // We should be phasing out our use of sites like these.  If we need
            // replacements, we should ask for volunteers to put this simple
            // php file on their web server that prints the client IP:
            //  <?php echo $_SERVER["REMOTE_ADDR"]; ?>
            if (nHost == 1)
            {
                addrConnect = CService("91.198.22.70",80); // checkip.dyndns.org

                if (nLookup == 1)
                {
                    CService addrIP("checkip.dyndns.org", 80, true);
                    if (addrIP.IsValid())
                        addrConnect = addrIP;
                }

                pszGet = "GET / HTTP/1.1\r\n"
                         "Host: checkip.dyndns.org\r\n"
                         "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n"
                         "Connection: close\r\n"
                         "\r\n";

                pszKeyword = "Address:";
            }
            else if (nHost == 2)
            {
                addrConnect = CService("74.208.43.192", 80); // www.showmyip.com

                if (nLookup == 1)
                {
                    CService addrIP("www.showmyip.com", 80, true);
                    if (addrIP.IsValid())
                        addrConnect = addrIP;
                }

                pszGet = "GET /simple/ HTTP/1.1\r\n"
                         "Host: www.showmyip.com\r\n"
                         "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n"
                         "Connection: close\r\n"
                         "\r\n";

                pszKeyword = NULL; // Returns just IP address
            }

            if (GetMyExternalIP2(addrConnect, pszGet, pszKeyword, ipRet))
                return true;
        }
    }

    return false;
}

void ThreadGetMyExternalIP(void* parg)
{
    // Make this thread recognisable as the external IP detection thread
    RenameThread("bitcoin-ext-ip");

    CNetAddr addrLocalHost;
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







CNode* FindNode(const CNetAddr& ip)
{
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if ((CNetAddr)pnode->addr == ip)
                return (pnode);
    }
    return NULL;
}

CNode* FindNode(std::string addrName)
{
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes)
        if (pnode->addrName == addrName)
            return (pnode);
    return NULL;
}

CNode* FindNode(const CService& addr)
{
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if ((CService)pnode->addr == addr)
                return (pnode);
    }
    return NULL;
}

CNode* ConnectNode(CAddress addrConnect, const char *pszDest, int64 nTimeout)
{
    if (pszDest == NULL) {
        if (IsLocal(addrConnect))
            return NULL;

        // Look for an existing connection
        CNode* pnode = FindNode((CService)addrConnect);
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
    printf("trying connection %s lastseen=%.1fhrs\n",
        pszDest ? pszDest : addrConnect.ToString().c_str(),
        pszDest ? 0 : (double)(GetAdjustedTime() - addrConnect.nTime)/3600.0);

    // Connect
    SOCKET hSocket;
    if (pszDest ? ConnectSocketByName(addrConnect, hSocket, pszDest, GetDefaultPort()) : ConnectSocket(addrConnect, hSocket))
    {
        addrman.Attempt(addrConnect);

        /// debug print
        printf("connected %s\n", pszDest ? pszDest : addrConnect.ToString().c_str());

        // Set to non-blocking
#ifdef WIN32
        u_long nOne = 1;
        if (ioctlsocket(hSocket, FIONBIO, &nOne) == SOCKET_ERROR)
            printf("ConnectSocket() : ioctlsocket non-blocking setting failed, error %d\n", WSAGetLastError());
#else
        if (fcntl(hSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
            printf("ConnectSocket() : fcntl non-blocking setting failed, error %d\n", errno);
#endif

        // Add node
        CNode* pnode = new CNode(hSocket, addrConnect, pszDest ? pszDest : "", false);
        if (nTimeout != 0)
            pnode->AddRef(nTimeout);
        else
            pnode->AddRef();

        {
            LOCK(cs_vNodes);
            vNodes.push_back(pnode);
        }

        pnode->nTimeConnected = GetTime();
        return pnode;
    }
    else
    {
        return NULL;
    }
}

void CNode::CloseSocketDisconnect()
{
    fDisconnect = true;
    if (hSocket != INVALID_SOCKET)
    {
        printf("disconnecting node %s\n", addrName.c_str());
        closesocket(hSocket);
        hSocket = INVALID_SOCKET;
        vRecv.clear();
    }
}

void CNode::Cleanup()
{
}


void CNode::PushVersion()
{
    /// when NTP implemented, change to just nTime = GetAdjustedTime()
    int64 nTime = (fInbound ? GetAdjustedTime() : GetTime());
    CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService("0.0.0.0",0)));
    CAddress addrMe = GetLocalAddress(&addr);
    RAND_bytes((unsigned char*)&nLocalHostNonce, sizeof(nLocalHostNonce));
    printf("send version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", PROTOCOL_VERSION, nBestHeight, addrMe.ToString().c_str(), addrYou.ToString().c_str(), addr.ToString().c_str());
    PushMessage("version", PROTOCOL_VERSION, nLocalServices, nTime, addrYou, addrMe,
                nLocalHostNonce, FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, std::vector<string>()), nBestHeight);
}


std::map<CNetAddr, int64> CNode::setBanned;
CCriticalSection CNode::cs_setBanned;

void CNode::ClearBanned()
{
    setBanned.clear();
}

bool CNode::IsBanned(CNetAddr ip)
{
    bool fResult = false;
    {
        LOCK(cs_setBanned);
        std::map<CNetAddr, int64>::iterator i = setBanned.find(ip);
        if (i != setBanned.end())
        {
            int64 t = (*i).second;
            if (GetTime() < t)
                fResult = true;
        }
    }
    return fResult;
}

bool CNode::Misbehaving(int howmuch)
{
    if (addr.IsLocal())
    {
        printf("Warning: Local node %s misbehaving (delta: %d)!\n", addrName.c_str(), howmuch);
        return false;
    }

    nMisbehavior += howmuch;
    if (nMisbehavior >= GetArg("-banscore", 100))
    {
        int64 banTime = GetTime()+GetArg("-bantime", 60*60*24);  // Default 24-hour ban
        printf("Misbehaving: %s (%d -> %d) DISCONNECTING\n", addr.ToString().c_str(), nMisbehavior-howmuch, nMisbehavior);
        {
            LOCK(cs_setBanned);
            if (setBanned[addr] < banTime)
                setBanned[addr] = banTime;
        }
        CloseSocketDisconnect();
        return true;
    } else
        printf("Misbehaving: %s (%d -> %d)\n", addr.ToString().c_str(), nMisbehavior-howmuch, nMisbehavior);
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
}
#undef X


void ThreadSocketHandler(void* parg)
{
    // Make this thread recognisable as the networking thread
    RenameThread("bitcoin-net");

    try
    {
        vnThreadsRunning[THREAD_SOCKETHANDLER]++;
        ThreadSocketHandler2(parg);
        vnThreadsRunning[THREAD_SOCKETHANDLER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_SOCKETHANDLER]--;
        PrintException(&e, "ThreadSocketHandler()");
    } catch (...) {
        vnThreadsRunning[THREAD_SOCKETHANDLER]--;
        throw; // support pthread_cancel()
    }
    printf("ThreadSocketHandler exited\n");
}

void ThreadSocketHandler2(void* parg)
{
    printf("ThreadSocketHandler started\n");
    list<CNode*> vNodesDisconnected;
    unsigned int nPrevNodeCount = 0;

    loop
    {
        //
        // Disconnect nodes
        //
        {
            LOCK(cs_vNodes);
            // Disconnect unused nodes
            vector<CNode*> vNodesCopy = vNodes;
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
            {
                if (pnode->fDisconnect ||
                    (pnode->GetRefCount() <= 0 && pnode->vRecv.empty() && pnode->vSend.empty()))
                {
                    // remove from vNodes
                    vNodes.erase(remove(vNodes.begin(), vNodes.end(), pnode), vNodes.end());

                    // release outbound grant (if any)
                    pnode->grantOutbound.Release();

                    // close socket and cleanup
                    pnode->CloseSocketDisconnect();
                    pnode->Cleanup();

                    // hold in disconnected pool until all refs are released
                    pnode->nReleaseTime = max(pnode->nReleaseTime, GetTime() + 15 * 60);
                    if (pnode->fNetworkNode || pnode->fInbound)
                        pnode->Release();
                    vNodesDisconnected.push_back(pnode);
                }
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
            }
        }
        if (vNodes.size() != nPrevNodeCount)
        {
            nPrevNodeCount = vNodes.size();
            uiInterface.NotifyNumConnectionsChanged(vNodes.size());
        }


        //
        // Find which sockets have data to receive
        //
        struct timeval timeout;
        timeout.tv_sec  = 0;
        timeout.tv_usec = 50000; // frequency to poll pnode->vSend

        fd_set fdsetRecv;
        fd_set fdsetSend;
        fd_set fdsetError;
        FD_ZERO(&fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        SOCKET hSocketMax = 0;
        bool have_fds = false;

        BOOST_FOREACH(SOCKET hListenSocket, vhListenSocket) {
            FD_SET(hListenSocket, &fdsetRecv);
            hSocketMax = max(hSocketMax, hListenSocket);
            have_fds = true;
        }
        {
            LOCK(cs_vNodes);
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
            }
        }

        vnThreadsRunning[THREAD_SOCKETHANDLER]--;
        int nSelect = select(have_fds ? hSocketMax + 1 : 0,
                             &fdsetRecv, &fdsetSend, &fdsetError, &timeout);
        vnThreadsRunning[THREAD_SOCKETHANDLER]++;
        if (fShutdown)
            return;
        if (nSelect == SOCKET_ERROR)
        {
            if (have_fds)
            {
                int nErr = WSAGetLastError();
                printf("socket select error %d\n", nErr);
                for (unsigned int i = 0; i <= hSocketMax; i++)
                    FD_SET(i, &fdsetRecv);
            }
            FD_ZERO(&fdsetSend);
            FD_ZERO(&fdsetError);
            Sleep(timeout.tv_usec/1000);
        }


        //
        // Accept new connections
        //
        BOOST_FOREACH(SOCKET hListenSocket, vhListenSocket)
        if (hListenSocket != INVALID_SOCKET && FD_ISSET(hListenSocket, &fdsetRecv))
        {
#ifdef USE_IPV6
            struct sockaddr_storage sockaddr;
#else
            struct sockaddr sockaddr;
#endif
            socklen_t len = sizeof(sockaddr);
            SOCKET hSocket = accept(hListenSocket, (struct sockaddr*)&sockaddr, &len);
            CAddress addr;
            int nInbound = 0;

            if (hSocket != INVALID_SOCKET)
                if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr))
                    printf("Warning: Unknown socket family\n");

            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                    if (pnode->fInbound)
                        nInbound++;
            }

            if (hSocket == INVALID_SOCKET)
            {
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK)
                    printf("socket error accept failed: %d\n", nErr);
            }
// WM            else if (nInbound >= GetArg("-maxconnections", DEFAULT_MAX_CONNECTIONS ) - /* WM - MAX_OUTBOUND_CONNECTIONS */ GetMaxOutboundConnections() )
            else if ( nInbound >= GetMaxConnections() - GetMaxOutboundConnections() )
            {
                {
                    LOCK(cs_setservAddNodeAddresses);
                    if (!setservAddNodeAddresses.count(addr))
                        closesocket(hSocket);
                }
            }
            else if (CNode::IsBanned(addr))
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
                    LOCK(cs_vNodes);
                    vNodes.push_back(pnode);
                }
            }
        }


        //
        // Service each socket
        //
        vector<CNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
                pnode->AddRef();
        }
        BOOST_FOREACH(CNode* pnode, vNodesCopy)
        {
            if (fShutdown)
                return;

            //
            // Receive
            //
            if (pnode->hSocket == INVALID_SOCKET)
                continue;
            if (FD_ISSET(pnode->hSocket, &fdsetRecv) || FD_ISSET(pnode->hSocket, &fdsetError))
            {
                TRY_LOCK(pnode->cs_vRecv, lockRecv);
                if (lockRecv)
                {
                    CDataStream& vRecv = pnode->vRecv;
                    unsigned int nPos = vRecv.size();

                    if (nPos > ReceiveBufferSize()) {
                        if (!pnode->fDisconnect)
                            printf("socket recv flood control disconnect (%"PRIszu" bytes)\n", vRecv.size());
                        pnode->CloseSocketDisconnect();
                    }
                    else {
                        // typical socket buffer is 8K-64K
                        char pchBuf[0x10000];
                        int nBytes = recv(pnode->hSocket, pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
                        if (nBytes > 0)
                        {
                            vRecv.resize(nPos + nBytes);
                            memcpy(&vRecv[nPos], pchBuf, nBytes);
                            pnode->nLastRecv = GetTime();
                        }
                        else if (nBytes == 0)
                        {
                            // socket closed gracefully
                            if (!pnode->fDisconnect)
                                printf("socket closed\n");
                            pnode->CloseSocketDisconnect();
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();
                            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                            {
                                if (!pnode->fDisconnect)
                                    printf("socket recv error %d\n", nErr);
                                pnode->CloseSocketDisconnect();
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
                    CDataStream& vSend = pnode->vSend;
                    if (!vSend.empty())
                    {
                        int nBytes = send(pnode->hSocket, &vSend[0], vSend.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
                        if (nBytes > 0)
                        {
                            vSend.erase(vSend.begin(), vSend.begin() + nBytes);
                            pnode->nLastSend = GetTime();
                        }
                        else if (nBytes < 0)
                        {
                            // error
                            int nErr = WSAGetLastError();
                            if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
                            {
                                printf("socket send error %d\n", nErr);
                                pnode->CloseSocketDisconnect();
                            }
                        }
                    }
                }
            }

            //
            // Inactivity checking
            //
            if (pnode->vSend.empty())
                pnode->nLastSendEmpty = GetTime();
            if (GetTime() - pnode->nTimeConnected > 60)
            {
                if (pnode->nLastRecv == 0 || pnode->nLastSend == 0)
                {
                    printf("socket no message in first 60 seconds, %d %d\n", pnode->nLastRecv != 0, pnode->nLastSend != 0);
                    pnode->fDisconnect = true;
                }
                else if (GetTime() - pnode->nLastSend > 90*60 && GetTime() - pnode->nLastSendEmpty > 90*60)
                {
                    printf("socket not sending\n");
                    pnode->fDisconnect = true;
                }
                else if (GetTime() - pnode->nLastRecv > 90*60)
                {
                    printf("socket inactivity timeout\n");
                    pnode->fDisconnect = true;
                }
            }
        }
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
                pnode->Release();
        }

        Sleep(10);
    }
}


#ifdef USE_UPNP
void ThreadMapPort(void* parg)
{
    // Make this thread recognisable as the UPnP thread
    RenameThread("bitcoin-UPnP");

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

        string strDesc = "YACoin " + FormatFullVersion();
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
        loop {
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
        loop {
            if (fShutdown || !fUseUPnP)
                return;
            Sleep(2000);
        }
    }
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
    // Intentionally left slightly less blank than the previous line.
}
#endif



// DNS seeds
// Each pair gives a source name and a seed name.
// The first name is used as information source for addrman.
// The second name should resolve to a list of seed addresses.
static const char *strDNSSeed[][2] = {
#ifdef _MSC_VER
    "", ""
    //NULL, NULL
#else
    //{"yacoin.org", "seed.novacoin.su"},    // WM - Umm...  FIXME
#endif
};

void ThreadDNSAddressSeed(void* parg)
{
    // Make this thread recognisable as the DNS seeding thread
    RenameThread("bitcoin-dnsseed");

    try
    {
        vnThreadsRunning[THREAD_DNSSEED]++;
        ThreadDNSAddressSeed2(parg);
        vnThreadsRunning[THREAD_DNSSEED]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_DNSSEED]--;
        PrintException(&e, "ThreadDNSAddressSeed()");
    } catch (...) {
        vnThreadsRunning[THREAD_DNSSEED]--;
        throw; // support pthread_cancel()
    }
    printf("ThreadDNSAddressSeed exited\n");
}

void ThreadDNSAddressSeed2(void* parg)
{
    printf("ThreadDNSAddressSeed started\n");
    int found = 0;


    if( !fTestNet )
    {
        printf("Loading addresses from DNS seeds (could take a while)\n");

        for( int seed_idx = 0; seed_idx < (int) ARRAYLEN( strDNSSeed ); seed_idx++ ) {
            if (HaveNameProxy()) {
                AddOneShot(strDNSSeed[seed_idx][1]);
            } else {
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
                        found++;
                    }
                }
                addrman.Add(vAdd, CNetAddr(strDNSSeed[seed_idx][0], true));
            }
        }
    }
    

    printf("%d addresses found from DNS seeds\n", found);
}

unsigned int pnSeed[] =
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
    0xaf0d722a, 0x0da306da, 0xa8865d6d, 0x0d5683b6, 0xcf934d5c, 0x3862507d, 0xdabbaf6f, 0xa900b155,
    0x9aa1f47b, 0x38d3165d, 0x4efb515f, 0x9b7b357b, 0x1fffd3de, 0xa41ce5c5, 0x520b3753, 0xd50c3131,
    0x2850b555, 0xdb4eb671, 0x3b15b4de, 0x2f00622e, 0xaada3453, 0x5cb8d13c, 0x78bc9640, 0x1af2a4b4,
    0x1a3ba7d5, 0xaf3c07c8, 0x4a95e073, 0xb23d3b78, 0x6c2f23c6, 0xf5fe247d, 0xaac7314e, 0xfbde888d,
    0x33d0323a, 0x1c631955, 0xea2e7cab, 0xce13275c, 0xd126ccc7, 0x229b2e48, 0x77b8fc47, 0x0c8cc675,
    0x27eb984f, 0xc8f1f824, 0x7ad74bb8, 0x1a19462e, 0x84c300b2, 0x6fe7c473, 0xfdbff502, 0x68434a71,
    0x92fcbb47, 0x1949415b, 0xe35c4371, 0xd0c87070, 0x3e8c132e, 0x259bb875, 0xcb1aded1, 0x62c16bda,
    0x2e39294d, 0x2302bb57, 0x543c0082, 0x762aafde, 0xd03d0643, 0x0b881576, 0x2132f952, 0xe8045e70,
    0x1706d45c, 0x1b0fb73d, 0x1c3dde0e, 0x615a0f4e, 0x54bbf055, 0xde23565d, 0xdba43fb7, 0x65708e6e,
    0xc9bf5872, 0xa3a56f71, 0x03f3680e, 0x3b63d1b7, 0xb3750ab2, 0x98dda17c, 0x8d0172b4, 0xc90594b6,
    0x22072378, 0x0406a943, 0x2ad44bb8, 0xfaeea26f, 0x04d6e45e, 0x75708e3d, 0x376c3ab0, 0x2fa1ef72,
    0x94f7cead, 0x5002aeb4, 0xdff8b5de, 0x6f56ed69, 0xeba76aaf, 0xbdad4f58, 0x23c732bd, 0x78b1f055,
    0xf63db25e, 0x55325a7a, 0xa5aa1e3e, 0x7fff3c92, 0x0ebfd25a, 0xc891c001, 0x7764b86e, 0x516ea705,
    0x0cd5e77a, 0x42e0a56f, 0x4c345475, 0xe36daf3c, 0xb786fdb2, 0xb38405b7, 0x880a7476, 0x6454e95d,
    0xf43d772a, 0x666ecf52, 0x0539717d, 0xc3c6f760, 0x022b7e02, 0x9d82854f, 0x9cc3e45c, 0x8c925d32,
    0x44305553, 0x7f5089bc, 0xfd87bfbe, 0x68cddeb2, 0xeafad2de, 0x24f92cc2, 0x316481d5, 0x3316a57b,
    0x8381a4b8, 0x7832917b, 0xbb375475, 0xc2125573, 0xc52a5e70, 0xb108645c, 0x616bb83c, 0x20e6ba3a,
    0x222c063a, 0x6c3e813d, 0x3c7c4358, 0x0b8c5001, 0xbaf82a75, 0x3dd2261b, 0xfc6c3547, 0xa6168471,
    0x9a7b3ead, 0x227d54c2, 0xd58ba47d, 0x0dd46759, 0x66dfe77a, 0x9cbee86d, 0x70826bd0, 0x5dcb0077,
    0x145ee497, 0xc5583601, 0x7ef6a843, 0x81bea377, 0xfafe2c53, 0x09b541ad, 0x96c29b7b, 0x4cb2f752,
    0xe002c701, 0xb00be062, 0x1bb70d1f, 0x1e46738c, 0x03555202, 0x2e128d75, 0xfcb6680e, 0x82251962,
    0x9a440455, 0x696a357b, 0x6b7aca75, 0x78731732, 0x48ab9959, 0x79426277, 0x2e7c0c6f, 0xb02a9c7a,
    0x8c25347b, 0x98d65070, 0xf53fba4d, 0x97264c90, 0x9e12554d, 0x1802b61f, 0xaf21e074, 0x032a5171,
    0x6be05d6d, 0x80472e5f, 0xea3788c6, 0xd4ed5d7b, 0x138adf02, 0xcfd438b7, 0x4f5b15b7, 0xe05e3bda,
    0xbdc26cda, 0xe336b34c, 0xf70c2e1b, 0xa70e535b, 0x2500a56d, 0xee258932, 0x2f135e3b, 0x5dee3eda,
    0x3dbdfc3a, 0x50a45a4e, 0x47d462bc, 0xde588753, 0x9e396399, 0x15c29b7b, 0xcdea856c, 0x29beba3d,
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
    0x003b4778, 0x1e411db7, 0x82745202, 0xb4aaeab2, 0x7c6ac075, 0xd024a84b, 0xd004585f, 0xa8f178bc,
    0xd55604da, 0x1458a8b4, 0x40c262b8, 0x8212b94d, 0xa58651da, 0x310dea79, 0xe78ea153, 0xf03d5b58,
    0xe76231d4, 0xea1cbd2e, 0x2975ac01, 0x5c5eadb4, 0x42bf5e70, 0xa260f93c, 0xffaede0e, 0x20875075,
    0x6c059f7b, 0x9512ba6a, 0x230a7e5e, 0x89fd92c2, 0x18cecead, 0xaddf1662, 0x9b040cdd, 0x51ea4371,
    0xebe0732a, 0xfae34e73, 0xcacf2bc8, 0x46206762, 0x0530f567, 0xdfd3d90e, 0xe28405ae, 0x56563b3a,
    0xa2bdc458, 0x22b751b7, 0x4ff6230e, 0x88c51a5e, 0x7d31b35a, 0x6ab1116e, 0xc9d00375, 0x34aa5255,
    0x30604824, 0x812aae75, 0xb013772a, 0x5501e555, 0x6af72a27, 0x93bcddb2, 0x05bfac71, 0x3461e9dd,
    0x6f34f13a, 0xd874db3a, 0x28dc3a6f, 0x7672b13a, 0xc1c6a76f, 0x68185065, 0x3a089baf, 0x0e4ab74d,
    0x0d2c7c5b, 0xbc6c08af, 0x6ad44bb8, 0xc6f5c851, 0x6e5bce5c, 0x33ad1518, 0xa745fa77, 0x23734271,
    0x9541095b, 0xb980207d, 0xf304a96d, 0xc96c50b7, 0x21641774, 0x5c053131, 0x17ab1671, 0xf1b86d71,
    0xb2086aaf, 0x03814705, 0x22a39759, 0xb8e35418, 0x24e0c871, 0x309a95d3, 0xf9709331, 0x03a4fc63,
    0x040d314e, 0xaec0d2cc, 0xa05c780e, 0xb2969a4f, 0xa0dba152, 0x7338031b, 0x9521a84b, 0x510aa1da,
    0x6a912845, 0x6a9f1186, 0x4072be4d, 0xf97a1b01, 0x91e37f32, 0x862a9bb4, 0x16887b4a, 0x596901b7,
    0x9a4c357b, 0xa89ac8c0, 0x6c07b943, 0xb5035971, 0x69e84db2, 0x05221c1f, 0x83254c6f, 0xbd64797d,
    0x4ee99e32, 0x4ac8302a, 0x450c2f73, 0x179ba971, 0x8fbcd073, 0xf474e774, 0xe190dfab, 0x1ebb575d,
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
    0xb7e95dd0, 0x8cdb1065, 0xdca1d431, 0xd54f0cb8, 0x7f8dbb77, 0x6e42157b, 0x6b37eb77, 0xdf426277,
    0x8a7be062, 0xb836717d, 0xb341d85e, 0x6f5478bc, 0x9e17515b, 0xf83922c0, 0x0f2d0e5e, 0x5d2c1ab7,
    0xafb7e497, 0xca0f2ab2, 0xbc971671, 0x3aa5787d, 0xc27e67d3, 0x2e23c270, 0x41b3ac47, 0x09bf6d71,
    0x97a0d879, 0xf53cac5d, 0xd77f0a2e, 0x69d39475, 0x0dadb501, 0xc2e05dda, 0x9a94d35f, 0xe51d4fdb,
    0x30d05bde, 0xc32ab5dc, 0x2e50ed70, 0x2b09ce5c, 0xa4c9a56d, 0xbd5dae50, 0xce6cf502, 0x0f5f772a,
    0x7517227d, 0xae30c1ad, 0x0c4ec54d, 0x3dd63a4a, 0x9a74b95b, 0x9ad2a8b4, 0xa4b308b7, 0xcb8921b6,
    0x4eadc46f, 0xf5ed0bcc, 0xd06c8753, 0xcd47f146, 0x02999352, 0x821b7765, 0xf9242e1b, 0x44b4b158,
    0x0e131edf, 0x23aa20b7, 0x2b13c401, 0x3ea7cc71, 0x40d7324f, 0x01ef2477, 0x56b287de, 0xc343e3dd,
    0x89c20a70, 0x05f8d374, 0xce43a87b, 0x643908dd, 0x5a94b077, 0xd5f1e85d, 0x3d1b2eb0, 0x75b2283a,
    0x23cf534b, 0xbb51e254, 0xba690dc6, 0xc22b5575, 0xf10a3024, 0x8cbbcdbb, 0x3909333a, 0x5da43701,
    0x1d24d5b0, 0xaee6f755, 0xcc7f157b, 0x1496bb6e, 0xa906c35c, 0x16b24f5d, 0xf0c71eae, 0x275b1bbc,
    0xdebaffbc, 0x9e5ef555, 0xdb5dae50, 0xfc7d111b, 0xc78f0077, 0x17a9c46f, 0xdd097c70, 0xd737594f,
    0xc2644f82, 0xb432354e, 0x6ef819bc, 0x4a44da0e, 0xdf27b86d, 0x64a53501, 0xca85f771, 0x6331f2b6,
    0x22cbf2b6, 0x5168d475, 0xc7297770, 0x7d528c43, 0xb6ce1a75, 0x11387770, 0x322db858, 0x77a8644f,
    0xe0adbe27, 0xfcb2752a, 0x41cb407d, 0xa42639ca, 0x5e44aab4, 0x35366848, 0xed5281be, 0x14acd7b4,
};

void DumpAddresses()
{
    int64 nStart = GetTimeMillis();

    CAddrDB adb;
    adb.Write(addrman);

    printf("Flushed %d addresses to peers.dat  %"PRI64d"ms\n",
           addrman.size(), GetTimeMillis() - nStart);
}

void ThreadDumpAddress2(void* parg)
{
    vnThreadsRunning[THREAD_DUMPADDRESS]++;
    while (!fShutdown)
    {
        DumpAddresses();
        vnThreadsRunning[THREAD_DUMPADDRESS]--;
        Sleep(100000);
        vnThreadsRunning[THREAD_DUMPADDRESS]++;
    }
    vnThreadsRunning[THREAD_DUMPADDRESS]--;
}

void ThreadDumpAddress(void* parg)
{
    // Make this thread recognisable as the address dumping thread
    RenameThread("bitcoin-adrdump");

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
    RenameThread("bitcoin-opencon");

    try
    {
        vnThreadsRunning[THREAD_OPENCONNECTIONS]++;
        ThreadOpenConnections2(parg);
        vnThreadsRunning[THREAD_OPENCONNECTIONS]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_OPENCONNECTIONS]--;
        PrintException(&e, "ThreadOpenConnections()");
    } catch (...) {
        vnThreadsRunning[THREAD_OPENCONNECTIONS]--;
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
    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, true);
    if (grant) {
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
        vnThreadsRunning[THREAD_MINTER]++;
        BitcoinMiner(pwallet, true);
        vnThreadsRunning[THREAD_MINTER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_MINTER]--;
        PrintException(&e, "ThreadStakeMinter()");
    } catch (...) {
        vnThreadsRunning[THREAD_MINTER]--;
        PrintException(NULL, "ThreadStakeMinter()");
    }
    printf("ThreadStakeMinter exiting, %d threads remaining\n", vnThreadsRunning[THREAD_MINTER]);
}

void ThreadOpenConnections2(void* parg)
{
    printf("ThreadOpenConnections started\n");

    // Connect to specific addresses
    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0)
    {
        for (int64 nLoop = 0;; nLoop++)
        {
            ProcessOneShot();
            BOOST_FOREACH(string strAddr, mapMultiArgs["-connect"])
            {
                CAddress addr;
                OpenNetworkConnection(addr, NULL, strAddr.c_str());
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    Sleep(500);
                    if (fShutdown)
                        return;
                }
            }
            Sleep(500);
        }
    }

    // Initiate network connections
    int64 nStart = GetTime();
    loop
    {
        ProcessOneShot();

        vnThreadsRunning[THREAD_OPENCONNECTIONS]--;
        Sleep(500);
        vnThreadsRunning[THREAD_OPENCONNECTIONS]++;
        if (fShutdown)
            return;


        vnThreadsRunning[THREAD_OPENCONNECTIONS]--;
        CSemaphoreGrant grant(*semOutbound);
        vnThreadsRunning[THREAD_OPENCONNECTIONS]++;
        if (fShutdown)
            return;

        // Add seed nodes if IRC isn't working
        if (addrman.size()==0 && (GetTime() - nStart > 60) && !fTestNet)
        {
            std::vector<CAddress> vAdd;
            for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
            {
                // It'll only connect to one or two seed nodes because once it connects,
                // it'll get a pile of addresses with newer timestamps.
                // Seed nodes are given a random 'last seen time' of between one and two
                // weeks ago.
                const int64 nOneWeek = 7*24*60*60;
                struct in_addr ip;
                memcpy(&ip, &pnSeed[i], sizeof(ip));
                CAddress addr(CService(ip, GetDefaultPort()));
                addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
                vAdd.push_back(addr);
            }
            addrman.Add(vAdd, CNetAddr("127.0.0.1"));
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per network group (/16 for IPv4).
        // Do this here so we don't have to critsect vNodes inside mapAddresses critsect.
        int nOutbound = 0;
        set<vector<unsigned char> > setConnected;
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes) {
                if (!pnode->fInbound) {
                    setConnected.insert(pnode->addr.GetGroup());
                    nOutbound++;
                }
            }
        }

        int64 nANow = GetAdjustedTime();

        int nTries = 0;
        loop
        {
            // use an nUnkBias between 10 (no outgoing connections) and 90 (8 outgoing connections)
            CAddress addr = addrman.Select(10 + min(nOutbound,8)*10);

            // if we selected an invalid address, restart
            if (!addr.IsValid() || setConnected.count(addr.GetGroup()) || IsLocal(addr))
                break;

            // If we didn't find an appropriate destination after trying 100 addresses fetched from addrman,
            // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new addrman addresses.
            nTries++;
            if (nTries > 100)
                break;

            if (IsLimited(addr))
                continue;

            // only consider very recently tried nodes after 30 failed attempts
            if (nANow - addr.nLastTry < 600 && nTries < 30)
                continue;

            // do not allow non-default ports, unless after 50 invalid addresses selected already
            if (addr.GetPort() != GetDefaultPort() && nTries < 50)
                continue;

            addrConnect = addr;
            break;
        }

        if (addrConnect.IsValid())
            OpenNetworkConnection(addrConnect, &grant);
    }
}

void ThreadOpenAddedConnections(void* parg)
{
    // Make this thread recognisable as the connection opening thread
    RenameThread("bitcoin-opencon");

    try
    {
        vnThreadsRunning[THREAD_ADDEDCONNECTIONS]++;
        ThreadOpenAddedConnections2(parg);
        vnThreadsRunning[THREAD_ADDEDCONNECTIONS]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_ADDEDCONNECTIONS]--;
        PrintException(&e, "ThreadOpenAddedConnections()");
    } catch (...) {
        vnThreadsRunning[THREAD_ADDEDCONNECTIONS]--;
        PrintException(NULL, "ThreadOpenAddedConnections()");
    }
    printf("ThreadOpenAddedConnections exited\n");
}

void ThreadOpenAddedConnections2(void* parg)
{
    printf("ThreadOpenAddedConnections started\n");

    if (mapArgs.count("-addnode") == 0)
        return;

    if (HaveNameProxy()) {
        while(!fShutdown) {
            BOOST_FOREACH(string& strAddNode, mapMultiArgs["-addnode"]) {
                CAddress addr;
                CSemaphoreGrant grant(*semOutbound);
                OpenNetworkConnection(addr, &grant, strAddNode.c_str());
                Sleep(500);
            }
            vnThreadsRunning[THREAD_ADDEDCONNECTIONS]--;
            Sleep(120000); // Retry every 2 minutes
            vnThreadsRunning[THREAD_ADDEDCONNECTIONS]++;
        }
        return;
    }

    vector<vector<CService> > vservAddressesToAdd(0);
    BOOST_FOREACH(string& strAddNode, mapMultiArgs["-addnode"])
    {
        vector<CService> vservNode(0);
        if(Lookup(strAddNode.c_str(), vservNode, GetDefaultPort(), fNameLookup, 0))
        {
            vservAddressesToAdd.push_back(vservNode);
            {
                LOCK(cs_setservAddNodeAddresses);
                BOOST_FOREACH(CService& serv, vservNode)
                    setservAddNodeAddresses.insert(serv);
            }
        }
    }
    loop
    {
        vector<vector<CService> > vservConnectAddresses = vservAddressesToAdd;
        // Attempt to connect to each IP for each addnode entry until at least one is successful per addnode entry
        // (keeping in mind that addnode entries can have many IPs if fNameLookup)
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
            {
                for (vector<vector<CService> >::iterator it = vservConnectAddresses.begin(); it != vservConnectAddresses.end(); it++)
                {
                    BOOST_FOREACH(CService& addrNode, *(it))
#ifndef _MSC_VER
                    {
                        if (pnode->addr == addrNode)
                        {
                            it = vservConnectAddresses.erase(it);
                            it--;
                            break;
                        }
                    }
#else
                    {
                        if (pnode->addr == addrNode)
                        {
                            it = vservConnectAddresses.erase(it);

                            // now it get tricky!
                            if( vservConnectAddresses.empty() )
                                break;          // can't legally --it, nor ++it
                            // else it's not empty, so
                            if (it == vservConnectAddresses.begin()) // can't --it
                                break;
                            --it;               // finally, a legal place!!    
                            break;
                        }
                        // else we stay in the inner BOOST_FOREACH() loop
                    }
                    if( vservConnectAddresses.empty() )
                        break;      // can't do a ++it
                    if (it == vservConnectAddresses.end())
                        break;      // can't do a ++it
#endif
                }
            }
        }
        BOOST_FOREACH(vector<CService>& vserv, vservConnectAddresses)
        {
            CSemaphoreGrant grant(*semOutbound);
            OpenNetworkConnection(CAddress(*(vserv.begin())), &grant);
            Sleep(500);
            if (fShutdown)
                return;
        }
        if (fShutdown)
            return;
        vnThreadsRunning[THREAD_ADDEDCONNECTIONS]--;
        Sleep(120000); // Retry every 2 minutes
        vnThreadsRunning[THREAD_ADDEDCONNECTIONS]++;
        if (fShutdown)
            return;
    }
}

// if successful, this moves the passed grant to the constructed node
bool OpenNetworkConnection(const CAddress& addrConnect, CSemaphoreGrant *grantOutbound, const char *strDest, bool fOneShot)
{
    //
    // Initiate outbound network connection
    //
    if (fShutdown)
        return false;
    if (!strDest)
        if (IsLocal(addrConnect) ||
            FindNode((CNetAddr)addrConnect) || CNode::IsBanned(addrConnect) ||
            FindNode(addrConnect.ToStringIPPort().c_str()))
            return false;
    if (strDest && FindNode(strDest))
        return false;

    vnThreadsRunning[THREAD_OPENCONNECTIONS]--;
    CNode* pnode = ConnectNode(addrConnect, strDest);
    vnThreadsRunning[THREAD_OPENCONNECTIONS]++;
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








void ThreadMessageHandler(void* parg)
{
    // Make this thread recognisable as the message handling thread
    RenameThread("bitcoin-msghand");

    try
    {
        vnThreadsRunning[THREAD_MESSAGEHANDLER]++;
        ThreadMessageHandler2(parg);
        vnThreadsRunning[THREAD_MESSAGEHANDLER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_MESSAGEHANDLER]--;
        PrintException(&e, "ThreadMessageHandler()");
    } catch (...) {
        vnThreadsRunning[THREAD_MESSAGEHANDLER]--;
        PrintException(NULL, "ThreadMessageHandler()");
    }
    printf("ThreadMessageHandler exited\n");
}

void ThreadMessageHandler2(void* parg)
{
    printf("ThreadMessageHandler started\n");
    SetThreadPriority(THREAD_PRIORITY_BELOW_NORMAL);
    while (!fShutdown)
    {
        vector<CNode*> vNodesCopy;
        {
            LOCK(cs_vNodes);
            vNodesCopy = vNodes;
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
                pnode->AddRef();
        }

        // Poll the connected nodes for messages
        CNode* pnodeTrickle = NULL;
        if (!vNodesCopy.empty())
            pnodeTrickle = vNodesCopy[GetRand(vNodesCopy.size())];
        BOOST_FOREACH(CNode* pnode, vNodesCopy)
        {
            // Receive messages
            {
                TRY_LOCK(pnode->cs_vRecv, lockRecv);
                if (lockRecv)
                    ProcessMessages(pnode);
            }
            if (fShutdown)
                return;

            // Send messages
            {
                TRY_LOCK(pnode->cs_vSend, lockSend);
                if (lockSend)
                    SendMessages(pnode, pnode == pnodeTrickle);
            }
            if (fShutdown)
                return;
        }

        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodesCopy)
                pnode->Release();
        }

        // Wait and allow messages to bunch up.
        // Reduce vnThreadsRunning so StopNode has permission to exit while
        // we're sleeping, but we must always check fShutdown after doing this.
        vnThreadsRunning[THREAD_MESSAGEHANDLER]--;
        Sleep(100);
        if (fRequestShutdown)
            StartShutdown();
        vnThreadsRunning[THREAD_MESSAGEHANDLER]++;
        if (fShutdown)
            return;
    }
}






bool BindListenPort(const CService &addrBind, string& strError)
{
    strError = "";
    int nOne = 1;

#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
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
        strError = strprintf("Error: bind address family for %s not supported", addrBind.ToString().c_str());
        printf("%s\n", strError.c_str());
        return false;
    }

    SOCKET hListenSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hListenSocket == INVALID_SOCKET)
    {
        strError = strprintf("Error: Couldn't open socket for incoming connections (socket returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
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
    if (ioctlsocket(hListenSocket, FIONBIO, (u_long*)&nOne) == SOCKET_ERROR)
#else
    if (fcntl(hListenSocket, F_SETFL, O_NONBLOCK) == SOCKET_ERROR)
#endif
    {
        strError = strprintf("Error: Couldn't set properties on socket for incoming connections (error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

#ifdef USE_IPV6
    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (addrBind.IsIPv6()) {
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
            strError = strprintf(_("Unable to bind to %s on this computer. YACoin is probably already running."), addrBind.ToString().c_str());
        else
            strError = strprintf(_("Unable to bind to %s on this computer (bind returned error %d, %s)"), addrBind.ToString().c_str(), nErr, strerror(nErr));
        printf("%s\n", strError.c_str());
        return false;
    }
    printf("Bound to %s\n", addrBind.ToString().c_str());

    // Listen for incoming connections
    if (listen(hListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf("Error: Listening for incoming connections failed (listen returned error %d)", WSAGetLastError());
        printf("%s\n", strError.c_str());
        return false;
    }

    vhListenSocket.push_back(hListenSocket);

    if (addrBind.IsRoutable() && fDiscover)
        AddLocal(addrBind, LOCAL_BIND);

    return true;
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
    RenameThread("bitcoin-start");

    if (semOutbound == NULL) {
        // initialize semaphore
        int nMaxOutbound = min( GetMaxOutboundConnections(), GetMaxConnections() );
        semOutbound = new CSemaphore(nMaxOutbound);
    }

    if (pnodeLocalHost == NULL)
        pnodeLocalHost = new CNode(INVALID_SOCKET, CAddress(CService("127.0.0.1", 0), nLocalServices));

    Discover();

    //
    // Start threads
    //

/*
    if (!GetBoolArg("-dnsseed", true))
        printf("DNS seeding disabled\n");
    else
        if (!NewThread(ThreadDNSAddressSeed, NULL))
            printf("Error: NewThread(ThreadDNSAddressSeed) failed\n");
*/

    if (!GetBoolArg("-dnsseed", false))
        printf("DNS seeding disabled\n");
    if (GetBoolArg("-dnsseed", false))
        printf("DNS seeding NYI\n");

    // Map ports with UPnP
    if (fUseUPnP)
        MapPort();

    // Get addresses from IRC and advertise ours
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

    // ppcoin: mint proof-of-stake blocks in the background
    if (!NewThread(ThreadStakeMinter, pwalletMain))
        printf("Error: NewThread(ThreadStakeMinter) failed\n");

    // Generate coins in the background
    GenerateBitcoins(GetBoolArg("-gen", false), pwalletMain);
}

bool StopNode()
{
    printf("StopNode()\n");
    fShutdown = true;
    nTransactionsUpdated++;
    int64 nStart = GetTime();
    if (semOutbound)
        for( int i = 0; i < GetMaxOutboundConnections(); i++ )
            semOutbound->post();
    do
    {
        int nThreadsRunning = 0;
        for (int n = 0; n < THREAD_MAX; n++)
            nThreadsRunning += vnThreadsRunning[n];
        if (nThreadsRunning == 0)
            break;
        if (GetTime() - nStart > 20)
            break;
        Sleep(20);
    } while(true);
    if (vnThreadsRunning[THREAD_SOCKETHANDLER] > 0) printf("ThreadSocketHandler still running\n");
    if (vnThreadsRunning[THREAD_OPENCONNECTIONS] > 0) printf("ThreadOpenConnections still running\n");
    if (vnThreadsRunning[THREAD_MESSAGEHANDLER] > 0) printf("ThreadMessageHandler still running\n");
    if (vnThreadsRunning[THREAD_MINER] > 0) printf("ThreadBitcoinMiner still running\n");
    if (vnThreadsRunning[THREAD_RPCLISTENER] > 0) printf("ThreadRPCListener still running\n");
    if (vnThreadsRunning[THREAD_RPCHANDLER] > 0) printf("ThreadsRPCServer still running\n");
#ifdef USE_UPNP
    if (vnThreadsRunning[THREAD_UPNP] > 0) printf("ThreadMapPort still running\n");
#endif
    if (vnThreadsRunning[THREAD_DNSSEED] > 0) printf("ThreadDNSAddressSeed still running\n");
    if (vnThreadsRunning[THREAD_ADDEDCONNECTIONS] > 0) printf("ThreadOpenAddedConnections still running\n");
    if (vnThreadsRunning[THREAD_DUMPADDRESS] > 0) printf("ThreadDumpAddresses still running\n");
    if (vnThreadsRunning[THREAD_MINTER] > 0) printf("ThreadStakeMinter still running\n");
    while (vnThreadsRunning[THREAD_MESSAGEHANDLER] > 0 || vnThreadsRunning[THREAD_RPCHANDLER] > 0)
        Sleep(20);
    Sleep(50);
    DumpAddresses();
    return true;
}

class CNetCleanup
{
public:
    CNetCleanup()
    {
    }
    ~CNetCleanup()
    {
#ifdef _MSC_VER
        bool
            fDidThisAlready = false;

        if( !fDidThisAlready )
        {
            fDidThisAlready = true;
            (void)printf(
                        "~CNetCleanup() destructor called..."
                        );
#endif
        // Close sockets
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (pnode->hSocket != INVALID_SOCKET)
                closesocket(pnode->hSocket);
        BOOST_FOREACH(SOCKET hListenSocket, vhListenSocket)
            if (hListenSocket != INVALID_SOCKET)
                if (closesocket(hListenSocket) == SOCKET_ERROR)
                    printf("closesocket(hListenSocket) failed with error %d\n", WSAGetLastError());

#ifdef WIN32
        // Shutdown Windows Sockets
        WSACleanup();
#endif
#ifdef _MSC_VER
            (void)printf( " done\n" );
            Sleep( 2000 );  // 2 seconds just to see who is the slowest to close
        }
#endif
    }
}
instance_of_cnetcleanup;

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
