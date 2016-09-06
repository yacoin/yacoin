#ifdef WIN32
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "strlcpy.h"
#include <vector>
#include "net.h"
#include "price.h"

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

 CCriticalSection cs_price;  // just want one call to getYACprice to not
                             // interrupt another call to the same function.


static const int
    nDefaultCharacterOffset = 3,
    nUnusualCharacterOffset = 2;
CProvider aBTCtoYACProviders[] =
    {
        {
            "data.bter.com",            // sDomain
            "last",                     // sPriceRatioKey
            "/api/1/ticker/yac_btc",    // sApi
            nDefaultCharacterOffset
        }
        ,
        {
            "pubapi2.cryptsy.com",
            "lasttradeprice",
            "/api.php?method=singlemarketdata&marketid=11",
            nDefaultCharacterOffset
        }
    };
CProvider aCurrencyToBTCProviders[] =
    {
        {
            "btc.blockr.io",
            "value",
            "/api/v1/coin/info",
            nUnusualCharacterOffset
        }
        ,
        {
            "api.bitcoinvenezuela.com",
            "USD",
            "/",
            nUnusualCharacterOffset
        }
        ,
        {
            "pubapi2.cryptsy.com",
            "lastdata",
            "/api.php?method=singlemarketdata&marketid=2",
            nDefaultCharacterOffset
        }
    };
std::vector< CProvider > vBTCtoYACProviders;
std::vector< CProvider > vUSDtoBTCProviders;


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
                    Sleep( nArbitraryShortTimeInMilliseconds );
                    continue;
                }
                // else it was something worthy of consideration?
            }
            if (!strLine.empty() )
                break;
            if (0 == nBytes)
            {   // done, socket closed
                return false;
            }
            else
            {   // socket error
                int
                    nErr = WSAGetLastError();
                printf("recv failed: error %d\n", nErr);
                clearLocalSocketError( hSocket );
                return false;
            }
        }
    }
    while( true );
    return true;
}

//_____________________________________________________________________________
static bool read_in_new_provider( std::string sKey, std::vector< CProvider > & vProviders )
{
    // here is where we should read in new providers from the configuration file
    // arguments, and add them to the vectors we already have.  This way we don't
    // have to recompile if there is even a temporary failure with a web provider.
    bool
        fProviderAdded;

    //fProviderAdded = IsProviderAdded( key, vProviders );

    std::string
        sProvider = GetArg( sKey, "" );

    static const int
        nArbitrayUrlDomainLength = 200,
        nArbitrayUrlArgumentLength = 200;

    CProvider
        cNewProvider;

    if( "" != sProvider )
    {
        string
            sTemp = "%200[^,],%200[^,],%200[^,],%d";

        if( fPrintToConsole )
        {
            printf( "scan string: %s\n", sTemp.c_str() );
        }
        printf( "received provider string:\n" );
        {
            printf( "%s\n", sProvider.c_str() );
        }
        if( nArbitrayUrlArgumentLength < (int)sProvider.length() )
        {   // could be trouble
            if( fPrintToConsole )
            {
                printf( "scan string: %s\n", sTemp.c_str() );
                printf( "Error: Probably too long?\n", sTemp.c_str() );
            }
            return false;
        }
        char
            caDomain[ nArbitrayUrlDomainLength + 1 ],
            caKey[ nArbitrayUrlDomainLength + 1 ],
            caApi[ nArbitrayUrlArgumentLength + 1 ];
        int
            nOffset,
            nPort;
        int
            nConverted = sscanf(
                                sProvider.c_str(),
                                sTemp.c_str(),
                                caDomain,
                                caKey,
                                caApi,
                                &nOffset
                               );
        if( 4 == nConverted )
        {
            cNewProvider.sDomain        = caDomain;
            cNewProvider.sPriceRatioKey = caKey;
            cNewProvider.sApi           = caApi;
            cNewProvider.nOffset        = nOffset;
            vProviders.insert( vProviders.begin(), cNewProvider );
          //vBTCtoYACProviders.push_back( cNewProvider );
          //nIndexBtcToYac = 0;
            if( fPrintToConsole )
            {
                printf( "adding new provider:"
                        "\n"
                        "%s\n%s\n%s\n%d"
                        "\n",
                        cNewProvider.sDomain.c_str(),
                        cNewProvider.sPriceRatioKey.c_str(),
                        cNewProvider.sApi.c_str(),
                        cNewProvider.nOffset
                      );
            }
            return true;
        }
        else
        {
            printf( "error parsing configuration file for provider, found string:"
                   "\n"
                   "%s"
                   "\n",
                   sProvider.c_str()
                  );
        }
    }
    return false;
}

//_____________________________________________________________________________
static void build_vectors()
{
    const int
        array_sizeUtoB = (int)( sizeof( aCurrencyToBTCProviders ) / sizeof( aCurrencyToBTCProviders[ 0 ] ) ),
        array_sizeBtoY = (int)( sizeof( aBTCtoYACProviders ) / sizeof( aBTCtoYACProviders[ 0 ] ) );

    for( int index = 0; index < array_sizeUtoB; ++index )
    {
        vUSDtoBTCProviders.push_back( aCurrencyToBTCProviders[ index ] );
    }
    for( int index = 0; index < array_sizeBtoY; ++index )
    {
        vBTCtoYACProviders.push_back( aBTCtoYACProviders[ index ] );
    }
}
//_____________________________________________________________________________

void initialize_price_vectors( int & nIndexBtcToYac, int & nIndexUsdToBtc )
{
    build_vectors();
    if( read_in_new_provider( "-btcyacprovider", vBTCtoYACProviders ) )
        nIndexBtcToYac = 0;
    if( read_in_new_provider( "-usdbtcprovider", vUSDtoBTCProviders) )
        nIndexUsdToBtc = 0;
}
//_____________________________________________________________________________

class CdoSocket
{
private:
    struct hostent
        *host;
    SOCKET
        SocketCopy;

    CdoSocket( const CdoSocket & );
    CdoSocket &operator = ( const CdoSocket & );

public:
    explicit CdoSocket( SOCKET & Socket, const string & sDomain, const int & nPort = DEFAULT_HTTP_PORT )
    {
        Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        host = gethostbyname( sDomain.c_str() );

        if( NULL != host )
        {
            SOCKADDR_IN
                SockAddr;

            SockAddr.sin_port = htons( (unsigned short)nPort ); // was 80
            SockAddr.sin_family = AF_INET;
            SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr); //  null ptr if net is down!!

            //cout << "Connecting...\n";

            int
                nResult = connect(Socket,(SOCKADDR*)(&SockAddr),sizeof(SockAddr) );

            if ( SOCKET_ERROR == nResult )
            {
                std::string
                    sS = strprintf(
                                    "Could not connect"
                                    "connect function failed with error: %d\n",
                                    WSAGetLastError()
                                  );
                clearLocalSocketError( Socket );
                nResult = closesocket(Socket);
                if (nResult == SOCKET_ERROR)
                    wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());
                //WSACleanup();
                throw runtime_error(
                        "getYACprice\n"
                        "Could not connect?"
                                   );
            }
            SocketCopy = Socket;
        }
        else    // network is down?
        {
            throw runtime_error(
                                "getYACprice\n"
                                "Network is down?"
                               );
        }
    }

    ~CdoSocket()
    {
        clearLocalSocketError( SocketCopy );
        closesocket( SocketCopy );
    }
};
//_____________________________________________________________________________
static bool GetMyExternalWebPage(
                          const string & sDomain,
                          const string & skey,
                          const char* pszTheFullUrl,
                          string & strBuffer,
                          double &dPrice,
                          const int & nOffset,
                          const int & nPort
                         )
{
    // here we should
    // pick a provider from vBTCtoYACProviders & vUSDtoBTCProviders
    // attempt a price, if fail, try another provider until OK, or error return
    //
    //
    {
        LOCK( cs_price );
        SOCKET
#ifdef _MSC_VER
            hSocket = NULL;
#else
            hSocket = 0;
#endif
        try
        {
            if( DEFAULT_HTTP_PORT != nPort )
            {
                CdoSocket
                    CthisSocketConnection(
                                          hSocket,
                                          sDomain,
                                          nPort
                                         );
            }
            else
            {
                CdoSocket
                    CthisSocketConnection(
                                          hSocket,
                                          sDomain           // for gethostbyname()
                                         );                 //RAII attempt on the socket!?
            }
        }
        catch( std::exception &e )
        {
            printf( "%s\n", (string("error: ") + e.what()).c_str() );
        }
        if (!hSocket)
        {
            return false;
        }
        else    //if (hSocket)    // then it's OK
        {
            int
                nUrlLength = (int)strlen(pszTheFullUrl),
                nBytesSent;
            {
                nBytesSent = send(hSocket, pszTheFullUrl, nUrlLength, MSG_NOSIGNAL);
            }
            if (nBytesSent != nUrlLength )
            {
                printf(
                        "send() error: only sent %d of %d?"
                        "\n",
                        nBytesSent,
                        nUrlLength
                      );
            }
            Sleep( nArbitraryShortTimeInMilliseconds );

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
                    if( string::npos != strLine.find( skey, 0 ) )
                    {
                        if(
                            ("" == skey)
                            ||
                            string::npos != strLine.find( skey, 0 )
                          )
                        {
                            string
                                sTemp;

                            if("" != skey)
                            {
                                if(
                                    ("USD" == skey)
                                    ||
                                    ("value" == skey)
                                  )
                                    sTemp = strLine.substr( strLine.find( skey, 0 ) + skey.size() + nOffset);
                                else
                                    sTemp = strLine.substr( strLine.find( skey, 0 ) + skey.size() + nOffset);
                            }
                            else
                                sTemp = strLine;

                            double
                                dTemp;

                            if (1 == sscanf( sTemp.c_str(), "%lf", &dTemp ) )
                            {
                               dPrice = dTemp;      // just so I can debug.  A good compiler
                                                    // can optimize this dTemp out!
                            }
                        }
                        // read rest of result
                        strLine = "";
                        do
                        {
                            fLineOK = recvAline(hSocket, strLine);
                            Sleep( nArbitraryShortTimeInMilliseconds ); // may not even be needed?
                            strLine = "";
                        }
                        while( fLineOK );
                        break;
                    }
                }
                strLine = "";
            }
            while( fLineOK );
        }
    }
    if ( 0 < strBuffer.size() )
    {
        if (fPrintToConsole)
        {
            printf(
                    "GetMyExternalWebPage() received:\n"
                    "%s"
                    "\n",
                    strBuffer.c_str()
                  );
        }
        if( dPrice > 0.0 )
        {
            return true;
        }
        else
            return false;
    }
    else
    {
        return error("error in recv() : connection closed?");
    }
}
//_____________________________________________________________________________
static bool GetExternalWebPage(
                        CProvider & Cprovider,
                        string & strBuffer,
                        double &dPriceRatio
                       )
{
    // we have all we need in Cprovider to get a price ratio,
    // first of YAC/BTC, then USD/BTC
    const string
        sLeadIn   = "GET ",
                    // here's where the api argument goes
        sPrologue = " HTTP/1.1"
                    "\r\n"
                    "Content-Type: text/html"
                    "\r\n"
                    "Accept: application/json, text/html"
                    "\r\n"
                    "Host: ",
                    // here's where the domain goes
        sEpilogue = "\r\n"
                    "Connection: close"
                    "\r\n"
                    "\r\n"
                    "";
    string
        sDomain          = Cprovider.sDomain,
        sPriceRatioKey   = Cprovider.sPriceRatioKey,
        sApi             = Cprovider.sApi;
    int
        nCharacterOffset = Cprovider.nOffset,
        nPort            = Cprovider.nPort;
    string
        sUrl = strprintf(
                         "%s%s%s%s%s",
                         sLeadIn.c_str(),
                         sApi.c_str(),
                         sPrologue.c_str(),
                         sDomain.c_str(),
                         sEpilogue.c_str()
                        );
    if (fPrintToConsole)
    {
        string
            sfb = strprintf( "Command:\n%s\n", sUrl.c_str() );
        printf( "%s", sfb.c_str() );
    }
    const char
        *pszTheFullUrl = sUrl.c_str();
    bool
        fReturnValue = GetMyExternalWebPage(
                                            sDomain,
                                            sPriceRatioKey,
                                            pszTheFullUrl,
                                            strBuffer,
                                            dPriceRatio,
                                            nCharacterOffset,
                                            nPort
                                           );
    return fReturnValue;
}
//_____________________________________________________________________________
bool GetMyExternalWebPage1( int & nIndexBtcToYac, string & strBuffer, double & dPrice )
{
    CProvider
        Cprovider;
    int
        nSaved = nIndexBtcToYac,
        nSize = (int)vBTCtoYACProviders.size();
    do
    {
        Cprovider = vBTCtoYACProviders[ nIndexBtcToYac ];
        if (GetExternalWebPage(
                                Cprovider,
                                strBuffer,
                                dPrice
                              )
           )
        {
            break;
        }
        //else  // failure, so try another provider
        nIndexBtcToYac = (++nIndexBtcToYac < nSize)? nIndexBtcToYac: nIndexBtcToYac = 0;
        if( nSaved == nIndexBtcToYac )    // we can't find a provider, so quit
        {
            return error( "can't find a provider for page 1?" );
        }
    }while( true );
    return true;
}
//_____________________________________________________________________________

bool GetMyExternalWebPage2( int & nIndexUsdToBtc, string & strBuffer, double & dPrice )
{
    CProvider
        Cprovider;
    int
        nSaved = nIndexUsdToBtc,
        nSize = (int)vUSDtoBTCProviders.size();
    do
    {
        Cprovider = vUSDtoBTCProviders[ nIndexUsdToBtc ];
        if (GetExternalWebPage(
                                Cprovider,
                                strBuffer,
                                dPrice
                              )
           )
        {
            break;
        }
        //else  // failure, so try another provider
        nIndexUsdToBtc = (++nIndexUsdToBtc < nSize)? nIndexUsdToBtc: nIndexUsdToBtc = 0;
        if( nSaved == nIndexUsdToBtc )    // we can't find a provider, so quit
        {
            return error( "can't find a provider for page 2?" );
        }
    }while( true );

    return true;
}
//_____________________________________________________________________________

#ifdef WIN32

double doGetYACprice()
{
    // first call gets BTC/YAC ratio
    // second call gets USD/BTC, so the product is USD/YAC
    double
        dPriceRatio = 0.0,
        dUSDperYACprice = 0.0,
        dUSDtoBTCprice = 0.0,
        dBTCtoYACprice = 0.0;

    string
        sDestination = "";

    // if the provider is good, which we could use the next time called
    // we could save which one say in a static index, set to 0 initially
    static int
        nIndexBtcToYac = 0,
        nIndexUsdToBtc = 0; // these both assume that the arrays have >= 1 element each!
    static bool
        fCopied = false;
    if( !fCopied )
    {
        initialize_price_vectors( nIndexBtcToYac, nIndexUsdToBtc );
        fCopied = true;
    }

    if (!GetMyExternalWebPage1( nIndexBtcToYac, sDestination, dPriceRatio ) )
    {
        throw runtime_error( "getYACprice\n" "Could not get page 1?" );
        return dUSDperYACprice;
    }
    //else    //OK, now we have YAC/BTC (Cryptsy's terminology), really BTC/YAC
    dBTCtoYACprice = dPriceRatio;
    sDestination = "";
    dPriceRatio = 0.0;
     if (!GetMyExternalWebPage2( nIndexUsdToBtc, sDestination, dPriceRatio ) )
    {
        throw runtime_error( "getYACprice\n" "Could not get page 2?" );
        return dUSDperYACprice;
    }
    // else USD/BTC is OK
    dUSDtoBTCprice = dPriceRatio;

    dUSDperYACprice = dBTCtoYACprice * dUSDtoBTCprice;
    if (fPrintToConsole)
    {
        printf(
                "b/y %lf, $/b %lf, $/y = %lf"
                "\n"
                , dBTCtoYACprice
                , dUSDtoBTCprice
                , dUSDperYACprice
              );
    }
    return dUSDperYACprice;
}

Value getYACprice(const Array& params, bool fHelp)
{
    if (
        fHelp ||
        (0 < params.size())
       )
    {
        throw runtime_error(
            "getyacprice \n"
            "Returns the current price of YAC in USD"
                           );
    }

    string sTemp;
    try
    {
        double
            dPrice = doGetYACprice();

        sTemp = strprintf( "%0.8lf", dPrice );
    }
    catch( std::exception &e )
    {
        printf( "%s\n", (string("error: ") + e.what()).c_str() );
        sTemp = "";
    }
    return sTemp;
}

#ifdef _MSC_VER
bool
    isThisInGMT( time_t & tBlock, struct tm  &aTimeStruct )
{
    bool
        fIsGMT = true;  // the least of all evils

    struct tm
        gmTimeStruct;

    if( !_localtime64_s( &aTimeStruct, &tBlock ) )   // OK
    {
        // are we in GMT?      to          from
        if( !_gmtime64_s( &gmTimeStruct, &tBlock ) )   // OK we can compare
        {
            if(
               // tBlock != _mkgmtime( &aTimeStruct )
               ( (aTimeStruct).tm_hour != (gmTimeStruct).tm_hour ) ||  // .tm_hour && .tm_mday
               ( (aTimeStruct).tm_mday != (gmTimeStruct).tm_mday )     // .tm_hour && .tm_mday
              )
                fIsGMT = false;
          //else    // we are in GMT to begin with
        }
      //else    // _gmtime64_s() errored
    }
    //else //_localtime64_s() errored
    return fIsGMT;
}
#endif

Value getcurrentblockandtime(const Array& params, bool fHelp)
{
    if (
        fHelp ||
        (0 != params.size())
       )
        throw runtime_error(
            "getblockcountt\n"
            "Returns the number of blocks in the longest block chain and "
            "the time of the latest block.  And in local time if different than GMT/UTC."
                           );

    CBlockIndex
        * pbi = FindBlockByHeight(nBestHeight);

    CBlock
        block;

    block.ReadFromDisk(pbi);

    struct tm
        aTimeStruct;

    time_t
        tBlock = block.GetBlockTime();

#ifdef _MSC_VER
    char
        buff[30];

    bool
        fIsGMT = true;  // the least of all evils
    fIsGMT = isThisInGMT( tBlock, aTimeStruct );
/**************
    struct tm
        gmTimeStruct;
    if( !_localtime64_s( &aTimeStruct, &tBlock ) )   // OK
    {
        // are we in GMT?      to          from
        if( !_gmtime64_s( &gmTimeStruct, &tBlock ) )   // OK we can compare
        {
            if(
               // tBlock != _mkgmtime( &aTimeStruct )
               ( (aTimeStruct).tm_hour != (gmTimeStruct).tm_hour ) ||  // .tm_hour && .tm_mday
               ( (aTimeStruct).tm_mday != (gmTimeStruct).tm_mday )     // .tm_hour && .tm_mday
              )
                fIsGMT = false;
          //else    // we are in GMT to begin with
        }
      //else    // _gmtime64_s() errored
    }
    //else //_localtime64_s() errored
**********************/
#else
    struct tm
        *paTimeStruct,
        *pgmTimeStruct;
    char
        *pbuff;
    bool
        fIsGMT = true;  // the least of all evils
    std::string
        strS;

    if( NULL != ( paTimeStruct = localtime( &tBlock ) ) )   // OK
    {
        aTimeStruct = *paTimeStruct;
        if( NULL != (pgmTimeStruct = gmtime( &tBlock ) ) )   // OK we can compare
        {
            if(
               ( (aTimeStruct).tm_hour != (*pgmTimeStruct).tm_hour ) ||  // .tm_hour && .tm_mday
               ( (aTimeStruct).tm_mday != (*pgmTimeStruct).tm_mday )     // .tm_hour && .tm_mday
              )
                fIsGMT = false;
            else    // we are in GMT to begin with
                strS = "Appear to be in GMT!?";   // this is what hits
        }
        else    // _gmtime64_s() errored
            strS = "gmtime() errored!?";
    }
    else //_localtime64_s() errored
        strS = "localtime() errored!?";
    if( true == fIsGMT )
    {
        fIsGMT = false;
        return strS;
    }
#endif
    if( fIsGMT )// for GMT or having errored trying to convert from GMT
    {
        std::string
            strS = strprintf(
                             "%d %s"
                             "\n"
                             "",
                             int(nBestHeight),
                             DateTimeStrFormat(
                                  " %Y-%m-%d %H:%M:%S",
                                  block.GetBlockTime()
                                              ).c_str()
                            );
        return strS;
    }
    // let's cook up local time
#ifdef _MSC_VER
    asctime_s( buff, sizeof(buff), &aTimeStruct );
    buff[ 24 ] = '\0';      // let's wipe out the \n
    printf( //"Local Time: "
            "%s"
            "\n"
            ""
            , buff );

    std::string
        strS = strprintf(
                         "%d %s (local %s)"
                         "\n"
                         "",
                         int(nBestHeight),
                         DateTimeStrFormat(
                              " %Y-%m-%d %H:%M:%S",
                              block.GetBlockTime()
                                          ).c_str()
                         ,
                         buff
                        );
#else
    pbuff = asctime( &aTimeStruct );
    if( '\n' == pbuff[ 24 ] )
        pbuff[ 24 ] = '\0';
    printf( //"Local Time: "
            "%s"
            "\n"
            ""
            , pbuff );
    strS = strprintf(
                     "%d %s (local %s)"
                     "\n"
                     "",
                     int(nBestHeight),
                     DateTimeStrFormat(
                          " %Y-%m-%d %H:%M:%S",
                          block.GetBlockTime()
                                      ).c_str()
                     ,
                     pbuff
                    );
#endif
    return strS;
}
#endif

#endif // WIN32
