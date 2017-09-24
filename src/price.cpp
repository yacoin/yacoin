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

#ifndef BITCOIN_NET_H
 #include "net.h"
#endif

#ifndef BITCOIN_STRLCPY_H
 #include "strlcpy.h"
#endif

#include <vector>

using std::string;
using std::runtime_error;
using std::vector;

const int 
    nArbitraryShortTimeInMilliseconds = nTenMilliseconds;
CCriticalSection 
    cs_price;  // just want one call to getYACprice to not
               // interrupt another call to the same function.

static const int
    nHttpsPort = 443,
    nSpecialCharacterOffset = 4,
    nDefaultCharacterOffset = 3,
    nUnusualCharacterOffset = 2;
CProvider aBTCtoYACProviders[] = 
    {    
        {   //http://api.coinmarketcap.com/v1/ticker/yacoin/
            "api.coinmarketcap.com",
            "price_btc",    //"price_usd",
            "/v1/ticker/yacoin/",
            nSpecialCharacterOffset,
            DEFAULT_HTTPS_PORT
        },
        {   
            "data.bter.com",            // sDomain
            "avg",                     // sPriceRatioKey
            "/api/1/ticker/yac_btc",    // sApi
            nDefaultCharacterOffset,
            DEFAULT_HTTP_PORT
        }
        ,
        {   //api.cryptonator.com/api/ticker/yac-btc
            "api.cryptonator.com", 
            "price", 
            "/api/ticker/yac-btc", 
            nDefaultCharacterOffset,
            DEFAULT_HTTP_PORT            //nHttpsPort
        }
        ,
        {   
            "pubapi2.cryptsy.com",      
            "lasttradeprice",   
            "/api.php?method=singlemarketdata&marketid=11", 
            nDefaultCharacterOffset,
            DEFAULT_HTTP_PORT
        }
    };
CProvider aCurrencyToBTCProviders[] = 
    {
        {   
            "api.bitcoinvenezuela.com",
            "USD",
            "/",
            nUnusualCharacterOffset,
            DEFAULT_HTTP_PORT
        }
        ,
        {   
            "btc.blockr.io",
            "value",
            "/api/v1/coin/info",
            nUnusualCharacterOffset,
            DEFAULT_HTTP_PORT
        }
        ,
        {   
            "pubapi2.cryptsy.com",
            "lastdata",
            "/api.php?method=singlemarketdata&marketid=2",
            nDefaultCharacterOffset,
            DEFAULT_HTTP_PORT
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
    //bool
    //    fProviderAdded;

    //fProviderAdded = IsProviderAdded( key, vProviders );

/*************************
*************************/

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
            sTemp = "%200[^,],%200[^,],%200[^,],%d,%d";

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
                printf( "Error: Probably too long?\n" );
            }
            return false;
        }
        char
            caDomain[ nArbitrayUrlDomainLength + 1 ],
            caKey[ nArbitrayUrlDomainLength + 1 ],
            caApi[ nArbitrayUrlArgumentLength + 1 ];
        int
            nPortNumber,
            nOffset;
        int
            nConverted = sscanf( 
                                sProvider.c_str(),
                                sTemp.c_str(),
                                caDomain,
                                caKey,
                                caApi,
                                &nOffset,
                                &nPortNumber
                               );
        if( 5 == nConverted )
        {
            cNewProvider.sDomain        = caDomain;
            cNewProvider.sPriceRatioKey = caKey;
            cNewProvider.sApi           = caApi;
            cNewProvider.nOffset        = nOffset;
            cNewProvider.nPort          = nPortNumber;

            vProviders.insert( vProviders.begin(), cNewProvider );
          //vBTCtoYACProviders.push_back( cNewProvider );
          //nIndexBtcToYac = 0;
            if( fPrintToConsole )
            {
                printf( "adding new provider:"
                        "\n"
                        "%s\n%s\n%s\n%d\n%d"
                        "\n",
                        cNewProvider.sDomain.c_str(),
                        cNewProvider.sPriceRatioKey.c_str(),
                        cNewProvider.sApi.c_str(),
                        cNewProvider.nOffset,
                        cNewProvider.nPort 
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
// this is the only section that needs a non Windows bit of code
// in this class, the ctor needs to be 'linux-ed', in other words
// how does one initialize and connect a socket in a non Windows environment?
// The MSVC++ & gcc in Windows versions work fine

// test of https
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
/*
#include <iostream>
#include <istream>
#include <ostream>
#include <string>
*/ 
 
class CClient
{
public:
	CClient(
			boost::asio::io_service& io_service, 
			boost::asio::ssl::context& context, 
			boost::asio::ip::tcp::resolver::iterator endpoint_iterator,
            const char *pszApi,
            const string & sDomain
	      ) : socket_(io_service, context), read_buffer_length( 866 ), sdomain( sDomain )

	{
        pszapi = pszApi;
        
        socket_.set_verify_mode( boost::asio::ssl::context::verify_none );
		socket_.set_verify_callback( 
									boost::bind(
												&CClient::verify_certificate, 
												this, 
												_1, 
												_2
											   )
								   );
 
	    boost::asio::async_connect(
								socket_.lowest_layer(), 
								endpoint_iterator, 
								boost::bind(
											&CClient::handle_connect, 
											this, 
											boost::asio::placeholders::error
										   )
								   );
	}
 
	bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx)
	{
		char subject_name[256];
		X509
			* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
			
		X509_NAME_oneline( X509_get_subject_name(cert), subject_name, 256 );
    
		std::cout << "Verifying:\n" << subject_name << std::endl;
 
		return preverified;
	}
 
	void handle_connect(const boost::system::error_code& error)
	{
		if(!error)
		{
			std::cout << "Connection OK!" << std::endl;
			socket_.async_handshake(
									boost::asio::ssl::stream_base::client, 
									boost::bind(
												&CClient::handle_handshake, 
												this, 
												boost::asio::placeholders::error
											   )
								   );
		}
		else
		{
			std::cout << "Connect failed: " << error.message() << std::endl;
		}
	}
 
	void handle_handshake(const boost::system::error_code& error)
	{
		if(!error)
		{
			std::cout << "Sending request: " << std::endl;
     
		std::stringstream request_;
 
        //https://api.coinmarketcap.com/v1/ticker/yacoin/

        //request_ << "POST " << rRequest.mcURI << " HTTP/1.1\r\n";
        //request_ << "Host: " << rRequest.mcHost << "\r\n";

	    request_ << "GET ";
	  //request_ << "POST ";
		
		request_ << pszapi; //"/v1/ticker/yacoin/ ";

		request_ << "HTTP/1.1\r\n";
		
		request_ << "Host: ";
		request_ << (sdomain + "\r\n").c_str() ;    //"api.coinmarketcap.com\r\n";
		
		request_ << "Accept-Encoding: application/json\r\n";

        //request_ << "Accept: application/json\r\n";
        request_ << "Accept: */*\r\n";

        request_ << "Content-Type: application/json; charset=UTF-8\r\n";
      //request_ << "Content-Type: application/text; charset=UTF-8\r\n";

        request_ << "Connection: close\r\n";
      //request_ << "Connection: keep-alive\r\n";

		request_ << "\r\n";
 
	  //std::cout << request_.str() << std::endl;
		std::cout << request_.str();
 
		boost::asio::async_write(
								socket_, 
								boost::asio::buffer(request_.str()), 
								boost::bind(
											&CClient::handle_write, 
											this, 
											boost::asio::placeholders::error, 
											boost::asio::placeholders::bytes_transferred
											)
								);
		}
		else
		{
			std::cout << "Handshake failed: " << error.message() << std::endl;
		}
	}
 
	void handle_write(const boost::system::error_code& error, size_t bytes_transferred)
	{
		if (!error)
		{
			std::cout << "Sending request OK!" << std::endl;
            //Sleep( 2 * nMillisecondsPerSecond );
			boost::asio::async_read(
									socket_, 
									boost::asio::buffer(
														reply_, 
														read_buffer_length //685   //bytes_transferred bullshit
                                                       ), 
									boost::bind(
												&CClient::handle_read, 
												this, 
												boost::asio::placeholders::error
                                                , boost::asio::placeholders::bytes_transferred
											   )
							       );
		}
		else
		{
			std::cout << "Write failed: " << error.message() << std::endl;
		}
	}
 
	void handle_read(const boost::system::error_code& error, size_t bytes_transferred)
	{
		if (!error)
		{
			std::cout << "Reply: ";
			std::cout.write(reply_, bytes_transferred);
			std::cout << std::endl;
			std::cout << "Reply done";
		  std::cout << ", count ";
		  std::cout << bytes_transferred;
			std::cout << std::endl;
		}
		else
		{
			std::cout << "Read failed: " << error.message() << std::endl;
		}
	}
 
private:
	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
	char reply_[0x1 << 16];
    const size_t read_buffer_length;
    const char *pszapi;
    const string & sdomain;

};
#ifdef _DEBUG
/*********************
//int main(int argc, char* argv[])
{
	try
	{
		boost::asio::io_service io_service;
 
		boost::asio::ip::tcp::resolver resolver( io_service );
		boost::asio::ip::tcp::resolver::query query( 
                                                    "api.coinmarketcap.com",
													"443"
												   );
		boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
 
		boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
	  //context.load_verify_file( "key.pem" );
		context.load_verify_file( "server.pem" );
 
		CClient c(io_service, context, iterator);
 
		io_service.run();
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << "\n";
		std::cout << "Exception: " << e.what() << "\n";
	}
 
    {
	    //std::cin.get();
        //// for test purposes
//        printf("Shutdown requested. Exiting.\n");
//        return false;
    }
}
*****************/
#endif
// end of test


class CdoSocket
{
private:
    struct hostent 
        *host;
#ifdef WIN32
    SOCKET      // in Windows, this is a UINT_PTR (see winsock2.h or ws2def.h)
                // in linux, I don't know, maybe uint32_t?
#else
    u_int
#endif
        SocketCopy;

    CdoSocket( const CdoSocket & );
    CdoSocket &operator = ( const CdoSocket & );

public:
    explicit CdoSocket(
#ifdef WIN32
                        SOCKET 
#else
                        u_int
#endif
                        & Socket, 
                        const string & sDomain, 
                        const int & nPort = DEFAULT_HTTP_PORT 
                      )
    {
        int
            nResult;

        SocketCopy = 
#ifdef _MSC_VER
            NULL;
#else
            0;
#endif
#ifdef WIN32
        Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
        // You have to put what's appropriate here?
        // from https://www.gnu.org/software/libc/manual/html_node/Inet-Example.html
        Socket = socket(PF_INET, SOCK_STREAM, 0);
#endif
        host = gethostbyname( sDomain.c_str() );

        if( NULL != host )
        {
#ifdef WIN32
            SOCKADDR_IN 
#else
            struct sockaddr_in 
#endif
                SockAddr;
#ifndef WIN32
            ;   // you have to put whatever is appropriate here?  Maybe something like this:
    #ifdef SO_NOSIGPIPE
            int set = 1;
            setsockopt(Socket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
    #endif
#endif
            SockAddr.sin_port = htons( (unsigned short)nPort ); // was 80
            SockAddr.sin_family = AF_INET;
            SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr); //  null ptr if net is down!!

#ifndef WIN32
            // Maybe linux needs something like this:
            int fFlags = fcntl(Socket, F_GETFL, 0);    // then more code??? Eventually
#endif
            //cout << "Connecting...\n";

#ifdef WIN32
            nResult = connect(Socket,(SOCKADDR *)(&SockAddr),sizeof(SockAddr) );
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
                if ( SOCKET_ERROR == nResult )
                    wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());
                //WSACleanup();
#else
            nResult = connect( Socket, (struct sockaddr *)&SockAddr, sizeof(struct sockaddr) );
            if ( -1 == nResult )
            {
                nResult = closesocket(Socket);  //I'm guessing here as I don't linux!
#endif
#ifdef _MSC_VER
                Socket = NULL;
#else
                Socket = 0;
#endif
              //throw runtime_error(
                (void)printf(
                        "getYACprice\n"
                        "Could not connect?"
                            );
            }
            SocketCopy = Socket;        // success
        }
        else    // network is down?
        {
            nResult = closesocket(Socket);
#ifdef WIN32
            if ( SOCKET_ERROR == nResult )
                wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());
            //WSACleanup();
#else
            if ( -1 == nResult )
                ;   // maybe some code?
#endif            

#ifdef _MSC_VER
            Socket = NULL;
#else
            Socket = 0;
#endif
         // throw runtime_error(
            (void)printf(
                         "getYACprice\n"
                         "Network is down?"
                        );
        }
    }

    ~CdoSocket()
    {
#ifdef _MSC_VER
        if (NULL != SocketCopy)
#else
        if (0 != SocketCopy)
#endif
        {
            clearLocalSocketError( SocketCopy );
            closesocket( SocketCopy );
        }
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
                          const int & nPort,
                          const char *pszApi
                         )
{
    // here we should
    // pick a provider from vBTCtoYACProviders & vUSDtoBTCProviders
    // attempt a price, if fail, try another provider until OK, or error return
    // 
    //
    {
        LOCK( cs_price );


        if (DEFAULT_HTTPS_PORT == nPort)
        {
        	try
        	{
        	    boost::asio::io_service io_service;
 
    	        boost::asio::ip::tcp::resolver resolver( io_service );
        		boost::asio::ip::tcp::resolver::query query( 
                                                        sDomain.c_str(),    //"api.coinmarketcap.com",
		    											strprintf( "\"%d\"", (int)DEFAULT_HTTPS_PORT ).c_str()  //"443"
		        										   );
        		boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
 
	            boost::asio::ssl::context context(boost::asio::ssl::context::sslv23);
        	  //context.load_verify_file( "key.pem" );
		        context.load_verify_file( "server.pem" );
 
        	    CClient c(io_service, context, iterator, pszApi, sDomain);
 
    	        io_service.run();
                // we should parse the result here and set dPrice & return true
                // else on error return false
        	}
        	catch (std::exception& e)
            {
		        std::cerr << "Exception: " << e.what() << "\n";
        	    std::cout << "Exception: " << e.what() << "\n";
                return false;
            }
            // we should exit here
            if( dPrice > 0.0 )
            {
                return true;
            }
            else
                return false;
        }
#ifdef _MSC_VER
        SOCKET 
            hSocket = NULL;
#else
        u_int
            hSocket = 0;
#endif
        try
        {
            CdoSocket 
                CthisSocketConnection( 
                                      hSocket,
                                      sDomain,
                                      nPort
                                     );
            if (
                (!hSocket) &&
                (DEFAULT_HTTPS_PORT != nPort)
               )
            {
                return false;
            }
            //else    //if (hSocket)    // then it's OK

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
        catch( std::exception &e )
        {
            printf( "%s\n", (string("error: ") + e.what()).c_str() );
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
        sPrologue = 
                    (DEFAULT_HTTP_PORT == Cprovider.nPort)? 
                    " HTTP/1.1"
                    "\r\n" 
                    "Content-Type: text/html"
                    "\r\n"
                    "Accept: application/json, text/html"
                    "\r\n"
                    "Host: "
                    // here's where the domain goes
                    : 
                    " HTTPS"
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
                                            nPort,
                                            sApi.c_str()
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
            if( dPrice > 0.0 )
            {
                if( fPrintToConsole )
                {
                    printf(
                            "\n"
                            "y/b = %lf"
                            "\n"
                            , 1.0/dPrice
                          );
                }
            }
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
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
