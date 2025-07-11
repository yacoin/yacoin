// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>
    #include "msvc_warnings.push.h"

 #ifndef BITCOIN_INIT_H
    #include "init.h"
 #endif
 #ifndef _BITCOINRPC_H_
    #include "bitcoinrpc.h"
 #endif

    #undef printf

    #include <boost/asio.hpp>
    #include <boost/asio/ip/v6_only.hpp>
    #include <boost/iostreams/stream.hpp>
    #include <boost/algorithm/string.hpp>
    #include <boost/asio/ssl.hpp>
#else
#include "init.h"
#include "util.h"
#include "sync.h"
#include "ui_interface.h"
#include "base58.h"
#include "bitcoinrpc.h"
#include "db.h"
#include "net_processing.h"

#undef printf
#include <boost/asio.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/iostreams/concepts.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/shared_ptr.hpp>
#include <list>
#include <openssl/rand.h>

#endif

using namespace boost;
using namespace boost::asio;
using namespace json_spirit;

using std::string;
using std::list;
using std::runtime_error;
using std::map;
using std::vector;
using std::set;
using std::ostringstream;
using std::invalid_argument;

void ThreadRPCServer2(void* parg);

static std::string strRPCUserColonPass;

const Object emptyobj;

void ThreadRPCServer3(void* parg);

static inline unsigned short GetDefaultRPCPort()
{
    return gArgs.GetBoolArg("-testnet", false)? 17687: 7687;
}

Object JSONRPCError(int code, const string& message)
{
    Object error;
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}

void RPCTypeCheck(const Array& params,
                  const list<Value_type>& typesExpected,
                  bool fAllowNull)
{
    unsigned int i = 0;
    BOOST_FOREACH(Value_type t, typesExpected)
    {
        if (params.size() <= i)
            break;

        const Value& v = params[i];
        if (!((v.type() == t) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s, got %s",
                                   Value_type_name[t], Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
        i++;
    }
}

void RPCTypeCheck(const Object& o,
                  const map<string, Value_type>& typesExpected,
                  bool fAllowNull)
{
    BOOST_FOREACH(const PAIRTYPE(string, Value_type)& t, typesExpected)
    {
        const Value& v = find_value(o, t.first);
        if (!fAllowNull && v.type() == null_type)
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing %s", t.first.c_str()));

        if (!((v.type() == t.second) || (fAllowNull && (v.type() == null_type))))
        {
            string err = strprintf("Expected type %s for %s, got %s",
                                   Value_type_name[t.second], t.first.c_str(), Value_type_name[v.type()]);
            throw JSONRPCError(RPC_TYPE_ERROR, err);
        }
    }
}

::int64_t AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > MAX_MONEY)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    ::int64_t nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    return nAmount;
}

std::string TokenValueFromAmount(const CAmount& amount, const std::string token_name)
{

    auto currentActiveTokenCache = GetCurrentTokenCache();
    if (!currentActiveTokenCache)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Token cache isn't available.");

    uint8_t units = OWNER_UNITS;
    if (!IsTokenNameAnOwner(token_name)) {
        CNewToken tokenData;
        if (!currentActiveTokenCache->GetTokenMetaDataIfExists(token_name, tokenData))
            units = MAX_UNIT;
            //throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't load token from cache: " + token_name);
        else
            units = tokenData.units;
    }

    return TokenValueFromAmountString(amount, units);
}

std::string TokenValueFromAmountString(const CAmount& amount, const int8_t units)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    remainder = remainder / pow(10, MAX_UNIT - units);

    if (units == 0 && remainder == 0) {
        return strprintf("%s%d", sign ? "-" : "", quotient);
    }
    else {
        return strprintf("%s%d.%0" + std::to_string(units) + "d", sign ? "-" : "", quotient, remainder);
    }
}

Value ValueFromAmount(::int64_t amount)
{
    return (double)amount / (double)COIN;
}

std::string ValueFromAmountStr(const CAmount& amount)
{
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / COIN;
    int64_t remainder = n_abs % COIN;
    return strprintf("%s%d.%06d", sign ? "-" : "", quotient, remainder);
}

std::string HexBits(unsigned int nBits)
{
    union
    {
        ::int32_t nBits;
        char cBits[4];
    } uBits;
    uBits.nBits = htonl((::int32_t)nBits);
    return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}


//
// Utilities: convert hex-encoded Values
// (throws error if not hex).
//
uint256 ParseHashV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}

uint256 ParseHashO(const Object& o, string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}

vector<unsigned char> ParseHexV(const Value& v, string strName)
{
    string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}

vector<unsigned char> ParseHexO(const Object& o, string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}


///
/// Note: This interface may still be subject to change.
///

string CRPCTable::help(string strCommand) const
{
    string strRet = "";
    set<rpcfn_type> setDone;
    boost::to_lower( strCommand );
    for (map<string, const CRPCCommand*>::const_iterator mi = mapCommands.begin(); mi != mapCommands.end(); ++mi)
    {
        const CRPCCommand *pcmd = mi->second;
        string strMethod = mi->first;
        // We already filter duplicates, but these deprecated screw up the sort order
        if (strMethod.find("label") != string::npos)
            continue;
        if (strCommand != "" && strMethod != strCommand)
            continue;
        try
        {
            Array params;
            rpcfn_type pfn = pcmd->actor;
            if (setDone.insert(pfn).second)
                (*pfn)(params, true);
        }
        catch (const std::exception& e)
        {   // Help text is returned in an exception
            string strHelp = string(e.what());
            if (strCommand == "")
                if (strHelp.find('\n') != string::npos)
                    strHelp = strHelp.substr(0, strHelp.find('\n'));
            strRet += strHelp + "\n";
        }
         catch (...) 
        {
            string strHelp = string("Unknown help Error?");
            if ( "" == strCommand )         // just a help w/ no arguments
            {
                if (strHelp.find('\n') != string::npos) // there is a \n in the message
                {
                    strHelp = strHelp.substr(0, strHelp.find('\n')); // truncate at that point, why?
                }
            }
            strRet += strHelp + "\n";
        }
    }
    if (strRet == "")
        strRet = strprintf("help: unknown command: %s\n", strCommand.c_str());
    strRet = strRet.substr(0,strRet.size()-1);
    return strRet;
}

Value help(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
    {
        throw runtime_error(
                            "help [command]\n"
                            "List commands, or get help for a command."
                           );
      //throw invalid_argument( "help [command]\n" "List commands, or get help for a command." );
    }
    string strCommand = "";
    if (params.size() > 0)
        strCommand = params[0].get_str();

    return tableRPC.help(strCommand);
}


Value stop(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "stop <detach>\n"
            "<detach> is true or false to detach the database or not for this stop only\n"
            "Stop YaCoin server (and possibly override the detachdb config value).");
    // Shutdown will take long enough that the response should get back
    if (params.size() > 0)
        bitdb.SetDetach(params[0].get_bool());
    StartShutdown();
    return "YaCoin server stopping";
}

Value getrpcinfo(const Array& params, bool fHelp){
    if(fHelp){
        throw runtime_error(
            "getrpcinfo\n"
            "Returns details of the RPC server.\n");
    }    
    
    Object command;
    command.push_back(Pair("method","getrpcinfo"));
    command.push_back(Pair("duration",1));
    
    Array commands;
    commands.push_back(command);

    Object res;
    res.push_back(Pair("active_commands",commands));
    res.push_back(Pair("logpath",GetDebugLogPathName()));
    res.push_back(Pair("RPCport", gArgs.GetArg("-rpcport", GetDefaultRPCPort()) ));
    return res;
}

Value setmocktime(const Array& params, bool fHelp){
    if(fHelp){
        throw runtime_error(
            "setmocktime <timestamp>\n"
            "<timestamp> mocktimestamp to be set\n");
    }

    SetMockTime(params[0].get_int64());

    return Value::null;
}

//
// HTTP protocol
//
// This ain't Apache.  We're just using HTTP header for the length field
// and to be compatible with other JSON-RPC implementations.
//

string HTTPPost(const string& strMsg, const map<string,string>& mapRequestHeaders)
{
    ostringstream s;
    s << "POST / HTTP/1.1\r\n"
      << "User-Agent: yacoin-json-rpc/" << FormatFullVersion() << "\r\n"
      << "Host: 127.0.0.1\r\n"
      << "Content-Type: application/json\r\n"
      << "Content-Length: " << strMsg.size() << "\r\n"
      << "Connection: close\r\n"
      << "Accept: application/json\r\n";
    BOOST_FOREACH(const PAIRTYPE(string, string)& item, mapRequestHeaders)
        s << item.first << ": " << item.second << "\r\n";
    s << "\r\n" << strMsg;

    return s.str();
}

string rfc1123Time()
{
    char buffer[64];
    time_t now;
    time(&now);
    struct tm* now_gmt = gmtime(&now);
    string locale(setlocale(LC_TIME, NULL));
    setlocale(LC_TIME, "C"); // we want POSIX (aka "C") weekday/month strings
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S +0000", now_gmt);
    setlocale(LC_TIME, locale.c_str());
    return string(buffer);
}

static string HTTPReply(int nStatus, const string& strMsg, bool keepalive)
{
    if (nStatus == HTTP_UNAUTHORIZED)
        return strprintf("HTTP/1.0 401 Authorization Required\r\n"
            "Date: %s\r\n"
            "Server: yacoin-json-rpc/%s\r\n"
            "WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 296\r\n"
            "\r\n"
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n"
            "\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n"
            "<HTML>\r\n"
            "<HEAD>\r\n"
            "<TITLE>Error</TITLE>\r\n"
            "<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n"
            "</HEAD>\r\n"
            "<BODY><H1>401 Unauthorized.</H1></BODY>\r\n"
            "</HTML>\r\n", rfc1123Time().c_str(), FormatFullVersion().c_str());
    const char *cStatus;
         if (nStatus == HTTP_OK) cStatus = "OK";
    else if (nStatus == HTTP_BAD_REQUEST) cStatus = "Bad Request";
    else if (nStatus == HTTP_FORBIDDEN) cStatus = "Forbidden";
    else if (nStatus == HTTP_NOT_FOUND) cStatus = "Not Found";
    else if (nStatus == HTTP_INTERNAL_SERVER_ERROR) cStatus = "Internal Server Error";
    else cStatus = "";
    return strprintf(
            "HTTP/1.1 %d %s\r\n"
            "Date: %s\r\n"
            "Connection: %s\r\n"
            "Content-Length: %" PRIszu "\r\n"
            "Content-Type: application/json\r\n"
            "Server: yacoin-json-rpc/%s\r\n"
            "\r\n"
            "%s",
        nStatus,
        cStatus,
        rfc1123Time().c_str(),
        keepalive ? "keep-alive" : "close",
        strMsg.size(),
        FormatFullVersion().c_str(),
        strMsg.c_str());
}

int ReadHTTPStatus(std::basic_istream<char>& stream, int &proto)
{
    string str;
    getline(stream, str);
    vector<string> vWords;
    boost::split(vWords, str, boost::is_any_of(" "));
    if (vWords.size() < 2)
        return HTTP_INTERNAL_SERVER_ERROR;
    proto = 0;
    const char *ver = strstr(str.c_str(), "HTTP/1.");
    if (ver != NULL)
        proto = atoi(ver+7);
    return atoi(vWords[1].c_str());
}

int ReadHTTPHeader(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet)
{
    int nLen = 0;
    while (true)
    {
        string str;
        std::getline(stream, str);
        if (str.empty() || str == "\r")
            break;
        string::size_type nColon = str.find(":");
        if (nColon != string::npos)
        {
            string strHeader = str.substr(0, nColon);
            boost::trim(strHeader);
            boost::to_lower(strHeader);
            string strValue = str.substr(nColon+1);
            boost::trim(strValue);
            mapHeadersRet[strHeader] = strValue;
            if (strHeader == "content-length")
                nLen = atoi(strValue.c_str());
        }
    }
    return nLen;
}

int ReadHTTP(std::basic_istream<char>& stream, map<string, string>& mapHeadersRet, string& strMessageRet)
{
    mapHeadersRet.clear();
    strMessageRet = "";

    // Read status
    int nProto = 0;
    int nStatus = ReadHTTPStatus(stream, nProto);

    // Read header
    int nLen = ReadHTTPHeader(stream, mapHeadersRet);
    if (nLen < 0 || nLen > (int)MAX_SIZE)
        return HTTP_INTERNAL_SERVER_ERROR;

    // Read message
    if (nLen > 0)
    {
        vector<char> vch(nLen);
        stream.read(&vch[0], nLen);
        strMessageRet = string(vch.begin(), vch.end());
    }

    string sConHdr = mapHeadersRet["connection"];

    if ((sConHdr != "close") && (sConHdr != "keep-alive"))
    {
        if (nProto >= 1)
            mapHeadersRet["connection"] = "keep-alive";
        else
            mapHeadersRet["connection"] = "close";
    }

    return nStatus;
}

bool HTTPAuthorized(map<string, string>& mapHeaders)
{
    string strAuth = mapHeaders["authorization"];
    if (strAuth.substr(0,6) != "Basic ")
        return false;
    string strUserPass64 = strAuth.substr(6); boost::trim(strUserPass64);
    string strUserPass = DecodeBase64(strUserPass64);
    return TimingResistantEqual(strUserPass, strRPCUserColonPass);
}

//
// JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
// but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
// unspecified (HTTP errors and contents of 'error').
//
// 1.0 spec: http://json-rpc.org/wiki/specification
// 1.2 spec: http://groups.google.com/group/json-rpc/web/json-rpc-over-http
// http://www.codeproject.com/KB/recipes/JSON_Spirit.aspx
//

string JSONRPCRequest(const string& strMethod, const Array& params, const Value& id)
{
    Object request;
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return write_string(Value(request), false) + "\n";
}

Object JSONRPCReplyObj(const Value& result, const Value& error, const Value& id)
{
    Object reply;
    if (error.type() != null_type)
        reply.push_back(Pair("result", Value::null));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return reply;
}

string JSONRPCReply(const Value& result, const Value& error, const Value& id)
{
    Object reply = JSONRPCReplyObj(result, error, id);
    return write_string(Value(reply), false) + "\n";
}

void ErrorReply(std::ostream& stream, const Object& objError, const Value& id)
{
    // Send error reply from json-rpc error object
    int nStatus = HTTP_INTERNAL_SERVER_ERROR;
    int code = find_value(objError, "code").get_int();
    if (code == RPC_INVALID_REQUEST) nStatus = HTTP_BAD_REQUEST;
    else if (code == RPC_METHOD_NOT_FOUND) nStatus = HTTP_NOT_FOUND;
    string strReply = JSONRPCReply(Value::null, objError, id);
    stream << HTTPReply(nStatus, strReply, false) << std::flush;
}

bool ClientAllowed(const boost::asio::ip::address& address)
{
    // Make sure that IPv4-compatible and IPv4-mapped IPv6 addresses are treated as IPv4 addresses
    if (address.is_v6()
     && (address.to_v6().is_v4_compatible()
      || address.to_v6().is_v4_mapped()))
        return ClientAllowed(address.to_v6().to_v4());

    if (address == asio::ip::address_v4::loopback()
     || address == asio::ip::address_v6::loopback()
     || (address.is_v4()
         // Check whether IPv4 addresses match 127.0.0.0/8 (loopback subnet)
      && (address.to_v4().to_ulong() & 0xff000000) == 0x7f000000))
        return true;

    const string strAddress = address.to_string();
    for (const std::string& strAllow : gArgs.GetArgs("-rpcallowip")) {
        if (WildcardMatch(strAddress, strAllow))
            return true;
    }
    return false;
}

//
// IOStream device that speaks SSL but can also speak non-SSL
//
template <typename Protocol>
class SSLIOStreamDevice : public iostreams::device<iostreams::bidirectional> {
public:
    SSLIOStreamDevice(asio::ssl::stream<typename Protocol::socket> &streamIn, bool fUseSSLIn) : stream(streamIn)
    {
        fUseSSL = fUseSSLIn;
        fNeedHandshake = fUseSSLIn;
    }

    void handshake(ssl::stream_base::handshake_type role)
    {
        if (!fNeedHandshake) return;
        fNeedHandshake = false;
        stream.handshake(role);
    }
    std::streamsize read(char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::server); // HTTPS servers read first
        if (fUseSSL) return stream.read_some(asio::buffer(s, n));
        return stream.next_layer().read_some(asio::buffer(s, n));
    }
    std::streamsize write(const char* s, std::streamsize n)
    {
        handshake(ssl::stream_base::client); // HTTPS clients write first
        if (fUseSSL) return asio::write(stream, asio::buffer(s, n));
        return asio::write(stream.next_layer(), asio::buffer(s, n));
    }
    bool connect(const std::string& server, const std::string& port)
    {
        ip::tcp::resolver resolver(stream.get_io_service());
        ip::tcp::resolver::query query(server.c_str(), port.c_str());
        ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        ip::tcp::resolver::iterator end;
        boost::system::error_code error = asio::error::host_not_found;
        while (error && endpoint_iterator != end)
        {
            stream.lowest_layer().close();
            stream.lowest_layer().connect(*endpoint_iterator++, error);
        }
        if (error)
            return false;
        return true;
    }

private:
    bool fNeedHandshake;
    bool fUseSSL;
    asio::ssl::stream<typename Protocol::socket>& stream;
};

class AcceptedConnection
{
public:
    virtual ~AcceptedConnection() {}

    virtual std::iostream& stream() = 0;
    virtual std::string peer_address_to_string() const = 0;
    virtual void close() = 0;
};

template <typename Protocol>
class AcceptedConnectionImpl : public AcceptedConnection
{
public:
    AcceptedConnectionImpl(
            asio::io_service& io_service,
            ssl::context &context,
            bool fUseSSL) :
        sslStream(io_service, context),
        _d(sslStream, fUseSSL),
        _stream(_d)
    {
    }

    virtual std::iostream& stream()
    {
        return _stream;
    }

    virtual std::string peer_address_to_string() const
    {
        return peer.address().to_string();
    }

    virtual void close()
    {
        _stream.close();
    }

    typename Protocol::endpoint peer;
    asio::ssl::stream<typename Protocol::socket> sslStream;

private:
    SSLIOStreamDevice<Protocol> _d;
    iostreams::stream< SSLIOStreamDevice<Protocol> > _stream;
};

void ThreadRPCServer(void* parg)
{
    // Make this thread recognisable as the RPC listener
    RenameThread("yacoin-rpclistener");

    try
    {
        vnThreadsRunning[THREAD_RPCLISTENER]++;
        ThreadRPCServer2(parg);
        vnThreadsRunning[THREAD_RPCLISTENER]--;
    }
    catch (std::exception& e) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(&e, "ThreadRPCServer()");
    } catch (...) {
        vnThreadsRunning[THREAD_RPCLISTENER]--;
        PrintException(NULL, "ThreadRPCServer()");
    }
    LogPrintf("ThreadRPCServer exited\n");
}

// Forward declaration required for RPCListen
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error);

/**
 * Sets up I/O resources to accept and handle a new connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCListen(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                   ssl::context& context,
                   const bool fUseSSL)
{
    // Accept connection
    AcceptedConnectionImpl<Protocol>* conn = new AcceptedConnectionImpl<Protocol>(acceptor->get_io_service(), context, fUseSSL);

    acceptor->async_accept(
            conn->sslStream.lowest_layer(),
            conn->peer,
            boost::bind(&RPCAcceptHandler<Protocol, SocketAcceptorService>,
                acceptor,
                boost::ref(context),
                fUseSSL,
                conn,
                boost::asio::placeholders::error));
}

/**
 * Accept and handle incoming connection.
 */
template <typename Protocol, typename SocketAcceptorService>
static void RPCAcceptHandler(boost::shared_ptr< basic_socket_acceptor<Protocol, SocketAcceptorService> > acceptor,
                             ssl::context& context,
                             const bool fUseSSL,
                             AcceptedConnection* conn,
                             const boost::system::error_code& error)
{
    vnThreadsRunning[THREAD_RPCLISTENER]++;

    // Immediately start accepting new connections, except when we're cancelled or our socket is closed.
    if (error != asio::error::operation_aborted
     && acceptor->is_open())
        RPCListen(acceptor, context, fUseSSL);

    AcceptedConnectionImpl<ip::tcp>* tcp_conn = dynamic_cast< AcceptedConnectionImpl<ip::tcp>* >(conn);

    // TODO: Actually handle errors
    if (error)
    {
        delete conn;
    }

    // Restrict callers by IP.  It is important to
    // do this before starting client thread, to filter out
    // certain DoS and misbehaving clients.
    else if (tcp_conn
          && !ClientAllowed(tcp_conn->peer.address()))
    {
        // Only send a 403 if we're not using SSL to prevent a DoS during the SSL handshake.
        if (!fUseSSL)
            conn->stream() << HTTPReply(HTTP_FORBIDDEN, "", false) << std::flush;
        delete conn;
    }

    // start HTTP client thread
    else if (!NewThread(ThreadRPCServer3, conn)) {
        LogPrintf("Failed to create RPC server client thread\n");
        delete conn;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
}

void ThreadRPCServer2(void* parg)
{
    LogPrintf("ThreadRPCServer2 started\n");

    strRPCUserColonPass = gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", "");
    if (gArgs.GetArg("-rpcpassword", "") == "")
    {
        unsigned char rand_pwd[32];
        RAND_bytes(rand_pwd, 32);
        string strWhatAmI = "To use yacoind";
        if (gArgs.IsArgSet("-server"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-server\"");
        else if (gArgs.IsArgSet("-daemon"))
            strWhatAmI = strprintf(_("To use the %s option"), "\"-daemon\"");
        uiInterface.ThreadSafeMessageBox(strprintf(
            _("%s, you must set a rpcpassword in the configuration file:\n %s\n"
              "It is recommended you use the following random password:\n"
              "rpcuser=yacoinrpc\n"
              "rpcpassword=%s\n"
              "(you do not need to remember this password)\n"
              "If the file does not exist, create it with owner-readable-only file permissions.\n"),
                strWhatAmI.c_str(),
                GetConfigFile(gArgs.GetArg("-conf", YACOIN_CONF_FILENAME)).string().c_str(),
                EncodeBase58(&rand_pwd[0],&rand_pwd[0]+32).c_str()),
            _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        StartShutdown();
        return;
    }

    const bool fUseSSL = gArgs.GetBoolArg("-rpcssl");

    asio::io_service io_service;

    ssl::context context(io_service, ssl::context::sslv23);
    if (fUseSSL)
    {
        context.set_options(ssl::context::no_sslv2);

        filesystem::path
            pathCertFile(gArgs.GetArg("-rpcsslcertificatechainfile", "server.cert"));

        if (!pathCertFile.is_complete()) 
            pathCertFile = filesystem::path(GetDataDir()) / pathCertFile;
        if (filesystem::exists(pathCertFile))
            context.use_certificate_chain_file(pathCertFile.string());
        else
          LogPrintf(
              "ThreadRPCServer2 ERROR: missing server certificate file %s\n",
              pathCertFile.string());

        filesystem::path
            pathPKFile(gArgs.GetArg("-rpcsslprivatekeyfile", "server.pem"));
        if (!pathPKFile.is_complete())
            pathPKFile = filesystem::path(GetDataDir()) / pathPKFile;
        if (filesystem::exists(pathPKFile))
            context.use_private_key_file(pathPKFile.string(), ssl::context::pem); // causes exceptions???
        else
          LogPrintf(
              "ThreadRPCServer2 ERROR: missing server private key file %s\n",
              pathPKFile.string());

        string
            strCiphers = gArgs.GetArg("-rpcsslciphers", "TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH");
        SSL_CTX_set_cipher_list(context.impl(), strCiphers.c_str());
    }

    // Try a dual IPv6/IPv4 socket, falling back to separate IPv4 and IPv6 sockets
    const bool loopback = !gArgs.IsArgSet("-rpcallowip");
    asio::ip::address bindAddress = loopback ? asio::ip::address_v6::loopback() : asio::ip::address_v6::any();
    ip::tcp::endpoint endpoint(bindAddress, gArgs.GetArg("-rpcport", GetDefaultRPCPort()));
    boost::system::error_code v6_only_error;
    boost::shared_ptr<ip::tcp::acceptor> acceptor(new ip::tcp::acceptor(io_service));

    boost::signals2::signal<void ()> StopRequests;

    bool fListening = false;
    std::string strerr;
    try
    {
        acceptor->open(endpoint.protocol());
        acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        // Try making the socket dual IPv6/IPv4 (if listening on the "any" address)
        acceptor->set_option(boost::asio::ip::v6_only(loopback), v6_only_error);

        acceptor->bind(endpoint);
        acceptor->listen(socket_base::max_connections);

        RPCListen(acceptor, context, fUseSSL);
        // Cancel outstanding listen-requests for this acceptor when shutting down
        StopRequests.connect(signals2::slot<void ()>(
                    static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
                .track(acceptor));

        fListening = true;
    }
    catch(boost::system::system_error &e)
    {
        strerr = strprintf(_("An error occurred while setting up the RPC port %u for listening on IPv6, falling back to IPv4: %s"), endpoint.port(), e.what());
    }

    try {
        // If dual IPv6/IPv4 failed (or we're opening loopback interfaces only), open IPv4 separately
        if (!fListening || loopback || v6_only_error)
        {
            bindAddress = loopback ? asio::ip::address_v4::loopback() : asio::ip::address_v4::any();
            endpoint.address(bindAddress);

            acceptor.reset(new ip::tcp::acceptor(io_service));
            acceptor->open(endpoint.protocol());
            acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
            acceptor->bind(endpoint);
            acceptor->listen(socket_base::max_connections);

            RPCListen(acceptor, context, fUseSSL);
            // Cancel outstanding listen-requests for this acceptor when shutting down
            StopRequests.connect(signals2::slot<void ()>(
                        static_cast<void (ip::tcp::acceptor::*)()>(&ip::tcp::acceptor::close), acceptor.get())
                    .track(acceptor));

            fListening = true;
        }
    }
    catch(boost::system::system_error &e)
    {
        strerr = strprintf(_("An error occurred while setting up the RPC port %u for listening on IPv4: %s"), endpoint.port(), e.what());
    }

    if (!fListening) {
        uiInterface.ThreadSafeMessageBox(strerr, _("Error"), CClientUIInterface::OK | CClientUIInterface::MODAL);
        StartShutdown();
        return;
    }

    vnThreadsRunning[THREAD_RPCLISTENER]--;
    while (!fShutdown)
        io_service.run_one();
    vnThreadsRunning[THREAD_RPCLISTENER]++;
    StopRequests();
}

class JSONRequest
{
public:
    Value id;
    string strMethod;
    Array params;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
    void convertParameterObjectToArray(string method, Value& valParams);
};

void JSONRequest::convertParameterObjectToArray(string method, Value& valParams){    
    params = Array();
    if(method == "importprivkey"){
        // copy those params in the order as expected by the improvprivkey function
        params.push_back(find_value(valParams.get_obj(), "privkey"));
        params.push_back(find_value(valParams.get_obj(), "label"));
    } else if(method == "generatetoaddress"){
        params.push_back(find_value(valParams.get_obj(), "nblocks"));
        Value addressValue = find_value(valParams.get_obj(), "address");
        if(!addressValue.is_null()){
            params.push_back(addressValue);
        }        
        Value maxtriesValue = find_value(valParams.get_obj(), "maxtries");
        if(!maxtriesValue.is_null()){
            params.push_back(maxtriesValue);
        }
    } else if (method == "getblockcount" || method == "getwalletinfo" || method == "stop") {
        // these methods do not require any parameter
    }
}

void JSONRequest::parse(const Value& valRequest)
{
    // Parse request
    if (valRequest.type() != obj_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid Request object");
    const Object& request = valRequest.get_obj();

    // Parse id now so errors from here on will have the id
    id = find_value(request, "id");

    // Parse method
    Value valMethod = find_value(request, "method");
    if (valMethod.type() == null_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Missing method");
    if (valMethod.type() != str_type)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Method must be a string");
    strMethod = valMethod.get_str();
    LogPrintf("ThreadRPCServer method=%s\n", strMethod);

    // Parse params
    Value valParams = find_value(request, "params");
    if(valParams.type() == obj_type)
    {
        convertParameterObjectToArray(valMethod.get_str(), valParams);
    }
    else if (valParams.type() == array_type)
    {
        params = valParams.get_array();
    }
    else if (valParams.type() == null_type)
    {
        params = Array();
    }
    else
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array");
    }
}

static Object JSONRPCExecOne(const Value& req)
{
    Object rpc_result;

    JSONRequest jreq;
    try
    {
        jreq.parse(req);

        Value result = tableRPC.execute(jreq.strMethod, jreq.params);
        rpc_result = JSONRPCReplyObj(result, Value::null, jreq.id);
    }
    catch (Object& objError)
    {
        rpc_result = JSONRPCReplyObj(Value::null, objError, jreq.id);
    }
    catch (std::exception& e)
    {
        rpc_result = JSONRPCReplyObj(Value::null,
                                     JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
    }

    return rpc_result;
}

static string JSONRPCExecBatch(const Array& vReq)
{
    Array ret;
    for (unsigned int reqIdx = 0; reqIdx < vReq.size(); reqIdx++)
        ret.push_back(JSONRPCExecOne(vReq[reqIdx]));

    return write_string(Value(ret), false) + "\n";
}

static CCriticalSection cs_THREAD_RPCHANDLER;

void ThreadRPCServer3(void* parg)
{
    // Make this thread recognisable as the RPC handler
    RenameThread("yacoin-rpchandler");

    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]++;
    }
    AcceptedConnection *conn = (AcceptedConnection *) parg;

    bool fRun = true;
    while (true)
    {
        if (fShutdown || !fRun)
        {
            conn->close();
            delete conn;
            {
                LOCK(cs_THREAD_RPCHANDLER);
                --vnThreadsRunning[THREAD_RPCHANDLER];
            }
            return;
        }
        map<string, string> mapHeaders;
        string strRequest;

        ReadHTTP(conn->stream(), mapHeaders, strRequest);

        // Check authorization
        if (mapHeaders.count("authorization") == 0)
        {
            conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (!HTTPAuthorized(mapHeaders))
        {
            LogPrintf("ThreadRPCServer3 incorrect password attempt from %s\n", conn->peer_address_to_string());
            /* Deter brute-forcing short passwords.
               If this results in a DOS the user really
               shouldn't have their RPC port exposed.*/
            if (gArgs.GetArg("-rpcpassword", "").size() < 20)
                Sleep(250);

            conn->stream() << HTTPReply(HTTP_UNAUTHORIZED, "", false) << std::flush;
            break;
        }
        if (mapHeaders["connection"] == "close")
            fRun = false;

        JSONRequest jreq;
        try
        {
            // Parse request
            Value valRequest;
            if (!read_string(strRequest, valRequest))
                throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");

            string strReply;

            // singleton request
            if (valRequest.type() == obj_type) {
                jreq.parse(valRequest);

                Value result = tableRPC.execute(jreq.strMethod, jreq.params);

                // Send reply
                strReply = JSONRPCReply(result, Value::null, jreq.id);

            // array of requests
            } else if (valRequest.type() == array_type)
                strReply = JSONRPCExecBatch(valRequest.get_array());
            else
                throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");

            conn->stream() << HTTPReply(HTTP_OK, strReply, fRun) << std::flush;
        }
        catch (Object& objError)
        {
            ErrorReply(conn->stream(), objError, jreq.id);
            break;
        }
        catch (std::exception& e)
        {
            ErrorReply(conn->stream(), JSONRPCError(RPC_PARSE_ERROR, e.what()), jreq.id);
            break;
        }
    }

    delete conn;
    {
        LOCK(cs_THREAD_RPCHANDLER);
        vnThreadsRunning[THREAD_RPCHANDLER]--;
    }
}

json_spirit::Value CRPCTable::execute(const std::string &strMethod, const json_spirit::Array &params) const
{
    // Find method
    const CRPCCommand *pcmd = tableRPC[strMethod];
    if (!pcmd)
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Method not found");

    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !gArgs.GetBoolArg("-disablesafemode") &&
        !pcmd->okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);

    try
    {
        // Execute
        Value result;
        {
            if (pcmd->unlocked)
                result = pcmd->actor(params, false);
            else 
            {
                LOCK2(cs_main, pwalletMain->cs_wallet);
                result = pcmd->actor(params, false);
            }
        }
        return result;
    }
    catch (std::exception& e)
    {
        throw JSONRPCError(RPC_MISC_ERROR, e.what());
    }
}


Object CallRPC(const string& strMethod, const Array& params)
{
    if (gArgs.GetArg("-rpcuser", "") == "" && gArgs.GetArg("-rpcpassword", "") == "")
        throw runtime_error(strprintf(
            _("You must set rpcpassword=<password> in the configuration file:\n%s\n"
              "If the file does not exist, create it with owner-readable-only file permissions."),
              GetConfigFile(gArgs.GetArg("-conf", YACOIN_CONF_FILENAME)).string().c_str()));

    // Connect to localhost
    bool fUseSSL = gArgs.GetBoolArg("-rpcssl");
    asio::io_service io_service;
    ssl::context context(io_service, ssl::context::sslv23);
    context.set_options(ssl::context::no_sslv2);
    asio::ssl::stream<asio::ip::tcp::socket> sslStream(io_service, context);
    SSLIOStreamDevice<asio::ip::tcp> d(sslStream, fUseSSL);
    iostreams::stream< SSLIOStreamDevice<asio::ip::tcp> > stream(d);
    if (!d.connect(gArgs.GetArg("-rpcconnect", "127.0.0.1"), gArgs.GetArg("-rpcport", itostr(GetDefaultRPCPort()))))
        throw runtime_error("couldn't connect to server");

    // HTTP basic authentication
    string strUserPass64 = EncodeBase64(gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", ""));
    map<string, string> mapRequestHeaders;
    mapRequestHeaders["Authorization"] = string("Basic ") + strUserPass64;

    // Send request
    string strRequest = JSONRPCRequest(strMethod, params, 1);
    string strPost = HTTPPost(strRequest, mapRequestHeaders);
    stream << strPost << std::flush;

    // Receive reply
    map<string, string> mapHeaders;
    string strReply;
    int nStatus = ReadHTTP(stream, mapHeaders, strReply);
    if (nStatus == HTTP_UNAUTHORIZED)
        throw runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (nStatus >= 400 && nStatus != HTTP_BAD_REQUEST && nStatus != HTTP_NOT_FOUND && nStatus != HTTP_INTERNAL_SERVER_ERROR)
        throw runtime_error(strprintf("server returned HTTP error %d", nStatus));
    else if (strReply.empty())
        throw runtime_error("no response from server");

    // Parse reply
    Value valReply;
    if (!read_string(strReply, valReply))
        throw runtime_error("couldn't parse reply from server");
    const Object& reply = valReply.get_obj();
    if (reply.empty())
        throw runtime_error("expected reply to have result, error and id properties");

    return reply;
}




template<typename T>
void ConvertTo(Value& value, bool fAllowNull=false)
{
    if (fAllowNull && value.type() == null_type)
        return;
    if (value.type() == str_type)
    {
        // reinterpret string as unquoted json value
        Value value2;
        string strJSON = value.get_str();
        if (!read_string(strJSON, value2))
            throw runtime_error(string("Error parsing JSON:")+strJSON);
        ConvertTo<T>(value2, fAllowNull);
        value = value2;
    }
    else
    {
        value = value.get_value<T>();
    }
}

//
// Call Table
//

static const CRPCCommand vRPCCommands[] =
{ //  name                      function                 safemd  unlocked
  //  ------------------------  -----------------------  ------  --------
    { "help",                   &help,                   true,   false },
    { "stop",                   &stop,                   true,   true  },
    { "getbestblockhash",       &getbestblockhash,       true,   false },
    { "gettimechaininfo",       &gettimechaininfo,       true,   false },
    { "getblockcount",          &getblockcount,          true,   false },
    { "getwalletinfo",          &getwalletinfo,          true,   false },
    { "getrpcinfo",             &getrpcinfo,             true,   false },
    { "setmocktime",            &setmocktime,            true,   false },
#ifdef WIN32
    { "getblockcountt",         &getcurrentblockandtime, true,   false },
#endif
    { "getyacprice",            &getYACprice,            true,   false },
    // network start
    { "getconnectioncount",     &getconnectioncount,     true,   false },
    { "ping",                   &ping,                   true,   true },
    { "getaddrmaninfo",         &getaddrmaninfo,         true,   false },
    { "getpeerinfo",            &getpeerinfo,            true,   false },
    { "addnode",                &addnode,                true,   true  },
    { "disconnectnode",         &disconnectnode,         true,   true  },
    { "getaddednodeinfo",       &getaddednodeinfo,       true,   true  },
    { "getnettotals",           &getnettotals,           true,   true  },
    { "getnetworkinfo",         &getnetworkinfo,         true,   true  },
    { "setban",                 &setban,                 true,   true  },
    { "listbanned",             &listbanned,             true,   true  },
    { "clearbanned",            &clearbanned,            true,   true  },
    { "setnetworkactive",       &setnetworkactive,       true,   true  },
    // network end
    { "getdifficulty",          &getdifficulty,          true,   false },
    { "getinfo",                &getinfo,                true,   false },
    { "getgenerate",            &getgenerate,            true,   false },
    { "setgenerate",            &setgenerate,            true,   false },
    { "generatetoaddress",      &generatetoaddress,      true,   true  },
    { "getsubsidy",             &getsubsidy,             true,   false },
    { "gethashespersec",        &gethashespersec,        true,   false },
    { "getmininginfo",          &getmininginfo,          true,   false },
    { "getnewaddress",          &getnewaddress,          true,   false },
    { "getaccountaddress",      &getaccountaddress,      true,   false },
    { "setaccount",             &setaccount,             true,   false },
    { "getaccount",             &getaccount,             false,  false },
    { "getaddressesbyaccount",  &getaddressesbyaccount,  true,   false },
    { "sendtoaddress",          &sendtoaddress,          false,  false },
    { "mergecoins",             &mergecoins,             false,  false },
    { "getreceivedbyaddress",   &getreceivedbyaddress,   false,  false },
    { "getreceivedbyaccount",   &getreceivedbyaccount,   false,  false },
    { "listreceivedbyaddress",  &listreceivedbyaddress,  false,  false },
    { "listreceivedbyaccount",  &listreceivedbyaccount,  false,  false },
    { "backupwallet",           &backupwallet,           true,   false },
    { "keypoolrefill",          &keypoolrefill,          true,   false },
    { "keypoolreset",           &keypoolreset,           true,   false },
    { "walletpassphrase",       &walletpassphrase,       true,   false },
    { "walletpassphrasechange", &walletpassphrasechange, false,  false },
    { "walletlock",             &walletlock,             true,   false },
    { "encryptwallet",          &encryptwallet,          false,  false },
    { "validateaddress",        &validateaddress,        true,   false },
    { "getbalance",             &getbalance,             false,  false },
    { "getavailablebalance",    &getavailablebalance,    false,  false },
    { "move",                   &movecmd,                false,  false },
    { "sendfrom",               &sendfrom,               false,  false },
    { "sendmany",               &sendmany,               false,  false },
    { "addmultisigaddress",     &addmultisigaddress,     false,  false },
	{ "createcltvaddress",     	&createcltvaddress,	     false,  false },
	{ "spendcltv",     			&spendcltv,	     		 false,  false },
	{ "createcsvaddress",       &createcsvaddress,       false,  false },
	{ "spendcsv",               &spendcsv,               false,  false },
    { "addredeemscript",        &addredeemscript,        false,  false },
    { "describeredeemscript",   &describeredeemscript,   false,  false },
    { "getrawmempool",          &getrawmempool,          true,   false },
    { "getblock",               &getblock,               false,  false },
    { "getblockbynumber",       &getblockbynumber,       false,  false },
    { "getblocktimes",          &getblocktimes,          false,  false },
    { "getblockhash",           &getblockhash,           false,  false },
    { "gettransaction",         &gettransaction,         false,  false },
    { "listtransactions",       &listtransactions,       false,  false },
    { "listaddressgroupings",   &listaddressgroupings,   false,  false },
    { "signmessage",            &signmessage,            false,  false },
    { "verifymessage",          &verifymessage,          false,  false },
    { "getwork",                &getwork,                true,   false },
    { "getworkex",              &getworkex,              true,   false },
    { "listaccounts",           &listaccounts,           false,  false },
    { "settxfee",               &settxfee,               false,  false },
    { "getblocktemplate",       &getblocktemplate,       true,   false },
    { "submitblock",            &submitblock,            false,  false },
    { "listsinceblock",         &listsinceblock,         false,  false },
    { "dumpprivkey",            &dumpprivkey,            false,  false },
    { "dumpwallet",             &dumpwallet,             true,   false },
    { "importwallet",           &importwallet,           false,  false },
    { "importprivkey",          &importprivkey,          false,  false },
    { "importaddress",          &importaddress,          false,  true  },
    { "removeaddress",          &removeaddress,          false,  true  },
    { "listunspent",            &listunspent,            false,  false },
    { "getrawtransaction",      &getrawtransaction,      false,  false },
    { "createrawtransaction",   &createrawtransaction,   false,  false },
    { "decoderawtransaction",   &decoderawtransaction,   false,  false },
    { "createmultisig",         &createmultisig,         false,  false },
    { "decodescript",           &decodescript,           false,  false },
    { "signrawtransaction",     &signrawtransaction,     false,  false },
    { "sendrawtransaction",     &sendrawtransaction,     false,  false },
    { "getcheckpoint",          &getcheckpoint,          true,   false },
    { "reservebalance",         &reservebalance,         false,  true  },
    { "checkwallet",            &checkwallet,            false,  true  },
    { "repairwallet",           &repairwallet,           false,  true  },
    { "resendtx",               &resendtx,               false,  true  },
    { "makekeypair",            &makekeypair,            false,  true  },
    /** YAC_TOKEN START */
    { "issue",                  &issue,                  false,  false },
    { "transfer",               &transfer,               false,  false },
    { "transferfromaddress",    &transferfromaddress,    false,  false },
    { "reissue",                &reissue,                false,  false },
    { "listmytokens",           &listmytokens,           false,  false },
    { "listtokens",             &listtokens,             false,  false },
    { "listaddressesbytoken",   &listaddressesbytoken,   false,  false },
    { "listtokenbalancesbyaddress",   &listtokenbalancesbyaddress,   false,  false },
    { "getaddressbalance",      &getaddressbalance,      false,  false },
    { "getaddressdeltas",       &getaddressdeltas,       false,  false },
    { "getaddressutxos",        &getaddressutxos,        false,  false },
    { "getaddresstxids",        &getaddresstxids,        false,  false },
    /** YAC_TOKEN END */
    { "timelockcoins",          &timelockcoins,          false,  false }
};

CRPCTable::CRPCTable()
{
    unsigned int vcidx;
    for (vcidx = 0; vcidx < (sizeof(vRPCCommands) / sizeof(vRPCCommands[0])); vcidx++)
    {
        const CRPCCommand *pcmd;

        pcmd = &vRPCCommands[vcidx];
        mapCommands[pcmd->name] = pcmd;
    }
}

const CRPCCommand *CRPCTable::operator[](string name) const
{
    map<string, const CRPCCommand*>::const_iterator it = mapCommands.find(name);
    if (it == mapCommands.end())
        return NULL;
    return (*it).second;
}

// Convert strings to command-specific RPC representation
Array RPCConvertValues(std::string &strMethod, const std::vector<std::string> &strParams)
{
    Array params;
    BOOST_FOREACH(const std::string &param, strParams)
        params.push_back(param);

    int n = params.size();

    //
    // Special case non-string parameter types
    //
    boost::to_lower( strMethod );
    if (strMethod == "stop"                   && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "getaddednodeinfo"       && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "setgenerate"            && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "setgenerate"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "sendtoaddress"          && n > 1) ConvertTo<double>(params[1]); // amount
    if (strMethod == "sendtoaddress"          && n > 2) ConvertTo<bool>(params[2]); // useExpiredTimelockUTXO
    if (strMethod == "mergecoins"            && n > 0) ConvertTo<double>(params[0]);
    if (strMethod == "mergecoins"            && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "mergecoins"            && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "settxfee"               && n > 0) ConvertTo<double>(params[0]);
    if (strMethod == "getreceivedbyaddress"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "getreceivedbyaccount"   && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "listreceivedbyaddress"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "listreceivedbyaddress"  && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "listreceivedbyaccount"  && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "listreceivedbyaccount"  && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getbalance"             && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "getavailablebalance"    && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "getblock"               && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblocktimes"          && n > 0) ConvertTo<int>(params[0]);
    if (strMethod == "getblockbynumber"       && n > 0) ConvertTo<int>(params[0]);
    if (strMethod == "getblockbynumber"       && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "getblockhash"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "move"                   && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "move"                   && n > 3) ConvertTo<boost::int64_t>(params[3]);
    if (strMethod == "sendfrom"               && n > 2) ConvertTo<double>(params[2]);
    if (strMethod == "sendfrom"               && n > 3) ConvertTo<bool>(params[3]);
    if (strMethod == "sendfrom"               && n > 4) ConvertTo<boost::int64_t>(params[4]);
    if (strMethod == "gettransaction"         && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "listtransactions"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "listtransactions"       && n > 2) ConvertTo<boost::int64_t>(params[2]);
    if (strMethod == "listaccounts"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "listaccounts"           && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "walletpassphrase"       && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "walletpassphrase"       && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "getblocktemplate"       && n > 0) ConvertTo<Object>(params[0]);
    if (strMethod == "listsinceblock"         && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "listsinceblock"         && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "sendmany"               && n > 1) ConvertTo<Object>(params[1]);
    if (strMethod == "sendmany"               && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "sendmany"               && n > 3) ConvertTo<boost::int64_t>(params[3]);
    if (strMethod == "reservebalance"         && n > 0) ConvertTo<bool>(params[0]);
    if (strMethod == "reservebalance"         && n > 1) ConvertTo<double>(params[1]);
    if (strMethod == "addmultisigaddress"     && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "addmultisigaddress"     && n > 1) ConvertTo<Array>(params[1]);
    if (strMethod == "createcltvaddress"      && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "spendcltv"         	  && n > 2) ConvertTo<boost::int64_t>(params[2]);
    if (strMethod == "createcsvaddress"       && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "createcsvaddress"       && n > 1) ConvertTo<bool>(params[1]);
    if (strMethod == "spendcsv"               && n > 2) ConvertTo<boost::int64_t>(params[2]);
    if (strMethod == "timelockcoins"          && n > 0) ConvertTo<double>(params[0]);         // amount
    if (strMethod == "timelockcoins"          && n > 1) ConvertTo<boost::int64_t>(params[1]); // lock_time
    if (strMethod == "timelockcoins"          && n > 2) ConvertTo<bool>(params[2]);           // isRelativeTimelock
    if (strMethod == "timelockcoins"          && n > 3) ConvertTo<bool>(params[3]);           // isBlockHeightLock
    if (strMethod == "listunspent"            && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "listunspent"            && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "listunspent"            && n > 2) ConvertTo<Array>(params[2]);
    if (strMethod == "getrawtransaction"      && n > 1) ConvertTo<boost::int64_t>(params[1]);
    if (strMethod == "createrawtransaction"   && n > 0) ConvertTo<Array>(params[0]);
    if (strMethod == "createrawtransaction"   && n > 1) ConvertTo<Object>(params[1]);
    if (strMethod == "createmultisig"         && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "createmultisig"         && n > 1) ConvertTo<Array>(params[1]);
    if (strMethod == "signrawtransaction"     && n > 1) ConvertTo<Array>(params[1], true);
    if (strMethod == "signrawtransaction"     && n > 2) ConvertTo<Array>(params[2], true);
    if (strMethod == "keypoolrefill"          && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "keypoolreset"           && n > 0) ConvertTo<boost::int64_t>(params[0]);
    if (strMethod == "importaddress"          && n > 2) ConvertTo<bool>(params[2]);
    if (strMethod == "generatetoaddress"      && n > 2) ConvertTo<int>(params[0]);
    if (strMethod == "generatetoaddress"      && n > 2) ConvertTo<int>(params[2]);
    /* Network-related RPC start */
    if (strMethod == "disconnectnode"         && n > 1) ConvertTo<boost::int64_t>(params[1]); // node id
    if (strMethod == "setban"                 && n > 2) ConvertTo<boost::int64_t>(params[2]); // banTime
    if (strMethod == "setban"                 && n > 3) ConvertTo<bool>(params[3]); // absolute
    if (strMethod == "setnetworkactive"       && n > 0) ConvertTo<bool>(params[0]); // state
    /* Network-related RPC end */
    /** YAC_TOKEN START */
    if (strMethod == "issue"               && n > 1) ConvertTo<double>(params[1]); // qty
    if (strMethod == "issue"               && n > 2) ConvertTo<boost::int64_t>(params[2]); // units
    if (strMethod == "issue"               && n > 3) ConvertTo<bool>(params[3]); // reissuable
    if (strMethod == "issue"               && n > 4) ConvertTo<bool>(params[4]); // has_ipfs
    if (strMethod == "transfer"            && n > 1) ConvertTo<double>(params[1]); // qty
    if (strMethod == "transferfromaddress" && n > 2) ConvertTo<double>(params[2]); // qty
    if (strMethod == "reissue"             && n > 1) ConvertTo<double>(params[1]); // qty
    if (strMethod == "reissue"             && n > 2) ConvertTo<bool>(params[2]); // reissuable
    if (strMethod == "reissue"             && n > 5) ConvertTo<boost::int64_t>(params[5]); // new_units
    if (strMethod == "listmytokens"        && n > 1) ConvertTo<bool>(params[1]); // verbose
    if (strMethod == "listmytokens"        && n > 2) ConvertTo<boost::int64_t>(params[2]); // count
    if (strMethod == "listmytokens"        && n > 3) ConvertTo<boost::int64_t>(params[3]); // start
    if (strMethod == "listmytokens"        && n > 4) ConvertTo<boost::int64_t>(params[4]); // confs
    if (strMethod == "listtokens"          && n > 1) ConvertTo<bool>(params[1]); // verbose
    if (strMethod == "listtokens"          && n > 2) ConvertTo<boost::int64_t>(params[2]); // count
    if (strMethod == "listtokens"          && n > 3) ConvertTo<boost::int64_t>(params[3]); // start
    if (strMethod == "listaddressesbytoken"       && n > 1) ConvertTo<bool>(params[1]); // onlytotal
    if (strMethod == "listaddressesbytoken"       && n > 2) ConvertTo<boost::int64_t>(params[2]); // count
    if (strMethod == "listaddressesbytoken"       && n > 3) ConvertTo<boost::int64_t>(params[3]); // start
    if (strMethod == "listtokenbalancesbyaddress" && n > 1) ConvertTo<bool>(params[1]); // onlytotal
    if (strMethod == "listtokenbalancesbyaddress" && n > 2) ConvertTo<boost::int64_t>(params[2]); // count
    if (strMethod == "listtokenbalancesbyaddress" && n > 3) ConvertTo<boost::int64_t>(params[3]); // start
    if (strMethod == "getaddressbalance"   && n > 0) ConvertTo<Object>(params[0]); // addresses
    if (strMethod == "getaddressbalance"   && n > 1) ConvertTo<bool>(params[1]); // includeTokens
    if (strMethod == "getaddressdeltas"    && n > 0) ConvertTo<Object>(params[0]); // addresses
    if (strMethod == "getaddressutxos"     && n > 0) ConvertTo<Object>(params[0]); // addresses
    if (strMethod == "getaddresstxids"     && n > 0) ConvertTo<Object>(params[0]); // addresses
    if (strMethod == "getaddresstxids"     && n > 1) ConvertTo<bool>(params[1]); // includeTokens
    /** YAC_TOKEN END */

    return params;
}

int CommandLineRPC(int argc, char *argv[])
{
    string strPrint;
    int nRet = 0;
    try
    {
        // Skip switches
        while (argc > 1 && IsSwitchChar(argv[1][0]))
        {
            argc--;
            argv++;
        }

        // Method
        if (argc < 2)
            throw invalid_argument("too few parameters");
        string strMethod = argv[1];

        // Parameters default to strings
        std::vector<std::string> strParams(&argv[2], &argv[argc]);
        Object reply;

        try
        {
            Array params = RPCConvertValues(strMethod, strParams);

            // Execute
            reply = CallRPC(strMethod, params);

            // Parse reply
            const Value& result = find_value(reply, "result");
            const Value& error  = find_value(reply, "error");

            if (error.type() != null_type)
            {
                // Error

                int code = find_value(error.get_obj(), "code").get_int();
                if (code == RPC_HELP_USAGE)
                {
                    strPrint = "RPC command help usage\n" + find_value(error.get_obj(), "message").get_str();
                }
                else
                {
                    strPrint = "error: " + write_string(error, false);
                }
                nRet = abs(code);
            }
            else
            {
                // Result
                if (result.type() == null_type)
                    strPrint = "";
                else if (result.type() == str_type)
                    strPrint = result.get_str();
                else
                    strPrint = write_string(result, true);
            }
        }
        catch (std::exception& e)
        {
            strPrint = string("error: ") + e.what();
            nRet = 87;
        }
        catch (...)
        {
            PrintException(NULL, "CommandLineRPC()");
            nRet = 88;
        }
    }
    catch (std::exception& e)
    {
        strPrint = string("Exception Error: ") + e.what();
        nRet = 87;
    }
    catch (...)
    {
      //PrintException(NULL, "Unknown CommandLineRPC() Error");
        strPrint = string("Unknown CommandLineRPC() Error: ");
        nRet = 88;
    }

    if (strPrint != "")
    {
        fprintf((nRet == 0 ? stdout : stderr), "%s\n", strPrint.c_str());
    }
    return nRet;
}

std::string HelpExampleCli(const std::string& methodname, const std::string& args)
{
    return "> yacoin-cli " + methodname + " " + args + "\n";
}

std::string HelpExampleRpc(const std::string& methodname, const std::string& args)
{
    return "> curl --user myusername --data-binary '{\"jsonrpc\": \"1.0\", \"id\":\"curltest\", "
        "\"method\": \"" + methodname + "\", \"params\": [" + args + "] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/\n";
}


#ifdef TEST
int main(int argc, char *argv[])
{
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFile("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    try
    {
        if (argc >= 2 && string(argv[1]) == "-server")
        {
            LogPrintf("server ready\n");
            ThreadRPCServer(NULL);
        }
        else
        {
            return CommandLineRPC(argc, argv);
        }
    }
    catch (std::exception& e) {
        PrintException(&e, "main()");
    } catch (...) {
        PrintException(NULL, "main()");
    }
    return 0;
}
#endif

const CRPCTable tableRPC;
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
