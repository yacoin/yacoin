// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef _BITCOINRPC_H_
 #include "bitcoinrpc.h"
#endif

#ifndef _BITCOINALERT_H_
 #include "alert.h"
#endif

#ifndef BITCOIN_WALLET_H
 #include "wallet.h"
#endif
#include "streams.h"
#include "net_processing.h"

using namespace json_spirit;

using std::runtime_error;
using std::vector;
using std::list;
using std::pair;
using std::string;
using std::map;

Value getconnectioncount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getconnectioncount\n"
            "\nReturns the number of connections to other nodes.\n"
            "\nResult:\n"
            "n          (numeric) The connection count\n"
            "\nExamples:\n"
            + HelpExampleCli("getconnectioncount", "")
            + HelpExampleRpc("getconnectioncount", "")
        );

    {
        return (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL);
    }
}

struct addrManItemSort 
{
    bool operator()(const CAddrInfo &leftItem, const CAddrInfo &rightItem) 
    {
        int64_t 
            nTime = GetTime();

        return leftItem.GetChance(nTime) > rightItem.GetChance(nTime);
    }
};

Value getaddrmaninfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getaddrmaninfo [networkType]\n"
            "Returns a dump of addrman data.");

    // Get a full list of "online" address items
    vector<CAddrInfo> vAddr = g_connman->GetAddressesInfo();

    // Sort by the GetChance result backwardly
    sort(vAddr.begin(), vAddr.end(), addrManItemSort());

    string 
        strFilterNetType = "";

    if (params.size() == 1)
        strFilterNetType = params[0].get_str();

    Array 
        ret;

    for(const CAddrInfo &addr : vAddr)
    {
        if (!addr.IsRoutable() || addr.IsLocal())
            continue;

        Object 
            addrManItem;

        addrManItem.push_back(Pair("address", addr.ToString()));

        string 
            strNetType;

        switch(addr.GetNetwork())
        {
            case NET_TOR:
                strNetType = "tor";
            break;

//            case NET_I2P:
//                strNetType = "i2p";
//            break;
            case NET_IPV6:
                strNetType = "ipv6";
            break;

            default:
            case NET_IPV4:
                strNetType = "ipv4";

        }

        if (strFilterNetType.size() != 0 && strNetType != strFilterNetType)
            continue;

        addrManItem.push_back(Pair("chance", addr.GetChance(GetTime())));
        addrManItem.push_back(Pair("type", strNetType));
        addrManItem.push_back(Pair("time", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", addr.nTime) ) );

        ret.push_back(addrManItem);
    }
    Object 
        addrManItem;

    addrManItem.push_back( Pair( "size: ", (int)vAddr.size() ) );
    ret.push_back( addrManItem );
    return ret;
}

Value getpeerinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getpeerinfo\n"
            "\nReturns data about each connected network node as a json array of objects.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"id\": n,                   (numeric) Peer index\n"
            "    \"addr\":\"host:port\",      (string) The IP address and port of the peer\n"
            "    \"addrbind\":\"ip:port\",    (string) Bind address of the connection to the peer\n"
            "    \"addrlocal\":\"ip:port\",   (string) Local address as reported by the peer\n"
            "    \"services\":\"xxxxxxxxxxxxxxxx\",   (string) The services offered\n"
            "    \"relaytxes\":true|false,    (boolean) Whether peer has asked us to relay transactions to it\n"
            "    \"lastsend\": ttt,           (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last send\n"
            "    \"lastrecv\": ttt,           (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last receive\n"
            "    \"bytessent\": n,            (numeric) The total bytes sent\n"
            "    \"bytesrecv\": n,            (numeric) The total bytes received\n"
            "    \"conntime\": ttt,           (numeric) The connection time in seconds since epoch (Jan 1 1970 GMT)\n"
            "    \"timeoffset\": ttt,         (numeric) The time offset in seconds\n"
            "    \"pingtime\": n,             (numeric) ping time (if available)\n"
            "    \"minping\": n,              (numeric) minimum observed ping time (if any at all)\n"
            "    \"pingwait\": n,             (numeric) ping wait (if non-zero)\n"
            "    \"version\": v,              (numeric) The peer version, such as 7001\n"
            "    \"subver\": \"/Satoshi:0.8.5/\",  (string) The string version\n"
            "    \"inbound\": true|false,     (boolean) Inbound (true) or Outbound (false)\n"
            "    \"addnode\": true|false,     (boolean) Whether connection was due to addnode and is using an addnode slot\n"
            "    \"startingheight\": n,       (numeric) The starting height (block) of the peer\n"
            "    \"banscore\": n,             (numeric) The ban score\n"
            "    \"synced_headers\": n,       (numeric) The last header we have in common with this peer\n"
            "    \"synced_blocks\": n,        (numeric) The last block we have in common with this peer\n"
            "    \"inflight\": [\n"
            "       n,                        (numeric) The heights of blocks we're currently asking from this peer\n"
            "       ...\n"
            "    ],\n"
            "    \"whitelisted\": true|false, (boolean) Whether the peer is whitelisted\n"
            "    \"bytessent_per_msg\": {\n"
            "       \"addr\": n,              (numeric) The total bytes sent aggregated by message type\n"
            "       ...\n"
            "    },\n"
            "    \"bytesrecv_per_msg\": {\n"
            "       \"addr\": n,              (numeric) The total bytes received aggregated by message type\n"
            "       ...\n"
            "    }\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getpeerinfo", "")
            + HelpExampleRpc("getpeerinfo", "")
        );

    std::vector<CNodeStats> vstats;
    g_connman->GetNodeStats(vstats);

    Array ret;

    for(const CNodeStats& stats : vstats) {
        Object obj;

        CNodeStateStats statestats;
        bool fStateStats = GetNodeStateStats(stats.nodeid, statestats);
        obj.push_back(Pair("id", (boost::int64_t)stats.nodeid));
        obj.push_back(Pair("addr", stats.addrName));
        if (!(stats.addrLocal.empty()))
            obj.push_back(Pair("addrlocal", stats.addrLocal));
        if (stats.addrBind.IsValid())
            obj.push_back(Pair("addrbind", stats.addrBind.ToString()));
        obj.push_back(Pair("services", strprintf("%016x", stats.nServices)));
        obj.push_back(Pair("relaytxes", stats.fRelayTxes));
        obj.push_back(Pair("lastsend", DateTimeStrFormat( "%Y-%m-%d %H:%M:%S", stats.nLastSend ) ) );
        obj.push_back(Pair("lastrecv", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", stats.nLastRecv) ) );
        obj.push_back(Pair("bytessent", (boost::int64_t)stats.nSendBytes));
        obj.push_back(Pair("bytesrecv", (boost::int64_t)stats.nRecvBytes));
        obj.push_back(Pair("conntime", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", stats.nTimeConnected) ) );
        obj.push_back(Pair("timeoffset", stats.nTimeOffset));
        if (stats.dPingTime > 0.0)
            obj.push_back(Pair("pingtime", stats.dPingTime));
        if (stats.dMinPing < std::numeric_limits<int64_t>::max()/1e6)
            obj.push_back(Pair("minping", stats.dMinPing));
        if (stats.dPingWait > 0.0)
            obj.push_back(Pair("pingwait", stats.dPingWait));
        obj.push_back(Pair("version", stats.nVersion));
        // Use the sanitized form of subver here, to avoid tricksy remote peers from
        // corrupting or modifying the JSON output by putting special characters in
        // their ver message.
        obj.push_back(Pair("subver", stats.cleanSubVer));
        obj.push_back(Pair("inbound", stats.fInbound));
        obj.push_back(Pair("addnode", stats.m_manual_connection));
        obj.push_back(Pair("startingheight", stats.nStartingHeight));
        if (fStateStats) {
            obj.push_back(Pair("banscore", statestats.nMisbehavior));
            obj.push_back(Pair("synced_headers", statestats.nSyncHeight));
            obj.push_back(Pair("synced_blocks", statestats.nCommonHeight));
            Array heights;
            for(int height : statestats.vHeightInFlight) {
                heights.push_back(height);
            }
            obj.push_back(Pair("inflight", heights));
        }
        obj.push_back(Pair("whitelisted", stats.fWhitelisted));

//        Object sendPerMsgCmd;
//        for (const mapMsgCmdSize::value_type &i : stats.mapSendBytesPerMsgCmd) {
//            if (i.second > 0)
//                sendPerMsgCmd.push_back(Pair(i.first, i.second));
//        }
//        obj.push_back(Pair("bytessent_per_msg", sendPerMsgCmd));
//
//        Object recvPerMsgCmd;
//        for (const mapMsgCmdSize::value_type &i : stats.mapRecvBytesPerMsgCmd) {
//            if (i.second > 0)
//                recvPerMsgCmd.push_back(Pair(i.first, i.second));
//        }
//        obj.push_back(Pair("bytesrecv_per_msg", recvPerMsgCmd));
        ret.push_back(obj);
    }
    Object 
        obj;

    obj.push_back(Pair("size: ", (int)vstats.size()));
    ret.push_back( obj );
    
    return ret;
}

Value addnode(const Array& params, bool fHelp)
{
    string strCommand;
    if (params.size() == 2)
        strCommand = params[1].get_str();
    if (fHelp || params.size() != 2 ||
        (strCommand != "onetry" && strCommand != "add" && strCommand != "remove"))
        throw std::runtime_error(
            "addnode \"node\" \"add|remove|onetry\"\n"
            "\nAttempts to add or remove a node from the addnode list.\n"
            "Or try a connection to a node once.\n"
            "\nArguments:\n"
            "1. \"node\"     (string, required) The node (see getpeerinfo for nodes)\n"
            "2. \"command\"  (string, required) 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once\n"
            "\nExamples:\n"
            + HelpExampleCli("addnode", "\"192.168.0.6:8333\" \"onetry\"")
            + HelpExampleRpc("addnode", "\"192.168.0.6:8333\", \"onetry\"")
        );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    string strNode = params[0].get_str();

    if (strCommand == "onetry")
    {
        CAddress addr;
        g_connman->OpenNetworkConnection(addr, false, nullptr, strNode.c_str());
        return Value::null;
    }

    if (strCommand == "add")
    {
        if(!g_connman->AddNode(strNode))
            throw JSONRPCError(RPC_CLIENT_NODE_ALREADY_ADDED, "Error: Node already added");
    }
    else if(strCommand == "remove")
    {
        if(!g_connman->RemoveAddedNode(strNode))
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
    }

    return Value::null;
}

Value getaddednodeinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "getaddednodeinfo ( \"node\" )\n"
            "\nReturns information about the given added node, or all added nodes\n"
            "(note that onetry addnodes are not listed here)\n"
            "\nArguments:\n"
            "1. \"node\"   (string, optional) If provided, return information about this specific node, otherwise all nodes are returned.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"addednode\" : \"192.168.0.201\",   (string) The node IP address or name (as provided to addnode)\n"
            "    \"connected\" : true|false,          (boolean) If connected\n"
            "    \"addresses\" : [                    (list of objects) Only when connected = true\n"
            "       {\n"
            "         \"address\" : \"192.168.0.201:8333\",  (string) The bitcoin server IP and port we're connected to\n"
            "         \"connected\" : \"outbound\"           (string) connection, inbound or outbound\n"
            "       }\n"
            "     ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddednodeinfo", "\"192.168.0.201\"")
            + HelpExampleRpc("getaddednodeinfo", "\"192.168.0.201\"")
        );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    std::vector<AddedNodeInfo> vInfo = g_connman->GetAddedNodeInfo();

    if (params.size() == 1 && !params[0].is_null()) {
        bool found = false;
        for (const AddedNodeInfo& info : vInfo) {
            if (info.strAddedNode == params[0].get_str()) {
                vInfo.assign(1, info);
                found = true;
                break;
            }
        }
        if (!found) {
            throw JSONRPCError(RPC_CLIENT_NODE_NOT_ADDED, "Error: Node has not been added.");
        }
    }

    Array ret;
    for (const AddedNodeInfo& info : vInfo) {
        Object obj;
        obj.push_back(Pair("addednode", info.strAddedNode));
        obj.push_back(Pair("connected", info.fConnected));
        Array addresses;
        if (info.fConnected) {
            Object address;
            address.push_back(Pair("address", info.resolvedAddress.ToString()));
            address.push_back(Pair("connected", info.fInbound ? "inbound" : "outbound"));
            addresses.push_back(address);
        }
        obj.push_back(Pair("addresses", addresses));
        ret.push_back(obj);
    }

    return ret;
}

extern CCriticalSection cs_mapAlerts;
extern map<uint256, CAlert> mapAlerts;

Value getnettotals(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw std::runtime_error(
            "getnettotals\n"
            "\nReturns information about network traffic, including bytes in, bytes out,\n"
            "and current time.\n"
            "\nResult:\n"
            "{\n"
            "  \"totalbytesrecv\": n,   (numeric) Total bytes received\n"
            "  \"totalbytessent\": n,   (numeric) Total bytes sent\n"
            "  \"timemillis\": t,       (numeric) Current UNIX time in milliseconds\n"
            "  \"uploadtarget\":\n"
            "  {\n"
            "    \"timeframe\": n,                         (numeric) Length of the measuring timeframe in seconds\n"
            "    \"target\": n,                            (numeric) Target in bytes\n"
            "    \"target_reached\": true|false,           (boolean) True if target is reached\n"
            "    \"serve_historical_blocks\": true|false,  (boolean) True if serving historical blocks\n"
            "    \"bytes_left_in_cycle\": t,               (numeric) Bytes left in current time cycle\n"
            "    \"time_left_in_cycle\": t                 (numeric) Seconds left in current time cycle\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getnettotals", "")
            + HelpExampleRpc("getnettotals", "")
       );

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    Object obj;
    obj.push_back(Pair("totalbytesrecv", g_connman->GetTotalBytesRecv()));
    obj.push_back(Pair("totalbytessent", g_connman->GetTotalBytesSent()));
    obj.push_back(Pair("timemillis", GetTimeMillis()));

    Object outboundLimit;
    outboundLimit.push_back(Pair("timeframe", g_connman->GetMaxOutboundTimeframe()));
    outboundLimit.push_back(Pair("target", g_connman->GetMaxOutboundTarget()));
    outboundLimit.push_back(Pair("target_reached", g_connman->OutboundTargetReached(false)));
    outboundLimit.push_back(Pair("serve_historical_blocks", !g_connman->OutboundTargetReached(true)));
    outboundLimit.push_back(Pair("bytes_left_in_cycle", g_connman->GetOutboundTargetBytesLeft()));
    outboundLimit.push_back(Pair("time_left_in_cycle", g_connman->GetMaxOutboundTimeLeftInCycle()));
    obj.push_back(Pair("uploadtarget", outboundLimit));
    return obj;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
