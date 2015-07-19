// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include "main.h"
#include "bitcoinrpc.h"

using namespace json_spirit;
using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        if (pindexBest == NULL)
            return 1.0;
        else
            blockindex = GetLastBlockIndex(pindexBest, false);
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}


Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail)
{
    Object 
        result;

    result.push_back(Pair("hash", block.GetHash().GetHex()));

    CMerkleTx txGen( block.vtx[ 0 ] );

    txGen.SetMerkleBranch(&block);

    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("mint", ValueFromAmount(blockindex->nMint)));
    result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    if (blockindex->pnext)
        result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));

    result.push_back(
                    Pair(
                        "flags", 
                        strprintf(
                                "%s%s", 
                                blockindex->IsProofOfStake()? "proof-of-stake" : "proof-of-work", 
                                blockindex->GeneratedStakeModifier()? " stake-modifier": ""
                                 )
                        )
                    );
    result.push_back(
                    Pair(
                        "proofhash", 
                        blockindex->IsProofOfStake()? 
                            blockindex->hashProofOfStake.GetHex() : 
                            blockindex->GetBlockHash().GetHex()
                        )
                    );
    result.push_back(Pair("entropybit", (int)blockindex->GetStakeEntropyBit()));
    result.push_back(Pair("modifier", strprintf("%016"PRI64x, blockindex->nStakeModifier)));
    result.push_back(Pair("modifierchecksum", strprintf("%08x", blockindex->nStakeModifierChecksum)));

    Array 
        txinfo;

    BOOST_FOREACH (const CTransaction& tx, block.vtx)
    {
        if (fPrintTransactionDetail)
        {
            Object 
                entry;

            entry.push_back(Pair("txid", tx.GetHash().GetHex()));
            TxToJSON(tx, 0, entry);

            txinfo.push_back(entry);
        }
        else
            txinfo.push_back(tx.GetHash().GetHex());
    }

    result.push_back(Pair("tx", txinfo));
    result.push_back(Pair("signature", HexStr(block.vchBlockSig.begin(), block.vchBlockSig.end())));

    return result;
}


Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}

#ifdef WIN32

double doGetYACprice()
{
    //-------------------------------------------------
    char 
        *csDomain = "pubapi2.cryptsy.com";
    //Set-Cookie: NAME=VALUE; OPTIONS is there a cookie?

    string
        sfb,
        sDomain = "pubapi2.cryptsy.com",
        sNewUrl1 = 
                    "GET"
                    " "
                    "/api.php?method=singlemarketdata&marketid=11"
                    " "
                    "HTTP/1.1"
                    "\r\n"
                    "Content-Type: text/html"
                    "\r\n"
                    "Accept: application/json, text/html"
                    "\r\n"
                    "Host: ";
    sNewUrl1 += sDomain;
    sNewUrl1 += 
                "\r\n"
                "Connection: close"
                "\r\n"
                "\r\n"
                "";

    string
        sNewUrl2 = 
                    "GET"
                    " "
                    "/api.php?method=singlemarketdata&marketid=2"
                    " "
                    "HTTP/1.1"
                    "\r\n"
                    "Content-Type: text/html"
                    "\r\n"
                    "Accept: application/json, text/html"
                    "\r\n"
                    "Host: ";
    sNewUrl2 += sDomain;
    sNewUrl2 += 
                "\r\n"
                "Connection: close"
                "\r\n"
                "\r\n"
                "";

    sfb = strprintf(
                    "Command 1:\n%s"
                    "\n"
                    "Command 2:\n%s"
                    "\n"
                    "",
                    sNewUrl1.c_str()
                    ,
                    sNewUrl2.c_str()
                   );
    if (fPrintToConsole) 
        printf( "%s", sfb.c_str() );

    Object 
        result;

    CNetAddr
        ipRet;
    
    int
        nResult;

    const char* 
        pszGet = sNewUrl1.c_str();
    string
        sDestination1 = "",
        sDestination2 = "";

    double
        dYACtoUSDPrice = 0.0,
        dBTCtoUSDPrice = 0.0,
        dYACtoBTCPrice = 0.0;

    if (GetMyExternalWebPage( sDomain, pszGet, sDestination1, dYACtoBTCPrice ) )   // the webpage is  ~40,023 bytes long
    {   //OK, now we have YAC/BTC
        pszGet = sNewUrl2.c_str();
        if (GetMyExternalWebPage( sDomain, pszGet, sDestination2, dBTCtoUSDPrice ) )
        {   // OK now we have BTC/USD
            dYACtoUSDPrice = dYACtoBTCPrice * dBTCtoUSDPrice;
        }
        else
        {
            throw runtime_error(
                        "getYACprice\n"
                        "Could not get page 2?"
                               );
        }
    }
    else
    {
        throw runtime_error(
            "getYACprice\n"
            "Could not get page 1?"
                           );
    }
    std::string
        stest = strprintf(
                            "result"
                            "\n"
                            "___________________________________________________________\n"
                            "___________________________________________________________\n"
                            "%s"
                            "\n"
                            "___________________________________________________________\n"
                            "%s"
                            "___________________________________________________________\n"
                            "___________________________________________________________\n"
                            "",
                            sDestination1.c_str(),
                            sDestination2.c_str()
                         );
    //if( dYACtoUSDPrice > 0.0 )
    return dYACtoUSDPrice;
    //return stest;
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
            "Returns the current price of YAC "
            "given by Cryptsy.com using their public API for YAC/BTC and BTC/USD."
                           );
    }

    double 
        dPrice = doGetYACprice();

    string
        sTemp = strprintf( "%0.6lf", dPrice );

    return sTemp;
}

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

    #ifdef _MSC_VER
    struct tm
        aTimeStruct,
        gmTimeStruct;
    char 
        buff[30];
    bool
        fIsGMT = true;  // the least of all evils
    time_t 
        tBlock = block.GetBlockTime();
                        //    to         from
    if( !_localtime64_s( &aTimeStruct, &tBlock ) )   // OK
    {   // are we in GMT?      to          from
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
    #else
    struct tm
        aTimeStruct,
        *paTimeStruct,
        *pgmTimeStruct;
    char 
        *pbuff;
    bool
        fIsGMT = true;  // the least of all evils
    time_t 
        tBlock = block.GetBlockTime();
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

Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the difficulty as a multiple of the minimum difficulty.");

    Object obj;
    obj.push_back(Pair("proof-of-work",        GetDifficulty()));
    obj.push_back(Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("search-interval",      (int)nLastCoinStakeSearchInterval));
    return obj;
}


Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1 || AmountFromValue(params[0]) < MIN_TX_FEE)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.01");

    nTransactionFee = AmountFromValue(params[0]);
    nTransactionFee = (nTransactionFee / CENT) * CENT;  // round to cent

    return true;
}

Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    mempool.queryHashes(vtxid);

    Array a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}

Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlockIndex* pblockindex = FindBlockByHeight(nHeight);
    return pblockindex->GetHash().GetHex();
}

Value getblock(const Array& params, bool fHelp)
{
    if (
        fHelp || 
        params.size() < 1 || 
        params.size() > 2
       )
        throw runtime_error(
            "getblock <hash> [true | false (txinfo)]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-hash.");

    std::string 
        strHash = params[0].get_str();

    uint256 
        hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock 
        block;

    CBlockIndex
        * pblockindex = mapBlockIndex[hash];

    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(
                        block, 
                        pblockindex, 
                        params.size() > 1 ? params[1].get_bool() : false
                      );
}

Value getblockbynumber(const Array& params, bool fHelp)
{
    if (
        fHelp || 
        params.size() < 1 || 
        params.size() > 2
       )
        throw runtime_error(
            "getblockbynumber <number> [txinfo]\n"
            "txinfo [1|0] optional to print more detailed tx info\n"
            "Returns details of a block with given block-number.");

    int 
        nHeight = params[0].get_int();

    if (
        nHeight < 0 || 
        nHeight > nBestHeight
       )
        throw runtime_error("Block number out of range.");

    CBlock 
        block;

    CBlockIndex
        * pblockindex = mapBlockIndex[hashBestChain];

    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;

    uint256 
        hash = pblockindex->GetHash();

    pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(
                        block, 
                        pblockindex, 
                        params.size() > 1 ? params[1].get_bool() : false
                      );
}

// ppcoin: get information of sync-checkpoint
Value getcheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getcheckpoint\n"
            "Show info of synchronized checkpoint.\n");

    Object result;
    CBlockIndex* pindexCheckpoint;

    result.push_back(Pair("synccheckpoint", Checkpoints::hashSyncCheckpoint.ToString().c_str()));
    pindexCheckpoint = mapBlockIndex[Checkpoints::hashSyncCheckpoint];        
    result.push_back(Pair("height", pindexCheckpoint->nHeight));
    result.push_back(Pair("timestamp", DateTimeStrFormat(pindexCheckpoint->GetBlockTime()).c_str()));
    if (mapArgs.count("-checkpointkey"))
        result.push_back(Pair("checkpointmaster", true));

    return result;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif