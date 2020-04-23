// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_MAIN_H
 #include "main.h"
#endif

#ifndef _BITCOINRPC_H_
 #include "bitcoinrpc.h"
#endif

using namespace json_spirit;

using std::max;
using std::string;
using std::runtime_error;
using std::vector;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);
extern enum Checkpoints::CPMode CheckpointsMode;

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

    int nShift = (blockindex->nBits >> 24) & 0xff;  // mask to top 8 bits

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);
                                                    // 64k/(mask lower 24 bits)
                                                    // can be <1, >1
    while (nShift < 29)     // can be 0 to 256
    {
        dDiff *= 256.0;     // sort of << 8
        nShift++;
    }                       // nShift is >=30 and <=255
    while (nShift > 29)
    {
        dDiff /= 256.0;     // sort of >>8
        nShift--;
    }

    return dDiff;
}

double GetPoWMHashPS()
{
    int nPoWInterval = 72;
    int64_t nTargetSpacingWorkMin = 30, nTargetSpacingWork = 30;

    CBlockIndex* pindex = pindexGenesisBlock;
    CBlockIndex* pindexPrevWork = pindexGenesisBlock;

    while (pindex)
    {
        if (pindex->IsProofOfWork())
        {
            int64_t nActualSpacingWork = pindex->GetBlockTime() - pindexPrevWork->GetBlockTime();
            nTargetSpacingWork = ((nPoWInterval - 1) * nTargetSpacingWork + nActualSpacingWork + nActualSpacingWork) / (nPoWInterval + 1);
            nTargetSpacingWork = max(nTargetSpacingWork, nTargetSpacingWorkMin);
            pindexPrevWork = pindex;
        }

        pindex = pindex->pnext;
    }

    return GetDifficulty() * 4294.967296 / nTargetSpacingWork;
}

double GetPoSKernelPS()
{
    int nPoSInterval = 72;
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    CBlockIndex* pindex = pindexBest;;
    CBlockIndex* pindexPrevStake = NULL;

    while (pindex && nStakesHandled < nPoSInterval)
    {
        if (pindex->IsProofOfStake())
        {
            dStakeKernelsTriedAvg += GetDifficulty(pindex) * 4294967296.0;
            nStakesTime += pindexPrevStake ? (pindexPrevStake->nTime - pindex->nTime) : 0;
            pindexPrevStake = pindex;
            nStakesHandled++;
        }

        pindex = pindex->pprev;
    }

    if (!nStakesHandled)
        return 0;

    return dStakeKernelsTriedAvg / nStakesTime;
}

Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);
    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("mint", ValueFromAmount(blockindex->nMint)));
    result.push_back(Pair("money supply", ValueFromAmount(blockindex->nMoneySupply)));
    result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("blocktrust", leftTrim(blockindex->GetBlockTrust().GetHex(), '0')));
    result.push_back(Pair("chaintrust", leftTrim(blockindex->bnChainTrust.GetHex(), '0')));
    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    if (blockindex->pnext)
        result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));

    result.push_back(Pair("flags", strprintf("%s%s", blockindex->IsProofOfStake()? "proof-of-stake" : "proof-of-work", blockindex->GeneratedStakeModifier()? " stake-modifier": "")));
    result.push_back(Pair("proofhash", blockindex->IsProofOfStake()? blockindex->hashProofOfStake.GetHex() : blockindex->GetBlockHash().GetHex()));
    result.push_back(Pair("entropybit", (int)blockindex->GetStakeEntropyBit()));
    result.push_back(Pair("modifier", strprintf("%016" PRIx64, blockindex->nStakeModifier)));
    result.push_back(Pair("modifierchecksum", strprintf("%08x", blockindex->nStakeModifierChecksum)));
    result.push_back(Pair("posblocks", (int)blockindex->nPosBlockCount));
    Array txinfo;
    BOOST_FOREACH (const CTransaction& tx, block.vtx)
    {
        if (fPrintTransactionDetail)
        {
            CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
            ssTx << tx;
            string strHex = HexStr(ssTx.begin(), ssTx.end());

            txinfo.push_back(strHex);
        }
        else
            txinfo.push_back(tx.GetHash().GetHex());
    }

    result.push_back(Pair("tx", txinfo));

    if ( block.IsProofOfStake() )
        result.push_back(Pair("signature", HexStr(block.vchBlockSig.begin(), block.vchBlockSig.end())));

    return result;
}

Value getbestblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "Returns the hash of the best block in the longest block chain.");

    return hashBestChain.GetHex();
}

Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return nBestHeight;
}

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
#if defined( QT_GUI )
        dPriceRatio = 0.0;
#else
        throw runtime_error( "getYACprice " "Could not get page 1?" );
#endif
        return dUSDperYACprice;
    }
    if (fPrintToConsole) 
    {
        printf(
                "\n"
                "b/y %.8lf"
                "\n"
                "\n"
                , dPriceRatio
              );
    }

    //else    //OK, now we have YAC/BTC (Cryptsy's terminology), really BTC/YAC
    dBTCtoYACprice = dPriceRatio;
    sDestination = "";
    dPriceRatio = 0.0;
     if (!GetMyExternalWebPage2( nIndexUsdToBtc, sDestination, dPriceRatio ) )
    {
#if defined( QT_GUI )
        dPriceRatio = 0.0;
#else
        throw runtime_error( "getYACprice " "Could not get page 2?" );
#endif
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
            "getyacprice "
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
    catch (...)
    {
        printf( "%s\n", "unknown error?" );
        sTemp = "";
    }
    return sTemp;
}

#ifdef WIN32
# ifdef _MSC_VER
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
# endif

Value getcurrentblockandtime(const Array& params, bool fHelp)
{
    if (
        fHelp || 
        (0 != params.size())
       )
        throw runtime_error(
            "getblockcountt "
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

# ifdef _MSC_VER
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
# else
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
# endif
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
# ifdef _MSC_VER
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
# else
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
# endif
    return strS;
}
#endif

Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the difficulty as a multiple of the minimum difficulty.");

    const CBlockIndex
        *pindex = GetLastBlockIndex( pindexBest, false ); // means PoW block
    uint256
        nTarget = CBigNum().SetCompact( pindex->nBits ).getuint256();

    Object obj;
    obj.push_back(Pair("proof-of-work",        GetDifficulty()));
    obj.push_back(Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    obj.push_back(Pair("search-interval",      (int)nLastCoinStakeSearchInterval));
    obj.push_back(
                  Pair(
                        "target",
                        nTarget.ToString().substr(0,16).c_str() 
                      ) 
                 );
    return obj;
}


Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1 || AmountFromValue(params[0]) < MIN_TX_FEE)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest " + FormatMoney(MIN_TX_FEE));

    nTransactionFee = AmountFromValue(params[0]);
    nTransactionFee = (nTransactionFee / MIN_TX_FEE) * MIN_TX_FEE;  // round to minimum fee

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
    return pblockindex->phashBlock->GetHex();
}

Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock <hash> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-hash.");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

Value getblocktimes(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1))
    {
        throw runtime_error(
            "getblocktimes <number of blocks> "
            "Returns a list of block times starting at the latest."
                           );
    }
    int nNumber = params[0].get_int();
    if ((nNumber < 1) || (nNumber > nBestHeight))   // maybe better is 2048?
        throw runtime_error("Number of blocks is out of range.");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[ hashBestChain ];

    block.ReadFromDisk(pblockindex, true);

    uint32_t
        nDelta,
        nTotal = 0,
        nTimeOfBlock = block.GetBlockTime();
    
    Array ret;
    for( int nCount = nNumber; nCount >= 1; --nCount )
    {
        pblockindex = pblockindex->pprev;
        block.ReadFromDisk(pblockindex, true);
        nDelta = nTimeOfBlock - block.GetBlockTime();
        ret.push_back( strprintf( "%d", nDelta) );
        nTotal += nDelta;
        nTimeOfBlock = block.GetBlockTime();
    }
    uint32_t
        nAverage = nTotal / nNumber;

    ret.push_back( strprintf( 
                            "%d blocks, average %d sec", 
                            nNumber, 
                            nAverage
                            ) 
                 );

    return ret;
}

Value getblockbynumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblockbynumber <number> [txinfo] "
            "txinfo optional to print more detailed tx info "
            "Returns details of a block with given block-number.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hashBestChain];
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;

    uint256 hash = *pblockindex->phashBlock;

    pblockindex = mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

// get information of sync-checkpoint
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

    if (Checkpoints::checkpointMessage.vchSig.size() != 0)
    {
        Object msgdata;
        CUnsignedSyncCheckpoint checkpoint;

        CDataStream sMsg(Checkpoints::checkpointMessage.vchMsg, SER_NETWORK, PROTOCOL_VERSION);
        sMsg >> checkpoint;

        Object parsed; // message version and data (block hash)
        parsed.push_back(Pair("version", checkpoint.nVersion));
        parsed.push_back(Pair("hash", checkpoint.hashCheckpoint.GetHex().c_str()));
        msgdata.push_back(Pair("parsed", parsed));

        Object raw; // raw checkpoint message data
        raw.push_back(Pair("data", HexStr(Checkpoints::checkpointMessage.vchMsg).c_str()));
        raw.push_back(Pair("signature", HexStr(Checkpoints::checkpointMessage.vchSig).c_str()));
        msgdata.push_back(Pair("raw", raw));

        result.push_back(Pair("data", msgdata));
    }

    // Check that the block satisfies synchronized checkpoint
    if (CheckpointsMode == Checkpoints::STRICT_)
        result.push_back(Pair("policy", "strict"));

    if (CheckpointsMode == Checkpoints::ADVISORY)
        result.push_back(Pair("policy", "advisory"));

    if (CheckpointsMode == Checkpoints::PERMISSIVE)
        result.push_back(Pair("policy", "permissive"));

    if (mapArgs.count("-checkpointkey"))
        result.push_back(Pair("checkpointmaster", true));

    return result;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
