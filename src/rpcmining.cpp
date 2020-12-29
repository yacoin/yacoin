// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_TXDB_H
 #include "txdb.h"
#endif

#ifndef BITCOIN_INIT_H
 #include "init.h"
#endif

#ifndef NOVACOIN_MINER_H
 #include "miner.h"
#endif

#ifndef _BITCOINRPC_H_
 #include "bitcoinrpc.h"
#endif

using namespace json_spirit;

using std::vector;
using std::runtime_error;
using std::map;
using std::pair;
using std::max;

Value gethashespersec(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "gethashespersec\n"
            "Returns a recent hashes per second performance measurement averaged over 30 seconds while generating.");

    if (GetTimeMillis() - nHPSTimerStart > 30000)
       return (boost::int64_t)dHashesPerSec;
    return (boost::int64_t)0;
}

Value getgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getgenerate\n"
            "Returns true or false.");

    return GetBoolArg("-gen");
}

Value setgenerate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "setgenerate <generate> [genproclimit]\n"
            "<generate> is true or false to turn generation on or off.\n"
            "Generation is limited to [genproclimit] processors, -1 is unlimited.");

    bool fGenerate = true;
    if (params.size() > 0)
        fGenerate = params[0].get_bool();

    if (params.size() > 1)
    {
        int nGenProcLimit = params[1].get_int();
        mapArgs["-genproclimit"] = itostr(nGenProcLimit);
        if (nGenProcLimit == 0)
            fGenerate = false;
    }
    mapArgs["-gen"] = (fGenerate ? "1" : "0");

    GenerateYacoins(fGenerate, pwalletMain);
    return Value::null;
}

Value getsubsidy(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getsubsidy [nTarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");

    unsigned int nBits = 0;

    if (params.size() != 0)
    {
        CBigNum bnTarget(uint256(params[0].get_str()));
        nBits = bnTarget.GetCompact();
    }
    else
    {
        nBits = GetNextTargetRequired(pindexBest, false);
    }

    return (Value_type)GetProofOfWorkReward(nBits);
}

Value generatetoaddress(const Array& params, bool fHelp){
    if (fHelp || params.size() == 0 || params.size() > 3)
            throw runtime_error(
                "generatetoaddress\n"
                "nblocks - How many blocks are generated immediately.\n"
                "address - The address to send the newly generated bitcoin to.\n"
                "maxtries - How many iterations to try.");
    int nblocks = -1;
    try {
        nblocks = params[0].get_int();
    } catch(...) {
        nblocks = atoi(params[0].get_str().c_str());
    }
    std::string address = "";
    int maxtries = -1;
    if(params.size()>1) {
        address = params[1].get_str();
    }
    if(params.size()>2) {
        maxtries = params[2].get_int();
    }
    
    Array res;
    // for(int i=0;i<nblocks;i++){
    //     std::string hash = mineSingleBlock(address, maxtries);
    //     res.push_back(hash);
    // }
    mapArgs["-gen"] = "1";
    mapArgs["-genproclimit"]="1";
    GenerateYacoins(true, pwalletMain, nblocks);
    mapArgs["-gen"] = "0";
    return res;
}

Value getmininginfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getmininginfo\n"
            "Returns an object containing mining-related information.");

    float 
        nKernelsRate = 0, 
        nCoinDaysRate = 0;

    pwalletMain->GetStakeStats(nKernelsRate, nCoinDaysRate);

    Object obj, diff, weight;
    obj.push_back(Pair("blocks",        (int)nBestHeight));
    obj.push_back(Pair("currentblocksize",(Value_type)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",(Value_type)nLastBlockTx));

    diff.push_back(Pair("proof-of-work",        GetDifficulty()));
    diff.push_back(Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(pindexBest, true))));
    diff.push_back(Pair("search-interval",      (Value_type)nLastCoinStakeSearchInterval));
    obj.push_back(Pair("difficulty",    diff));

    // YACOIN TODO - May need to re-enable blockvalue if used in any custom api's
    obj.push_back(Pair("blockvalue",    GetProofOfWorkReward(GetLastBlockIndex(pindexBest, false)->nBits)));
    // WM - Report current Proof-of-Work block reward.
    obj.push_back(Pair("powreward", ((double)GetProofOfWorkReward(GetLastBlockIndex(pindexBest, false)->nBits, 0, true) / (double)COIN)));
    obj.push_back(Pair("netmhashps",     GetPoWMHashPS()));
    obj.push_back(Pair("netstakeweight", GetPoSKernelPS()));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    obj.push_back(Pair("generate",      GetBoolArg("-gen")));
    obj.push_back(Pair("genproclimit",  (int)GetArg("-genproclimit", -1)));
    obj.push_back(Pair("hashespersec",  gethashespersec(params, false)));
    obj.push_back(Pair("pooledtx",      (Value_type)mempool.size()));

    weight.push_back(Pair("kernelsrate",   nKernelsRate));
    weight.push_back(Pair("cdaysrate",   nCoinDaysRate));
    obj.push_back(Pair("stakestats", weight));

    obj.push_back(Pair("stakeinterest %",(Value_type)GetProofOfStakeReward(0, GetLastBlockIndex(pindexBest, true)->nBits,
                                                                 GetLastBlockIndex(pindexBest, true)->nTime, true) / 10000));
    obj.push_back(Pair("testnet",       fTestNet));

    // WM - Tweaks to report current Nfactor and N.
    unsigned char 
        Nfactor = GetNfactor(pindexBest->GetBlockTime(), nBestHeight >= nMainnetNewLogicBlockNumber? true : false);

    uint64_t 
        N;
#ifdef _MSC_VER
    N = uint64_t( 1 ) << ( Nfactor + 1 );    
#else    
    N = 1 << ( Nfactor + 1 );
#endif    
    obj.push_back( Pair( "Nfactor", Nfactor ) );
    obj.push_back( Pair( "N", (Value_type)N ) );
    obj.push_back( Pair( "Epoch Interval", (Value_type)nEpochInterval ) );
    obj.push_back( Pair( "Difficulty Interval", (Value_type)nDifficultyInterval ) );

    return obj;
}

Value getworkex(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
            "getworkex [data, coinbase]\n"
            "If [data, coinbase] is not specified, returns extended work data.\n"
        );

    if (vNodes.empty())
        throw JSONRPCError(-9, "Yacoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(-10, "Yacoin is downloading blocks...");

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;
    static vector<CBlock*> vNewBlock;
    static CReserveKey reservekey(pwalletMain);

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static CBlock* pblock;
        if (pindexPrev != pindexBest ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlock* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }
            nTransactionsUpdatedLast = nTransactionsUpdated;
            pindexPrev = pindexBest;
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(pwalletMain);
            if (!pblock)
                throw JSONRPCError(-7, "Out of memory");
            vNewBlock.push_back(pblock);
        }

        // Update nTime
        pblock->nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        // Prebuild hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        CTransaction coinbaseTx = pblock->vtx[0];
        std::vector<uint256> merkle = pblock->GetMerkleBranch(0);

        Object result;
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << coinbaseTx;
        result.push_back(Pair("coinbase", HexStr(ssTx.begin(), ssTx.end())));

        Array merkle_arr;

        BOOST_FOREACH(uint256 merkleh, merkle) {
            merkle_arr.push_back(HexStr(BEGIN(merkleh), END(merkleh)));
        }

        result.push_back(Pair("merkle", merkle_arr));


        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> vchData = ParseHex(params[0].get_str());
        vector<unsigned char> coinbase;

        if(params.size() == 2)
            coinbase = ParseHex(params[1].get_str());

        if (vchData.size() != 128)
            throw JSONRPCError(-8, "Invalid parameter");

        CBlock* pdata = (CBlock*)&vchData[0];

        // Byte reverse
        for (unsigned int i = 0; i < 128/sizeof( uint32_t ); ++i)     // fix this awful magic# code
      //for (int i = 0; i < 128/4; ++i)     // fix this awful magic# code
            ((uint32_t *)pdata)[i] = ByteReverse(((uint32_t *)pdata)[i]);

        // Get saved block
        if (!mapNewBlock.count(pdata->hashMerkleRoot))
            return false;
        CBlock* pblock = mapNewBlock[pdata->hashMerkleRoot].first;

        pblock->nTime = pdata->nTime;
        pblock->nNonce = pdata->nNonce;

        if(coinbase.size() == 0)
            pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->hashMerkleRoot].second;
        else
            CDataStream(coinbase, SER_NETWORK, PROTOCOL_VERSION) >> pblock->vtx[0]; // FIXME - HACK!

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        if (!pblock->SignBlock(*pwalletMain))
            throw JSONRPCError(-100, "Unable to sign block, wallet locked?");

        return CheckWork(pblock, *pwalletMain, reservekey);
    }
}


Value getwork(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Yacoin is downloading blocks...");

    typedef map<uint256, pair<CBlock*, CScript> > mapNewBlock_t;
    static mapNewBlock_t mapNewBlock;    // FIXME: thread safety
    static vector<CBlock*> vNewBlock;
    static CReserveKey reservekey(pwalletMain);

    if (params.size() == 0)
    {
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        static CBlock* pblock;
        if (pindexPrev != pindexBest ||
            (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60))
        {
            if (pindexPrev != pindexBest)
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                BOOST_FOREACH(CBlock* pblock, vNewBlock)
                    delete pblock;
                vNewBlock.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = NULL;

            // Store the pindexBest used before CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = nTransactionsUpdated;
            CBlockIndex* pindexPrevNew = pindexBest;
            nStart = GetTime();

            // Create new block
            pblock = CreateNewBlock(pwalletMain);
            if (!pblock)
            {
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            }
            vNewBlock.push_back(pblock);

            // Need to update only after we know CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }

        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save
        mapNewBlock[pblock->hashMerkleRoot] = make_pair(pblock, pblock->vtx[0].vin[0].scriptSig);

        printf("rpc getwork,\n"
               "params.size() == 0,\n"
               "pblock->nVersion = %d,\n"
               "pblock->hashPrevBlock = %s,\n"
               "pblock->hashMerkleRoot = %s,\n"
               "pblock->nTime = %lld,\n"
               "pblock->nBits = %u,\n"
               "pblock->nNonce = %u\n",
               pblock->nVersion, pblock->hashPrevBlock.ToString().c_str(), pblock->hashMerkleRoot.ToString().c_str(),
               pblock->nTime, pblock->nBits, pblock->nNonce);

        // Pre-build hash buffers
        char pmidstate[32];
        char pdata[128];
        char phash1[64];
        if (pblock->nVersion >= VERSION_of_block_for_yac_05x_new)
        {
            FormatHashBuffers_64bit_nTime((char*)pblock, pmidstate, pdata, phash1);
        }
        else
        {
            FormatHashBuffers(pblock, pmidstate, pdata, phash1);
        }

        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

        Object result;
        result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

        return result;
    }
    else
    {
        // Parse parameters
        vector<unsigned char> 
            vchData = ParseHex(params[0].get_str());

        if (vchData.size() != 128)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }

        struct block_header* pdata = (struct block_header*)&vchData[0];

        // Byte reverse
        for (unsigned int i = 0; i < 128/sizeof( uint32_t ); ++i)
      //for (int i = 0; i < 128/4; i++) //really, the limit is sizeof( *pdata ) / sizeof( uint32_t
            ((uint32_t *)pdata)[i] = ByteReverse(((uint32_t *)pdata)[i]);

        printf("rpc getwork,\n"
               "params.size() != 0,\n"
               "pdata->nVersion = %d,\n"
               "pdata->hashPrevBlock = %s,\n"
               "pdata->hashMerkleRoot = %s,\n"
               "pdata->nTime = %lld,\n"
               "pdata->nBits = %u,\n"
               "pdata->nNonce = %u\n",
               pdata->version, pdata->prev_block.ToString().c_str(), pdata->merkle_root.ToString().c_str(),
               pdata->timestamp, pdata->bits, pdata->nonce);

        // Get saved block
        if (!mapNewBlock.count(pdata->merkle_root))
        {
            printf("rpc getwork, No saved block\n");
            return false;
        }

        CBlock* pblock = mapNewBlock[pdata->merkle_root].first;

        // Parse nTime based on block version
        if (pblock->nVersion >= VERSION_of_block_for_yac_05x_new)
        {
            pblock->nTime = pdata->timestamp;
            pblock->nNonce = pdata->nonce;
        }
        else
        {
            pblock->nTime = ((uint32_t *)pdata)[17];
            pblock->nNonce = ((uint32_t *)pdata)[19];
        }
        pblock->vtx[0].vin[0].scriptSig = mapNewBlock[pdata->merkle_root].second;

        pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        if (!pblock->SignBlock(*pwalletMain))
        {
            printf("rpc getwork, Unable to sign block\n");
            throw JSONRPCError(-100, "Unable to sign block, wallet locked?");
        }
        
        return CheckWork(pblock, *pwalletMain, reservekey);
    }
}


Value getblocktemplate(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getblocktemplate [params]\n"
            "Returns data needed to construct a block to work on:\n"
            "  \"version\" : block version\n"
            "  \"previousblockhash\" : hash of current highest block\n"
            "  \"transactions\" : contents of non-coinbase transactions that should be included in the next block\n"
            "  \"coinbaseaux\" : data that should be included in coinbase\n"
            "  \"coinbasevalue\" : maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"target\" : hash target\n"
            "  \"mintime\" : minimum timestamp appropriate for next block\n"
            "  \"curtime\" : current timestamp\n"
            "  \"mutable\" : list of ways the block template may be changed\n"
            "  \"noncerange\" : range of valid nonces\n"
            "  \"sigoplimit\" : limit of sigops in blocks\n"
            "  \"sizelimit\" : limit of block size\n"
            "  \"bits\" : compressed target of next block\n"
            "  \"height\" : height of the next block\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    std::string strMode = "template";
    if (params.size() > 0)
    {
        const Object& oparam = params[0].get_obj();
        const Value& modeval = find_value(oparam, "mode");
        if (modeval.type() == str_type)
            strMode = modeval.get_str();
        else if (modeval.type() == null_type)
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (vNodes.empty())
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Yacoin is downloading blocks...");

    static CReserveKey reservekey(pwalletMain);

    // Update block
    static unsigned int nTransactionsUpdatedLast;
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static CBlock* pblock;
    if (pindexPrev != pindexBest ||
        (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrevNew = pindexBest;
        nStart = GetTime();

        // Create new block
        if(pblock)
        {
            delete pblock;
            pblock = NULL;
        }
        pblock = CreateNewBlock(pwalletMain);
        if (!pblock)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }

    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    Array transactions;
    map<uint256, Value_type> setTxIndex;
    int i = 0;
    CTxDB txdb("r");
    BOOST_FOREACH (CTransaction& tx, pblock->vtx)
    {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = (Value_type)(i++);

        if (tx.IsCoinBase() || tx.IsCoinStake())
            continue;

        Object entry;

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));

        entry.push_back(Pair("hash", txHash.GetHex()));

        MapPrevTx mapInputs;
        map<uint256, CTxIndex> mapUnused;
        bool fInvalid = false;
        if (tx.FetchInputs(txdb, mapUnused, false, false, mapInputs, fInvalid))
        {
            entry.push_back(Pair("fee", (Value_type)(tx.GetValueIn(mapInputs) - tx.GetValueOut())));

            Array deps;
            BOOST_FOREACH (MapPrevTx::value_type& inp, mapInputs)
            {
                if (setTxIndex.count(inp.first)){
                    Value_type temp = setTxIndex[inp.first];
                    deps.push_back(temp);
                }
            }
            entry.push_back(Pair("depends", deps));

            int64_t nSigOps = tx.GetLegacySigOpCount();
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            entry.push_back(Pair("sigops", (Value_type)nSigOps));
        }

        transactions.push_back(entry);
    }

    Object aux;
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    static Array aMutable;
    if (aMutable.empty())
    {
        aMutable.push_back("time");
        aMutable.push_back("transactions");
        aMutable.push_back("prevblock");
    }

    Object result;
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (Value_type)pblock->vtx[0].vout[0].nValue));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (Value_type)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (Value_type)GetMaxSize(MAX_BLOCK_SIGOPS)));
    result.push_back(Pair("sizelimit", (Value_type)GetMaxSize(MAX_BLOCK_SIZE)));
    result.push_back(Pair("curtime", (Value_type)pblock->nTime));
    result.push_back(Pair("bits", HexBits(pblock->nBits)));
    result.push_back(Pair("height", (Value_type)(pindexPrev->nHeight+1)));

    return result;
}

Value submitblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "submitblock <hex data> [optional-params-obj]\n"
            "[optional-params-obj] parameter is currently ignored.\n"
            "Attempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.");

    vector<unsigned char> blockData(ParseHex(params[0].get_str()));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    try {
        ssBlock >> block;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }
    while (pwalletMain->IsLocked())
    {
        //strMintWarning = strMintMessage;
        Sleep(nMillisecondsPerSecond);
    }

    if (!block.SignBlock(*pwalletMain))
        throw JSONRPCError(-100, "Unable to sign block, wallet locked?");

    bool fAccepted = ProcessBlock(NULL, &block);
    if (!fAccepted)
        return "rejected";

    return Value::null;
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
