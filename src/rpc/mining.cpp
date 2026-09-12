// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2025 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "init.h"
#include "validation.h"
#include "miner.h"
#include "net.h"
#include "policy/fees.h"
#include "pow.h"
#include "rpc/blockchain.h"
#include "rpc/mining.h"
#include "rpc/server.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "warnings.h"
#include "wallet/rpcwallet.h"

#include <memory>
#include <stdint.h>

#include <univalue.h>

extern uint64_t nHashesPerSec;

double GetPoWMHashPS()
{
    int nPoWInterval = 72;
    int64_t nTargetSpacingWorkMin = 30, nTargetSpacingWork = 30;

    CBlockIndex* pindex = chainActive.Genesis();
    CBlockIndex* pindexPrevWork = chainActive.Genesis();

    while (pindex)
    {
        if (pindex->IsProofOfWork())
        {
            int64_t nActualSpacingWork = pindex->GetBlockTime() - pindexPrevWork->GetBlockTime();
            nTargetSpacingWork = ((nPoWInterval - 1) * nTargetSpacingWork + nActualSpacingWork + nActualSpacingWork) / (nPoWInterval + 1);
            nTargetSpacingWork = std::max(nTargetSpacingWork, nTargetSpacingWorkMin);
            pindexPrevWork = pindex;
        }

        pindex = chainActive.Next(pindex);
    }

    return GetDifficulty() * 4294.967296 / nTargetSpacingWork;
}

UniValue gethashespersec(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "gethashespersec\n"
            "Returns a recent hashes per second performance measurement averaged over 30 seconds while generating.");

   return (int64_t)nHashesPerSec;
}

UniValue getgenerate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getgenerate\n"
            "\nReturn if the server is set to generate coins or not. The default is false.\n"
            "It is set with the command line argument -gen (or " + std::string(YACOIN_CONF_FILENAME) + " setting gen)\n"
            "It can also be set with the setgenerate call.\n"
            "\nResult\n"
            "true|false      (boolean) If the server is set to generate coins or not\n"
            "\nExamples:\n"
            + HelpExampleCli("getgenerate", "")
            + HelpExampleRpc("getgenerate", "")
        );

    LOCK(cs_main);
    return gArgs.GetBoolArg("-gen", DEFAULT_GENERATE);
}

UniValue setgenerate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "setgenerate generate ( genproclimit )\n"
            "\nSet 'generate' true or false to turn generation on or off.\n"
            "Generation is limited to 'genproclimit' processors, -1 is unlimited.\n"
            "See the getgenerate call for the current setting.\n"
            "\nArguments:\n"
            "1. generate         (boolean, required) Set to true to turn on generation, false to turn off.\n"
            "2. genproclimit     (numeric, optional) Set the processor limit for when generation is on. Can be -1 for unlimited.\n"
            "\nExamples:\n"
            "\nSet the generation on with a limit of one processor\n"
            + HelpExampleCli("setgenerate", "true 1") +
            "\nCheck the setting\n"
            + HelpExampleCli("getgenerate", "") +
            "\nTurn off generation\n"
            + HelpExampleCli("setgenerate", "false") +
            "\nUsing json rpc\n"
            + HelpExampleRpc("setgenerate", "true, 1")
        );

    bool fGenerate = true;
    if (request.params.size() > 0)
        fGenerate = request.params[0].get_bool();

    int nGenProcLimit = gArgs.GetArg("-genproclimit", DEFAULT_GENERATE_THREADS);
    if (request.params.size() > 1)
    {
        nGenProcLimit = request.params[1].get_int();
        if (nGenProcLimit == 0)
            fGenerate = false;
    }

    gArgs.ForceSetArg("-gen", (fGenerate ? "1" : "0"));
    gArgs.ForceSetArg("-genproclimit", itostr(nGenProcLimit));
    int numCores = GenerateYacoins(fGenerate, nGenProcLimit);

    nGenProcLimit = nGenProcLimit >= 0 ? nGenProcLimit : numCores;
    std::string msg = std::to_string(nGenProcLimit) + " of " + std::to_string(numCores);
    return msg;
}

UniValue getsubsidy(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getsubsidy [ntarget]\n"
            "Returns proof-of-work subsidy value for the specified value of target.");

    unsigned int nBits = 0;

    if (request.params.size() != 0)
    {
        CBigNum bnTarget(uint256(request.params[0].get_str()));
        nBits = bnTarget.GetCompact();
    }
    else
    {
        nBits = GetNextTargetRequired(chainActive.Tip(), false);
    }

    return GetProofOfWorkReward(nBits, 0, chainActive.Height() + 1);
}

UniValue generateBlocks(std::shared_ptr<CReserveScript> coinbaseScript, int nGenerate, uint64_t nMaxTries, bool keepScript)
{
    static const int nInnerLoopCount = 0x10000;
    int nHeightEnd = 0;
    int nHeight = 0;

    {   // Don't keep cs_main locked
        LOCK(cs_main);
        nHeight = chainActive.Height();
        nHeightEnd = nHeight+nGenerate;
    }
    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);
    while (nHeight < nHeightEnd)
    {
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler().CreateNewBlock(coinbaseScript->reserveScript));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            IncrementExtraNonce(pblock, chainActive.Tip(), nExtraNonce);
        }
        while (nMaxTries > 0 && pblock->nNonce < nInnerLoopCount && !CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus())) {
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0) {
            break;
        }
        if (pblock->nNonce == nInnerLoopCount) {
            continue;
        }
        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
        ++nHeight;
        blockHashes.push_back(pblock->GetHash().GetHex());

        //mark script as important because it was used at least for one coinbase output if the script came from the wallet
        if (keepScript)
        {
            coinbaseScript->KeepScript();
        }
    }
    return blockHashes;
}

//UniValue generatetoaddress(const JSONRPCRequest& request)
//{
//    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
//        throw std::runtime_error(
//            "generatetoaddress nblocks address (maxtries)\n"
//            "\nMine blocks immediately to a specified address (before the RPC call returns)\n"
//            "\nArguments:\n"
//            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
//            "2. address      (string, required) The address to send the newly generated bitcoin to.\n"
//            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
//            "\nResult:\n"
//            "[ blockhashes ]     (array) hashes of blocks generated\n"
//            "\nExamples:\n"
//            "\nGenerate 11 blocks to myaddress\n"
//            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
//        );
//
//    int nGenerate = request.params[0].get_int();
//    uint64_t nMaxTries = 1000000;
//    if (!request.params[2].isNull()) {
//        nMaxTries = request.params[2].get_int();
//    }
//
//    CBitcoinAddress address(request.params[1].get_str());
//    if (!address.IsValid())
//        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
//
//    std::shared_ptr<CReserveScript> coinbaseScript = std::make_shared<CReserveScript>();
//    coinbaseScript->reserveScript = GetScriptForDestination(address.Get());
//
//    return generateBlocks(coinbaseScript, nGenerate, nMaxTries, false);
//}

UniValue generatetoaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "generatetoaddress nblocks address (maxtries)\n"
            "\nMine blocks immediately to a specified address (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
            "2. address      (string, required) The address to send the newly generated bitcoin to.\n"
            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
            "\nResult:\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
        );

    int nGenerate = request.params[0].get_int();
    uint64_t nMaxTries = 1000000;
    if (!request.params[2].isNull()) {
        nMaxTries = request.params[2].get_int();
    }

    CBitcoinAddress address(request.params[1].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");

    std::shared_ptr<CReserveScript> coinbaseScript = std::make_shared<CReserveScript>();
    coinbaseScript->reserveScript = GetScriptForDestination(address.Get());

    return generateBlocks(coinbaseScript, nGenerate, nMaxTries, false);
}

UniValue getmininginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblockweight\": nnn, (numeric) The last block weight\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"errors\": \"...\"            (string) Current errors\n"
            "  \"networkhashps\": nnn,      (numeric) The network hashes per second\n"
            "  \"pooledtx\": n              (numeric) The size of the mempool\n"
            "  \"chain\": \"xxxx\",           (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
        );


    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("blocks",           (int)chainActive.Height()));
    obj.push_back(Pair("currentblocksize",(uint64_t)nLastBlockSize));
    obj.push_back(Pair("currentblocktx",   (uint64_t)nLastBlockTx));
    obj.push_back(Pair("difficulty",       (double)GetDifficulty()));

    uint64_t blockvalue=(uint64_t)GetProofOfWorkReward(GetLastBlockIndex(chainActive.Tip(), false)->nBits, 0, chainActive.Height());
    obj.push_back(Pair("blockvalue", blockvalue)); // for testing purposes, easier to compare than float
    obj.push_back(Pair("powreward", (double)blockvalue / 1000000.0));
    obj.push_back(Pair("netmhashps",     GetPoWMHashPS()));
    obj.push_back(Pair("errors",           GetWarnings("statusbar")));
    obj.push_back(Pair("generate",      gArgs.GetBoolArg("-gen")));
    obj.push_back(Pair("genproclimit",  (int)gArgs.GetArg("-genproclimit", -1)));
    obj.push_back(Pair("hashespersec",  gethashespersec(request)));
    obj.push_back(Pair("pooledtx",         (uint64_t)mempool.size()));
    obj.push_back(Pair("chain",            Params().NetworkIDString()));

    // WM - Tweaks to report current Nfactor and N.
    unsigned char Nfactor = GetNfactor(chainActive.Tip()->GetBlockTime(), chainActive.Height() >= nMainnetNewLogicBlockNumber? true : false);
    uint64_t N = 1 << ( Nfactor + 1 );
    obj.push_back( Pair( "Nfactor", Nfactor ) );
    obj.push_back( Pair( "N", (uint64_t)N ) );
    obj.push_back( Pair( "Epoch Interval", (uint64_t)nEpochInterval ) );
    obj.push_back( Pair( "Difficulty Interval", (uint64_t)nDifficultyInterval ) );
    return obj;
}

UniValue getwork(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getwork [data]\n"
            "If [data] is not specified, returns formatted hash data to work on:\n"
            "  \"midstate\" : precomputed hash state after hashing the first half of the data (DEPRECATED)\n" // deprecated
            "  \"data\" : block data\n"
            "  \"hash1\" : formatted hash buffer for second hash (DEPRECATED)\n" // deprecated
            "  \"target\" : little endian hash target\n"
            "If [data] is specified, tries to solve the block and returns true if it was successful.");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Yacoin is downloading blocks...");

    typedef std::map<uint256, std::pair<std::shared_ptr<CBlock>, CScript> > mapNewBlock_t;
    static std::mutex mining_mutex;  // Protect mapNewBlock and vNewBlockTemplate
    static mapNewBlock_t mapNewBlock;    // Now thread-safe with mutex
    static std::vector<std::shared_ptr<CBlockTemplate>> vNewBlockTemplate;
    static CReserveKey reservekey(pwallet);
    std::shared_ptr<CReserveScript> coinbase_script;
    pwallet->GetScriptForMining(coinbase_script);

    if (request.params.size() == 0)
    {
        // Lock mutex for entire getwork operation to prevent race conditions
        std::lock_guard<std::mutex> lock(mining_mutex);
        
        // Update block
        static unsigned int nTransactionsUpdatedLast;
        static CBlockIndex* pindexPrev;
        static int64_t nStart;
        unsigned int nTransactionsUpdated = mempool.GetTransactionsUpdated();

        if ((pindexPrev != chainActive.Tip())
            || (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
            || (GetTime() - nStart > nMaxClockDrift*0.75)
            )
        {
            if (pindexPrev != chainActive.Tip())
            {
                // Deallocate old blocks since they're obsolete now
                mapNewBlock.clear();
                vNewBlockTemplate.clear();
            }

            // Clear pindexPrev so future getworks make a new block, despite any failures from here on
            pindexPrev = NULL;

            // Store the chainActive.Tip() used before CreateNewBlock, to avoid races
            nTransactionsUpdatedLast = nTransactionsUpdated;
            CBlockIndex* pindexPrevNew = chainActive.Tip();
            nStart = GetTime();

            // Create new block
            auto pblocktemplate = BlockAssembler().CreateNewBlock(coinbase_script->reserveScript);
            if (!pblocktemplate)
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
            vNewBlockTemplate.push_back(std::shared_ptr<CBlockTemplate>(std::move(pblocktemplate)));

            // Need to update only after we know CreateNewBlock succeeded
            pindexPrev = pindexPrevNew;
        }
        CBlock* pblock = &vNewBlockTemplate.back()->block; // pointer for convenience
        // Update nTime
        pblock->UpdateTime(pindexPrev);
        pblock->nNonce = 0;

        // Update nExtraNonce
        static unsigned int nExtraNonce = 0;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        // Save - create shared_ptr that shares ownership with the template
        std::shared_ptr<CBlock> pblock_shared;
        pblock_shared = std::shared_ptr<CBlock>(vNewBlockTemplate.back(), &vNewBlockTemplate.back()->block);
        mapNewBlock[pblock->hashMerkleRoot] = std::make_pair(pblock_shared, pblock->vtx[0].vin[0].scriptSig);

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

        UniValue result(UniValue::VOBJ);
        result.push_back(Pair("midstate", HexStr(BEGIN(pmidstate), END(pmidstate)))); // deprecated
        result.push_back(Pair("data",     HexStr(BEGIN(pdata), END(pdata))));
        result.push_back(Pair("hash1",    HexStr(BEGIN(phash1), END(phash1)))); // deprecated
        result.push_back(Pair("target",   HexStr(BEGIN(hashTarget), END(hashTarget))));

        // Serialize block header to hex string (similar to getblockheader)
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pblock->GetBlockHeader();
        std::string strBlockHex = HexStr(ssBlock.begin(), ssBlock.end());

        LogPrintf("rpc getwork,\n"
            "params.size() == 0,\n"
            "pblock->nVersion = %d,\n"
            "pblock->hashPrevBlock = %s,\n"
            "pblock->hashMerkleRoot = %s,\n"
            "pblock->nTime = %lld,\n"
            "pblock->nBits = %u,\n"
            "pblock->nNonce = %u\n"
            "midstate = %s,\n"
            "data = %s,\n"
            "hash1 = %s,\n"
            "target = %s\n"
            "target_BE = %s\n"
            "raw_block_header_hex = %s\n",
            pblock->nVersion, pblock->hashPrevBlock.ToString(), pblock->hashMerkleRoot.ToString(),
            pblock->nTime, pblock->nBits, pblock->nNonce,
            HexStr(BEGIN(pmidstate), END(pmidstate)),
            HexStr(BEGIN(pdata), END(pdata)),
            HexStr(BEGIN(phash1), END(phash1)),
            HexStr(BEGIN(hashTarget), END(hashTarget)),
            hashTarget.GetHex(),
            strBlockHex.c_str());

        return result;
    }
    else
    {
        // Parse parameters
        std::vector<unsigned char> vchData = ParseHex(request.params[0].get_str());

        if (vchData.size() != 128)
        {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }

        struct block_header* pdata = (struct block_header*)&vchData[0];

        // Byte reverse
        for (unsigned int i = 0; i < 128/sizeof( uint32_t ); ++i)
            ((uint32_t *)pdata)[i] = ByteReverse(((uint32_t *)pdata)[i]);

        LogPrintf("rpc getwork,\n"
               "params.size() != 0,\n"
               "pdata->nVersion = %d,\n"
               "pdata->hashPrevBlock = %s,\n"
               "pdata->hashMerkleRoot = %s,\n"
               "pdata->nTime = %lld,\n"
               "pdata->nBits = %u,\n"
               "pdata->nNonce = %u\n",
               pdata->version, pdata->prev_block.ToString(), pdata->merkle_root.ToString(),
               pdata->timestamp, pdata->bits, pdata->nonce);

        // Take a DEEP COPY of the cached template out of mapNewBlock instead
        // of holding a shared_ptr to it. Two failure modes this prevents:
        //
        // 1) Concurrent submissions for the same template (same merkle_root)
        //    used to dereference the SAME CBlock via the map's shared_ptr.
        //    The second submission's `pblock->nNonce = pdata->nonce` write
        //    overwrote the first submission's nNonce mid-CheckWork. The
        //    first submission's GetHash() had already cached the scrypt hash
        //    of the original nonce, so CheckWork passed the PoW check; but
        //    `std::make_shared<CBlock>(*pblock)` inside CheckWork then copied
        //    pblock with its NEW (second submission's) nNonce, and
        //    ProcessNewBlock serialized those bytes for storage and P2P
        //    broadcast. Result: this node's index pointed at the first hash
        //    while its on-disk bytes and outgoing P2P bytes carried the
        //    second nonce, permanently diverging from peers.
        //
        // 2) Even without two submissions, a concurrent get-new-job call
        //    in the params.size()==0 branch holds mining_mutex and mutates
        //    the cached pblock (UpdateTime, IncrementExtraNonce). The old
        //    code read pblock outside the lock, so a submit could see a
        //    half-updated CBlock.
        //
        // The deep copy here is a CBlock value-copy: header fields, the
        // mutable scrypt-hash cache, vchBlockSig, vtx, and vMerkleTree are
        // all copied into a stack-local object that no other thread can
        // see. Subsequent mutation, SignBlock, and CheckWork all operate
        // on the local copy.
        CBlock pblock;
        CScript scriptSig;
        {
            std::lock_guard<std::mutex> lock(mining_mutex);
            auto it = mapNewBlock.find(pdata->merkle_root);
            if (it == mapNewBlock.end())
            {
                LogPrintf("rpc getwork, No saved block\n");
                return false;
            }
            pblock = *(it->second.first);   // deep copy of CBlock under lock
            scriptSig = it->second.second;  // deep copy of CScript under lock
        }

        // Parse nTime based on block version
        if (pblock.nVersion >= VERSION_of_block_for_yac_05x_new)
        {
            pblock.nTime = pdata->timestamp;
            pblock.nNonce = pdata->nonce;
        }
        else
        {
            pblock.nTime = ((uint32_t *)pdata)[17];
            pblock.nNonce = ((uint32_t *)pdata)[19];
        }
        pblock.vtx[0].vin[0].scriptSig = scriptSig;

        pblock.hashMerkleRoot = pblock.BuildMerkleTree();

        // Serialize block header to hex string (similar to getblockheader)
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pblock.GetBlockHeader();
        std::string strBlockHex = HexStr(ssBlock.begin(), ssBlock.end());
        LogPrintf("rpc getwork params.size() != 0, raw_block_header_hex = %s\n", strBlockHex.c_str());

        if (!pblock.SignBlock(*pwallet))
        {
            LogPrintf("rpc getwork, Unable to sign block\n");
            throw JSONRPCError(-100, "Unable to sign block, wallet locked?");
        }

        return CheckWork(&pblock, *pwallet, reservekey);
    }
}

// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

UniValue getblocktemplate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getblocktemplate ( TemplateRequest )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "For full specification, see BIPs 22 and 23:\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"

            "\nArguments:\n"
            "1. template_request         (json object, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\", \"proposal\" (see BIP 23), or omitted\n"
            "       \"capabilities\":[     (array, optional) A list of strings, accepted and ignored\n"
            "           \"support\"          (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "       ],\n"
            "       \"rules\":[            (array, optional) A list of strings, accepted and ignored\n"
            "           \"support\"          (string) client side supported softfork deployment\n"
            "           ,...\n"
            "       ],\n"
            "       \"longpollid\":\"xxxx\"   (string, optional) A longpollid from an earlier template. The call blocks until the best block changes, or until the mempool has moved and a minute has passed\n"
            "       \"data\":\"xxxx\"         (string, required for mode 'proposal') hex-encoded block to check against consensus without mining it\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"capabilities\" : [ \"proposal\" ],  (array of strings) features supported by this server\n"
            "  \"version\" : n,                    (numeric) The preferred block version\n"
            "  \"rules\" : [ ],                     (array of strings) always empty: Yacoin has no BIP9 deployment\n"
            "  \"vbavailable\" : { },               (json object) always empty: Yacoin has no BIP9 deployment\n"
            "  \"vbrequired\" : 0,                 (numeric) always zero: Yacoin has no BIP9 deployment\n"
            "  \"previousblockhash\" : \"xxxx\",     (string) The hash of current highest block\n"
            "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",             (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"txid\" : \"xxxx\",             (string) transaction id encoded in little-endian hexadecimal\n"
            "         \"hash\" : \"xxxx\",             (string) same value as txid: Yacoin carries no witness data\n"
            "         \"depends\" : [                (array) array of numbers \n"
            "             n                          (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                    (numeric) difference in value between transaction inputs and outputs; if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,                (numeric) total SigOps count, as counted for purposes of block limits; if key is not present, sigop count is unknown and clients MUST NOT assume it is zero\n"
            "         \"required\" : true|false      (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
            "  \"coinbaseaux\" : {                 (json object) data that should be included in the coinbase's scriptSig content\n"
            "      \"flags\" : \"xx\"                  (string) key name is to be ignored, and value included in scriptSig\n"
            "  },\n"
            "  \"coinbasevalue\" : n,              (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees\n"
            "  \"longpollid\" : \"xxxx\",            (string) identifier to pass back in a following call to wait for the next template\n"
            "  \"target\" : \"xxxx\",                (string) The hash target\n"
            "  \"mintime\" : ttt,                  (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                     (array of string) list of ways the block template may be changed \n"
            "     \"value\"                          (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",(string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxxxxxxx\",              (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getblocktemplate", "")
            + HelpExampleRpc("getblocktemplate", "")
         );

    LOCK(cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    if (request.params.size() > 0 && !request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            BlockMap::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end()) {
                CBlockIndex *pindex = mi->second;
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = chainActive.Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        // Client-declared softfork rules are read so that a BIP9-aware client is
        // accepted, and validated only for shape. Yacoin runs no versionbits
        // deployment, so there is nothing for them to select.
        const UniValue& aClientRules = find_value(oparam, "rules");
        if (aClientRules.isArray()) {
            for (unsigned int idx = 0; idx < aClientRules.size(); ++idx) {
                const UniValue& v = aClientRules[idx];
                setClientRules.insert(v.get_str());
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if (!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Yacoin is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Yacoin is downloading blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        boost::system_time checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release the main lock while waiting
        bool fClientGone = false;
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = boost::get_system_time() + boost::posix_time::minutes(1);

            boost::unique_lock<boost::mutex> lock(csBestBlock);
            while (chainActive.Tip()->GetBlockHash() == hashWatchedChain && IsRPCRunning())
            {
                // A miner that hung up is not worth an HTTP worker. Nothing else
                // in the server would notice, and on a chain that is not moving
                // this wait outlives client after client until the pool is gone
                // and the daemon answers no RPC at all. Checked on every wake,
                // so a dead client costs at most one wait interval.
                if (!request.IsClientConnected())
                {
                    fClientGone = true;
                    break;
                }

                if (!cvBlockChange.timed_wait(lock, checktxtime))
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += boost::posix_time::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        // Both of these have to be raised out here: throwing while cs_main is
        // released would unwind past the LOCK that expects to still hold it.
        if (fClientGone)
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Client disconnected");
        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;

    if (pindexPrev != chainActive.Tip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5))
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = NULL;

        // Store the chainActive.Tip() used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainActive.Tip();
        nStart = GetTime();

        // Create new block. The coinbase output script is a placeholder: a miner
        // building on this template replaces the whole coinbase with one paying
        // itself, so the daemon needs no wallet here.
        CScript scriptDummy = CScript() << OP_TRUE;
        pblocktemplate = BlockAssembler().CreateNewBlock(scriptDummy);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience
    // Update nTime
    pblock->UpdateTime(pindexPrev);
    pblock->nNonce = 0;

    UniValue aCaps(UniValue::VARR);
    aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for(CTransaction& tx : pblock->vtx)
    {
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase() || tx.IsCoinStake())
            continue;

        UniValue entry(UniValue::VOBJ);

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << tx;
        entry.push_back(Pair("data", HexStr(ssTx.begin(), ssTx.end())));
        entry.push_back(Pair("txid", txHash.GetHex()));
        entry.push_back(Pair("hash", txHash.GetHex()));

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.push_back(Pair("depends", deps));

        int index_in_template = i - 1;
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template]));
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        entry.push_back(Pair("sigops", nTxSigOps));
        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    // Yacoin runs no BIP9 deployment, so these three are constant. They are
    // emitted anyway so that a BIP9-aware client parses the response.
    UniValue aRules(UniValue::VARR);
    UniValue vbavailable(UniValue::VOBJ);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("capabilities", aCaps));
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("rules", aRules));
    result.push_back(Pair("vbavailable", vbavailable));
    result.push_back(Pair("vbrequired", int(0)));
    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0].vout[0].nValue));
    result.push_back(Pair("longpollid", chainActive.Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast)));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    result.push_back(Pair("sigoplimit", (uint64_t)GetMaxSize(MAX_BLOCK_SIGOPS)));
    result.push_back(Pair("sizelimit", (uint64_t)GetMaxSize(MAX_BLOCK_SIZE)));
    result.push_back(Pair("curtime", (int64_t)pblock->nTime));
    result.push_back(Pair("bits", strprintf("%08x", pblock->nBits)));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));

    return result;
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    void BlockChecked(const CBlock& block, const CValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

UniValue submitblock(const JSONRPCRequest& request)
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "submitblock \"hexdata\"  ( \"dummy\" )\n"
            "\nAttempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"        (string, required) the hex-encoded block data to submit\n"
            "2. \"dummy\"          (optional) dummy value, for compatibility with BIP22. This value is ignored.\n"
            "\nResult:\n"
            "null                (json null) the block was accepted\n"
            "\"duplicate\"         (string) the node already has this block\n"
            "\"duplicate-invalid\" (string) the node already has this block, and it is invalid\n"
            "\"inconclusive\"      (string) the node has not reached a verdict on this block\n"
            "\"<reason>\"          (string) the consensus rule the block broke, for example bad-txnmrklroot\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );
    }

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (block.vtx.empty() || !block.vtx[0].IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(Params(), blockptr, true, nullptr);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent) {
        if (fAccepted && !sc.found) {
            return "duplicate-inconclusive";
        }
        return "duplicate";
    }
    if (!sc.found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc.state);
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "gethashespersec",        &gethashespersec,        true,   {} },
    { "mining",             "getmininginfo",          &getmininginfo,          true,  {} },
    { "mining",             "getsubsidy",             &getsubsidy,             true,  {"ntarget"} },
    { "mining",             "getwork",                &getwork,                true,  {"data"} },
    { "mining",             "getblocktemplate",       &getblocktemplate,       true,  {"template_request"} },
    { "mining",             "submitblock",            &submitblock,            true,  {"hexdata","dummy"} },

    /* Coin generation */
    { "generating",         "getgenerate",            &getgenerate,            true, {}  },
    { "generating",         "setgenerate",            &setgenerate,            true, {"generate", "genproclimit"}  },
    { "generating",         "generatetoaddress",      &generatetoaddress,      true,  {"nblocks","address","maxtries"} },
};

void RegisterMiningRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
