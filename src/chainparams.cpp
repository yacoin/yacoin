// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    CTransaction txNew;
    txNew.nTime = (::uint32_t) nTime;
    txNew.nVersion = nVersion;
    txNew.vin.resize(1);
    txNew.vout.resize(1);

    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].SetEmpty();

    CBlock block;
    block.vtx.push_back(txNew);
    block.hashPrevBlock = 0;
    block.hashMerkleRoot = block.BuildMerkleTree();
    block.nVersion = 1;
    block.nTime = (::uint32_t)(nTime + 20);
    block.nBits = nBits;
    block.nNonce = nNonce;

    return block;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion)
{
    const char* pszTimestamp = "https://bitcointalk.org/index.php?topic=196196";
    return CreateGenesisBlock(pszTimestamp, nTime, nNonce, nBits, nVersion);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
        consensus.powLimit = CBigNum(~uint256(0) >> 20);
        consensus.initialHashTarget = CBigNum(~uint256(0) >> 20);
        consensus.initialMoneySupply = 0;
#else
        consensus.powLimit = CBigNum(~uint256(0) >> 3);
        consensus.initialHashTarget = CBigNum(~uint256(0) >> 8);
        consensus.initialMoneySupply = 1E14;
#endif
        consensus.BIP65Height = 1890000; // 0000030f8402abf3d0e2efeb72274da8a4b4389ef8267d2c2a14fe58f2e088d0
        consensus.BIP68Height = 1890000; // 0000030f8402abf3d0e2efeb72274da8a4b4389ef8267d2c2a14fe58f2e088d0
        consensus.HeliopolisHardforkHeight = 1890000; // 0000030f8402abf3d0e2efeb72274da8a4b4389ef8267d2c2a14fe58f2e088d0
        consensus.nPowTargetTimespan = 21000 * 60;  // 21000 blocks * 60 seconds
        consensus.nPowTargetSpacing = 1 * 60; // 1 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 19950; // 95% of 21000
        consensus.nMinerConfirmationWindow = 6; // similar to COINBASE_MATURITY_AFTER_HARDFORK
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.nStakeMaxAge = 60 * 60 * 24 * 90; // 90 days as full weight
        consensus.nStakeMinAge = 60 * 60 * 24 * 30; // minimum age for coin age
        consensus.nModifierInterval = 6 * 60 * 60; // Modifier interval: time to elapse before new modifier is computed

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xd9;
        pchMessageStart[1] = 0xe6;
        pchMessageStart[2] = 0xe7;
        pchMessageStart[3] = 0xe5;
        nDefaultPort = 7688;
        nPruneAfterHeight = 100000;

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
        const uint32_t nNonceGenesisBlock = 127357;
#else
        const uint32_t nNonceGenesisBlock = 127358;
#endif

        genesis = CreateGenesisBlock(nChainStartTime, nNonceGenesisBlock, consensus.powLimit.GetCompact(), 1);
        consensus.hashGenesisBlock = genesis.GetHash();

#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
        Yassert(consensus.hashGenesisBlock == uint256S("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5"));
        Yassert(genesis.hashMerkleRoot == uint256S("0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f"));
#else
        Yassert(consensus.hashGenesisBlock == uint256S("0x1ddf335eb9c59727928cabf08c4eb1253348acde8f36c6c4b75d0b9686a28848"));
        Yassert(genesis.hashMerkleRoot == uint256S("0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f"));
#endif

        // TODO: Implement later
        // Note that of those with the service bits flag, most only support a subset of possible options
//        vSeeds.emplace_back("seed.bitcoin.sipa.be", true); // Pieter Wuille, only supports x1, x5, x9, and xd
//        vSeeds.emplace_back("dnsseed.bluematt.me", true); // Matt Corallo, only supports x9
//        vSeeds.emplace_back("dnsseed.bitcoin.dashjr.org", false); // Luke Dashjr
//        vSeeds.emplace_back("seed.bitcoinstats.com", true); // Christian Decker, supports x1 - xf
//        vSeeds.emplace_back("seed.bitcoin.jonasschnelli.ch", true); // Jonas Schnelli, only supports x1, x5, x9, and xd
//        vSeeds.emplace_back("seed.btc.petertodd.org", true); // Peter Todd, only supports x1, x5, x9, and xd

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,77);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,139);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,205);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
        fMiningRequiresPeers = true;
#else
        fMiningRequiresPeers = false;
#endif

        checkpointData = (CCheckpointData) {
            {
                { 0, consensus.hashGenesisBlock },
                { 15000, uint256("0x00000082cab82d04354692fac3b83d19cbe3c3ab4b73610d0e73397545eb012e") },
                { 30000, uint256("0x0000000af2f6e71951d6e8befbd43a3dac36681b5095cb822b5c9c8de626e371") },
                { 45000, uint256("0x00000000591110a1411cf37739cde0c558c0c070aa38686d89b2e70fe39b654f") },
                { 60000, uint256("0x000000000c067c5df98a8285ff045c3ffee46eb64b248bc6622f6bdceb8558be") },
                { 75000, uint256("0x000000004ab2d277c8a056f55f32efa515a9931cb0404d60d0efc4f573412e66") },
                { 90000, uint256("0x000000000cfe2ec9d27b784c2627c3864d26e5829cc5b18b4eff37d863ed0675") },
                { 105000, uint256("0x00000000b0480b6a15fee32ee47d4b30dc82dc44ab680f1debb2ce2b13f73aab") },
                { 120000, uint256("0x00000000d843c5c818620d00c9352e0cc3bbf7fdb9d69093795fbfffff13c92a") },
                { 135000, uint256("0x0000000292cb16d5935e015a786d33f3228da23d92dfeb6ddff7249a3227f956") },
                { 150000, uint256("0x000000035d01ee7f75032c0293a7e6b1217d447fe3e000ede7911cb0520c60c7") },
                { 165000, uint256("0x00000001e790d65de9541af419465338220de69e3ffcbda427af2fc94741d321") },
                { 180000, uint256("0x000000054595380eb246887c79ff25fd997eebd3e59385830e4987c11153a31d") },
                { 195000, uint256("0x00000007c12dc0533ab2dbf66c56308ee0b259e1a5f09435381ea6d541b6a2c5") },
                { 214998, uint256("0x000000054e1a96d68bddda9b63276d604f33b6679d7dab079e4d241a1ee31be9") },
                { 236895, uint256("0x00000000a103442adaf96aa2af5cbc083e74cddbea558a7740c7a6781f561c08") },
                { 259405, uint256("0x00000019f67b00bc3482208d5b82393df96c648b510f24ab0d3318294a9bcde5") },
                { 281002, uint256("0x0000003076d627bd2e13e914a3032c2ef8a69de4792452c697bc23a6e158be2b") },
                { 303953, uint256("0x0000007c2fd3ca884a5b77e9b2a508cb617b75f2162beacafffa7193d2db7069") },
                { 388314, uint256("0x0000001d9a76c3a52288638568dad601a8a69ba7dc1038ff4d12b614de73a49a") },
                { 420000, uint256("0x000000368f2f40e3d2d9ed2a2220c8a424e3d80871c0b72c2bdeea35863aa779") },
                { 465000, uint256("0x0000000826f7b8b504fde92ba0388b647b2179d4b2c7cdfd232505cd7d79ac61") },
                { 487658, uint256("0x00000008dee4518a08084c5b65d647a57faf7ff28bc7d8786719ac13d21356d4") },
                { 550177, uint256("0x000000087d507052cb66d5a3770cf62f8ff9196ab861ffec3452d939b818567b") },
                { 612177, uint256("0x0000004bc02ebb045398fd8cdb249b790892a4fa3a8b03dbbbf5743c53f2a508") },
                { 712177, uint256("0x000001881da9ee73de48a54ebae7d0dec3b453d795b6704d62414e4b581e3aea") },
                { 750000, uint256("0x000001d36056e88f70b27d1415cdf7cedbafb4a7c1f2f78d5a8d9f713aee4a5a") },
                { 800000, uint256("0x000000ca19b5cd837c373f40b5e511866c90ce37945fd43fe13e55fe51c22c06") },
                { 850000, uint256("0x0000003aa373b33950c52daf60c82f6e5dae67dba2b7affd0e0a95560ace68ce") },
                { 900000, uint256("0x0000029f3ce6e19adbf7c08e051b91c55d4586d99223964abc0387170c375bfd") },
                { 950000, uint256("0x0000031c836162928d81fd50bc8db3e995a80cbdef27785f7b11f46c86b327bb") },
                { 1000000, uint256("0x00000173fff346c1f83138ee23c15debb96eea78b63c8dea5e02da5e1a775a54") },
                { 1050000, uint256("0x00000118eb156fca5d4cea18ccc56d51175c9fa03e2301adc96d36dedbc4dd39") },
                { 1100000, uint256("0x000001875f4f515559d683c750db1952a1e5b896f6f4390023c6d445fef63f64") },
                { 1150000, uint256("0x00000979215bbb8205c42961b10b22900aa5c127e3a61061f340541295e65bf1") },
                { 1200000, uint256("0x0000084191c31d1c27cba87fbc4308b7e67cff8e89f13fcee51958db0e3918ee") },
                { 1250000, uint256("0x00000d72f9b23ae645eb875af19aa30279c597429ec5652da0e39a0edd5bd4f9") },
                { 1300000, uint256("0x00000a3336e2c336c0182945837573c5ffe68550f77393244d4bf26d36ae0f6c") },
                { 1350000, uint256("0x00000b6d09db4e5443094d05f8ea061e2305c44a787b5b4e3cdab9ddfa78034b") },
                { 1400000, uint256("0x0000061aa7e66eb0a1adcf5f4cf773eb6351a5e0905a3794cca135edc72799ab") },
                { 1450000, uint256("0x00000a99ea3603a90460600e8c1f4cb688abf8fcb8fc9d6a1848917690df049f") },
                { 1500000, uint256("0x0000072187440ce4016fa230c177a8967840d475278eff633dce66837e550f9e") },
                { 1550000, uint256("0x000005b5842fe8e453b7360c50cbe580ef4874d2b8976a3e5d336dc5e34b4683") },
                { 1600000, uint256("0x0000088ced0e7c97afb9635b315f286f94a25eb5d0490ce7b12e2ce0905c3f31") },
                { 1650000, uint256("0x000007439ff054f2307766a5a30eff4fc0268de68e72c76efde767ccee91830c") },
                { 1700000, uint256("0x00000797ae41dbf32c6cb73c1254fbd804b068263ef2de77755fb1829dd2ab1d") },
                { 1750000, uint256("0xd1806e1fa74087ef43fe0a8b37e558c1f9b523529f17b8cb91ca619dd90e4eec") },
                { 1800000, uint256("0x00000670c3f5b879d8b2b0c403c824af78cf95f536d2da66b198efcf9d9ff355") },
                { 1850000, uint256("0x00000e1b13b2b08d36598664d508a38500c59fcff4cf3d3746de0738b6eef457") },
                { 1890005, uint256("0x00000dfd4e2286daee184a67b9266e40b8c1c5daf3a29a2321fd23e6c2da62e2") },
                { 1911210, uint256("000009e3b1cc249ba64c3749430b96cf0f3c25acbb2bd3cb0b69e3b28288607b") },
            }
        };

        // TODO: Implement later
        chainTxData = ChainTxData{
            // Data as of block 00000c75a8a38f320cb41ce2ea86557b6b53f9daddc9a085d95f1c77aebbc547 (height 1949485).
            1749704574, // * UNIX timestamp of last known number of transactions
            2525586,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0005         // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.powLimit = CBigNum(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.initialHashTarget = CBigNum(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.initialMoneySupply = 1E14; // With this value, each block reward in the first interval is  3.802570 YAC
        consensus.BIP65Height = 0; // 0000030f8402abf3d0e2efeb72274da8a4b4389ef8267d2c2a14fe58f2e088d0
        consensus.BIP68Height = 0; // 0000030f8402abf3d0e2efeb72274da8a4b4389ef8267d2c2a14fe58f2e088d0
        consensus.HeliopolisHardforkHeight = 0; // 0000030f8402abf3d0e2efeb72274da8a4b4389ef8267d2c2a14fe58f2e088d0
        consensus.nPowTargetTimespan = 10;  // 10blocks
        consensus.nPowTargetSpacing = 1 * 60; // 1 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 2;
        consensus.nMinerConfirmationWindow = 6; // similar to COINBASE_MATURITY_AFTER_HARDFORK
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.nStakeMaxAge = 60 * 60 * 24 * 90; // 90 days as full weight
        consensus.nStakeMinAge = 60 * 60 * 24 * 30; // minimum age for coin age
        consensus.nModifierInterval = 6 * 60 * 60; // Modifier interval: time to elapse before new modifier is computed

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xd9;
        pchMessageStart[1] = 0xe6;
        pchMessageStart[2] = 0xe7;
        pchMessageStart[3] = 0xe5;
        nDefaultPort = 7688;
        nPruneAfterHeight = 100000;

        const uint32_t nNonceGenesisBlock = 127357;
        genesis = CreateGenesisBlock(nChainStartTime, nNonceGenesisBlock, consensus.powLimit.GetCompact(), 1);
        consensus.hashGenesisBlock = genesis.GetHash();
        Yassert(consensus.hashGenesisBlock == uint256S("0x08603b3b7020256db3a4a1e2e1d18cebd51f7000d0ba1a32e65eabeb449f4e2e"));
        Yassert(genesis.hashMerkleRoot == uint256S("0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f"));

        // TODO: Implement later
        // Note that of those with the service bits flag, most only support a subset of possible options
//        vSeeds.emplace_back("seed.bitcoin.sipa.be", true); // Pieter Wuille, only supports x1, x5, x9, and xd
//        vSeeds.emplace_back("dnsseed.bluematt.me", true); // Matt Corallo, only supports x9
//        vSeeds.emplace_back("dnsseed.bitcoin.dashjr.org", false); // Luke Dashjr
//        vSeeds.emplace_back("seed.bitcoinstats.com", true); // Christian Decker, supports x1 - xf
//        vSeeds.emplace_back("seed.bitcoin.jonasschnelli.ch", true); // Jonas Schnelli, only supports x1, x5, x9, and xd
//        vSeeds.emplace_back("seed.btc.petertodd.org", true); // Peter Todd, only supports x1, x5, x9, and xd

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,77);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,139);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,205);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = false;

        checkpointData = (CCheckpointData) {
            {
                {0, consensus.hashGenesisBlock},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
