// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "data/tx_invalid.json.h"
#include "data/tx_valid.json.h"
#include "test/test_bitcoin.h"

#include "clientversion.h"
#include "checkqueue.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "validation.h"
#include "policy/policy.h"
#include "script/script.h"
#include "script/sign.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "utilstrencodings.h"

#include <map>
#include <string>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

typedef std::vector<unsigned char> valtype;

// In script_tests.cpp
extern UniValue read_json(const std::string& jsondata);

static std::map<std::string, unsigned int> mapFlagNames = {
    {std::string("NONE"), (unsigned int)SCRIPT_VERIFY_NONE},
    {std::string("P2SH"), (unsigned int)SCRIPT_VERIFY_P2SH},
    {std::string("STRICTENC"), (unsigned int)SCRIPT_VERIFY_STRICTENC},
    {std::string("DERSIG"), (unsigned int)SCRIPT_VERIFY_DERSIG},
    {std::string("LOW_S"), (unsigned int)SCRIPT_VERIFY_LOW_S},
    {std::string("SIGPUSHONLY"), (unsigned int)SCRIPT_VERIFY_SIGPUSHONLY},
    {std::string("MINIMALDATA"), (unsigned int)SCRIPT_VERIFY_MINIMALDATA},
    {std::string("NULLDUMMY"), (unsigned int)SCRIPT_VERIFY_NULLDUMMY},
    {std::string("DISCOURAGE_UPGRADABLE_NOPS"), (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
    {std::string("CLEANSTACK"), (unsigned int)SCRIPT_VERIFY_CLEANSTACK},
    {std::string("NULLFAIL"), (unsigned int)SCRIPT_VERIFY_NULLFAIL},
    {std::string("CHECKLOCKTIMEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
    {std::string("CHECKSEQUENCEVERIFY"), (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
};

unsigned int ParseScriptFlags(std::string strFlags)
{
    if (strFlags.empty()) {
        return 0;
    }
    unsigned int flags = 0;
    std::vector<std::string> words;
    boost::algorithm::split(words, strFlags, boost::algorithm::is_any_of(","));

    for (std::string word : words)
    {
        if (!mapFlagNames.count(word))
            BOOST_ERROR("Bad test: unknown verification flag '" << word << "'");
        flags |= mapFlagNames[word];
    }

    return flags;
}

std::string FormatScriptFlags(unsigned int flags)
{
    if (flags == 0) {
        return "";
    }
    std::string ret;
    std::map<std::string, unsigned int>::const_iterator it = mapFlagNames.begin();
    while (it != mapFlagNames.end()) {
        if (flags & it->second) {
            ret += it->first + ",";
        }
        it++;
    }
    return ret.substr(0, ret.size() - 1);
}

BOOST_FIXTURE_TEST_SUITE(transaction_tests, BasicTestingSetup)

//BOOST_AUTO_TEST_CASE(tx_valid)
//{
//    // Read tests from test/data/tx_valid.json
//    // Format is an array of arrays
//    // Inner arrays are either [ "comment" ]
//    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"], serializedTransaction, verifyFlags
//    // ... where all scripts are stringified scripts.
//    //
//    // verifyFlags is a comma separated list of script verification flags to apply, or "NONE"
//    UniValue tests = read_json(std::string(json_tests::tx_valid, json_tests::tx_valid + sizeof(json_tests::tx_valid)));
//
//    ScriptError err;
//    for (unsigned int idx = 0; idx < tests.size(); idx++) {
//        UniValue test = tests[idx];
//        std::string strTest = test.write();
//        if (test[0].isArray())
//        {
//            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
//            {
//                BOOST_ERROR("Bad test: " << strTest);
//                continue;
//            }
//
//            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
//            std::map<COutPoint, int64_t> mapprevOutValues;
//            UniValue inputs = test[0].get_array();
//            bool fValid = true;
//	    for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
//	        const UniValue& input = inputs[inpIdx];
//                if (!input.isArray())
//                {
//                    fValid = false;
//                    break;
//                }
//                UniValue vinput = input.get_array();
//                if (vinput.size() < 3 || vinput.size() > 4)
//                {
//                    fValid = false;
//                    break;
//                }
//                COutPoint outpoint(uint256S(vinput[0].get_str()), vinput[1].get_int());
//                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
//                if (vinput.size() >= 4)
//                {
//                    mapprevOutValues[outpoint] = vinput[3].get_int64();
//                }
//            }
//            if (!fValid)
//            {
//                BOOST_ERROR("Bad test: " << strTest);
//                continue;
//            }
//
//            std::string transaction = test[1].get_str();
//            CDataStream stream(ParseHex(transaction), SER_NETWORK, PROTOCOL_VERSION);
//            CTransaction tx(deserialize, stream);
//
//            CValidationState state;
//            BOOST_CHECK_MESSAGE(CheckTransaction(tx, state), strTest);
//            BOOST_CHECK(state.IsValid());
//
//            for (unsigned int i = 0; i < tx.vin.size(); i++)
//            {
//                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout))
//                {
//                    BOOST_ERROR("Bad test: " << strTest);
//                    break;
//                }
//
//                CAmount amount = 0;
//                if (mapprevOutValues.count(tx.vin[i].prevout)) {
//                    amount = mapprevOutValues[tx.vin[i].prevout];
//                }
//                unsigned int verify_flags = ParseScriptFlags(test[2].get_str());
//                BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[i].scriptSig, mapprevOutScriptPubKeys[tx.vin[i].prevout],
//                                                 verify_flags, TransactionSignatureChecker(&tx, i), &err),
//                                    strTest);
//                BOOST_CHECK_MESSAGE(err == SCRIPT_ERR_OK, ScriptErrorString(err));
//            }
//        }
//    }
//}
//
//BOOST_AUTO_TEST_CASE(tx_invalid)
//{
//    // Read tests from test/data/tx_invalid.json
//    // Format is an array of arrays
//    // Inner arrays are either [ "comment" ]
//    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"], serializedTransaction, verifyFlags
//    // ... where all scripts are stringified scripts.
//    //
//    // verifyFlags is a comma separated list of script verification flags to apply, or "NONE"
//    UniValue tests = read_json(std::string(json_tests::tx_invalid, json_tests::tx_invalid + sizeof(json_tests::tx_invalid)));
//
//    // Initialize to SCRIPT_ERR_OK. The tests expect err to be changed to a
//    // value other than SCRIPT_ERR_OK.
//    ScriptError err = SCRIPT_ERR_OK;
//    for (unsigned int idx = 0; idx < tests.size(); idx++) {
//        UniValue test = tests[idx];
//        std::string strTest = test.write();
//        if (test[0].isArray())
//        {
//            if (test.size() != 3 || !test[1].isStr() || !test[2].isStr())
//            {
//                BOOST_ERROR("Bad test: " << strTest);
//                continue;
//            }
//
//            std::map<COutPoint, CScript> mapprevOutScriptPubKeys;
//            std::map<COutPoint, int64_t> mapprevOutValues;
//            UniValue inputs = test[0].get_array();
//            bool fValid = true;
//	    for (unsigned int inpIdx = 0; inpIdx < inputs.size(); inpIdx++) {
//	        const UniValue& input = inputs[inpIdx];
//                if (!input.isArray())
//                {
//                    fValid = false;
//                    break;
//                }
//                UniValue vinput = input.get_array();
//                if (vinput.size() < 3 || vinput.size() > 4)
//                {
//                    fValid = false;
//                    break;
//                }
//                COutPoint outpoint(uint256S(vinput[0].get_str()), vinput[1].get_int());
//                mapprevOutScriptPubKeys[outpoint] = ParseScript(vinput[2].get_str());
//                if (vinput.size() >= 4)
//                {
//                    mapprevOutValues[outpoint] = vinput[3].get_int64();
//                }
//            }
//            if (!fValid)
//            {
//                BOOST_ERROR("Bad test: " << strTest);
//                continue;
//            }
//
//            std::string transaction = test[1].get_str();
//            CDataStream stream(ParseHex(transaction), SER_NETWORK, PROTOCOL_VERSION );
//            CTransaction tx(deserialize, stream);
//
//            CValidationState state;
//            fValid = CheckTransaction(tx, state) && state.IsValid();
//
//            for (unsigned int i = 0; i < tx.vin.size() && fValid; i++)
//            {
//                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout))
//                {
//                    BOOST_ERROR("Bad test: " << strTest);
//                    break;
//                }
//
//                unsigned int verify_flags = ParseScriptFlags(test[2].get_str());
//                CAmount amount = 0;
//                if (mapprevOutValues.count(tx.vin[i].prevout)) {
//                    amount = mapprevOutValues[tx.vin[i].prevout];
//                }
//                fValid = VerifyScript(tx.vin[i].scriptSig, mapprevOutScriptPubKeys[tx.vin[i].prevout],
//                                      verify_flags, TransactionSignatureChecker(&tx, i), &err);
//            }
//            BOOST_CHECK_MESSAGE(!fValid, strTest);
//            BOOST_CHECK_MESSAGE(err != SCRIPT_ERR_OK, ScriptErrorString(err));
//        }
//    }
//}

BOOST_AUTO_TEST_CASE(basic_transaction_tests)
{
    // Random real transaction (4877d3b664859a1b0ec0a8ba7da83640e602459178ffe2b2facf45c7fac6b658)
    unsigned char ch[] = {
        0x02, 0x00, 0x00, 0x00, 0xbe, 0xc8, 0x75, 0x68, 0x00, 0x00, 0x00, 0x00,
        0x03, 0xf0, 0x58, 0x08, 0x07, 0xe1, 0xeb, 0xf2, 0x8b, 0x51, 0x7d, 0xd7,
        0xb9, 0x45, 0x9e, 0x48, 0x39, 0xcb, 0xdc, 0x1f, 0x0d, 0xd8, 0x25, 0x96,
        0xe1, 0x7f, 0x97, 0xca, 0x01, 0x4c, 0x1a, 0xc7, 0x05, 0x01, 0x00, 0x00,
        0x00, 0x6b, 0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0x8f, 0x09, 0x75, 0x34,
        0x5c, 0xfa, 0xb9, 0xe3, 0x32, 0xa8, 0x37, 0xa1, 0x1c, 0xed, 0x59, 0x1c,
        0x00, 0xee, 0xec, 0xac, 0x72, 0xf5, 0xc1, 0xa7, 0x1e, 0x8d, 0x50, 0x63,
        0x87, 0x14, 0xda, 0x03, 0x02, 0x20, 0x7b, 0x57, 0x98, 0x04, 0xa7, 0xf6,
        0x41, 0x11, 0x51, 0x20, 0xd6, 0x24, 0x6a, 0x99, 0x03, 0x4e, 0x23, 0xff,
        0x5e, 0xae, 0x21, 0x07, 0x6d, 0x19, 0xf6, 0x72, 0x4c, 0x04, 0x8d, 0x2e,
        0x63, 0x0a, 0x01, 0x21, 0x02, 0x98, 0x43, 0x93, 0x6c, 0x2a, 0x2f, 0xfa,
        0xb1, 0x55, 0x48, 0x43, 0xc6, 0x8c, 0x26, 0xff, 0x67, 0x38, 0x63, 0xce,
        0x14, 0xf7, 0x7d, 0x07, 0xc3, 0x6b, 0x6a, 0x55, 0xc5, 0x84, 0xa3, 0x06,
        0x68, 0xff, 0xff, 0xff, 0xff, 0x5c, 0xc2, 0xe8, 0x01, 0xeb, 0x74, 0x92,
        0xd8, 0x99, 0xcb, 0x03, 0xc8, 0xf8, 0x4f, 0xea, 0x53, 0x0a, 0xcf, 0x33,
        0xe1, 0xb6, 0x34, 0x59, 0xeb, 0xa9, 0xaf, 0x5e, 0x0b, 0xc7, 0x4a, 0x92,
        0x6c, 0x01, 0x00, 0x00, 0x00, 0x6a, 0x47, 0x30, 0x44, 0x02, 0x20, 0x66,
        0x4b, 0x6a, 0x64, 0x59, 0x33, 0x03, 0x57, 0xaf, 0x90, 0x4e, 0x29, 0xad,
        0xb1, 0xeb, 0xcf, 0x86, 0xf7, 0x33, 0x8f, 0xf9, 0xbd, 0x07, 0x0b, 0x88,
        0xfa, 0xc7, 0x3d, 0x27, 0xf5, 0xe6, 0x8e, 0x02, 0x20, 0x52, 0x99, 0x65,
        0x38, 0x40, 0x45, 0x62, 0x2b, 0x43, 0xd4, 0xb6, 0x83, 0xb8, 0x0b, 0xf0,
        0x4e, 0x79, 0x7a, 0xe6, 0x5d, 0x73, 0x11, 0x12, 0xcf, 0x0d, 0xe0, 0xe2,
        0x6b, 0x55, 0x02, 0x04, 0xd7, 0x01, 0x21, 0x02, 0x73, 0xab, 0x48, 0x78,
        0xe6, 0x64, 0xd8, 0xa1, 0xd6, 0x22, 0xb2, 0x31, 0x8c, 0x65, 0x7c, 0x82,
        0xe2, 0x76, 0x44, 0xa4, 0x91, 0x18, 0xe7, 0xb0, 0x2d, 0x39, 0xe6, 0x0c,
        0x6d, 0xed, 0x1f, 0xb5, 0xff, 0xff, 0xff, 0xff, 0xb5, 0xaf, 0x09, 0xac,
        0x27, 0x42, 0x89, 0x48, 0xad, 0x5c, 0xfe, 0xdc, 0xb5, 0xe3, 0x86, 0x1a,
        0x41, 0x42, 0x20, 0x7a, 0x21, 0xee, 0x50, 0x84, 0x7e, 0x39, 0xa4, 0xed,
        0x5b, 0x8f, 0xdc, 0xfb, 0x01, 0x00, 0x00, 0x00, 0x6a, 0x47, 0x30, 0x44,
        0x02, 0x20, 0x7b, 0x7a, 0xc0, 0x47, 0xd7, 0x67, 0x70, 0xfd, 0xf4, 0xce,
        0x38, 0xd0, 0xdf, 0x1e, 0xd0, 0xa2, 0x88, 0x58, 0x4b, 0xdb, 0x52, 0x0a,
        0x91, 0x28, 0x95, 0x74, 0x32, 0x51, 0xde, 0xc3, 0x2a, 0xd3, 0x02, 0x20,
        0x51, 0xe2, 0xfd, 0x14, 0xf5, 0x53, 0xef, 0x46, 0xe2, 0x3d, 0x78, 0xe3,
        0x00, 0x12, 0x0f, 0x7d, 0x93, 0x39, 0x82, 0x72, 0xbe, 0xb0, 0x5f, 0xe6,
        0x23, 0x6f, 0xfa, 0x6e, 0x18, 0x6a, 0xdf, 0x9f, 0x01, 0x21, 0x02, 0xc8,
        0xdb, 0x0d, 0xd3, 0x3c, 0xc4, 0x44, 0xb6, 0x68, 0xbb, 0x59, 0x56, 0x96,
        0x3a, 0xaf, 0x8e, 0xff, 0x00, 0xfe, 0x45, 0xfb, 0x8c, 0xe1, 0x2e, 0x6f,
        0x2a, 0xc0, 0xe5, 0x6d, 0x44, 0x9d, 0x71, 0xff, 0xff, 0xff, 0xff, 0x02,
        0xa0, 0x7b, 0x62, 0xa4, 0x19, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14,
        0x8b, 0x7e, 0x58, 0x50, 0xba, 0xf6, 0x02, 0xdb, 0xb5, 0x1d, 0x95, 0x70,
        0xe8, 0x9e, 0x9a, 0x56, 0x17, 0xb1, 0xfa, 0xfd, 0x88, 0xac, 0x2c, 0x8d,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0x4b, 0x09,
        0xe5, 0xc0, 0x7a, 0xde, 0x5e, 0xa5, 0x08, 0x9c, 0x97, 0x16, 0x74, 0x8b,
        0x00, 0x79, 0x98, 0xfc, 0x65, 0x07, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00,
        0x00};
    std::vector<unsigned char> vch(ch, ch + sizeof(ch) -1);
    CDataStream stream(vch, SER_DISK, CLIENT_VERSION);
    CMutableTransaction tx;
    stream >> tx;
    CValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(tx, state) && state.IsValid(), "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!CheckTransaction(tx, state) || !state.IsValid(), "Transaction with duplicate txins should be invalid.");
}

//
// Helper: create two dummy transactions, each with
// two outputs.  The first has 11 and 50 CENT outputs
// paid to a TX_PUBKEY, the second 21 and 22 CENT outputs
// paid to a TX_PUBKEYHASH.
//
static std::vector<CMutableTransaction>
SetupDummyInputs(CBasicKeyStore& keystoreRet, CCoinsViewCache& coinsRet)
{
    std::vector<CMutableTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 11*CENT;
    dummyTransactions[0].vout[0].scriptPubKey << ToByteVector(key[0].GetPubKey()) << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = 50*CENT;
    dummyTransactions[0].vout[1].scriptPubKey << ToByteVector(key[1].GetPubKey()) << OP_CHECKSIG;
    AddCoins(coinsRet, dummyTransactions[0], 0, uint256());

    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = 21*CENT;
    dummyTransactions[1].vout[0].scriptPubKey = GetScriptForDestination(key[2].GetPubKey().GetID());
    dummyTransactions[1].vout[1].nValue = 22*CENT;
    dummyTransactions[1].vout[1].scriptPubKey = GetScriptForDestination(key[3].GetPubKey().GetID());
    AddCoins(coinsRet, dummyTransactions[1], 0, uint256());

    return dummyTransactions;
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CMutableTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(AreInputsStandard(t1, coins));
    BOOST_CHECK_EQUAL(coins.GetValueIn(t1), (50+21+22)*CENT);
}

void CreateCreditAndSpend(const CKeyStore& keystore, const CScript& outscript, CTransactionRef& output, CMutableTransaction& input, bool success = true)
{
    CMutableTransaction outputm;
    outputm.nVersion = 1;
    outputm.vin.resize(1);
    outputm.vin[0].prevout.SetNull();
    outputm.vin[0].scriptSig = CScript();
    outputm.vout.resize(1);
    outputm.vout[0].nValue = 1;
    outputm.vout[0].scriptPubKey = outscript;
    CDataStream ssout(SER_NETWORK, PROTOCOL_VERSION);
    ssout << outputm;
    ssout >> output;
    assert(output->vin.size() == 1);
    assert(output->vin[0] == outputm.vin[0]);
    assert(output->vout.size() == 1);
    assert(output->vout[0] == outputm.vout[0]);

    CTransaction inputm;
    inputm.nVersion = 1;
    inputm.vin.resize(1);
    inputm.vin[0].prevout.hash = output->GetHash();
    inputm.vin[0].prevout.n = 0;
    inputm.vout.resize(1);
    inputm.vout[0].nValue = 1;
    inputm.vout[0].scriptPubKey = CScript();
    bool ret = SignSignature(keystore, *output, inputm, 0, SIGHASH_ALL);
    assert(ret == success);
    CDataStream ssin(SER_NETWORK, PROTOCOL_VERSION);
    ssin << inputm;
    ssin >> input;
    assert(input.vin.size() == 1);
    assert(input.vin[0] == inputm.vin[0]);
    assert(input.vout.size() == 1);
    assert(input.vout[0] == inputm.vout[0]);
}

void CheckWithFlag(const CTransactionRef& output, const CMutableTransaction& input, int flags, bool success)
{
    ScriptError error;
    CTransaction inputi(input);
    bool ret = VerifyScript(inputi.vin[0].scriptSig, output->vout[0].scriptPubKey, flags, TransactionSignatureChecker(&inputi, 0), &error);
    assert(ret == success);
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else {
            result << v;
        }
    }
    return result;
}

void ReplaceRedeemScript(CScript& script, const CScript& redeemScript)
{
    std::vector<valtype> stack;
    EvalScript(stack, script, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker());
    assert(stack.size() > 0);
    stack.back() = std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());
    script = PushAll(stack);
}

BOOST_AUTO_TEST_CASE(test_big_transaction) {
    CTransaction mtx;
    mtx.nVersion = 2;

    CKey key;
    key.MakeNewKey(true);
    CBasicKeyStore keystore;
    keystore.AddKeyPubKey(key, key.GetPubKey());
    CScript scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

    std::vector<int> sigHashes;
    sigHashes.push_back(SIGHASH_NONE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    sigHashes.push_back(SIGHASH_NONE);
    sigHashes.push_back(SIGHASH_SINGLE);
    sigHashes.push_back(SIGHASH_ALL);

    // create a big transaction of 4500 inputs signed by the same key
    for(uint32_t ij = 0; ij < 4500; ij++) {
        uint32_t i = mtx.vin.size();
        uint256 prevId;
        prevId.SetHex("0000000000000000000000000000000000000000000000000000000000000100");
        COutPoint outpoint(prevId, i);

        mtx.vin.resize(mtx.vin.size() + 1);
        mtx.vin[i].prevout = outpoint;
        mtx.vin[i].scriptSig = CScript();

        mtx.vout.resize(mtx.vout.size() + 1);
        mtx.vout[i].nValue = 1000;
        mtx.vout[i].scriptPubKey = CScript() << OP_1;
    }

    // sign all inputs
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        bool hashSigned = SignSignature(keystore, scriptPubKey, mtx, i, sigHashes.at(i % sigHashes.size()));
        assert(hashSigned);
    }

    CTransaction tx(mtx);

    // check all inputs concurrently, with the cache
    boost::thread_group threadGroup;
    CCheckQueue<CScriptCheck> scriptcheckqueue(128);
    CCheckQueueControl<CScriptCheck> control(&scriptcheckqueue);

    for (int i=0; i<20; i++)
        threadGroup.create_thread(boost::bind(&CCheckQueue<CScriptCheck>::Thread, boost::ref(scriptcheckqueue)));

    std::vector<Coin> coins;
    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        Coin coin;
        coin.nHeight = 1;
        coin.fCoinBase = false;
        coin.out.nValue = 1000;
        coin.out.scriptPubKey = scriptPubKey;
        coins.emplace_back(std::move(coin));
    }

    for(uint32_t i = 0; i < mtx.vin.size(); i++) {
        std::vector<CScriptCheck> vChecks;
        const CTxOut& output = coins[tx.vin[i].prevout.n].out;
        CScriptCheck check(output.scriptPubKey, tx, i, SCRIPT_VERIFY_P2SH, false);
        vChecks.push_back(CScriptCheck());
        check.swap(vChecks.back());
        control.Add(vChecks);
    }

    bool controlCheck = control.Wait();
    assert(controlCheck);

    threadGroup.interrupt_all();
    threadGroup.join_all();
}

BOOST_AUTO_TEST_CASE(test_IsStandard)
{
    LOCK(cs_main);
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CMutableTransaction t;
    t.vin.resize(1);
    t.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t.vin[0].prevout.n = 1;
    t.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t.vout.resize(1);
    t.vout[0].nValue = 90*CENT;
    CKey key;
    key.MakeNewKey(true);
    t.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());

    std::string reason;
    BOOST_CHECK(IsStandardTx(t, reason));

    t.vout[0].scriptPubKey = CScript() << OP_1;
    BOOST_CHECK(!IsStandardTx(t, reason));

    // Data payload can be encoded in any way...
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("");
    BOOST_CHECK(IsStandardTx(t, reason));
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("00") << ParseHex("01");
    BOOST_CHECK(IsStandardTx(t, reason));
    // OP_RESERVED *is* considered to be a PUSHDATA type opcode by IsPushOnly()!
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RESERVED << -1 << 0 << ParseHex("01") << 2 << 3 << 4 << 5 << 6 << 7 << 8 << 9 << 10 << 11 << 12 << 13 << 14 << 15 << 16;
    BOOST_CHECK(IsStandardTx(t, reason));
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << 0 << ParseHex("01") << 2 << ParseHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    BOOST_CHECK(IsStandardTx(t, reason));

    // ...so long as it only contains PUSHDATA's
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << OP_RETURN;
    BOOST_CHECK(!IsStandardTx(t, reason));

    // TX_NULL_DATA w/o PUSHDATA
    t.vout.resize(1);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(IsStandardTx(t, reason));

    // Only one TX_NULL_DATA permitted in all cases
    t.vout.resize(2);
    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38");
    BOOST_CHECK(!IsStandardTx(t, reason));

    t.vout[0].scriptPubKey = CScript() << OP_RETURN << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38");
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(!IsStandardTx(t, reason));

    t.vout[0].scriptPubKey = CScript() << OP_RETURN;
    t.vout[1].scriptPubKey = CScript() << OP_RETURN;
    BOOST_CHECK(!IsStandardTx(t, reason));
}

BOOST_AUTO_TEST_SUITE_END()
