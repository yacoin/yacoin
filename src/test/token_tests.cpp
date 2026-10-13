// Copyright (c) 2017-2019 The Raven Core developers
// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Name tests adapted from Ravencoin's src/test/assets/asset_tests.cpp, with
// YACoin's rules: no restricted, qualifier or message channel tokens, and
// YAC/YACOIN reserved instead of RVN/RAVEN.

#include "amount.h"
#include "script/script.h"
#include "tokens/tokens.h"
#include "utilstrencodings.h"
#include "wallet/wallet.h"

#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(token_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(name_validation)
{
    ETokenType type;

    // YA-tokens: 3-30 characters of A-Z 0-9 . _
    BOOST_CHECK(IsTokenNameValid("MIN", type));
    BOOST_CHECK(type == ETokenType::YATOKEN);
    BOOST_CHECK(IsTokenNameValid("MAX_TOKEN_IS_30_CHARACTERS_LNG", type));
    BOOST_CHECK(!IsTokenNameValid("MAX_TOKEN_IS_31_CHARACTERS_LONG", type));
    BOOST_CHECK(type == ETokenType::INVALID);
    BOOST_CHECK(IsTokenNameValid("A_BCDEFGHIJKLMNOPQRSTUVWXY.Z"));
    BOOST_CHECK(IsTokenNameValid("0_12345678.9"));

    BOOST_CHECK(!IsTokenNameValid("NO"));
    BOOST_CHECK(!IsTokenNameValid("nolower"));
    BOOST_CHECK(!IsTokenNameValid("NO SPACE"));
    BOOST_CHECK(!IsTokenNameValid("(#&$(&*^%$))"));
    BOOST_CHECK(!IsTokenNameValid(""));

    BOOST_CHECK(!IsTokenNameValid("_ABC"));
    BOOST_CHECK(!IsTokenNameValid("ABC_"));
    BOOST_CHECK(!IsTokenNameValid(".ABC"));
    BOOST_CHECK(!IsTokenNameValid("ABC."));
    BOOST_CHECK(!IsTokenNameValid("AB..C"));
    BOOST_CHECK(!IsTokenNameValid("A__BC"));
    BOOST_CHECK(!IsTokenNameValid("A._BC"));
    BOOST_CHECK(!IsTokenNameValid("AB_.C"));

    // Names of the coin itself are reserved, variations are allowed
    BOOST_CHECK(!IsTokenNameValid("YAC"));
    BOOST_CHECK(!IsTokenNameValid("YACOIN"));
    BOOST_CHECK(IsTokenNameValid("YAC.COIN"));
    BOOST_CHECK(IsTokenNameValid("YAC_COIN"));
    BOOST_CHECK(IsTokenNameValid("YACSPYDER"));
    BOOST_CHECK(IsTokenNameValid("SPYDERYAC"));
    BOOST_CHECK(IsTokenNameValid("YACOINS"));

    // Ravencoin-only token kinds don't exist in YACoin
    BOOST_CHECK(!IsTokenNameValid("ABC~CHANNEL"));
    BOOST_CHECK(!IsTokenNameValid("#QUALIFIER"));
    BOOST_CHECK(!IsTokenNameValid("$RESTRICTED"));

    // Anything over 40 characters is rejected before the regexes run
    BOOST_CHECK(!IsTokenNameValid(std::string(41, 'A')));

    // Sub tokens
    BOOST_CHECK(IsTokenNameValid("ABC/A", type));
    BOOST_CHECK(type == ETokenType::SUB);
    BOOST_CHECK(IsTokenNameValid("ABC/A/1"));
    BOOST_CHECK(IsTokenNameValid("ABC/A_1/1.A"));
    BOOST_CHECK(IsTokenNameValid("ABC/AB/XYZ/STILL/MAX/30/123456"));

    BOOST_CHECK(!IsTokenNameValid("ABC//MIN_1"));
    BOOST_CHECK(!IsTokenNameValid("ABC/"));
    BOOST_CHECK(!IsTokenNameValid("ABC/NOTRAIL/"));
    BOOST_CHECK(!IsTokenNameValid("ABC/_X"));
    BOOST_CHECK(!IsTokenNameValid("ABC/X_"));
    BOOST_CHECK(!IsTokenNameValid("ABC/.X"));
    BOOST_CHECK(!IsTokenNameValid("ABC/X."));
    BOOST_CHECK(!IsTokenNameValid("ABC/X__X"));
    BOOST_CHECK(!IsTokenNameValid("ABC/X..X"));
    BOOST_CHECK(!IsTokenNameValid("ABC/X_.X"));
    BOOST_CHECK(!IsTokenNameValid("ABC/X._X"));
    BOOST_CHECK(!IsTokenNameValid("ABC/nolower"));
    BOOST_CHECK(!IsTokenNameValid("ABC/NO SPACE"));
    BOOST_CHECK(!IsTokenNameValid("ABC/(*#^&$%)"));
    BOOST_CHECK(!IsTokenNameValid("ABC/AB/XYZ/STILL/MAX/30/OVERALL/1234"));
    BOOST_CHECK(!IsTokenNameValid("AB/SUB")); // parent still needs 3 characters

    // Unique tokens: the tag also allows lower case and punctuation
    BOOST_CHECK(IsTokenNameValid("ABC#AZaz09", type));
    BOOST_CHECK(type == ETokenType::UNIQUE);
    BOOST_CHECK(IsTokenNameValid("ABC#abc123ABC@$%&*()[]{}-_.?:"));
    BOOST_CHECK(!IsTokenNameValid("ABC#no!bangs"));
    BOOST_CHECK(IsTokenNameValid("ABC/THING#_STILL_31_MAX-------_"));
    BOOST_CHECK(!IsTokenNameValid("ABC/THING#_STILL_31_MAX--------_"));

    BOOST_CHECK(!IsTokenNameValid("MIN#"));
    BOOST_CHECK(!IsTokenNameValid("ABC#NO#HASH"));
    BOOST_CHECK(!IsTokenNameValid("ABC#NO SPACE"));
    BOOST_CHECK(!IsTokenNameValid("ABC#RESERVED/"));
    BOOST_CHECK(!IsTokenNameValid("ABC#RESERVED~"));
    BOOST_CHECK(!IsTokenNameValid("ABC#RESERVED^"));

    // Owner tokens
    BOOST_CHECK(IsTokenNameValid("ABC!", type));
    BOOST_CHECK(type == ETokenType::OWNER);
    BOOST_CHECK(IsTokenNameAnOwner("ABC!"));
    BOOST_CHECK(!IsTokenNameAnOwner("ABC"));
    BOOST_CHECK(!IsTokenNameAnOwner("ABC!COIN"));
    BOOST_CHECK(IsTokenNameAnOwner("MAX_TOKEN_IS_30_CHARACTERS_LNG!"));
    BOOST_CHECK(!IsTokenNameAnOwner("MAX_TOKEN_IS_31_CHARACTERS_LONG!"));
    BOOST_CHECK(IsTokenNameAnOwner("ABC/A!"));
    BOOST_CHECK(IsTokenNameAnOwner("ABC/A/1!"));
    BOOST_CHECK(!IsTokenNameAnOwner("ABC#TAG!"));

    // Vote tokens
    BOOST_CHECK(IsTokenNameValid("ABC^VOTE"));
    BOOST_CHECK(!IsTokenNameValid("ABC^"));
    BOOST_CHECK(IsTokenNameValid("ABC^VOTING_IS_30_CHARACTERS_LN"));
    BOOST_CHECK(IsTokenNameValid("ABC/SUB/SUB^VOTE", type));
    BOOST_CHECK(type == ETokenType::VOTE);
    BOOST_CHECK(!IsTokenNameValid("ABC^vote"));

    // Combinations
    BOOST_CHECK(IsTokenNameValid("TEST/UYTH#UNIQUE", type));
    BOOST_CHECK(type == ETokenType::UNIQUE);
    BOOST_CHECK(IsTokenNameValid("TEST/UYTH/SUB#UNIQUE", type));
    BOOST_CHECK(type == ETokenType::UNIQUE);
    BOOST_CHECK(!IsTokenNameValid("TEST/UYTH/SUB#UNIQUE^VOTE"));
    BOOST_CHECK(!IsTokenNameValid("TEST/UYTH/SUB#UNIQUE#UNIQUE"));
    BOOST_CHECK(!IsTokenNameValid("TEST/UYTH/SUB^VOTE!"));

    BOOST_CHECK(IsTokenNameAYatoken("ABC"));
    BOOST_CHECK(!IsTokenNameAYatoken("ABC/SUB"));
    BOOST_CHECK(!IsTokenNameAYatoken("ABC!"));
}

BOOST_AUTO_TEST_CASE(name_helpers)
{
    BOOST_CHECK_EQUAL(GetParentName("TEST!"), "TEST!");
    BOOST_CHECK_EQUAL(GetParentName("TEST"), "TEST");
    BOOST_CHECK_EQUAL(GetParentName("TEST/SUB"), "TEST");
    BOOST_CHECK_EQUAL(GetParentName("TEST/SUB#UNIQUE"), "TEST/SUB");
    BOOST_CHECK_EQUAL(GetParentName("TEST/TEST/SUB/SUB"), "TEST/TEST/SUB");
    BOOST_CHECK_EQUAL(GetParentName("TEST/SUB^VOTE"), "TEST/SUB");
    BOOST_CHECK_EQUAL(GetParentName("#TEST"), "");
    BOOST_CHECK_EQUAL(GetParentName("._INVALIDNAME"), "");

    BOOST_CHECK_EQUAL(GetUniqueTokenName("ABC", "TAG"), "ABC#TAG");
    BOOST_CHECK_EQUAL(GetUniqueTokenName("ABC/SUB", "tag.1"), "ABC/SUB#tag.1");
    BOOST_CHECK_EQUAL(GetUniqueTokenName("_.INVALID", "TAG"), "");
    BOOST_CHECK_EQUAL(GetUniqueTokenName("#TAG", "TAG"), "");
    BOOST_CHECK_EQUAL(GetUniqueTokenName("ABC", "BAD TAG"), "");

    // The unique tag keeps its case, everything else is upper-cased
    BOOST_CHECK_EQUAL(capitalizeTokenName("abc/sub"), "ABC/SUB");
    BOOST_CHECK_EQUAL(capitalizeTokenName("abc#Tag"), "ABC#Tag");
    BOOST_CHECK_EQUAL(capitalizeTokenName("abc!"), "ABC!");

    BOOST_CHECK(IsUniqueTagValid("Tag@1"));
    BOOST_CHECK(!IsUniqueTagValid("no space"));
}

/* Script detection and parsing: build each token script, then read it back */
BOOST_AUTO_TEST_CASE(new_token_script_round_trip)
{
    const std::string strIpfs = TestIpfsHash();
    BOOST_CHECK_EQUAL(strIpfs.size(), 34U);

    // Short payload ("yac" marker at byte 27) and long one (OP_PUSHDATA1, marker at byte 28)
    std::vector<CNewToken> tokens = {
        CNewToken("ABC", 1000 * COIN, 0, 1, 0, ""),
        CNewToken("MAX_TOKEN_IS_30_CHARACTERS_LNG", 21 * COIN + 5, 6, 0, 1, strIpfs),
    };
    for (const CNewToken& token : tokens) {
        CScript script = NewTokenScript(token);
        int nType = -1;
        bool fIsOwner = true;
        int nStart = 0;
        BOOST_CHECK(script.IsTokenScript(nType, fIsOwner, nStart));
        BOOST_CHECK_EQUAL(nType, TX_NEW_TOKEN);
        BOOST_CHECK(!fIsOwner);
        BOOST_CHECK_EQUAL(nStart, script.size() < 105 ? 31 : 32);
        BOOST_CHECK(IsScriptNewToken(script));
        BOOST_CHECK(!IsScriptNewUniqueToken(script));
        BOOST_CHECK(!IsScriptOwnerToken(script));
        BOOST_CHECK(!IsScriptReissueToken(script));
        BOOST_CHECK(!IsScriptTransferToken(script));
        BOOST_CHECK(CheckIssueDataTx(CTxOut(0, script)));

        CNewToken parsed;
        std::string strAddress;
        BOOST_CHECK(TokenFromScript(script, parsed, strAddress));
        BOOST_CHECK_EQUAL(strAddress, TestTokenAddress());
        BOOST_CHECK_EQUAL(parsed.strName, token.strName);
        BOOST_CHECK_EQUAL(parsed.nAmount, token.nAmount);
        BOOST_CHECK_EQUAL(parsed.units, token.units);
        BOOST_CHECK_EQUAL(parsed.nReissuable, token.nReissuable);
        BOOST_CHECK_EQUAL(parsed.nHasIPFS, token.nHasIPFS);
        BOOST_CHECK(parsed.strIPFSHash == token.strIPFSHash);

        CTokenOutputEntry data;
        BOOST_CHECK(GetTokenData(script, data));
        BOOST_CHECK_EQUAL(data.tokenName, token.strName);
        BOOST_CHECK_EQUAL(data.nAmount, token.nAmount);
        BOOST_CHECK(data.type == TX_NEW_TOKEN);
        BOOST_CHECK_EQUAL(EncodeDestination(data.destination), TestTokenAddress());

        uint160 hashBytes;
        std::string strName;
        CAmount nAmount;
        BOOST_CHECK(ParseTokenScript(script, hashBytes, strName, nAmount));
        BOOST_CHECK(hashBytes == uint160(std::vector<unsigned char>(20, 1)));
        BOOST_CHECK_EQUAL(strName, token.strName);
        BOOST_CHECK_EQUAL(nAmount, token.nAmount);
    }
    BOOST_CHECK(NewTokenScript(tokens[0]).size() < 105);
    BOOST_CHECK(NewTokenScript(tokens[1]).size() >= 105);
}

BOOST_AUTO_TEST_CASE(owner_transfer_reissue_unique_scripts)
{
    std::string strAddress;
    int nType;
    bool fIsOwner;

    // Owner
    CScript owner = OwnerTokenScript(CNewToken("ABC", 1000 * COIN));
    BOOST_CHECK(owner.IsTokenScript(nType, fIsOwner));
    BOOST_CHECK(nType == TX_NEW_TOKEN && fIsOwner);
    BOOST_CHECK(IsScriptOwnerToken(owner));
    BOOST_CHECK(!IsScriptNewToken(owner));
    BOOST_CHECK(CheckOwnerDataTx(CTxOut(0, owner)));
    std::string strOwner;
    BOOST_CHECK(OwnerTokenFromScript(owner, strOwner, strAddress));
    BOOST_CHECK_EQUAL(strOwner, "ABC!");
    BOOST_CHECK_EQUAL(strAddress, TestTokenAddress());
    std::string strName;
    CAmount nAmount;
    BOOST_CHECK(GetTokenInfoFromScript(owner, strName, nAmount));
    BOOST_CHECK_EQUAL(strName, "ABC!");
    BOOST_CHECK_EQUAL(nAmount, OWNER_TOKEN_AMOUNT);

    // Transfer
    CScript transfer = TransferTokenScript(CTokenTransfer("ABC", 7 * COIN), 2);
    BOOST_CHECK(IsScriptTransferToken(transfer));
    BOOST_CHECK(CheckTransferOwnerTx(CTxOut(0, transfer)));
    CTokenTransfer parsedTransfer;
    BOOST_CHECK(TransferTokenFromScript(transfer, parsedTransfer, strAddress));
    BOOST_CHECK_EQUAL(parsedTransfer.strName, "ABC");
    BOOST_CHECK_EQUAL(parsedTransfer.nAmount, 7 * COIN);
    BOOST_CHECK_EQUAL(strAddress, TestTokenAddress(2));

    // Reissue, with and without a new IPFS hash and units
    for (const CReissueToken& reissue : {CReissueToken("ABC", 5 * COIN, -1, 1, ""),
                                         CReissueToken("ABC", 0, 3, 0, TestIpfsHash())}) {
        CScript script = ReissueTokenScript(reissue);
        BOOST_CHECK(IsScriptReissueToken(script));
        BOOST_CHECK(CheckReissueDataTx(CTxOut(0, script)));
        CReissueToken parsed;
        BOOST_CHECK(ReissueTokenFromScript(script, parsed, strAddress));
        BOOST_CHECK_EQUAL(parsed.strName, reissue.strName);
        BOOST_CHECK_EQUAL(parsed.nAmount, reissue.nAmount);
        BOOST_CHECK_EQUAL(parsed.nUnits, reissue.nUnits);
        BOOST_CHECK_EQUAL(parsed.nReissuable, reissue.nReissuable);
        BOOST_CHECK(parsed.strIPFSHash == reissue.strIPFSHash);
    }

    // Unique: a new-token script whose name is a unique token
    CScript unique = NewTokenScript(CNewToken("ABC#TAG", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""));
    BOOST_CHECK(IsScriptNewToken(unique));
    BOOST_CHECK(IsScriptNewUniqueToken(unique));

    // Counting output types
    std::vector<CTxOut> vout = {CTxOut(0, owner), CTxOut(0, transfer), CTxOut(0, transfer),
                                CTxOut(0, ReissueTokenScript(CReissueToken("ABC", 1, -1, 1, ""))),
                                CTxOut(0, unique), CTxOut(COIN, TestTokenScriptBase())};
    int issues = 0, reissues = 0, transfers = 0, owners = 0;
    GetTxOutETokenTypes(vout, issues, reissues, transfers, owners);
    BOOST_CHECK_EQUAL(issues, 1);
    BOOST_CHECK_EQUAL(reissues, 1);
    BOOST_CHECK_EQUAL(transfers, 2);
    BOOST_CHECK_EQUAL(owners, 1);
}

BOOST_AUTO_TEST_CASE(non_token_scripts)
{
    CScript p2pkh = TestTokenScriptBase();
    CScript p2sh = GetScriptForDestination(CScriptID(p2pkh));
    CScript opReturn = CScript() << OP_RETURN << std::vector<unsigned char>(40, 'y');
    for (const CScript& script : {p2pkh, p2sh, opReturn, CScript()}) {
        BOOST_CHECK(!script.IsTokenScript());
        CTokenOutputEntry data;
        BOOST_CHECK(!GetTokenData(script, data));
        uint160 hashBytes;
        std::string strName;
        CAmount nAmount;
        BOOST_CHECK(!ParseTokenScript(script, hashBytes, strName, nAmount));
    }

    // OP_YAC_TOKEN in place but an unknown marker after "yac"
    CScript script = TestTokenScriptBase();
    std::vector<unsigned char> vch = {YAC_Y, YAC_A, YAC_C, 'x', 1, 2, 3, 4, 5, 6, 7, 8};
    script << OP_YAC_TOKEN << vch << OP_DROP;
    BOOST_CHECK(!script.IsTokenScript());

    // A token script whose payload doesn't deserialize is detected but not parsed
    CScript truncated = TestTokenScriptBase();
    std::vector<unsigned char> bad = {YAC_Y, YAC_A, YAC_C, YAC_T, 50, 'A', 'B', 'C', 0, 0, 0, 0};
    truncated << OP_YAC_TOKEN << bad << OP_DROP;
    BOOST_CHECK(IsScriptTransferToken(truncated));
    CTokenTransfer transfer;
    std::string strAddress;
    BOOST_CHECK(!TransferTokenFromScript(truncated, transfer, strAddress));
}

BOOST_AUTO_TEST_CASE(amount_units_and_ipfs)
{
    // nAmount must be a multiple of 10^(6 - units)
    BOOST_CHECK(CheckAmountWithUnits(1, 6));
    BOOST_CHECK(CheckAmountWithUnits(COIN, 0));
    BOOST_CHECK(!CheckAmountWithUnits(COIN + 1, 0));
    BOOST_CHECK(CheckAmountWithUnits(COIN / 10, 1));
    BOOST_CHECK(!CheckAmountWithUnits(COIN / 100, 1));
    BOOST_CHECK(CheckAmountWithUnits(0, 0));

    // CIDv0 and CIDv1 decode to the same 34-byte multihash and encode back
    CIDVersion version;
    std::string decoded = DecodeTokenData(TEST_IPFS_CIDV0, version);
    BOOST_CHECK(version == CIDVersion::CIDv0);
    BOOST_CHECK_EQUAL(HexStr(decoded), "1220b657a63340bb213562ca069060430f9b8f381d13e17bbdf9dcdc058a73554e6c");
    BOOST_CHECK_EQUAL(EncodeTokenData(decoded), TEST_IPFS_CIDV0);

    const std::string cidv1 = "bafybeifwk6tdgqf3ee2wfsqgsbqegd43r44b2e7bpo67txg4awfhgvkonq";
    BOOST_CHECK_EQUAL(EncodeTokenData(decoded, CIDVersion::CIDv1), cidv1);
    BOOST_CHECK(DecodeTokenData(cidv1, version) == decoded);
    BOOST_CHECK(version == CIDVersion::CIDv1);

    // Malformed input decodes to nothing
    BOOST_CHECK_EQUAL(DecodeTokenData("QmTooShort", version), "");
    BOOST_CHECK(version == CIDVersion::UNKNOWN);
    BOOST_CHECK_EQUAL(DecodeTokenData("", version), "");
    BOOST_CHECK_EQUAL(EncodeTokenData("short"), "");

    // Consensus stores the 34-byte form and only accepts what encodes to a CIDv0
    std::string strError;
    BOOST_CHECK(CheckEncoded(decoded, strError));
    BOOST_CHECK(!CheckEncoded(std::string(34, 'x'), strError));
    BOOST_CHECK(!CheckEncoded("", strError));
}

BOOST_AUTO_TEST_CASE(lock_amount_and_duration)
{
    // Issuing or reissuing anything except owner and vote tokens locks the same amount
    const CAmount nLock = GetLockAmount(ETokenType::YATOKEN);
    const uint32_t nDuration = GetLockDuration(ETokenType::YATOKEN);
#ifndef LOW_DIFFICULTY_FOR_DEVELOPMENT
    BOOST_CHECK_EQUAL(nLock, 2100 * COIN);
    BOOST_CHECK_EQUAL(nDuration, 21000U);
#endif
    for (ETokenType type : {ETokenType::SUB, ETokenType::UNIQUE, ETokenType::REISSUE}) {
        BOOST_CHECK_EQUAL(GetLockAmount(type), nLock);
        BOOST_CHECK_EQUAL(GetLockDuration(type), nDuration);
    }
    for (ETokenType type : {ETokenType::OWNER, ETokenType::VOTE, ETokenType::INVALID}) {
        BOOST_CHECK_EQUAL(GetLockAmount(type), 0);
        BOOST_CHECK_EQUAL(GetLockDuration(type), 0U);
    }
    BOOST_CHECK_EQUAL(GetLockAmount((int)ETokenType::SUB), nLock);

    // The wallet's lock output satisfies the checks
    BOOST_CHECK(CheckIssueLockTx(TokenLockOutput(ETokenType::YATOKEN), ETokenType::YATOKEN));
    BOOST_CHECK(CheckIssueLockTx(TokenLockOutput(ETokenType::SUB), ETokenType::SUB));
    BOOST_CHECK(CheckIssueLockTx(TokenLockOutput(ETokenType::UNIQUE, 3), ETokenType::UNIQUE, 3));
    BOOST_CHECK(CheckReissueLockTx(TokenLockOutput(ETokenType::REISSUE)));

    // Wrong amount, wrong count, wrong duration, or a type that doesn't lock
    CTxOut lock = TokenLockOutput(ETokenType::YATOKEN);
    CTxOut lockShort(lock.nValue - 1, lock.scriptPubKey);
    BOOST_CHECK(!CheckIssueLockTx(lockShort, ETokenType::YATOKEN));
    BOOST_CHECK(!CheckReissueLockTx(lockShort));
    BOOST_CHECK(!CheckIssueLockTx(TokenLockOutput(ETokenType::UNIQUE, 2), ETokenType::UNIQUE, 3));
    std::vector<unsigned char> vch(20, 1);
    CTxOut lockShortDuration(lock.nValue, GetScriptForCsvP2PKH(nDuration - 1, CKeyID(uint160(vch))));
    BOOST_CHECK(!CheckIssueLockTx(lockShortDuration, ETokenType::YATOKEN));
    BOOST_CHECK(!CheckReissueLockTx(lockShortDuration));
    BOOST_CHECK(!CheckIssueLockTx(lock, ETokenType::OWNER));
    BOOST_CHECK(!CheckIssueLockTx(lock, ETokenType::REISSUE));
    // A plain payment of the lock amount isn't a lock
    BOOST_CHECK(!CheckIssueLockTx(CTxOut(lock.nValue, TestTokenScriptBase()), ETokenType::YATOKEN));
}

BOOST_AUTO_TEST_CASE(check_new_token)
{
    std::string strError;
    BOOST_CHECK(CheckNewToken(CNewToken("ABC", 1000 * COIN, 0, 1, 0, ""), strError));
    BOOST_CHECK(CheckNewToken(CNewToken("ABC/SUB", 1, 6, 0, 1, TestIpfsHash()), strError));
    BOOST_CHECK(CheckNewToken(CNewToken("ABC#TAG", UNIQUE_TOKEN_AMOUNT, 0, 0, 0, ""), strError));
    BOOST_CHECK(CheckNewToken(CNewToken("ABC", MAX_MONEY, 0, 1, 0, ""), strError));

    // Name
    BOOST_CHECK(!CheckNewToken(CNewToken("abc", COIN, 0, 1, 0, ""), strError));
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC!", COIN, 0, 1, 0, ""), strError));
    // Amount
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC", 0, 0, 1, 0, ""), strError));
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC", -COIN, 0, 1, 0, ""), strError));
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC", MAX_MONEY + COIN, 0, 1, 0, ""), strError));
    // Units
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC", COIN, 7, 1, 0, ""), strError));
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC", COIN, -1, 1, 0, ""), strError));
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC", COIN + 1, 5, 1, 0, ""), strError));
    // Flags
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC", COIN, 0, 2, 0, ""), strError));
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC", COIN, 0, 1, 2, ""), strError));
    // Unique tokens: exactly 1 token, 0 units, not reissuable
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC#TAG", 2 * COIN, 0, 0, 0, ""), strError));
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC#TAG", COIN, 1, 0, 0, ""), strError));
    BOOST_CHECK(!CheckNewToken(CNewToken("ABC#TAG", COIN, 0, 1, 0, ""), strError));
}

BOOST_AUTO_TEST_CASE(check_reissue_token)
{
    std::string strError;
    BOOST_CHECK(CheckReissueToken(CReissueToken("ABC", COIN, -1, 1, ""), strError));
    BOOST_CHECK(CheckReissueToken(CReissueToken("ABC", 0, 6, 0, TestIpfsHash()), strError));
    BOOST_CHECK(CheckReissueToken(CReissueToken("ABC", MAX_MONEY - 1, 0, 1, ""), strError));

    BOOST_CHECK(!CheckReissueToken(CReissueToken("ABC", -1, 0, 1, ""), strError));
    // Unlike CheckNewToken (amount > MAX_MONEY), a reissue of exactly MAX_MONEY is rejected
    BOOST_CHECK(!CheckReissueToken(CReissueToken("ABC", MAX_MONEY, 0, 1, ""), strError));
    BOOST_CHECK(!CheckReissueToken(CReissueToken("ABC", COIN, 7, 1, ""), strError));
    BOOST_CHECK(!CheckReissueToken(CReissueToken("ABC", COIN, -2, 1, ""), strError));
    BOOST_CHECK(!CheckReissueToken(CReissueToken("ABC", COIN, 0, 2, ""), strError));
}

/* LibBoolEE (adapted from Ravencoin's boolean_expression_evaluator_test, without
 * the verifier-string helpers YACoin doesn't have) */
BOOST_AUTO_TEST_CASE(boolean_expression_resolve)
{
    LibBoolEE::Vals vals = {{"#KY_C", true}, {"#CI.A", false}, {"#DEF", true}};
    BOOST_CHECK(LibBoolEE::resolve("#KY_C & !#CI.A", vals));
    BOOST_CHECK(!LibBoolEE::resolve("#KY_C & #CI.A", vals));
    BOOST_CHECK(LibBoolEE::resolve("#CI.A | #KY_C", vals));
    BOOST_CHECK(LibBoolEE::resolve("((#KY_C & !#CI.A) | #CI.A) & #DEF", vals));
    BOOST_CHECK(!LibBoolEE::resolve("!(#KY_C | #CI.A)", vals));

    BOOST_CHECK_THROW(LibBoolEE::resolve("#KY_C|#MISS", vals), std::runtime_error);
    BOOST_CHECK_THROW(LibBoolEE::resolve("BAD -- EXPRESSION -- BUST", vals), std::runtime_error);
    BOOST_CHECK_THROW(LibBoolEE::resolve("(#KY_C & !#CI.A) | #DEF)", vals), std::runtime_error);
    BOOST_CHECK_THROW(LibBoolEE::resolve("(#KY_C && #DEF)", vals), std::runtime_error);
    BOOST_CHECK_THROW(LibBoolEE::resolve("(#KY_C || #DEF)", vals), std::runtime_error);
    BOOST_CHECK_THROW(LibBoolEE::resolve("()(#KY_C)", vals), std::runtime_error);
    BOOST_CHECK_THROW(LibBoolEE::resolve("((#KY_C) | #DEF", vals), std::runtime_error);

    BOOST_CHECK_EQUAL(LibBoolEE::removeWhitespaces(" a & b \t"), "a&b");
    BOOST_CHECK_EQUAL(LibBoolEE::removeCharacter("#A&#B", '#'), "A&B");
}

BOOST_AUTO_TEST_SUITE_END()
