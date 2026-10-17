// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"

#include "clientversion.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "test/test_bitcoin.h"

#include <stdint.h>
#include <algorithm>
#include <cstdio>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/program_options/errors.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(util_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(util_criticalsection)
{
    CCriticalSection cs;

    do {
        LOCK(cs);
        break;

        BOOST_ERROR("break was swallowed!");
    } while(0);

    do {
        TRY_LOCK(cs, lockTest);
        if (lockTest)
            break;

        BOOST_ERROR("break was swallowed!");
    } while(0);
}

static const unsigned char ParseHex_expected[65] = {
    0x04, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55, 0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30, 0xb7,
    0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39, 0x09, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61, 0xde,
    0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef, 0x38, 0xc4, 0xf3, 0x55, 0x04, 0xe5, 0x1e, 0xc1, 0x12,
    0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0x0b, 0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0xf1, 0x1d,
    0x5f
};
BOOST_AUTO_TEST_CASE(util_ParseHex)
{
    std::vector<unsigned char> result;
    std::vector<unsigned char> expected(ParseHex_expected, ParseHex_expected + sizeof(ParseHex_expected));
    // Basic test vector
    result = ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());

    // Spaces between bytes must be supported
    result = ParseHex("12 34 56 78");
    BOOST_CHECK(result.size() == 4 && result[0] == 0x12 && result[1] == 0x34 && result[2] == 0x56 && result[3] == 0x78);

    // Leading space must be supported (used in CDBEnv::Salvage)
    result = ParseHex(" 89 34 56 78");
    BOOST_CHECK(result.size() == 4 && result[0] == 0x89 && result[1] == 0x34 && result[2] == 0x56 && result[3] == 0x78);

    // Stop parsing at invalid value
    result = ParseHex("1234 invalid 1234");
    BOOST_CHECK(result.size() == 2 && result[0] == 0x12 && result[1] == 0x34);
}

BOOST_AUTO_TEST_CASE(util_HexStr)
{
    BOOST_CHECK_EQUAL(
        HexStr(ParseHex_expected, ParseHex_expected + sizeof(ParseHex_expected)),
        "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");

    BOOST_CHECK_EQUAL(
        HexStr(ParseHex_expected, ParseHex_expected + 5, true),
        "04 67 8a fd b0");

    BOOST_CHECK_EQUAL(
        HexStr(ParseHex_expected, ParseHex_expected, true),
        "");

    std::vector<unsigned char> ParseHex_vec(ParseHex_expected, ParseHex_expected + 5);

    BOOST_CHECK_EQUAL(
        HexStr(ParseHex_vec, true),
        "04 67 8a fd b0");
}


BOOST_AUTO_TEST_CASE(util_DateTimeStrFormat)
{
    BOOST_CHECK_EQUAL(DateTimeStrFormat("%Y-%m-%d %H:%M:%S", 0), "1970-01-01 00:00:00");
    BOOST_CHECK_EQUAL(DateTimeStrFormat("%Y-%m-%d %H:%M:%S", 0x7FFFFFFF), "2038-01-19 03:14:07");
    BOOST_CHECK_EQUAL(DateTimeStrFormat("%Y-%m-%d %H:%M:%S", 1317425777), "2011-09-30 23:36:17");
    BOOST_CHECK_EQUAL(DateTimeStrFormat("%Y-%m-%d %H:%M", 1317425777), "2011-09-30 23:36");
    BOOST_CHECK_EQUAL(DateTimeStrFormat("%a, %d %b %Y %H:%M:%S +0000", 1317425777), "Fri, 30 Sep 2011 23:36:17 +0000");
}

class TestArgsManager : public ArgsManager
{
public:
    std::map<std::string, std::string>& GetMapArgs()
    {
        return mapArgs;
    };
    const std::map<std::string, std::vector<std::string> >& GetMapMultiArgs()
    {
        return mapMultiArgs;
    };

    // Reach the protected maps of any ArgsManager (gArgs included) through a pointer to
    // member formed in this derived class, so fixtures can save and restore gArgs.
    static std::map<std::string, std::string>& MapArgsOf(ArgsManager& a)
    {
        return a.*(&TestArgsManager::mapArgs);
    }
    static std::map<std::string, std::vector<std::string> >& MapMultiArgsOf(ArgsManager& a)
    {
        return a.*(&TestArgsManager::mapMultiArgs);
    }
    static void EraseArg(ArgsManager& a, const std::string& strArg)
    {
        MapArgsOf(a).erase(strArg);
        MapMultiArgsOf(a).erase(strArg);
    }
};

BOOST_AUTO_TEST_CASE(util_ParseParameters)
{
    TestArgsManager testArgs;
    const char *argv_test[] = {"-ignored", "-a", "-b", "-ccc=argument", "-ccc=multiple", "f", "-d=e"};

    testArgs.ParseParameters(0, (char**)argv_test);
    BOOST_CHECK(testArgs.GetMapArgs().empty() && testArgs.GetMapMultiArgs().empty());

    testArgs.ParseParameters(1, (char**)argv_test);
    BOOST_CHECK(testArgs.GetMapArgs().empty() && testArgs.GetMapMultiArgs().empty());

    testArgs.ParseParameters(5, (char**)argv_test);
    // expectation: -ignored is ignored (program name argument),
    // -a, -b and -ccc end up in map, -d ignored because it is after
    // a non-option argument (non-GNU option parsing)
    BOOST_CHECK(testArgs.GetMapArgs().size() == 3 && testArgs.GetMapMultiArgs().size() == 3);
    BOOST_CHECK(testArgs.IsArgSet("-a") && testArgs.IsArgSet("-b") && testArgs.IsArgSet("-ccc")
                && !testArgs.IsArgSet("f") && !testArgs.IsArgSet("-d"));
    BOOST_CHECK(testArgs.GetMapMultiArgs().count("-a") && testArgs.GetMapMultiArgs().count("-b") && testArgs.GetMapMultiArgs().count("-ccc")
                && !testArgs.GetMapMultiArgs().count("f") && !testArgs.GetMapMultiArgs().count("-d"));

    BOOST_CHECK(testArgs.GetMapArgs()["-a"] == "" && testArgs.GetMapArgs()["-ccc"] == "multiple");
    BOOST_CHECK(testArgs.GetArgs("-ccc").size() == 2);
}

BOOST_AUTO_TEST_CASE(util_GetArg)
{
    TestArgsManager testArgs;
    testArgs.GetMapArgs().clear();
    testArgs.GetMapArgs()["strtest1"] = "string...";
    // strtest2 undefined on purpose
    testArgs.GetMapArgs()["inttest1"] = "12345";
    testArgs.GetMapArgs()["inttest2"] = "81985529216486895";
    // inttest3 undefined on purpose
    testArgs.GetMapArgs()["booltest1"] = "";
    // booltest2 undefined on purpose
    testArgs.GetMapArgs()["booltest3"] = "0";
    testArgs.GetMapArgs()["booltest4"] = "1";

    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest1", "default"), "string...");
    BOOST_CHECK_EQUAL(testArgs.GetArg("strtest2", "default"), "default");
    BOOST_CHECK_EQUAL(testArgs.GetArg("inttest1", -1), 12345);
    BOOST_CHECK_EQUAL(testArgs.GetArg("inttest2", -1), 81985529216486895LL);
    BOOST_CHECK_EQUAL(testArgs.GetArg("inttest3", -1), -1);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest1", false), true);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest2", false), false);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest3", false), false);
    BOOST_CHECK_EQUAL(testArgs.GetBoolArg("booltest4", false), true);
}

BOOST_AUTO_TEST_CASE(util_FormatMoney)
{
    BOOST_CHECK_EQUAL(FormatMoney(0), "0.00");
    BOOST_CHECK_EQUAL(FormatMoney((COIN/10000)*123456789), "12345.6789");
    BOOST_CHECK_EQUAL(FormatMoney(-COIN), "-1.00");

    BOOST_CHECK_EQUAL(FormatMoney(COIN*100000000), "100000000.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN*10000000), "10000000.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN*1000000), "1000000.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN*100000), "100000.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN*10000), "10000.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN*1000), "1000.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN*100), "100.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN*10), "10.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN), "1.00");
    BOOST_CHECK_EQUAL(FormatMoney(COIN/10), "0.10");
    BOOST_CHECK_EQUAL(FormatMoney(COIN/100), "0.01");
    BOOST_CHECK_EQUAL(FormatMoney(COIN/1000), "0.001");
    BOOST_CHECK_EQUAL(FormatMoney(COIN/10000), "0.0001");
    BOOST_CHECK_EQUAL(FormatMoney(COIN/100000), "0.00001");
    BOOST_CHECK_EQUAL(FormatMoney(COIN/1000000), "0.000001");
}

BOOST_AUTO_TEST_CASE(util_ParseMoney)
{
    CAmount ret = 0;
    BOOST_CHECK(ParseMoney("0.0", ret));
    BOOST_CHECK_EQUAL(ret, 0);

    BOOST_CHECK(ParseMoney("12345.6789", ret));
    BOOST_CHECK_EQUAL(ret, (COIN/10000)*123456789);

    BOOST_CHECK(ParseMoney("100000000.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN*100000000);
    BOOST_CHECK(ParseMoney("10000000.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN*10000000);
    BOOST_CHECK(ParseMoney("1000000.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN*1000000);
    BOOST_CHECK(ParseMoney("100000.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN*100000);
    BOOST_CHECK(ParseMoney("10000.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN*10000);
    BOOST_CHECK(ParseMoney("1000.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN*1000);
    BOOST_CHECK(ParseMoney("100.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN*100);
    BOOST_CHECK(ParseMoney("10.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN*10);
    BOOST_CHECK(ParseMoney("1.00", ret));
    BOOST_CHECK_EQUAL(ret, COIN);
    BOOST_CHECK(ParseMoney("1", ret));
    BOOST_CHECK_EQUAL(ret, COIN);
    BOOST_CHECK(ParseMoney("0.1", ret));
    BOOST_CHECK_EQUAL(ret, COIN/10);
    BOOST_CHECK(ParseMoney("0.01", ret));
    BOOST_CHECK_EQUAL(ret, COIN/100);
    BOOST_CHECK(ParseMoney("0.001", ret));
    BOOST_CHECK_EQUAL(ret, COIN/1000);
    BOOST_CHECK(ParseMoney("0.0001", ret));
    BOOST_CHECK_EQUAL(ret, COIN/10000);
    BOOST_CHECK(ParseMoney("0.00001", ret));
    BOOST_CHECK_EQUAL(ret, COIN/100000);
    BOOST_CHECK(ParseMoney("0.000001", ret));
    BOOST_CHECK_EQUAL(ret, COIN/1000000);

    // Attempted 63 bit overflow should fail
    BOOST_CHECK(!ParseMoney("92233720368.54775808", ret));

    // Parsing negative amounts must fail
    BOOST_CHECK(!ParseMoney("-1", ret));
}

BOOST_AUTO_TEST_CASE(util_IsHex)
{
    BOOST_CHECK(IsHex("00"));
    BOOST_CHECK(IsHex("00112233445566778899aabbccddeeffAABBCCDDEEFF"));
    BOOST_CHECK(IsHex("ff"));
    BOOST_CHECK(IsHex("FF"));

    BOOST_CHECK(!IsHex(""));
    BOOST_CHECK(!IsHex("0"));
    BOOST_CHECK(!IsHex("a"));
    BOOST_CHECK(!IsHex("eleven"));
    BOOST_CHECK(!IsHex("00xx00"));
    BOOST_CHECK(!IsHex("0x0000"));
}

BOOST_AUTO_TEST_CASE(util_IsHexNumber)
{
    BOOST_CHECK(IsHexNumber("0x0"));
    BOOST_CHECK(IsHexNumber("0"));
    BOOST_CHECK(IsHexNumber("0x10"));
    BOOST_CHECK(IsHexNumber("10"));
    BOOST_CHECK(IsHexNumber("0xff"));
    BOOST_CHECK(IsHexNumber("ff"));
    BOOST_CHECK(IsHexNumber("0xFfa"));
    BOOST_CHECK(IsHexNumber("Ffa"));
    BOOST_CHECK(IsHexNumber("0x00112233445566778899aabbccddeeffAABBCCDDEEFF"));
    BOOST_CHECK(IsHexNumber("00112233445566778899aabbccddeeffAABBCCDDEEFF"));

    BOOST_CHECK(!IsHexNumber(""));   // empty string not allowed
    BOOST_CHECK(!IsHexNumber("0x")); // empty string after prefix not allowed
    BOOST_CHECK(!IsHexNumber("0x0 ")); // no spaces at end,
    BOOST_CHECK(!IsHexNumber(" 0x0")); // or beginning,
    BOOST_CHECK(!IsHexNumber("0x 0")); // or middle,
    BOOST_CHECK(!IsHexNumber(" "));    // etc.
    BOOST_CHECK(!IsHexNumber("0x0ga")); // invalid character
    BOOST_CHECK(!IsHexNumber("x0"));    // broken prefix
    BOOST_CHECK(!IsHexNumber("0x0x00")); // two prefixes not allowed

}

BOOST_AUTO_TEST_CASE(util_seed_insecure_rand)
{
    SeedInsecureRand(true);
    for (int mod=2;mod<11;mod++)
    {
        int mask = 1;
        // Really rough binomial confidence approximation.
        int err = 30*10000./mod*sqrt((1./mod*(1-1./mod))/10000.);
        //mask is 2^ceil(log2(mod))-1
        while(mask<mod-1)mask=(mask<<1)+1;

        int count = 0;
        //How often does it get a zero from the uniform range [0,mod)?
        for (int i = 0; i < 10000; i++) {
            uint32_t rval;
            do{
                rval=InsecureRand32()&mask;
            }while(rval>=(uint32_t)mod);
            count += rval==0;
        }
        BOOST_CHECK(count<=10000/mod+err);
        BOOST_CHECK(count>=10000/mod-err);
    }
}

BOOST_AUTO_TEST_CASE(util_TimingResistantEqual)
{
    BOOST_CHECK(TimingResistantEqual(std::string(""), std::string("")));
    BOOST_CHECK(!TimingResistantEqual(std::string("abc"), std::string("")));
    BOOST_CHECK(!TimingResistantEqual(std::string(""), std::string("abc")));
    BOOST_CHECK(!TimingResistantEqual(std::string("a"), std::string("aa")));
    BOOST_CHECK(!TimingResistantEqual(std::string("aa"), std::string("a")));
    BOOST_CHECK(TimingResistantEqual(std::string("abc"), std::string("abc")));
    BOOST_CHECK(!TimingResistantEqual(std::string("abc"), std::string("aba")));
}

/* Test strprintf formatting directives.
 * Put a string before and after to ensure sanity of element sizes on stack. */
#define B "check_prefix"
#define E "check_postfix"
BOOST_AUTO_TEST_CASE(strprintf_numbers)
{
    int64_t s64t = -9223372036854775807LL; /* signed 64 bit test value */
    uint64_t u64t = 18446744073709551615ULL; /* unsigned 64 bit test value */
    BOOST_CHECK(strprintf("%s %d %s", B, s64t, E) == B" -9223372036854775807 " E);
    BOOST_CHECK(strprintf("%s %u %s", B, u64t, E) == B" 18446744073709551615 " E);
    BOOST_CHECK(strprintf("%s %x %s", B, u64t, E) == B" ffffffffffffffff " E);

    size_t st = 12345678; /* unsigned size_t test value */
    ssize_t sst = -12345678; /* signed size_t test value */
    BOOST_CHECK(strprintf("%s %d %s", B, sst, E) == B" -12345678 " E);
    BOOST_CHECK(strprintf("%s %u %s", B, st, E) == B" 12345678 " E);
    BOOST_CHECK(strprintf("%s %x %s", B, st, E) == B" bc614e " E);

    ptrdiff_t pt = 87654321; /* positive ptrdiff_t test value */
    ptrdiff_t spt = -87654321; /* negative ptrdiff_t test value */
    BOOST_CHECK(strprintf("%s %d %s", B, spt, E) == B" -87654321 " E);
    BOOST_CHECK(strprintf("%s %u %s", B, pt, E) == B" 87654321 " E);
    BOOST_CHECK(strprintf("%s %x %s", B, pt, E) == B" 5397fb1 " E);
}
#undef B
#undef E

/* Check for mingw/wine issue #3494
 * Remove this test before time.ctime(0xffffffff) == 'Sun Feb  7 07:28:15 2106'
 */
BOOST_AUTO_TEST_CASE(gettime)
{
    BOOST_CHECK((GetTime() & ~0xFFFFFFFFLL) == 0);
}

BOOST_AUTO_TEST_CASE(test_ParseInt32)
{
    int32_t n;
    // Valid values
    BOOST_CHECK(ParseInt32("1234", nullptr));
    BOOST_CHECK(ParseInt32("0", &n) && n == 0);
    BOOST_CHECK(ParseInt32("1234", &n) && n == 1234);
    BOOST_CHECK(ParseInt32("01234", &n) && n == 1234); // no octal
    BOOST_CHECK(ParseInt32("2147483647", &n) && n == 2147483647);
    BOOST_CHECK(ParseInt32("-2147483648", &n) && n == (-2147483647 - 1)); // (-2147483647 - 1) equals INT_MIN
    BOOST_CHECK(ParseInt32("-1234", &n) && n == -1234);
    // Invalid values
    BOOST_CHECK(!ParseInt32("", &n));
    BOOST_CHECK(!ParseInt32(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseInt32("1 ", &n));
    BOOST_CHECK(!ParseInt32("1a", &n));
    BOOST_CHECK(!ParseInt32("aap", &n));
    BOOST_CHECK(!ParseInt32("0x1", &n)); // no hex
    BOOST_CHECK(!ParseInt32("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseInt32(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseInt32("-2147483649", nullptr));
    BOOST_CHECK(!ParseInt32("2147483648", nullptr));
    BOOST_CHECK(!ParseInt32("-32482348723847471234", nullptr));
    BOOST_CHECK(!ParseInt32("32482348723847471234", nullptr));
}

BOOST_AUTO_TEST_CASE(test_ParseInt64)
{
    int64_t n;
    // Valid values
    BOOST_CHECK(ParseInt64("1234", nullptr));
    BOOST_CHECK(ParseInt64("0", &n) && n == 0LL);
    BOOST_CHECK(ParseInt64("1234", &n) && n == 1234LL);
    BOOST_CHECK(ParseInt64("01234", &n) && n == 1234LL); // no octal
    BOOST_CHECK(ParseInt64("2147483647", &n) && n == 2147483647LL);
    BOOST_CHECK(ParseInt64("-2147483648", &n) && n == -2147483648LL);
    BOOST_CHECK(ParseInt64("9223372036854775807", &n) && n == (int64_t)9223372036854775807);
    BOOST_CHECK(ParseInt64("-9223372036854775808", &n) && n == (int64_t)-9223372036854775807-1);
    BOOST_CHECK(ParseInt64("-1234", &n) && n == -1234LL);
    // Invalid values
    BOOST_CHECK(!ParseInt64("", &n));
    BOOST_CHECK(!ParseInt64(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseInt64("1 ", &n));
    BOOST_CHECK(!ParseInt64("1a", &n));
    BOOST_CHECK(!ParseInt64("aap", &n));
    BOOST_CHECK(!ParseInt64("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseInt64(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseInt64("-9223372036854775809", nullptr));
    BOOST_CHECK(!ParseInt64("9223372036854775808", nullptr));
    BOOST_CHECK(!ParseInt64("-32482348723847471234", nullptr));
    BOOST_CHECK(!ParseInt64("32482348723847471234", nullptr));
}

BOOST_AUTO_TEST_CASE(test_ParseUInt32)
{
    uint32_t n;
    // Valid values
    BOOST_CHECK(ParseUInt32("1234", nullptr));
    BOOST_CHECK(ParseUInt32("0", &n) && n == 0);
    BOOST_CHECK(ParseUInt32("1234", &n) && n == 1234);
    BOOST_CHECK(ParseUInt32("01234", &n) && n == 1234); // no octal
    BOOST_CHECK(ParseUInt32("2147483647", &n) && n == 2147483647);
    BOOST_CHECK(ParseUInt32("2147483648", &n) && n == (uint32_t)2147483648);
    BOOST_CHECK(ParseUInt32("4294967295", &n) && n == (uint32_t)4294967295);
    // Invalid values
    BOOST_CHECK(!ParseUInt32("", &n));
    BOOST_CHECK(!ParseUInt32(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseUInt32(" -1", &n));
    BOOST_CHECK(!ParseUInt32("1 ", &n));
    BOOST_CHECK(!ParseUInt32("1a", &n));
    BOOST_CHECK(!ParseUInt32("aap", &n));
    BOOST_CHECK(!ParseUInt32("0x1", &n)); // no hex
    BOOST_CHECK(!ParseUInt32("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseUInt32(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseUInt32("-2147483648", &n));
    BOOST_CHECK(!ParseUInt32("4294967296", &n));
    BOOST_CHECK(!ParseUInt32("-1234", &n));
    BOOST_CHECK(!ParseUInt32("-32482348723847471234", nullptr));
    BOOST_CHECK(!ParseUInt32("32482348723847471234", nullptr));
}

BOOST_AUTO_TEST_CASE(test_ParseUInt64)
{
    uint64_t n;
    // Valid values
    BOOST_CHECK(ParseUInt64("1234", nullptr));
    BOOST_CHECK(ParseUInt64("0", &n) && n == 0LL);
    BOOST_CHECK(ParseUInt64("1234", &n) && n == 1234LL);
    BOOST_CHECK(ParseUInt64("01234", &n) && n == 1234LL); // no octal
    BOOST_CHECK(ParseUInt64("2147483647", &n) && n == 2147483647LL);
    BOOST_CHECK(ParseUInt64("9223372036854775807", &n) && n == 9223372036854775807ULL);
    BOOST_CHECK(ParseUInt64("9223372036854775808", &n) && n == 9223372036854775808ULL);
    BOOST_CHECK(ParseUInt64("18446744073709551615", &n) && n == 18446744073709551615ULL);
    // Invalid values
    BOOST_CHECK(!ParseUInt64("", &n));
    BOOST_CHECK(!ParseUInt64(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseUInt64(" -1", &n));
    BOOST_CHECK(!ParseUInt64("1 ", &n));
    BOOST_CHECK(!ParseUInt64("1a", &n));
    BOOST_CHECK(!ParseUInt64("aap", &n));
    BOOST_CHECK(!ParseUInt64("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseUInt64(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseUInt64("-9223372036854775809", nullptr));
    BOOST_CHECK(!ParseUInt64("18446744073709551616", nullptr));
    BOOST_CHECK(!ParseUInt64("-32482348723847471234", nullptr));
    BOOST_CHECK(!ParseUInt64("-2147483648", &n));
    BOOST_CHECK(!ParseUInt64("-9223372036854775808", &n));
    BOOST_CHECK(!ParseUInt64("-1234", &n));
}

BOOST_AUTO_TEST_CASE(test_ParseDouble)
{
    double n;
    // Valid values
    BOOST_CHECK(ParseDouble("1234", nullptr));
    BOOST_CHECK(ParseDouble("0", &n) && n == 0.0);
    BOOST_CHECK(ParseDouble("1234", &n) && n == 1234.0);
    BOOST_CHECK(ParseDouble("01234", &n) && n == 1234.0); // no octal
    BOOST_CHECK(ParseDouble("2147483647", &n) && n == 2147483647.0);
    BOOST_CHECK(ParseDouble("-2147483648", &n) && n == -2147483648.0);
    BOOST_CHECK(ParseDouble("-1234", &n) && n == -1234.0);
    BOOST_CHECK(ParseDouble("1e6", &n) && n == 1e6);
    BOOST_CHECK(ParseDouble("-1e6", &n) && n == -1e6);
    // Invalid values
    BOOST_CHECK(!ParseDouble("", &n));
    BOOST_CHECK(!ParseDouble(" 1", &n)); // no padding inside
    BOOST_CHECK(!ParseDouble("1 ", &n));
    BOOST_CHECK(!ParseDouble("1a", &n));
    BOOST_CHECK(!ParseDouble("aap", &n));
    BOOST_CHECK(!ParseDouble("0x1", &n)); // no hex
    const char test_bytes[] = {'1', 0, '1'};
    std::string teststr(test_bytes, sizeof(test_bytes));
    BOOST_CHECK(!ParseDouble(teststr, &n)); // no embedded NULs
    // Overflow and underflow
    BOOST_CHECK(!ParseDouble("-1e10000", nullptr));
    BOOST_CHECK(!ParseDouble("1e10000", nullptr));
}

BOOST_AUTO_TEST_CASE(test_FormatParagraph)
{
    BOOST_CHECK_EQUAL(FormatParagraph("", 79, 0), "");
    BOOST_CHECK_EQUAL(FormatParagraph("test", 79, 0), "test");
    BOOST_CHECK_EQUAL(FormatParagraph(" test", 79, 0), " test");
    BOOST_CHECK_EQUAL(FormatParagraph("test test", 79, 0), "test test");
    BOOST_CHECK_EQUAL(FormatParagraph("test test", 4, 0), "test\ntest");
    BOOST_CHECK_EQUAL(FormatParagraph("testerde test", 4, 0), "testerde\ntest");
    BOOST_CHECK_EQUAL(FormatParagraph("test test", 4, 4), "test\n    test");

    // Make sure we don't indent a fully-new line following a too-long line ending
    BOOST_CHECK_EQUAL(FormatParagraph("test test\nabc", 4, 4), "test\n    test\nabc");

    BOOST_CHECK_EQUAL(FormatParagraph("This_is_a_very_long_test_string_without_any_spaces_so_it_should_just_get_returned_as_is_despite_the_length until it gets here", 79), "This_is_a_very_long_test_string_without_any_spaces_so_it_should_just_get_returned_as_is_despite_the_length\nuntil it gets here");

    // Test wrap length is exact
    BOOST_CHECK_EQUAL(FormatParagraph("a b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p", 79), "a b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de\nf g h i j k l m n o p");
    BOOST_CHECK_EQUAL(FormatParagraph("x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p", 79), "x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de\nf g h i j k l m n o p");
    // Indent should be included in length of lines
    BOOST_CHECK_EQUAL(FormatParagraph("x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 a b c d e fg h i j k", 79, 4), "x\na b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 a b c de\n    f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 6 7 8 9 a b c d e fg\n    h i j k");

    BOOST_CHECK_EQUAL(FormatParagraph("This is a very long test string. This is a second sentence in the very long test string.", 79), "This is a very long test string. This is a second sentence in the very long\ntest string.");
    BOOST_CHECK_EQUAL(FormatParagraph("This is a very long test string.\nThis is a second sentence in the very long test string. This is a third sentence in the very long test string.", 79), "This is a very long test string.\nThis is a second sentence in the very long test string. This is a third\nsentence in the very long test string.");
    BOOST_CHECK_EQUAL(FormatParagraph("This is a very long test string.\n\nThis is a second sentence in the very long test string. This is a third sentence in the very long test string.", 79), "This is a very long test string.\n\nThis is a second sentence in the very long test string. This is a third\nsentence in the very long test string.");
    BOOST_CHECK_EQUAL(FormatParagraph("Testing that normal newlines do not get indented.\nLike here.", 79), "Testing that normal newlines do not get indented.\nLike here.");
}

BOOST_AUTO_TEST_CASE(test_FormatSubVersion)
{
    std::vector<std::string> comments;
    comments.push_back(std::string("comment1"));
    std::vector<std::string> comments2;
    comments2.push_back(std::string("comment1"));
    comments2.push_back(SanitizeString(std::string("Comment2; .,_?@-; !\"#$%&'()*+/<=>[]\\^`{|}~"), SAFE_CHARS_UA_COMMENT)); // Semicolon is discouraged but not forbidden by BIP-0014
    BOOST_CHECK_EQUAL(FormatSubVersion("Test", 99900, std::vector<std::string>()),std::string("/Test:0.9.99/"));
    BOOST_CHECK_EQUAL(FormatSubVersion("Test", 99900, comments),std::string("/Test:0.9.99(comment1)/"));
    BOOST_CHECK_EQUAL(FormatSubVersion("Test", 99900, comments2),std::string("/Test:0.9.99(comment1; Comment2; .,_?@-; )/"));
}

BOOST_AUTO_TEST_CASE(test_ParseFixedPoint)
{
    int64_t amount = 0;
    BOOST_CHECK(ParseFixedPoint("0", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 0LL);
    BOOST_CHECK(ParseFixedPoint("1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 100000000LL);
    BOOST_CHECK(ParseFixedPoint("0.0", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 0LL);
    BOOST_CHECK(ParseFixedPoint("-0.1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, -10000000LL);
    BOOST_CHECK(ParseFixedPoint("1.1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 110000000LL);
    BOOST_CHECK(ParseFixedPoint("1.10000000000000000", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 110000000LL);
    BOOST_CHECK(ParseFixedPoint("1.1e1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 1100000000LL);
    BOOST_CHECK(ParseFixedPoint("1.1e-1", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 11000000LL);
    BOOST_CHECK(ParseFixedPoint("1000", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 100000000000LL);
    BOOST_CHECK(ParseFixedPoint("-1000", 8, &amount));
    BOOST_CHECK_EQUAL(amount, -100000000000LL);
    BOOST_CHECK(ParseFixedPoint("0.00000001", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 1LL);
    BOOST_CHECK(ParseFixedPoint("0.0000000100000000", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 1LL);
    BOOST_CHECK(ParseFixedPoint("-0.00000001", 8, &amount));
    BOOST_CHECK_EQUAL(amount, -1LL);
    BOOST_CHECK(ParseFixedPoint("1000000000.00000001", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 100000000000000001LL);
    BOOST_CHECK(ParseFixedPoint("9999999999.99999999", 8, &amount));
    BOOST_CHECK_EQUAL(amount, 999999999999999999LL);
    BOOST_CHECK(ParseFixedPoint("-9999999999.99999999", 8, &amount));
    BOOST_CHECK_EQUAL(amount, -999999999999999999LL);

    BOOST_CHECK(!ParseFixedPoint("", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("a-1000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-a1000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-1000a", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-01000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("00.1", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint(".1", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("--0.1", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("0.000000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-0.000000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("0.00000001000000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-10000000000.00000000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("10000000000.00000000", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-10000000000.00000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("10000000000.00000001", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-10000000000.00000009", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("10000000000.00000009", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-99999999999.99999999", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("99999909999.09999999", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("92233720368.54775807", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("92233720368.54775808", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-92233720368.54775808", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("-92233720368.54775809", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("1.1e", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("1.1e-", 8, &amount));
    BOOST_CHECK(!ParseFixedPoint("1.", 8, &amount));
}

static void WriteFile(const fs::path& p, const std::string& s)
{
    // Binary mode, so CR/LF bytes reach the file exactly as given on every platform
    FILE* f = fsbridge::fopen(p, "wb");
    BOOST_REQUIRE(f);
    size_t written = fwrite(s.data(), 1, s.size(), f);
    fclose(f);
    BOOST_REQUIRE_EQUAL(written, s.size());
}

static std::string ReadFile(const fs::path& p)
{
    FILE* f = fsbridge::fopen(p, "rb");
    BOOST_REQUIRE(f);
    std::string s;
    std::vector<char> buf(1 << 16);
    size_t n;
    while ((n = fread(buf.data(), 1, buf.size(), f)) > 0)
        s.append(buf.data(), n);
    fclose(f);
    return s;
}

/** Gives a test case its own datadir (gArgs -datadir) and restores gArgs afterwards. */
struct UtilDataDirSetup : public BasicTestingSetup {
    fs::path pathTemp;
    std::map<std::string, std::string> savedArgs;
    std::map<std::string, std::vector<std::string> > savedMultiArgs;

    UtilDataDirSetup()
    {
        savedArgs = TestArgsManager::MapArgsOf(gArgs);
        savedMultiArgs = TestArgsManager::MapMultiArgsOf(gArgs);
        pathTemp = fs::system_complete(fs::temp_directory_path() /
            strprintf("test_bitcoin_util_%lu_%i", (unsigned long)GetTime(), (int)InsecureRandRange(100000)));
        fs::create_directories(pathTemp);
        // Earlier suites may leave -conf or -datadir behind
        TestArgsManager::EraseArg(gArgs, "-conf");
        gArgs.ForceSetArg("-datadir", pathTemp.string());
        ClearDatadirCache();
    }

    ~UtilDataDirSetup()
    {
        // Leave both datadir caches filled: an empty cache would make the next GetDataDir()
        // recompute from whatever args are restored (possibly $HOME).
        gArgs.ForceSetArg("-datadir", pathTemp.string());
        GetDataDir(false);
        GetDataDir(true);
        TestArgsManager::MapArgsOf(gArgs) = savedArgs;
        TestArgsManager::MapMultiArgsOf(gArgs) = savedMultiArgs;
        boost::system::error_code ec;
        fs::remove_all(pathTemp, ec);
    }
};

BOOST_FIXTURE_TEST_CASE(util_GetConfigFile, UtilDataDirSetup)
{
    BOOST_CHECK(GetDataDir(false) == pathTemp);
    // Relative names resolve against the datadir, absolute paths are used as they are
    BOOST_CHECK(GetConfigFile("x.conf") == pathTemp / "x.conf");
    const fs::path abs = pathTemp / "sub" / "a.conf";
    BOOST_CHECK(GetConfigFile(abs.string()) == abs);
}

BOOST_FIXTURE_TEST_CASE(util_ReadConfigFile_syntax, UtilDataDirSetup)
{
    const fs::path conf = pathTemp / "syntax.conf";
    WriteFile(conf,
        "# full-line comment\n"
        "   # indented comment\n"
        "\n"
        "foo=1\n"
        "  spaced   =   value with spaces  \n"
        "tabbed\t=\tx\t\n"
        "crlf=yes\r\n"
        "empty=\n"
        "blank=   \n"
        "eq=a=b=c\n"
        "hash=abc#def\n"
        "foo=2\n"
        "nofoo=1\n"
        "Case=Upper\n"
        "case=lower\n"
        "nobar=1\n"
        "nobaz=0\n"
        "noqux=\n"
        "no=1\n"
        "nfoo=1\n"
        "-dash=1\n"
        "[sect]\n"
        "inner=1\n");
    TestArgsManager testArgs;
    testArgs.ReadConfigFile(conf.string());

    // Current behaviour: in the file the first value wins (on the command line the last one
    // does); every value (also from -nofoo) is kept in order
    BOOST_CHECK_EQUAL(testArgs.GetArg("-foo", ""), "1");
    BOOST_CHECK(testArgs.GetArgs("-foo") == std::vector<std::string>({"1", "2", "0"}));
    // Whitespace around names and values is trimmed (also tabs and a CR), not inside values
    BOOST_CHECK_EQUAL(testArgs.GetArg("-spaced", ""), "value with spaces");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-tabbed", ""), "x");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-crlf", ""), "yes");
    // An empty value is set and counts as true (current behaviour)
    BOOST_CHECK(testArgs.IsArgSet("-empty"));
    BOOST_CHECK_EQUAL(testArgs.GetArg("-empty", "default"), "");
    BOOST_CHECK(testArgs.GetBoolArg("-empty", false));
    BOOST_CHECK_EQUAL(testArgs.GetArg("-blank", "default"), "");
    // Split at the first '=', and '#' starts a comment even inside a value (current behaviour)
    BOOST_CHECK_EQUAL(testArgs.GetArg("-eq", ""), "a=b=c");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-hash", ""), "abc");
    // Names are case sensitive
    BOOST_CHECK_EQUAL(testArgs.GetArg("-Case", ""), "Upper");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-case", ""), "lower");
    // noX=v becomes -X=!v; an empty value counts as true, so noqux= disables -qux
    BOOST_CHECK_EQUAL(testArgs.GetArg("-bar", ""), "0");
    BOOST_CHECK(!testArgs.IsArgSet("-nobar"));
    BOOST_CHECK_EQUAL(testArgs.GetArg("-baz", ""), "1");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-qux", ""), "0");
    // Only names longer than "no" that start with "no" are negations
    BOOST_CHECK_EQUAL(testArgs.GetArg("-no", ""), "1");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-nfoo", ""), "1");
    // A leading dash in the file gives a "--" key that no option lookup uses
    BOOST_CHECK(testArgs.IsArgSet("--dash"));
    BOOST_CHECK(!testArgs.IsArgSet("-dash"));
    // Keys after a section header get the section as prefix
    BOOST_CHECK_EQUAL(testArgs.GetArg("-sect.inner", ""), "1");
    BOOST_CHECK(!testArgs.IsArgSet("-inner"));
    // Nothing else (e.g. from the comment lines) was added
    BOOST_CHECK_EQUAL(testArgs.GetMapArgs().size(), 17U);
}

BOOST_FIXTURE_TEST_CASE(util_ReadConfigFile_cmdline_wins, UtilDataDirSetup)
{
    const fs::path conf = pathTemp / "cmdline.conf";
    WriteFile(conf, "foo=file\nbar=1\nnobaz=1\nnew=conf\n");
    TestArgsManager testArgs;
    const char* argv[] = {"prog", "-foo=cmd", "-nobar", "-baz=1"};
    testArgs.ParseParameters(4, argv);
    testArgs.ReadConfigFile(conf.string());

    // Command line values win, but the file values are still appended after them
    BOOST_CHECK_EQUAL(testArgs.GetArg("-foo", ""), "cmd");
    BOOST_CHECK(testArgs.GetArgs("-foo") == std::vector<std::string>({"cmd", "file"}));
    BOOST_CHECK(!testArgs.GetBoolArg("-bar", true));
    BOOST_CHECK(testArgs.GetArgs("-bar") == std::vector<std::string>({"0", "1"}));
    BOOST_CHECK(testArgs.GetBoolArg("-baz", false));
    BOOST_CHECK(testArgs.GetArgs("-baz") == std::vector<std::string>({"1", "0"}));
    BOOST_CHECK_EQUAL(testArgs.GetArg("-new", ""), "conf");
}

BOOST_FIXTURE_TEST_CASE(util_ReadConfigFile_empty, UtilDataDirSetup)
{
    const fs::path conf = pathTemp / "empty.conf";
    for (const std::string& body : {std::string(), std::string("# only a comment\n\n   \n")}) {
        WriteFile(conf, body);
        TestArgsManager testArgs;
        testArgs.ReadConfigFile(conf.string());
        BOOST_CHECK(testArgs.GetMapArgs().empty());
        BOOST_CHECK(testArgs.GetMapMultiArgs().empty());
        // An existing (even empty) file is not replaced by a generated one
        BOOST_CHECK(ReadFile(conf) == body);
        BOOST_CHECK(!fs::exists(pathTemp / "yacoin.conf"));
    }
}

static bool MentionsJustakey(const boost::program_options::invalid_config_file_syntax& e)
{
    return std::string(e.what()).find("'justakey'") != std::string::npos;
}

BOOST_FIXTURE_TEST_CASE(util_ReadConfigFile_invalid_line, UtilDataDirSetup)
{
    const fs::path conf = pathTemp / "invalid.conf";
    WriteFile(conf, "a=1\njustakey\nb=2\n");
    TestArgsManager testArgs;
    BOOST_CHECK_EXCEPTION(testArgs.ReadConfigFile(conf.string()),
                          boost::program_options::invalid_config_file_syntax, MentionsJustakey);
    // Parsing stops at the bad line (yacoind aborts startup on the exception)
    BOOST_CHECK_EQUAL(testArgs.GetArg("-a", ""), "1");
    BOOST_CHECK(!testArgs.IsArgSet("-b"));

    // A line with an empty name is rejected as well
    WriteFile(conf, "=v\n");
    TestArgsManager testArgs2;
    BOOST_CHECK_THROW(testArgs2.ReadConfigFile(conf.string()), boost::program_options::error);
    BOOST_CHECK(testArgs2.GetMapArgs().empty());
}

BOOST_FIXTURE_TEST_CASE(util_ReadConfigFile_creates_default, UtilDataDirSetup)
{
    // A missing default config file is generated and then read
    const fs::path conf = pathTemp / YACOIN_CONF_FILENAME;
    BOOST_REQUIRE(!fs::exists(conf));
    TestArgsManager testArgs;
    testArgs.ReadConfigFile(YACOIN_CONF_FILENAME);
    BOOST_CHECK(fs::exists(conf));
    BOOST_CHECK_EQUAL(testArgs.GetArg("-rpcuser", ""), "user");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-rpcport", ""), "7687");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-port", ""), "7688");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-daemon", ""), "0");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-server", ""), "0");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-rpcallowip", ""), "127.0.0.1");
    BOOST_CHECK_EQUAL(testArgs.GetArg("-testnet", ""), "0");
    BOOST_CHECK_EQUAL(testArgs.GetMapArgs().size(), 8U);

    // Once it exists it is read, not regenerated
    const std::string before = ReadFile(conf);
    TestArgsManager testArgs2;
    testArgs2.ReadConfigFile(YACOIN_CONF_FILENAME);
    BOOST_CHECK(ReadFile(conf) == before);
    BOOST_CHECK(testArgs2.GetMapArgs() == testArgs.GetMapArgs());
    BOOST_CHECK(testArgs2.GetMapMultiArgs() == testArgs.GetMapMultiArgs());

    // If the file can't be created (missing directory) the read returns early: nothing is
    // read and the datadir cache isn't cleared (a changed -datadir doesn't take effect yet)
    const fs::path dir2 = pathTemp / "other";
    fs::create_directories(dir2);
    BOOST_CHECK(GetDataDir(false) == pathTemp);
    gArgs.ForceSetArg("-datadir", dir2.string());
    gArgs.ForceSetArg("-conf", "missingdir/x.conf");
    TestArgsManager testArgs3;
    testArgs3.ReadConfigFile("missingdir/x.conf");
    BOOST_CHECK(testArgs3.GetMapArgs().empty());
    BOOST_CHECK(!fs::exists(pathTemp / "missingdir"));
    BOOST_CHECK(GetDataDir(false) == pathTemp);
    gArgs.ForceSetArg("-datadir", pathTemp.string());

    // createConf writes to the file named by gArgs -conf
    gArgs.ForceSetArg("-conf", "custom.conf");
    createConf();
    TestArgsManager testArgs5;
    testArgs5.ReadConfigFile((pathTemp / "custom.conf").string());
    BOOST_CHECK_EQUAL(testArgs5.GetArg("-rpcuser", ""), "user");
    BOOST_CHECK_EQUAL(testArgs5.GetArg("-rpcallowip", ""), "127.0.0.1");
    BOOST_CHECK_EQUAL(testArgs5.GetMapArgs().size(), 8U);
}

BOOST_FIXTURE_TEST_CASE(util_ReadConfigFile_datadir, UtilDataDirSetup)
{
    const fs::path dir2 = pathTemp / "other";
    fs::create_directories(dir2);
    const fs::path conf = pathTemp / YACOIN_CONF_FILENAME;
    WriteFile(conf, "datadir=" + dir2.string() + "\n");

    // -datadir on the command line wins over the file
    BOOST_CHECK(GetDataDir(false) == pathTemp);
    gArgs.ReadConfigFile(YACOIN_CONF_FILENAME);
    BOOST_CHECK_EQUAL(gArgs.GetArg("-datadir", ""), pathTemp.string());
    BOOST_CHECK(GetDataDir(false) == pathTemp);

    // Without it, the file's datadir takes effect at once: reading the file clears the
    // cached datadir (read by absolute path, so the old datadir isn't consulted). Without
    // -datadir only the cache keeps GetDataDir() away from the real default datadir, so it
    // is checked right before each read.
    TestArgsManager::EraseArg(gArgs, "-datadir");
    BOOST_REQUIRE(GetDataDir(false) == pathTemp); // still cached
    gArgs.ReadConfigFile(conf.string());
    BOOST_CHECK(GetDataDir(false) == dir2);
    BOOST_CHECK(GetDataDir(true) == dir2);

    // A datadir that doesn't exist gives an empty path
    WriteFile(conf, "datadir=" + (pathTemp / "missing").string() + "\n");
    TestArgsManager::EraseArg(gArgs, "-datadir");
    BOOST_REQUIRE(GetDataDir(false) == dir2);
    gArgs.ReadConfigFile(conf.string());
    BOOST_CHECK(GetDataDir(false).empty());
    BOOST_CHECK(!fs::exists(pathTemp / "missing"));
}

/** Saves and restores the logging globals. */
struct LogStateSetup : public BasicTestingSetup {
    const uint32_t savedCategories = logCategories;
    const bool savedDebugLog = fPrintToDebugLog;
    const bool savedConsole = fPrintToConsole;
    const bool savedTimestamps = fLogTimestamps;
    const bool savedTimeMicros = fLogTimeMicros;
    const int64_t savedMockTime = GetMockTime();

    ~LogStateSetup()
    {
        logCategories = savedCategories;
        fPrintToDebugLog = savedDebugLog;
        fPrintToConsole = savedConsole;
        fLogTimestamps = savedTimestamps;
        fLogTimeMicros = savedTimeMicros;
        SetMockTime(savedMockTime);
    }
};

BOOST_FIXTURE_TEST_CASE(util_LogCategories, LogStateSetup)
{
    uint32_t flag = 0xDEADBEEF;
    const std::string net("net");
    BOOST_CHECK(!GetLogCategory(nullptr, &net));
    BOOST_CHECK(!GetLogCategory(&flag, nullptr));
    // Unknown names (matching is exact and case sensitive) leave the flag untouched
    for (const std::string& bad : {"NET", "foo", " net", "net "}) {
        BOOST_CHECK(!GetLogCategory(&flag, &bad));
        BOOST_CHECK_EQUAL(flag, 0xDEADBEEF);
    }
    const std::vector<std::pair<std::string, uint32_t> > known = {
        {"", BCLog::ALL}, {"0", BCLog::NONE}, {"1", BCLog::ALL}, {"all", BCLog::ALL},
        {"net", BCLog::NET}, {"rpc", BCLog::RPC}, {"leveldb", BCLog::LEVELDB}};
    for (const auto& k : known) {
        flag = 0xDEADBEEF;
        BOOST_CHECK(GetLogCategory(&flag, &k.first));
        BOOST_CHECK_EQUAL(flag, k.second);
    }

    // The list leaves out the special entries 0, 1 and all
    const std::string list = ListLogCategories();
    BOOST_CHECK_EQUAL(list, "net, tor, mempool, http, bench, zmq, db, rpc, estimatefee, addrman, "
        "selectcoins, reindex, cmpctblock, rand, prune, proxy, mempoolrej, libevent, coindb, qt, leveldb");

    // Every listed name parses to its own single bit
    std::vector<std::string> names;
    boost::split(names, list, boost::is_any_of(","));
    BOOST_REQUIRE_EQUAL(names.size(), 21U);
    uint32_t all = 0;
    for (std::string& name : names) {
        boost::trim(name);
        BOOST_REQUIRE(GetLogCategory(&flag, &name));
        BOOST_CHECK(flag != 0 && (flag & (flag - 1)) == 0);
        BOOST_CHECK((all & flag) == 0);
        all |= flag;
    }
    BOOST_CHECK_EQUAL(all, (1U << 21) - 1);

    // Active flags follow logCategories, in the same order as the list
    const size_t netPos = std::find(names.begin(), names.end(), "net") - names.begin();
    const size_t leveldbPos = std::find(names.begin(), names.end(), "leveldb") - names.begin();
    BOOST_REQUIRE(netPos < names.size() && leveldbPos < names.size());
    for (uint32_t cats : {(uint32_t)BCLog::NONE, (uint32_t)(BCLog::NET | BCLog::LEVELDB), (uint32_t)BCLog::ALL}) {
        logCategories = cats;
        const std::vector<CLogCategoryActive> active = ListActiveLogCategories();
        BOOST_REQUIRE_EQUAL(active.size(), names.size());
        for (size_t i = 0; i < active.size(); ++i) {
            BOOST_CHECK_EQUAL(active[i].category, names[i]);
            const bool expected = cats == BCLog::ALL || (cats != BCLog::NONE && (i == netPos || i == leveldbPos));
            BOOST_CHECK_EQUAL(active[i].active, expected);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(util_LogPrintStr_timestamps, LogStateSetup)
{
    // Without an open debug.log the text is buffered where tests can't see it, so only the
    // returned lengths are checked: the stamp format and the mocktime text themselves can't
    // be compared here. A stamp is "YYYY-mm-dd HH:MM:SS " (20 chars).
    const int stamp = 20;
    fPrintToConsole = false;
    fPrintToDebugLog = true;
    fLogTimeMicros = false;
    SetMockTime(0);

    fLogTimestamps = false;
    BOOST_CHECK_EQUAL(LogPrintStr("abc\n"), 4);

    fLogTimestamps = true;
    LogPrintStr("\n"); // start on a fresh line whatever was logged before
    BOOST_CHECK_EQUAL(LogPrintStr("abc"), stamp + 3);
    BOOST_CHECK_EQUAL(LogPrintStr("def\n"), 4); // continuation of the same line
    BOOST_CHECK_EQUAL(LogPrintStr(""), stamp);  // stamped, and doesn't end the line
    BOOST_CHECK_EQUAL(LogPrintStr("\n"), 1);

    fLogTimeMicros = true;
    BOOST_CHECK_EQUAL(LogPrintStr("x\n"), stamp + 7 + 2); // ".123456"
    fLogTimeMicros = false;

    SetMockTime(1317425777);
    BOOST_CHECK_EQUAL(LogPrintStr("x\n"), stamp + 32 + 2); // " (mocktime: 2011-09-30 23:36:17)"
}

BOOST_FIXTURE_TEST_CASE(util_ShrinkDebugFile, UtilDataDirSetup)
{
    const fs::path log = pathTemp / "debug.log";
    BOOST_CHECK_EQUAL(GetDebugLogPathName(), log.string());

    // No debug.log: nothing happens and none is created
    ShrinkDebugFile();
    BOOST_CHECK(!fs::exists(log));

    // Position-dependent text without CR/LF (the file is opened in text mode). The pattern
    // repeats every 676 bytes, so the exact size check below matters as much as the content
    std::string content(11000001, ' ');
    for (size_t i = 0; i < content.size(); ++i)
        content[i] = 'a' + (i * 7 + i / 26) % 26;

    // Up to 11,000,000 bytes the file is left alone
    const std::string limit = content.substr(0, 11000000);
    WriteFile(log, limit);
    ShrinkDebugFile();
    BOOST_CHECK(ReadFile(log) == limit);

    // One byte more and only the last 10,000,000 bytes are kept
    WriteFile(log, content);
    ShrinkDebugFile();
    const std::string shrunk = ReadFile(log);
    BOOST_CHECK_EQUAL(shrunk.size(), 10000000U);
    BOOST_CHECK(shrunk == content.substr(1000001));
}

BOOST_FIXTURE_TEST_CASE(util_GetFilesize_TryCreateDirectories, UtilDataDirSetup)
{
    const fs::path file = pathTemp / "five";
    WriteFile(file, "12345");
    FILE* f = fsbridge::fopen(file, "rb");
    BOOST_REQUIRE(f);
    BOOST_REQUIRE_EQUAL(fseek(f, 2, SEEK_SET), 0);
    BOOST_CHECK_EQUAL(GetFilesize(f), 5);
    BOOST_CHECK_EQUAL(ftell(f), 2); // the position is restored
    fclose(f);

    BOOST_CHECK(TryCreateDirectories(pathTemp / "new" / "sub"));
    BOOST_CHECK(fs::is_directory(pathTemp / "new" / "sub"));
    BOOST_CHECK(!TryCreateDirectories(pathTemp / "new" / "sub")); // already there
    // A regular file in the way is an error that is passed on
    BOOST_CHECK_THROW(TryCreateDirectories(file), fs::filesystem_error);
    BOOST_CHECK_THROW(TryCreateDirectories(file / "sub"), fs::filesystem_error);
}

BOOST_AUTO_TEST_CASE(util_WildcardMatch)
{
    BOOST_CHECK(WildcardMatch("", ""));
    BOOST_CHECK(WildcardMatch("abc", "abc"));
    BOOST_CHECK(!WildcardMatch("a", ""));
    BOOST_CHECK(!WildcardMatch("abc", "ab"));
    BOOST_CHECK(!WildcardMatch("ab", "abc"));
    BOOST_CHECK(!WildcardMatch("abc", "abd"));
    BOOST_CHECK(!WildcardMatch("ABC", "abc")); // case sensitive
    // '?' matches exactly one character
    BOOST_CHECK(WildcardMatch("a", "?"));
    BOOST_CHECK(!WildcardMatch("", "?"));
    BOOST_CHECK(!WildcardMatch("ab", "?"));
    BOOST_CHECK(WildcardMatch("abc", "a?c"));
    BOOST_CHECK(!WildcardMatch("ac", "a?c"));
    BOOST_CHECK(!WildcardMatch("ab", "ab?"));
    // '*' matches any run, including an empty one
    BOOST_CHECK(WildcardMatch("", "*"));
    BOOST_CHECK(WildcardMatch("abc", "*"));
    BOOST_CHECK(WildcardMatch("abc", "a*"));
    BOOST_CHECK(WildcardMatch("abc", "abc*"));
    BOOST_CHECK(WildcardMatch("abc", "a**c"));
    BOOST_CHECK(!WildcardMatch("abc", "*d"));
    BOOST_CHECK(!WildcardMatch("abc", "a*b"));
    // These need backtracking: the first candidate for '*' isn't the right one
    BOOST_CHECK(WildcardMatch("abc", "*c"));
    BOOST_CHECK(WildcardMatch("abcbc", "a*bc"));
    BOOST_CHECK(WildcardMatch("aXbXc", "a*b*c"));
    BOOST_CHECK(WildcardMatch("127.0.0.1", "127.0.0.*"));
    BOOST_CHECK(!WildcardMatch("127.0.0.10", "127.0.0.?"));
    // std::string overload
    BOOST_CHECK(WildcardMatch(std::string("x.y"), std::string("?.*")));
    BOOST_CHECK(!WildcardMatch(std::string("xy"), std::string("?.*")));
}

BOOST_AUTO_TEST_CASE(util_ParseString)
{
    typedef std::vector<std::string> V;
    // Empty input adds nothing; results are appended, never cleared
    V v{"keep"};
    ParseString("", ',', v);
    BOOST_CHECK(v == V({"keep"}));
    ParseString("abc", ',', v);
    BOOST_CHECK(v == V({"keep", "abc"}));

    const std::vector<std::pair<std::string, V> > cases = {
        {"a,b,c", {"a", "b", "c"}}, {"a,,b", {"a", "", "b"}}, {",a", {"", "a"}},
        {"a,", {"a", ""}}, {",", {"", ""}}};
    for (const auto& c : cases) {
        V out;
        ParseString(c.first, ',', out);
        BOOST_CHECK_MESSAGE(out == c.second, "ParseString(\"" + c.first + "\")");
    }
    V spaces;
    ParseString("1 2", ' ', spaces);
    BOOST_CHECK(spaces == V({"1", "2"}));
}

BOOST_AUTO_TEST_CASE(util_DumpString)
{
    // Bytes up to space, from 128 up, and '%' are escaped as lowercase hex
    BOOST_CHECK_EQUAL(EncodeDumpString(" "), "%20");
    BOOST_CHECK_EQUAL(EncodeDumpString("!"), "!");
    BOOST_CHECK_EQUAL(EncodeDumpString(std::string(1, '\0')), "%00");
    BOOST_CHECK_EQUAL(EncodeDumpString("\x7f"), "\x7f");
    BOOST_CHECK_EQUAL(EncodeDumpString("\x80"), "%80");
    BOOST_CHECK_EQUAL(EncodeDumpString("\xff"), "%ff");
    BOOST_CHECK_EQUAL(EncodeDumpString("a b%"), "a%20b%25");

    BOOST_CHECK_EQUAL(DecodeDumpString(""), "");
    BOOST_CHECK_EQUAL(DecodeDumpString("%41"), "A");
    BOOST_CHECK_EQUAL(DecodeDumpString("x%41y"), "xAy");
    BOOST_CHECK_EQUAL(DecodeDumpString("%6a%6A"), "jj");
    BOOST_CHECK_EQUAL(DecodeDumpString("%00"), std::string(1, '\0'));
    // A '%' without two following characters is kept as it is
    BOOST_CHECK_EQUAL(DecodeDumpString("%"), "%");
    BOOST_CHECK_EQUAL(DecodeDumpString("%4"), "%4");
    BOOST_CHECK_EQUAL(DecodeDumpString("a%2"), "a%2");

    // Round trip over all byte values
    std::string all;
    for (int c = 0; c < 256; ++c)
        all += (char)c;
    const std::string encoded = EncodeDumpString(all);
    for (unsigned char c : encoded)
        BOOST_CHECK(c > 32 && c < 128);
    BOOST_CHECK(DecodeDumpString(encoded) == all);

    BOOST_CHECK_EQUAL(EncodeDumpTime(1317425777), "2011-09-30T23:36:17Z");
    BOOST_CHECK_EQUAL(DecodeDumpTime("2011-09-30T23:36:17Z"), 1317425777);
    BOOST_CHECK_EQUAL(DecodeDumpTime("garbage"), 0);
    BOOST_CHECK_EQUAL(DecodeDumpTime(""), 0);
}

BOOST_AUTO_TEST_SUITE_END()
