// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Token DB listings (TokenDir, TokenAddressDir, AddressDir) on entries written
// directly to the database: filters, paging, totals and unreadable entries.

#include "tokens/tokendb.h"
#include "tokens/tokens.h"
#include "tinyformat.h"
#include "uint256.h"

#include "test/test_bitcoin.h"
#include "test/token_test_util.h"

#include <algorithm>

#include <boost/test/unit_test.hpp>

// Key prefixes of the token database (file-static in tokens/tokendb.cpp)
static const char TOKEN_FLAG = 'A';
static const char TOKEN_ADDRESS_QUANTITY_FLAG = 'B';
static const char ADDRESS_TOKEN_QUANTITY_FLAG = 'C';

BOOST_FIXTURE_TEST_SUITE(token_db_tests, TokenTestingSetup)

/** Distinct metadata per entry so the round trip can tell entries apart */
static CNewToken DbToken(const std::string& name, int n)
{
    return CNewToken(name, n * COIN, n % 7, n % 2, 0, "");
}

static uint256 DbBlockHash(int n)
{
    return uint256S(strprintf("0xb10c%02x", n));
}

static std::vector<std::string> Dir(const std::string& filter, size_t count, long start, bool fExpectOk = true)
{
    std::vector<CDatabasedTokenData> tokens;
    BOOST_CHECK_EQUAL(ptokensdb->TokenDir(tokens, filter, count, start), fExpectOk);
    std::vector<std::string> names;
    for (const auto& data : tokens)
        names.push_back(data.token.strName);
    return names;
}

static int HolderTotal(const std::string& name)
{
    std::vector<std::pair<std::string, CAmount> > vec;
    int nTotal = 99;
    BOOST_CHECK(ptokensdb->TokenAddressDir(vec, nTotal, true, name, 10, 0));
    BOOST_CHECK(vec.empty());
    return nTotal;
}

static int HoldingTotal(const std::string& address)
{
    std::vector<std::pair<std::string, CAmount> > vec;
    int nTotal = 99;
    BOOST_CHECK(ptokensdb->AddressDir(vec, nTotal, true, address, 10, 0));
    BOOST_CHECK(vec.empty());
    return nTotal;
}

static std::string Entry(const std::string& key, CAmount amount)
{
    return key + "=" + std::to_string(amount);
}

BOOST_AUTO_TEST_CASE(token_dir_filters_and_paging)
{
    // Written out of order; the database returns them by name length, then bytes
    const std::vector<std::string> written = {"ABC/X", "CCC", "ABCD", "AAA", "ABC#T", "BBB", "ABC"};
    for (size_t i = 0; i < written.size(); i++)
        BOOST_REQUIRE(ptokensdb->WriteTokenData(DbToken(written[i], i + 1), i + 1, DbBlockHash(i + 1)));
    // A key of another table after the token table ends the scans
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("AAA", TestTokenAddress(1), COIN));
    const std::vector<std::string> all = {"AAA", "ABC", "BBB", "CCC", "ABCD", "ABC#T", "ABC/X"};

    // Every field comes back as written
    std::vector<CDatabasedTokenData> tokens;
    BOOST_REQUIRE(ptokensdb->TokenDir(tokens));
    BOOST_REQUIRE_EQUAL(tokens.size(), all.size());
    for (size_t i = 0; i < tokens.size(); i++) {
        BOOST_CHECK_EQUAL(tokens[i].token.strName, all[i]);
        size_t n = std::find(written.begin(), written.end(), all[i]) - written.begin() + 1;
        const CNewToken expected = DbToken(all[i], n);
        BOOST_CHECK_EQUAL(tokens[i].token.nAmount, expected.nAmount);
        BOOST_CHECK_EQUAL((int)tokens[i].token.units, (int)expected.units);
        BOOST_CHECK_EQUAL((int)tokens[i].token.nReissuable, (int)expected.nReissuable);
        BOOST_CHECK_EQUAL((int)tokens[i].token.nHasIPFS, 0);
        BOOST_CHECK_EQUAL(tokens[i].token.strIPFSHash, "");
        BOOST_CHECK_EQUAL(tokens[i].nHeight, (int)n);
        BOOST_CHECK(tokens[i].blockHash == DbBlockHash(n));
    }

    // Filters: everything, a prefix, an exact name, no match
    TOKEN_CHECK_LIST(Dir("*", 100, 0), all);
    TOKEN_CHECK_LIST(Dir("ABC*", 100, 0), {"ABC", "ABCD", "ABC#T", "ABC/X"});
    TOKEN_CHECK_LIST(Dir("ABC/*", 100, 0), {"ABC/X"});
    TOKEN_CHECK_LIST(Dir("ABC", 100, 0), {"ABC"});
    TOKEN_CHECK_LIST(Dir("ZZZ", 100, 0), {});
    TOKEN_CHECK_LIST(Dir("ZZZ*", 100, 0), {});

    // Paging from the front
    TOKEN_CHECK_LIST(Dir("*", 2, 0), {"AAA", "ABC"});
    TOKEN_CHECK_LIST(Dir("*", 2, 2), {"BBB", "CCC"});
    TOKEN_CHECK_LIST(Dir("*", 10, 6), {"ABC/X"});
    TOKEN_CHECK_LIST(Dir("*", 10, 7), {});
    TOKEN_CHECK_LIST(Dir("*", 10, 100), {});
    TOKEN_CHECK_LIST(Dir("*", 0, 0), {});
    // Only matching entries count toward the offset
    TOKEN_CHECK_LIST(Dir("ABC*", 2, 1), {"ABCD", "ABC#T"});

    // A negative start counts back from the end of the filtered list
    TOKEN_CHECK_LIST(Dir("*", 1, -1), {"ABC/X"});
    TOKEN_CHECK_LIST(Dir("*", 2, -3), {"ABCD", "ABC#T"});
    TOKEN_CHECK_LIST(Dir("*", 100, -7), all);
    TOKEN_CHECK_LIST(Dir("*", 100, -8), {});
    TOKEN_CHECK_LIST(Dir("ABC*", 10, -1), {"ABC/X"});
    TOKEN_CHECK_LIST(Dir("ABC*", 10, -4), {"ABC", "ABCD", "ABC#T", "ABC/X"});
    TOKEN_CHECK_LIST(Dir("ABC", 10, -1), {"ABC"});
    TOKEN_CHECK_LIST(Dir("ZZZ", 10, -1), {});
}

BOOST_AUTO_TEST_CASE(token_dir_empty_and_unreadable)
{
    TOKEN_CHECK_LIST(Dir("*", 10, 0), {});
    TOKEN_CHECK_LIST(Dir("*", 10, -1), {});

    // An unreadable entry fails the listing only when it would be returned
    BOOST_REQUIRE(ptokensdb->WriteTokenData(DbToken("AAA", 1), 1, DbBlockHash(1)));
    BOOST_REQUIRE(ptokensdb->Write(std::make_pair(TOKEN_FLAG, std::string("BAD")), uint8_t(1)));
    TOKEN_CHECK_LIST(Dir("*", 10, 0, false), {"AAA"});
    TOKEN_CHECK_LIST(Dir("*", 10, 1, false), {});
    TOKEN_CHECK_LIST(Dir("*", 1, 0), {"AAA"});
    TOKEN_CHECK_LIST(Dir("AAA", 10, 0), {"AAA"});
}

BOOST_AUTO_TEST_CASE(token_address_dir_totals_and_paging)
{
    const std::string a1 = TestTokenAddress(1), a2 = TestTokenAddress(2), a3 = TestTokenAddress(3);
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("ABC", a2, 2 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("ABC", a1, 1 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("ABC", a3, 3 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("ABCD", a1, 4 * COIN));
    // Entries of the other tables don't show up
    BOOST_REQUIRE(ptokensdb->WriteTokenData(DbToken("ABC", 1), 1, DbBlockHash(1)));
    BOOST_REQUIRE(ptokensdb->WriteAddressTokenQuantity(a1, "ABC", 1 * COIN));

    const std::vector<std::string> all = TokenEntriesInDbOrder({{a1, 1 * COIN}, {a2, 2 * COIN}, {a3, 3 * COIN}});

    // Totals count the exact name only; the passed-in total is reset
    BOOST_CHECK_EQUAL(HolderTotal("ABC"), 3);
    BOOST_CHECK_EQUAL(HolderTotal("ABCD"), 1);
    BOOST_CHECK_EQUAL(HolderTotal("NONE"), 0);

    TOKEN_CHECK_LIST(TokenHolders("ABC", 100, 0), all);
    TOKEN_CHECK_LIST(TokenHolders("ABC", 2, 0), {all[0], all[1]});
    TOKEN_CHECK_LIST(TokenHolders("ABC", 2, 2), {all[2]});
    TOKEN_CHECK_LIST(TokenHolders("ABC", 10, 3), {});
    TOKEN_CHECK_LIST(TokenHolders("ABC", 0, 0), {});
    TOKEN_CHECK_LIST(TokenHolders("ABCD", 100, 0), {Entry(a1, 4 * COIN)});
    TOKEN_CHECK_LIST(TokenHolders("NONE", 100, 0), {});

    // An unreadable quantity fails the listing, not the total or a page that skips it
    BOOST_REQUIRE(ptokensdb->Write(std::make_pair(TOKEN_ADDRESS_QUANTITY_FLAG, std::make_pair(std::string("BAD"), a1)), uint8_t(1)));
    TOKEN_CHECK_LIST(TokenHolders("BAD", 10, 0, false), {});
    BOOST_CHECK_EQUAL(HolderTotal("BAD"), 1);
    TOKEN_CHECK_LIST(TokenHolders("BAD", 10, 1), {});
}

BOOST_AUTO_TEST_CASE(address_dir_totals_and_paging)
{
    const std::string a1 = TestTokenAddress(1), a2 = TestTokenAddress(2), a3 = TestTokenAddress(3);
    BOOST_REQUIRE(ptokensdb->WriteAddressTokenQuantity(a1, "XYZ", 3 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteAddressTokenQuantity(a1, "ABCD", 2 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteAddressTokenQuantity(a1, "ABC", 1 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteAddressTokenQuantity(a2, "ABC", 5 * COIN));
    BOOST_REQUIRE(ptokensdb->WriteTokenData(DbToken("ABC", 1), 1, DbBlockHash(1)));
    BOOST_REQUIRE(ptokensdb->WriteTokenAddressQuantity("ABC", a1, 1 * COIN));

    BOOST_CHECK_EQUAL(HoldingTotal(a1), 3);
    BOOST_CHECK_EQUAL(HoldingTotal(a2), 1);
    BOOST_CHECK_EQUAL(HoldingTotal(TestTokenAddress(9)), 0);

    TOKEN_CHECK_LIST(TokenHoldings(a1, 100, 0), {"ABC=1000000", "XYZ=3000000", "ABCD=2000000"});
    TOKEN_CHECK_LIST(TokenHoldings(a1, 1, 1), {"XYZ=3000000"});
    TOKEN_CHECK_LIST(TokenHoldings(a1, 10, 3), {});
    TOKEN_CHECK_LIST(TokenHoldings(a1, 0, 0), {});
    TOKEN_CHECK_LIST(TokenHoldings(a2, 100, 0), {"ABC=5000000"});
    TOKEN_CHECK_LIST(TokenHoldings(TestTokenAddress(9), 100, 0), {});

    BOOST_REQUIRE(ptokensdb->Write(std::make_pair(ADDRESS_TOKEN_QUANTITY_FLAG, std::make_pair(a3, std::string("BAD"))), uint8_t(1)));
    TOKEN_CHECK_LIST(TokenHoldings(a3, 10, 0, false), {});
    BOOST_CHECK_EQUAL(HoldingTotal(a3), 1);
    TOKEN_CHECK_LIST(TokenHoldings(a3, 10, 1), {});
}

BOOST_AUTO_TEST_SUITE_END()
