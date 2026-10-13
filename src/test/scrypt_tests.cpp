// Copyright (c) 2026 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "primitives/block.h"
#include "scrypt.h"
#include "utilstrencodings.h"

extern "C" {
#include "scrypt-jane/scrypt-jane.h"
}

#include "test/consensus_test_util.h"
#include "test/test_bitcoin.h"

#include <string.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(scrypt_tests, BasicTestingSetup)

/* Start of each N-factor for pre-1.0 (32-bit nTime) block headers, copied from
 * CBlockHeader::CalculateHash: from time[i] on, the N-factor is i + 5. */
static const ::int64_t NFACTOR_SCHEDULE[] = {
    1368515488, 1368777632, 1369039776, 1369826208, 1370088352, 1372185504,
    1373234080, 1376379808, 1380574112, 1384768416, 1401545632, 1409934240,
    1435100064, 1468654496, 1502208928, 1602872224, 1636426656, 1904862112,
    2173297568, 2441733024, 3247039392,
};

/* scrypt-jane's own known-answer vectors for keccak512 + chacha20/8, the
 * combination YACoin is built with (SCRYPT_KECCAK512, SCRYPT_CHACHA). */
BOOST_AUTO_TEST_CASE(scrypt_jane_known_answers)
{
    struct {
        const char *pw, *salt;
        unsigned char Nfactor, rfactor, pfactor;
        const char* hex;
    } vectors[] = {
        {"", "", 3, 0, 0,
         "77cb70bfaed44c5bbcd3ec8a82438db37f1ffb7036324da6b7133777300c3cfb"
         "2c208f2af4474d698eae2dadba35e92fe6997af8cf7078bb0c7264958b36773d"},
        {"password", "NaCl", 9, 3, 4,
         "c643171687095f12ed21e2b4ad55a1a149509070ab81837acddf235219c0a2d8"
         "8e98ebf037abadfd1c0497184285f74b182c55d3a9e689fb580ab237b9f8fbc5"},
    };
    for (const auto& v : vectors) {
        unsigned char out[64];
        BOOST_CHECK(scrypt((const unsigned char*)v.pw, strlen(v.pw), (const unsigned char*)v.salt, strlen(v.salt),
                           v.Nfactor, v.rfactor, v.pfactor, out, sizeof(out)));
        BOOST_CHECK_EQUAL(HexStr(out, out + sizeof(out)), v.hex);
    }
}

/* scrypt_hash is scrypt-jane with the input as its own salt and r = p = 1 */
BOOST_AUTO_TEST_CASE(scrypt_hash_matches_scrypt_jane)
{
    const unsigned char input[] = "yacoin block header";
    for (unsigned char nFactor = 4; nFactor <= 6; nFactor++) {
        uint256 hash, expected;
        BOOST_CHECK(scrypt_hash(input, sizeof(input), (::uint32_t*)hash.begin(), nFactor));
        BOOST_CHECK(scrypt(input, sizeof(input), input, sizeof(input), nFactor, 0, 0, expected.begin(), 32));
        BOOST_CHECK(hash == expected);
    }
}

/* The display formula in GetNfactor matches the consensus table at every step */
BOOST_AUTO_TEST_CASE(nfactor_schedule)
{
    BOOST_CHECK_EQUAL(GetNfactor(nChainStartTime), 4);
    BOOST_CHECK_EQUAL(GetNfactor(nChainStartTime - 1000), 4);

    unsigned char nExpected = 4;
    for (::int64_t nStart : NFACTOR_SCHEDULE) {
        BOOST_CHECK_EQUAL(GetNfactor(nStart - 1), nExpected);
        ++nExpected;
        BOOST_CHECK_EQUAL(GetNfactor(nStart), nExpected);
    }
    BOOST_CHECK_EQUAL(nExpected, MAXIMUM_N_FACTOR);
    BOOST_CHECK_EQUAL(GetNfactor(3515474848LL), MAXIMUM_N_FACTOR);
    BOOST_CHECK_EQUAL(GetNfactor(1LL << 40), MAXIMUM_N_FACTOR);
}

/* After the fork every block and tx uses the fixed N-factor (mainnet 21) */
BOOST_AUTO_TEST_CASE(nfactor_after_fork)
{
    ConsensusGlobalsGuard globals;
    nFactorAtHardfork = 21;
    BOOST_CHECK_EQUAL(GetNfactor(nChainStartTime, true), 21);
    BOOST_CHECK_EQUAL(GetNfactor(1LL << 40, true), 21);
    nFactorAtHardfork = 7;
    BOOST_CHECK_EQUAL(GetNfactor(1700000000, true), 7);
}

static CBlockHeader TestHeader(int nVersion, ::int64_t nTime)
{
    CBlockHeader header;
    header.nVersion = nVersion;
    header.hashPrevBlock = uint256S("0x0000060fc90618113cde415ead019a1052a9abc43afcccff38608ff8751353e5");
    header.hashMerkleRoot = uint256S("0x678b76419ff06676a591d3fa9d57d7f7b26d8021b7cc69dde925f39d4cf2244f");
    header.nTime = nTime;
    header.nBits = 0x1e0fffff;
    header.nNonce = 12345;
    return header;
}

/* Pre-1.0 headers (32-bit nTime) hash the 80-byte header with the N-factor of their timestamp */
BOOST_AUTO_TEST_CASE(old_header_hash_uses_nfactor_schedule)
{
    for (int i = 0; i < 4; i++) {
        // Last second of N-factor i + 4
        ::int64_t nTime = NFACTOR_SCHEDULE[i] - 1;
        CBlockHeader header = TestHeader(VERSION_of_block_for_yac_049, nTime);

        old_block_header raw;
        raw.version = header.nVersion;
        raw.prev_block = header.hashPrevBlock;
        raw.merkle_root = header.hashMerkleRoot;
        raw.timestamp = header.nTime;
        raw.bits = header.nBits;
        raw.nonce = header.nNonce;
        BOOST_CHECK_EQUAL(sizeof(raw), 80U);

        uint256 expected, other;
        BOOST_CHECK(scrypt_hash(&raw, sizeof(raw), (::uint32_t*)expected.begin(), GetNfactor(nTime)));
        BOOST_CHECK(scrypt_hash(&raw, sizeof(raw), (::uint32_t*)other.begin(), GetNfactor(nTime) + 1));
        BOOST_CHECK_EQUAL(GetNfactor(nTime), i + 4);
        BOOST_CHECK(header.CalculateHash() == expected);
        BOOST_CHECK(header.CalculateHash() != other);
    }
}

/* 1.0 headers (64-bit nTime) hash the 84-byte header with nFactorAtHardfork, whatever the time */
BOOST_AUTO_TEST_CASE(new_header_hash_uses_hardfork_nfactor)
{
    ConsensusGlobalsGuard globals;
    CBlockHeader header = TestHeader(VERSION_of_block_for_yac_05x_new, NFACTOR_SCHEDULE[0] - 1);

    block_header raw;
    raw.version = header.nVersion;
    raw.prev_block = header.hashPrevBlock;
    raw.merkle_root = header.hashMerkleRoot;
    raw.timestamp = header.nTime;
    raw.bits = header.nBits;
    raw.nonce = header.nNonce;
    BOOST_CHECK_EQUAL(sizeof(raw), 84U);

    for (unsigned char nFactor = 5; nFactor <= 6; nFactor++) {
        nFactorAtHardfork = nFactor;
        uint256 expected;
        BOOST_CHECK(scrypt_hash(&raw, sizeof(raw), (::uint32_t*)expected.begin(), nFactor));
        // CalculateHash, not GetHash: GetHash caches the result per header
        BOOST_CHECK(header.CalculateHash() == expected);
    }
}

BOOST_AUTO_TEST_SUITE_END()
