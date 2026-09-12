// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bloom.h"

#include "base58.h"
#include "clientversion.h"
#include "key.h"
#include "merkleblock.h"
#include "random.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize)
{
    CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "Bloom filter doesn't contain just-inserted object (3)!");

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    std::vector<unsigned char> vch = ParseHex("03614e9b050000000000000001");
    std::vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());

    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    filter.clear();
    BOOST_CHECK_MESSAGE( !filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter should be empty!");
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize_with_tweak)
{
    // Same test as bloom_create_insert_serialize, but we add a nTweak of 100
    CBloomFilter filter(3, 0.01, 2147483649UL, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "Bloom filter doesn't contain just-inserted object (3)!");

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    std::vector<unsigned char> vch = ParseHex("03ce4299050000000100008001");
    std::vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_key)
{
    std::string strSecret = std::string("XTAiSHynQ9KFddSttzPP1cpmPR4FspCe3GLhsbLZT251odfqN6Eo");
    CBitcoinSecret vchSecret;
    BOOST_CHECK(vchSecret.SetString(strSecret));

    CKey key = vchSecret.GetKey();
    CPubKey pubkey = key.GetPubKey();
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CBloomFilter filter(2, 0.001, 0, BLOOM_UPDATE_ALL);
    filter.insert(vchPubKey);
    uint160 hash = pubkey.GetID();
    filter.insert(std::vector<unsigned char>(hash.begin(), hash.end()));

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    std::vector<unsigned char> vch = ParseHex("0364d253080000000000000001");
    std::vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_match)
{
    // Random real transaction (05c71a4c01ca977fe19625d80d1fdccb39489e45b9d77d518bf2ebe1070858f0)
    CDataStream stream(ParseHex("0200000003c875680000000001e782694f2b16e1438cea65675888f22a6502883ca1ec03b967153da00137fe67000000006b483045022100d1722aa4cba5d80b22a3382a5b3340f0a4fbc3d1719265bb193adc132771946302205e45d9bd7c47ab2f585970512569d55cad860395efae5e1373d6e1efea68203d01210273ab4878e664d8a1d622b2318c657c82e27644a49118e7b02d39e60c6ded1fb5ffffffff020050d6dc010000001976a914e480473de775e89c7425ab353b8795f1acdaf96088ac1c60f8a3190000001976a9143098b7b181ebeb08051e2fb0db4e3e149aacb57e88ac00000000"), SER_DISK, CLIENT_VERSION);
    CTransaction tx(deserialize, stream);

    // and one which spends it (4877d3b664859a1b0ec0a8ba7da83640e602459178ffe2b2facf45c7fac6b658)
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
    CDataStream spendStream(vch, SER_DISK, CLIENT_VERSION);
    CTransaction spendingTx(deserialize, spendStream);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256S("05c71a4c01ca977fe19625d80d1fdccb39489e45b9d77d518bf2ebe1070858f0"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // byte-reversed tx hash
    filter.insert(ParseHex("f0580807e1ebf28b517dd7b9459e4839cbdc1f0dd82596e17f97ca014c1ac705"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("3045022100d1722aa4cba5d80b22a3382a5b3340f0a4fbc3d1719265bb193adc132771946302205e45d9bd7c47ab2f585970512569d55cad860395efae5e1373d6e1efea68203d01"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input signature");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("0273ab4878e664d8a1d622b2318c657c82e27644a49118e7b02d39e60c6ded1fb5"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input pub key");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("3098b7b181ebeb08051e2fb0db4e3e149aacb57e"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output address");
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(spendingTx), "Simple Bloom filter didn't add output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("e480473de775e89c7425ab353b8795f1acdaf960"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x67fe3701a03d1567b903eca13c8802652af288586765ea8c43e1162b4f6982e7"), 0));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    COutPoint prevOutPoint(uint256S("0x67fe3701a03d1567b903eca13c8802652af288586765ea8c43e1162b4f6982e7"), 0);
    {
        std::vector<unsigned char> data(32 + sizeof(unsigned int));
        memcpy(&data[0], prevOutPoint.hash.begin(), 32);
        memcpy(&data[32], &prevOutPoint.n, sizeof(unsigned int));
        filter.insert(data);
    }
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256S("00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("0000006d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x67fe3701a03d1567b903eca13c8802652af288586765ea8c43e1162b4f6982e7"), 1));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x000000d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");
}

static std::vector<unsigned char> RandomData()
{
    uint256 r = InsecureRand256();
    return std::vector<unsigned char>(r.begin(), r.end());
}

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    // last-100-entry, 1% false positive:
    CRollingBloomFilter rb1(100, 0.01);

    // Overfill:
    static const int DATASIZE=399;
    std::vector<unsigned char> data[DATASIZE];
    for (int i = 0; i < DATASIZE; i++) {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    // Last 100 guaranteed to be remembered:
    for (int i = 299; i < DATASIZE; i++) {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // false positive rate is 1%, so we should get about 100 hits if
    // testing 10,000 random keys. We get worst-case false positive
    // behavior when the filter is as full as possible, which is
    // when we've inserted one minus an integer multiple of nElement*2.
    unsigned int nHits = 0;
    for (int i = 0; i < 10000; i++) {
        if (rb1.contains(RandomData()))
            ++nHits;
    }
    // Run test_bitcoin with --log_level=message to see BOOST_TEST_MESSAGEs:
    BOOST_TEST_MESSAGE("RollingBloomFilter got " << nHits << " false positives (~100 expected)");

    // Insanely unlikely to get a fp count outside this range:
    BOOST_CHECK(nHits > 25);
    BOOST_CHECK(nHits < 175);

    BOOST_CHECK(rb1.contains(data[DATASIZE-1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATASIZE-1]));

    // Now roll through data, make sure last 100 entries
    // are always remembered:
    for (int i = 0; i < DATASIZE; i++) {
        if (i >= 100)
            BOOST_CHECK(rb1.contains(data[i-100]));
        rb1.insert(data[i]);
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // Insert 999 more random entries:
    for (int i = 0; i < 999; i++) {
        std::vector<unsigned char> d = RandomData();
        rb1.insert(d);
        BOOST_CHECK(rb1.contains(d));
    }
    // Sanity check to make sure the filter isn't just filling up:
    nHits = 0;
    for (int i = 0; i < DATASIZE; i++) {
        if (rb1.contains(data[i]))
            ++nHits;
    }
    // Expect about 5 false positives, more than 100 means
    // something is definitely broken.
    BOOST_TEST_MESSAGE("RollingBloomFilter got " << nHits << " false positives (~5 expected)");
    BOOST_CHECK(nHits < 100);

    // last-1000-entry, 0.01% false positive:
    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATASIZE; i++) {
        rb2.insert(data[i]);
    }
    // ... room for all of them:
    for (int i = 0; i < DATASIZE; i++) {
        BOOST_CHECK(rb2.contains(data[i]));
    }
}

BOOST_AUTO_TEST_SUITE_END()
