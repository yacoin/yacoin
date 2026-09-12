#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPCs related to blockchainstate.

Test the following RPCs:
    - gettimechaininfo
    - getbestblockhash
    - getblockhash
    - getblockheader
    - getchaintxstats
    - verifychain

Tests correspond to code in rpc/blockchain.cpp.
"""

from decimal import Decimal
import http.client
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises,
    assert_raises_rpc_error,
    assert_is_hex_string,
    assert_is_hash_string,
)
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    TIME_GENESIS_BLOCK,
)
from test_framework.messages import (
    msg_block,
)
from test_framework.mininode import (
    P2PInterface,
)


class BlockchainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False

    def run_test(self):
        self.mine_chain()

        self.log.info("Running blockchain tests")
        self._test_gettimechaininfo()
        self._test_getchaintxstats()
        self._test_getblockheader()
        assert self.nodes[0].verifychain(4, 0)

    def mine_chain(self):
        self.log.info('Create some old blocks')
        address = self.nodes[0].get_deterministic_priv_key().address
        for t in range(TIME_GENESIS_BLOCK, TIME_GENESIS_BLOCK + 40 * 60, 60):
            # 1-minute steps from genesis block time
            self.nodes[0].setmocktime(t)
            self.nodes[0].generatetoaddress(1, address)
        assert_equal(self.nodes[0].gettimechaininfo()['blocks'], 40)

    def _test_gettimechaininfo(self):
        self.log.info("Test gettimechaininfo")

        keys = [
            'Latest block time',
            'bestblockhash',
            'blocks',
            'bnChainTrust',
            'chain',
            'difficulty',
            'headers',
            'txcount',
            'verificationprogress'
        ]
        res = self.nodes[0].gettimechaininfo()
        # should have exact keys
        assert_equal(sorted(res.keys()), keys)
        
        assert_equal(res['blocks'], 40)
        assert_equal(res['headers'], 40)
        assert_equal(res['txcount'], 41)

    def _test_getchaintxstats(self):
        self.log.info("Test getchaintxstats")

        # Test `getchaintxstats` invalid extra parameters
        assert_raises_rpc_error(-1, 'getchaintxstats', self.nodes[0].getchaintxstats, 0, '', 0)

        # Test `getchaintxstats` invalid `nblocks`
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", self.nodes[0].getchaintxstats, '')
        assert_raises_rpc_error(-8, "Invalid block count: should be between 1 and the block's height", self.nodes[0].getchaintxstats, -1)

        # Test `getchaintxstats` invalid `blockhash`
        assert_raises_rpc_error(-1, "JSON value is not a string as expected", self.nodes[0].getchaintxstats, blockhash=0)
        assert_raises_rpc_error(-5, "Block not found", self.nodes[0].getchaintxstats, blockhash='0000000000000000000000000000000000000000000000000000000000000000')

        chaintxstats = self.nodes[0].getchaintxstats(nblocks=1)
        # 40 txs plus genesis tx
        assert_equal(chaintxstats['txcount'], 41)
        # tx rate should be 1 per minute, or 1/60
        # we have to round because of binary math
        assert_equal(round(chaintxstats['txrate'] * 60, 10), Decimal(1))

        b1_hash = self.nodes[0].getblockhash(1)
        b1 = self.nodes[0].getblock(b1_hash)
        b40_hash = self.nodes[0].getblockhash(40)
        b40 = self.nodes[0].getblock(b40_hash)
        time_diff = b40['time'] - b1['time']

        chaintxstats = self.nodes[0].getchaintxstats(39)
        assert_equal(chaintxstats['time'], b40['time'])
        assert_equal(chaintxstats['txcount'], 41)
        assert_equal(round(chaintxstats['txrate'] * time_diff, 10), Decimal(39))

    def _test_getblockheader(self):
        node = self.nodes[0]

        assert_raises_rpc_error(-5, "Block not found", node.getblockheader, "nonsense")

        besthash = node.getbestblockhash()
        secondbesthash = node.getblockhash(39)
        header = node.getblockheader(blockhash=besthash)

        assert_equal(header['hash'], besthash)
        assert_equal(header['height'], 40)
        assert_equal(header['confirmations'], 1)
        assert_equal(header['previousblockhash'], secondbesthash)
        assert_is_hex_string(header['chaintrust'])
        assert_is_hash_string(header['hash'])
        assert_is_hash_string(header['previousblockhash'])
        assert_is_hash_string(header['merkleroot'])
        assert_is_hash_string(header['bits'], length=None)
        assert isinstance(header['time'], int)
        assert isinstance(header['nonce'], int)
        assert isinstance(header['version'], int)
        assert isinstance(int(header['versionHex'], 16), int)
        assert isinstance(header['difficulty'], Decimal)


if __name__ == '__main__':
    BlockchainTest().main()
