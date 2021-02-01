#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining RPCs

- getmininginfo
- getblocktemplate proposal mode
- submitblock"""

import copy
import time
from decimal import Decimal

from test_framework.blocktools import (
    create_coinbase,
    TIME_GENESIS_BLOCK,
)
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    BLOCK_HEADER_SIZE
)
from test_framework.mininode import (
    P2PDataStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_approx,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.script import CScriptNum


def assert_template(node, block, expect, rehash=True):
    if rehash:
        block.hashMerkleRoot = block.calc_merkle_root()
    rsp = node.getblocktemplate(template_request={'data': block.serialize().hex(), 'mode': 'proposal', 'rules': ['segwit']})
    assert_equal(rsp, expect)


class MiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime=TIME_GENESIS_BLOCK

    def setmocktimeforallnodes(self, mocktime):
        self.mocktime = mocktime
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks_init(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        self.setmocktimeforallnodes(self.mocktime)
        self.mocktime=self.mocktime+timeBetweenBlocks+timeBetweenBlocks*numberOfBlocks      
        self.nodes[nodeId].generate(numberOfBlocks)
        self.sync_all()

    def mine_blocks(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        for _ in range(numberOfBlocks):
            self.setmocktimeforallnodes(self.mocktime)
            self.mocktime=self.mocktime+timeBetweenBlocks      
            self.nodes[nodeId].generate(1)
        self.sync_all()

    def run_test(self):
        # mine a few blocks and check that the balance is available after block 6
        self.mine_blocks(0, 20)
        mining_info = self.nodes[0].getmininginfo()
        
        for i in range(5):
            self.log.info(">>> MINING block "+str(i+21))
            self.mine_blocks(0,1)
            mining_info = self.nodes[0].getmininginfo()
            balance = self.nodes[0].getbalance()
            assert_equal(mining_info['blocks'], (20+i+1))
            assert_equal(mining_info['currentblocksize'], 1000)
            assert_equal(mining_info['N'], 32)
            # the low difficulty is only valid because of the low difficulty flag
            assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0000000777459625'))
            # low nfactor is set for testing
            assert_equal(mining_info['Nfactor'], 4)
            # powreward is based on 100,000,000 initial money supply for testing
            assert_approx(mining_info['powreward'], 3.80257)
            assert_approx(balance,60.841127 + i*3.80257)
        
        # mine block 6
        self.mine_blocks(0, 1)
        mining_info = self.nodes[0].getmininginfo()
        balance=self.nodes[0].getbalance()
        assert_equal(mining_info['blocks'], 26)
        assert_approx(balance,79.853986)

        # mine till block 9 (epoch)
        for i in range(3):
            self.mine_blocks(0, 1)
            mining_info = self.nodes[0].getmininginfo()
            assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0000000777459625'))
        assert_equal(mining_info['blocks'], 29)
        assert_approx(mining_info['powreward'], 3.8025705377)

        # mine block 10 (epoch calculation) and difficulty change
        self.mine_blocks(0, 1)
        mining_info = self.nodes[0].getmininginfo()
        balance=self.nodes[0].getbalance()
        assert_equal(mining_info['blocks'], 30)
        assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0000000777459625'))
        assert_approx(mining_info['powreward'], 3.8025705377)
        assert_approx(float(balance), 95.064278)

        # mine block 15 (pow reward available)
        self.mine_blocks(0, 5)
        mining_info = self.nodes[0].getmininginfo()
        balance=self.nodes[0].getbalance()
        assert_equal(mining_info['blocks'], 35)
        assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0000000777459625'))
        assert_approx(balance, 114.077144)

if __name__ == '__main__':
    MiningTest().main()
