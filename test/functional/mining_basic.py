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
   
    def run_test(self):
        # mine a few blocks and check that the balance is available after block 6
        mocktime=TIME_GENESIS_BLOCK
        timeBetweenBlocksInSeconds=120
        for i in range(5):
            self.log.info(">>> MINING block "+str(i+1))            
            self.nodes[0].setmocktime(mocktime)
            mocktime=mocktime+timeBetweenBlocksInSeconds      
            self.nodes[0].generate(1)
            mining_info = self.nodes[0].getmininginfo()
            balance = self.nodes[0].getbalance()
            assert_equal(mining_info['blocks'], (i+1))
            assert_equal(mining_info['currentblocksize'], 1000)
            assert_equal(mining_info['N'], 32)
            # the low difficulty is only valid because of the low difficulty flag
            assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0000000596046448'))
            # low nfactor is set for testing
            assert_equal(mining_info['Nfactor'], 4)
            # powreward is set to 1000000 (only applies if the yacoin version is started like this, so only for testing)
            assert_equal(mining_info['powreward'], Decimal('10000000'))
            assert_equal(balance,Decimal('0.0'))
        # mine block 6
        self.nodes[0].setmocktime(mocktime)
        mocktime=mocktime+timeBetweenBlocksInSeconds
        self.nodes[0].generate(1)
        mining_info = self.nodes[0].getmininginfo()
        balance=self.nodes[0].getbalance()
        assert_equal(mining_info['blocks'], 6)
        assert_equal(balance,Decimal('10000000'))

        # mine till block 9 (epoch)
        for i in range(3):
            self.nodes[0].setmocktime(mocktime)
            mocktime=mocktime+timeBetweenBlocksInSeconds
            self.nodes[0].generate(1)
            mining_info = self.nodes[0].getmininginfo()
            assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0000000596046448'))
        assert_equal(mining_info['blocks'], 9)
        assert_approx(mining_info['powreward'], 3.422313)

        # mine block 10 (epoch calculation) and difficulty change
        self.nodes[0].setmocktime(mocktime)
        mocktime=mocktime+timeBetweenBlocksInSeconds
        self.nodes[0].generate(1)
        mining_info = self.nodes[0].getmininginfo()
        balance=self.nodes[0].getbalance()
        assert_equal(mining_info['blocks'], 10)
        assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0000000380457032'))
        assert_approx(mining_info['powreward'], 3.422313)
        assert_equal(balance,Decimal('50000000'))

        # mine block 15 (pow reward available)
        for i in range(5):
            self.nodes[0].setmocktime(mocktime)
            mocktime=mocktime+timeBetweenBlocksInSeconds
            self.nodes[0].generate(1)            
        mining_info = self.nodes[0].getmininginfo()
        balance=self.nodes[0].getbalance()
        assert_equal(mining_info['blocks'], 15)
        assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0000000380457032'))
        assert_approx(balance,90000003.422313)

if __name__ == '__main__':
    MiningTest().main()
