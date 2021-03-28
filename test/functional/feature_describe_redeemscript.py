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
import re
from decimal import Decimal

from test_framework.blocktools import (
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


class OP_CSV_Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK

    def setmocktimeforallnodes(self, mocktime):
        self.mocktime = mocktime
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        for i in range(numberOfBlocks):
            self.setmocktimeforallnodes(self.mocktime)
            self.mocktime=self.mocktime+timeBetweenBlocks      
            self.nodes[nodeId].generate(1)
        self.sync_all()

    def log_accounts(self, description):
        node_0_accounts = self.nodes[0].listaccounts()
        node_1_accounts = self.nodes[0].listaccounts()
        self.log.info('List accounts 0 '+description+': '+str(node_0_accounts))
        self.log.info('List accounts 1 '+description+': '+str(node_1_accounts))

    def run_test(self):
        self.setmocktimeforallnodes(TIME_GENESIS_BLOCK)
        csv_info = self.nodes[0].createcsvaddress(1200, False, 'csv_1')
        csv_address = csv_info['csv address']
        csv_redeemscript = csv_info['redeemScript']
        testaddress=self.nodes[0].getaddressesbyaccount('csv_1')[0]
        assert_equal(testaddress, csv_address)
        balance = self.nodes[0].getreceivedbyaccount('csv_1')
        assert_equal(balance, Decimal('0.0000'))
        description = self.nodes[0].describeredeemscript(csv_redeemscript)
        self.log.info(str(description))
        assert_equal(description['RedeemScript hex'], csv_redeemscript)        
        assert_equal(description['csv address'], csv_address)
        assert_equal(description['Lock type'], 'Time-based lock')
        nlocktime = int(re.match('(\d+) ', description['RedeemScript format']).groups()[0])
        assert_equal(nlocktime>>31,0)
        assert_equal(nlocktime>>30,1)
        assert_equal(nlocktime & 0x3fffffff, 1200)

        csv_info = self.nodes[0].createcsvaddress(100, True, 'csv_2')
        csv_address = csv_info['csv address']
        csv_redeemscript = csv_info['redeemScript']
        testaddress=self.nodes[0].getaddressesbyaccount('csv_2')[0]
        assert_equal(testaddress, csv_address)
        balance = self.nodes[0].getreceivedbyaccount('csv_2')
        assert_equal(balance, Decimal('0.0000'))
        description = self.nodes[0].describeredeemscript(csv_redeemscript)
        self.log.info(str(description))
        assert_equal(description['RedeemScript hex'], csv_redeemscript)        
        assert_equal(description['csv address'], csv_address)
        assert_equal(description['Lock type'], 'Block-based lock')
        nlocktime = int(re.match('(\d+) ', description['RedeemScript format']).groups()[0])
        assert_equal(nlocktime>>31,0)
        assert_equal(nlocktime>>30,0)
        assert_equal(nlocktime & 0x3fffffff, 100)

        cltv_info = self.nodes[0].createcltvaddress(TIME_GENESIS_BLOCK+1200, 'cltv_1')
        cltv_address = cltv_info['cltv address']
        cltv_redeemscript = cltv_info['redeemScript']
        testaddress=self.nodes[0].getaddressesbyaccount('cltv_1')[0]
        assert_equal(testaddress, cltv_address)
        balance = self.nodes[0].getreceivedbyaccount('cltv_1')
        assert_equal(balance, Decimal('0.0000'))
        description = self.nodes[0].describeredeemscript(cltv_redeemscript)
        self.log.info(str(description))        
        assert_equal(description['RedeemScript hex'], cltv_redeemscript)
        assert_equal(description['cltv address'], cltv_address)
        assert_equal(description['Lock type'], 'Time-based lock')
        nlocktime = int(re.match('(\d+) ', description['RedeemScript format']).groups()[0])
        assert_equal(nlocktime, TIME_GENESIS_BLOCK+1200)

        cltv_info = self.nodes[0].createcltvaddress(1000, 'cltv_2')
        cltv_address = cltv_info['cltv address']
        cltv_redeemscript = cltv_info['redeemScript']
        testaddress=self.nodes[0].getaddressesbyaccount('cltv_2')[0]
        assert_equal(testaddress, cltv_address)
        balance = self.nodes[0].getreceivedbyaccount('cltv_2')
        assert_equal(balance, Decimal('0.0000'))
        description = self.nodes[0].describeredeemscript(cltv_redeemscript)
        self.log.info(str(description))
        assert_equal(description['RedeemScript hex'], cltv_redeemscript)        
        assert_equal(description['cltv address'], cltv_address)
        assert_equal(description['Lock type'], 'Block-based lock')
        nlocktime = int(re.match('(\d+) ', description['RedeemScript format']).groups()[0])
        assert_equal(nlocktime, 1000)

if __name__ == '__main__':
    OP_CSV_Test().main()
