#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test sending and receiving coins 
"""

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


class BasicTransfer_Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK
        
    def setmocktimeforallnodes(self, mocktime):
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
        node_1_accounts = self.nodes[1].listaccounts()
        self.log.info('List accounts 0 '+description+': '+str(node_0_accounts))
        self.log.info('List accounts 1 '+description+': '+str(node_1_accounts))

    def run_test(self):
        address_0 = self.nodes[0].getaccountaddress('')
        address_1 = self.nodes[1].getaccountaddress('')
        self.log.info('Address 0: '+str(address_0))
        self.log.info('Address 1: '+str(address_1))

        self.mine_blocks(0, 10)
        assert_equal(self.nodes[0].getblockcount(), 10)
        assert_equal(self.nodes[1].getblockcount(), 10)
        
        balance_0 = self.nodes[0].getbalance()
        balance_1 = self.nodes[1].getbalance()
        assert_equal(balance_0, Decimal('50000000.0'))
        assert_equal(balance_1, Decimal('0.0'))

        self.log.info('Balances after initial mining')
        self.log.info('Balance node 0: '+str(balance_0))
        self.log.info('Balance node 1: '+str(balance_1))
        self.log_accounts("after 10")

        transaction_id = self.nodes[0].sendtoaddress(address_1, 100.0)
        tx_details = self.nodes[0].gettransaction(transaction_id)
        self.log.info(str(tx_details))
        assert_equal(tx_details['vout'][1]['value'],Decimal('100.0'))
        assert_equal(tx_details['vout'][1]['scriptPubKey']['addresses'][0],address_1)
        assert_equal(tx_details['confirmations'],Decimal('0'))
                
        self.mine_blocks(0, 10)        
        self.log_accounts("after 20")
        assert_equal(self.nodes[0].getblockcount(), 20)
        balance_0 = self.nodes[0].getbalance()
        balance_1 = self.nodes[1].getbalance()
        assert_approx(balance_0, 89999920.523877)
        assert_equal(balance_1, Decimal('100.0'))
        node_0_accounts = self.nodes[0].listaccounts()
        node_1_accounts = self.nodes[1].listaccounts()
        assert_equal(node_0_accounts[''],balance_0)
        assert_equal(node_1_accounts[''],balance_1)

        tx_details = self.nodes[0].gettransaction(transaction_id)
        self.log.info(str(tx_details))
        assert_equal(tx_details['confirmations'],Decimal('10'))
        

if __name__ == '__main__':
    BasicTransfer_Test().main()
