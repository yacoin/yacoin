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

    def mine_blocks_init(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        self.setmocktimeforallnodes(self.mocktime)
        self.mocktime=self.mocktime+timeBetweenBlocks+timeBetweenBlocks*numberOfBlocks      
        self.nodes[nodeId].generate(numberOfBlocks)
        self.sync_all()

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
        self.log_accounts("init")
        self.mine_blocks_init(0, 20)
        self.mine_blocks(0, 10)
        self.mine_blocks(1, 10)
        # assert_equal(self.nodes[0].getblockcount(), 20)
        # assert_equal(self.nodes[1].getblockcount(), 20)
        
        balance_0 = self.nodes[0].getbalance()
        balance_1 = self.nodes[1].getbalance()
        assert(balance_0 > 10)
        self.log.info('Balances after initial mining')
        self.log.info('Balance node 0: '+str(balance_0))
        self.log.info('Balance node 1: '+str(balance_1))
        
        csv_info = self.nodes[1].createcsvaddress(1200, False, 'csv_1')
        csv_address = csv_info['csv address']
        csv_redeemscript = csv_info['redeemScript']
        testaddress=self.nodes[1].getaddressesbyaccount('csv_1')[0]
        assert_equal(testaddress, csv_address)
        balance_csv_1 = self.nodes[1].getreceivedbyaccount('csv_1')
        assert_equal(balance_csv_1, Decimal('0.0000'))

        transaction_id = self.nodes[0].sendtoaddress(csv_address, 10.0)
        assert_equal(int(self.nodes[0].gettransaction(transaction_id)['version']), 2)
        self.mine_blocks(0,10)
        # assert_equal(self.nodes[0].getblockcount(), 30)
        # assert_equal(self.nodes[1].getblockcount(), 30)
        
        received_coins = self.nodes[1].getreceivedbyaccount('csv_1')
        assert_equal(received_coins, Decimal('10.0'))

        receiver_address = self.nodes[0].getnewaddress('receiver')
        receiver_balance = self.nodes[0].getreceivedbyaccount('receiver')
        assert_equal(receiver_balance, Decimal('0.0'))

        assert_raises_rpc_error(-1, "unknown!?", self.nodes[1].spendcsv,csv_address, receiver_address, 10.0)

        self.mine_blocks(0, 10)
        self.mine_blocks(1, 10)

        self.log_accounts("before spendcsv")
        transaction_id_csv = self.nodes[1].spendcsv(csv_address, receiver_address, 2.0)
        tx_details = self.nodes[1].gettransaction(transaction_id_csv)
        self.log.info(str(tx_details))
        assert_equal(tx_details['vout'][1]['scriptPubKey']['addresses'][0], receiver_address)
        assert_equal(tx_details['confirmations'], Decimal('0'))
        assert_equal(tx_details['version'], 2)

        self.mine_blocks(1, 10)
        self.log_accounts("after spendcsv")

        tx_details = self.nodes[1].gettransaction(transaction_id_csv)
        self.log.info(str(tx_details))
        assert_equal(tx_details['confirmations'], Decimal('10'))

        receiver_balance = self.nodes[0].getreceivedbyaccount('receiver')
        self.log.info('Receiver balance: '+str(receiver_balance))

        balance_csv_1 = self.nodes[1].getreceivedbyaccount('csv_1')
        self.log.info('csv_1 balance: '+str(balance_csv_1))

        assert_equal(receiver_balance, Decimal('2.0'))

if __name__ == '__main__':
    OP_CSV_Test().main()
