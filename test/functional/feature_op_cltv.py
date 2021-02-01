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


class OP_CLTV_Test(BitcoinTestFramework):
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

    def run_test(self):
        self.mine_blocks_init(0, 20)
        self.mine_blocks(0, 10)
        # assert_equal(self.nodes[0].getblockcount(), 30)
        # assert_equal(self.nodes[1].getblockcount(), 30)
        self.mine_blocks(1, 10)
        # assert_equal(self.nodes[0].getblockcount(), 40)
        # assert_equal(self.nodes[1].getblockcount(), 40)
        
        balance_0 = self.nodes[0].getbalance()
        balance_1 = self.nodes[1].getbalance()
        assert(balance_0 > 10)
        self.log.info('Balances after initial mining')
        self.log.info('Balance node 0: '+str(balance_0))
        self.log.info('Balance node 1: '+str(balance_1))
        
        cltv_info = self.nodes[1].createcltvaddress(TIME_GENESIS_BLOCK+60*60, 'cltv_1')
        cltv_address = cltv_info['cltv address']
        cltv_redeemscript = cltv_info['redeemScript']
        testaddress=self.nodes[1].getaddressesbyaccount('cltv_1')[0]
        assert_equal(testaddress, cltv_address)
        balance_cltv_1 = self.nodes[1].getreceivedbyaccount('cltv_1')
        assert_equal(balance_cltv_1, Decimal('0.0000'))

        transaction_id = self.nodes[0].sendtoaddress(cltv_address, 10.0)
        assert_equal(int(self.nodes[0].gettransaction(transaction_id)['version']), 2)
        self.mine_blocks(0,10)
        # assert_equal(self.nodes[0].getblockcount(), 50)
        # assert_equal(self.nodes[1].getblockcount(), 50)
        
        received_coins = self.nodes[1].getreceivedbyaccount('cltv_1')
        assert_equal(received_coins, Decimal('10.0'))

        receiver_address = self.nodes[0].getnewaddress('receiver')
        receiver_balance = self.nodes[0].getreceivedbyaccount('receiver')
        assert_equal(receiver_balance, Decimal('0.0'))

        assert_raises_rpc_error(-1, "unknown!?", self.nodes[1].spendcltv,cltv_address, receiver_address, 10.0)

        self.setmocktimeforallnodes(TIME_GENESIS_BLOCK + 60*60+1)
        self.mine_blocks(0, 1)
        # assert_equal(self.nodes[0].getblockcount(), 51)
        # assert_equal(self.nodes[1].getblockcount(), 51)

        transaction_id_cltv = self.nodes[1].spendcltv(cltv_address, receiver_address, 2.0)
        tx_details = self.nodes[1].gettransaction(transaction_id_cltv)
        assert_equal(tx_details['vout'][1]['scriptPubKey']['addresses'][0], receiver_address)
        assert_equal(tx_details['confirmations'], Decimal('0'))
        assert_equal(tx_details['version'], 2)

        self.mine_blocks(1, 10)
        self.mine_blocks(0, 10)
        tx_details = self.nodes[1].gettransaction(transaction_id_cltv)
        assert_equal(tx_details['confirmations'], Decimal('20'))

        receiver_balance = self.nodes[0].getreceivedbyaccount('receiver')
        assert_equal(receiver_balance, Decimal('2.0'))

if __name__ == '__main__':
    OP_CLTV_Test().main()
