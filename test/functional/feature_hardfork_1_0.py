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


class Hardfork_Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK
        self.block_fork_1_0 = 30
        
    def setmocktimeforallnodes(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks_once(self, nodeId, numberOfBlocksAtOnce):
        timeBetweenBlocks = 60
        self.setmocktimeforallnodes(self.mocktime)        
        self.nodes[nodeId].generate(numberOfBlocksAtOnce)
        self.mocktime=self.mocktime+timeBetweenBlocks*numberOfBlocksAtOnce
        self.sync_all()

    def mine_blocks(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        for _ in range(numberOfBlocks):
            self.setmocktimeforallnodes(self.mocktime)        
            self.nodes[nodeId].generate(1)
            self.mocktime=self.mocktime+timeBetweenBlocks
        self.sync_all()

    def log_accounts(self, description):
        node_0_accounts = self.nodes[0].listaccounts()
        node_1_accounts = self.nodes[1].listaccounts()
        self.log.info('List accounts 0 '+description+': '+str(node_0_accounts))
        self.log.info('List accounts 1 '+description+': '+str(node_1_accounts))
        self.log.info('Balance 0: '+str(self.nodes[0].getbalance()))
        self.log.info('Balance 1: '+str(self.nodes[1].getbalance()))

    def run_test(self):
        self.mine_blocks(0, self.block_fork_1_0-1)

        assert_equal(self.nodes[0].getblockcount(), self.block_fork_1_0-1)
        mininginfo = self.nodes[0].getmininginfo()
        info=self.nodes[0].getinfo()
        moneSupply_before_fork = int(info['moneysupply'])
        self.log.info(mininginfo)
        self.log.info(info)
        assert_equal(int(self.nodes[0].getbalance()), 0)

        # coinbase transaction is version 1 before fork
        blockhash=self.nodes[0].getblockhash(14)
        transactionid=self.nodes[0].getblock(blockhash)['tx'][0]
        transaction_version=self.nodes[0].gettransaction(transactionid)['version']        
        assert_equal(transaction_version, 1)        

        # FORK
        self.mine_blocks(0,1)
        assert_equal(self.nodes[0].getblockcount(), self.block_fork_1_0)
        assert_equal(self.nodes[1].getblockcount(), self.block_fork_1_0)

        blockhash=self.nodes[0].getblockhash(15)
        transactionid=self.nodes[0].getblock(blockhash)['tx'][0]
        transaction_version=self.nodes[0].gettransaction(transactionid)['version']

        # new pow reward logic after fork
        mininginfo = self.nodes[0].getmininginfo()
        info=self.nodes[0].getinfo()
        self.log.info(mininginfo)
        self.log.info(info)
        powreward = int(mininginfo['blockvalue'])
        expected_reward = int(moneSupply_before_fork*1000000 * 0.02 / (365*24*60 + 6*60))
        assert_equal(powreward, expected_reward)
        
        self.log.info("Balance after fork: "+str(self.nodes[0].getbalance()))
        self.mine_blocks(0,6)
        self.log.info("Balance after 6 blocks after fork: "+str(self.nodes[0].getbalance()))
        assert_equal(self.nodes[0].getblockcount(), self.block_fork_1_0 + 6)
        assert_equal(self.nodes[1].getblockcount(), self.block_fork_1_0 + 6)

        # coinbase transactions are v2 after fork
        blockhash=self.nodes[0].getblockhash(self.block_fork_1_0+1)
        transactionid=self.nodes[0].getblock(blockhash)['tx'][0]
        transaction_version=self.nodes[0].gettransaction(transactionid)['version']        
        assert_equal(transaction_version, 2)
        
        # regular transactions are v2 after fork
        address_1 = self.nodes[1].getaccountaddress('')
        transaction_id = self.nodes[0].sendtoaddress(address_1, 2.0)
        tx_details = self.nodes[0].gettransaction(transaction_id)
        assert_equal(tx_details['version'], 2)
        self.mine_blocks(0,1)
        assert_equal(self.nodes[1].getbalance(), Decimal('2.0'))

        # mining reward available after 6 blocks        
        self.mine_blocks(1,5)
        assert_equal(self.nodes[1].getbalance(), Decimal('2.0')) # mining reward not available yet
        self.mine_blocks(1,1)
        assert_approx(self.nodes[1].getbalance(), 5.802632)

if __name__ == '__main__':
    Hardfork_Test().main()