#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getmininginfo and getsubsidy while mining.

Check the block count, block size, N, N-factor, difficulty and PoW reward
fields, and the wallet balance growing with mature coinbases. Then:
- getsubsidy() is the next coinbase value; after the fork its argument is
  ignored, and it isn't checked (known failure R-26); argument errors.
- Before the fork (a node with a later fork height) the reward follows the
  target given.
- getmininginfo's mempool and last-template fields and the rest of its
  keys, which its help doesn't document (known failure R-22).
"""

from decimal import Decimal

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_approx,
    assert_greater_than,
    assert_raises_rpc_error,
    connect_nodes,
)

BUG_CARD = "IvbXjqbT"


class MiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        # node2: a later fork height, for getsubsidy before the fork. It has
        # another consensus, so it stays unconnected.
        self.extra_args = [[], [], ['-testnetNewLogicBlockNumber=1000']]
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime=TIME_GENESIS_BLOCK

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[1], 0)

    def setmocktimeforallnodes(self, mocktime):
        self.mocktime = mocktime
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks_init(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        self.setmocktimeforallnodes(self.mocktime)
        self.mocktime=self.mocktime+timeBetweenBlocks+timeBetweenBlocks*numberOfBlocks      
        self.nodes[nodeId].generate(numberOfBlocks)
        self.sync_all(self.nodes[:2])

    def mine_blocks(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        for _ in range(numberOfBlocks):
            self.setmocktimeforallnodes(self.mocktime)
            self.mocktime=self.mocktime+timeBetweenBlocks      
            self.nodes[nodeId].generate(1)
        self.sync_all(self.nodes[:2])

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
            assert_equal(mining_info['difficulty'], Decimal('7.774596252921252E-08'))
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
            assert_equal(mining_info['difficulty'], Decimal('7.774596252921252E-08'))
        assert_equal(mining_info['blocks'], 29)
        assert_approx(mining_info['powreward'], 3.8025705377)

        # mine block 10 (epoch calculation) and difficulty change
        self.mine_blocks(0, 1)
        mining_info = self.nodes[0].getmininginfo()
        balance=self.nodes[0].getbalance()
        assert_equal(mining_info['blocks'], 30)
        assert_equal(mining_info['difficulty'], Decimal('7.774596252921252E-08'))
        assert_approx(mining_info['powreward'], 3.8025705377)
        assert_approx(float(balance), 95.064278)

        # mine block 15 (pow reward available)
        self.mine_blocks(0, 5)
        mining_info = self.nodes[0].getmininginfo()
        balance=self.nodes[0].getbalance()
        assert_equal(mining_info['blocks'], 35)
        assert_equal(mining_info['difficulty'], Decimal('7.774596252921252E-08'))
        assert_approx(balance, 114.077144)

        self.test_getsubsidy()
        self.test_getsubsidy_before_fork()
        self.test_getmininginfo_fields()

    def test_getsubsidy(self):
        self.log.info("getsubsidy is the next coinbase value; its argument is ignored after the fork")
        node = self.nodes[0]
        subsidy = node.getsubsidy()
        self.mine_blocks(0, 1)
        coinbase = node.getrawtransaction(node.getblock(node.getbestblockhash())['tx'][0], 1)
        assert_equal(coinbase['vout'][0]['value'] * COIN, subsidy)
        subsidy = node.getsubsidy()
        for target in ('00' * 32, 'ff' * 32, '00000fff' + '00' * 28):
            assert_equal(node.getsubsidy(target), subsidy)
        self.known_failure("R-26 (%s)" % BUG_CARD,
                           lambda: assert_raises_rpc_error(-8, None, node.getsubsidy, 'zz'),
                           expected="No exception raised")
        assert_raises_rpc_error(-1, "JSON value is not a string as expected", node.getsubsidy, 1)
        assert_raises_rpc_error(-1, "getsubsidy [ntarget]", node.getsubsidy, '00', '00')

    def test_getsubsidy_before_fork(self):
        self.log.info("Before the fork the reward follows the target")
        node = self.nodes[2]
        node.generate(3)
        subsidy = node.getsubsidy()
        coinbase = node.getrawtransaction(node.getblock(node.generate(1)[0])['tx'][0], 1)
        assert_equal(coinbase['vout'][0]['value'] * COIN, subsidy)
        assert_equal(node.getsubsidy('00ffff' + '00' * 29), 56120000)
        assert_equal(node.getsubsidy('00000fff' + '00' * 28), 14030000)
        assert_equal(node.getsubsidy('0000000fff' + '00' * 27), 5560000)
        # capped at MAX_MINT_PROOF_OF_WORK (100 YAC)
        assert_equal(node.getsubsidy('ff' * 32), 100 * COIN)

    def test_getmininginfo_fields(self):
        self.log.info("getmininginfo: mempool, last template and the other fields")
        node = self.nodes[0]
        address = self.nodes[1].getnewaddress()
        for _ in range(2):
            node.sendtoaddress(address, 1)
        info = node.getmininginfo()
        assert_equal(info['pooledtx'], 2)
        assert_equal(info['pooledtx'], len(node.getrawmempool()))
        self.mine_blocks(0, 1)
        info = node.getmininginfo()
        assert_equal(info['pooledtx'], 0)
        # currentblocktx/currentblocksize describe the last block template
        # built (here the one generate used)
        assert_equal(info['currentblocktx'], 2)
        assert_greater_than(info['currentblocksize'], 1000)
        assert_equal((info['chain'], info['errors']), ('main', ''))
        assert_equal((info['Epoch Interval'], info['Difficulty Interval']), (10, 10))
        assert_greater_than(info['netmhashps'], 0)
        assert_equal(info['blockvalue'], int(info['powreward'] * COIN))
        help_text = node.help('getmininginfo')
        self.known_failure("R-22 (%s)" % BUG_CARD,
                           lambda: self.assert_documented(info, help_text),
                           expected="not in help")

    @staticmethod
    def assert_documented(info, help_text):
        missing = [key for key in sorted(info) if '"%s"' % key not in help_text]
        assert not missing, "getmininginfo keys not in help: %s" % missing

if __name__ == '__main__':
    MiningTest().main()
