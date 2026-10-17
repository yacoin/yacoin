#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the epoch block reward.

Mine 39 blocks with epochinterval=10 and check the block value and
difficulty after every block and the money supply after each epoch.
"""

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_approx,
)


class EpochTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK
        self.blocks_mined = 0
        self.block_fork_1_0 = 1
        
    def setmocktimeforallnodes(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks(self, nodeId, numberOfBlocks, blockvalue, moneysupplyAtEnd, difficulty):
        timeBetweenBlocks = 120
        for _ in range(numberOfBlocks):            
            self.log.info("Mining block "+str(self.blocks_mined+1))
            self.setmocktimeforallnodes(self.mocktime)
            self.mocktime=self.mocktime+timeBetweenBlocks            
            self.nodes[nodeId].generate(1)
            self.blocks_mined += 1
            info = self.nodes[nodeId].getinfo()
            self.log.info("moneysupply "+str(info['moneysupply']))
            mininginfo = self.nodes[nodeId].getmininginfo()
            assert_equal(mininginfo['blockvalue'], blockvalue) # use blockvalue instead of powreward for checking
            assert_approx(mininginfo['difficulty'],difficulty, vspan=1E-12)            
            self.log.info(str(self.blocks_mined)+ " Difficulty "+str(mininginfo['difficulty']))
        info = self.nodes[nodeId].getinfo()
        assert_equal(int(info['moneysupply']*1000000),moneysupplyAtEnd)
        self.sync_all()

    def run_test(self):
        self.mine_blocks(0, 9, 3802570, 100000034223130, 5.96046448E-8)
        self.mine_blocks(0, 10, 3802571, 100000072248840, 3.80457032E-8)
        self.mine_blocks(0, 10, 3802573, 100000110274570, 1.98682149E-8)
        self.mine_blocks(0, 10, 3802574, 100000148300310, 1.98682149E-8)        

if __name__ == '__main__':
    EpochTest().main()
