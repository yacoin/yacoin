#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the default P2P port of addnode.

addnode with an explicit port tries that port; without one the node uses
the default port 7688. The address is unreachable, so the test checks the
"trying connection" and "timeout" log lines.
"""

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework


class DefaultPortTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK
        self.block_fork_1_0=0
        
    def setmocktimeforallnodes(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        for _ in range(numberOfBlocks):
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
        # connect() 192.168.1.26:6688 failed after select(): Connection refused
        msgs = ["trying connection 192.168.5.5:1688", "connection to 192.168.5.5:1688 timeout"]
        with self.nodes[0].assert_debug_log(expected_msgs=msgs):
            self.nodes[0].addnode("192.168.5.5:1688","onetry")        
        
        # testing default port
        msgs = ["trying connection 192.168.5.5", "connection to 192.168.5.5:7688 timeout"]
        with self.nodes[0].assert_debug_log(expected_msgs=msgs):
            self.nodes[0].addnode("192.168.5.5","onetry")        
        

if __name__ == '__main__':
    DefaultPortTest().main()
