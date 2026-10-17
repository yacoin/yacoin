#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test restarting the node with -reindex and -reindex-fast.

- Start a single node and generate 3 blocks.
- Restart it with -reindex and wait until it is back at its block count.
- Generate 3 more and restart it with -reindex-fast; repeat both once more.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import wait_until

class ReindexTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.block_fork_1_0 = 1

    def reindex(self, fast=False):
        self.nodes[0].generatetoaddress(3, self.nodes[0].get_deterministic_priv_key().address)
        blockcount = self.nodes[0].getblockcount()
        self.stop_nodes()
        extra_args = [["-reindex-fast" if fast else "-reindex"]]
        self.start_nodes(extra_args)
        wait_until(lambda: self.nodes[0].getblockcount() == blockcount)
        self.log.info("Success")

    def run_test(self):
        self.reindex(False)
        self.reindex(True)
        self.reindex(False)
        self.reindex(True)

if __name__ == '__main__':
    ReindexTest().main()
