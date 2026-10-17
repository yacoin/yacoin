#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test p2p mempool message.

Test that a peer sending a mempool message is disconnected. The node never
offers NODE_BLOOM, so this applies to every peer that isn't whitelisted.
"""

from test_framework.messages import msg_mempool
from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, peers

class P2PMempoolTests(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        # Add a p2p connection
        self.nodes[0].add_p2p_connection(P2PInterface())

        #request mempool
        self.nodes[0].p2p.send_message(msg_mempool())
        self.nodes[0].p2p.wait_for_disconnect()

        #mininode must be disconnected at this point
        assert_equal(len(peers(self.nodes[0])), 0)

if __name__ == '__main__':
    P2PMempoolTests().main()
