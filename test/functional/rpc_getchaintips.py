#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the getchaintips RPC.

- introduce a network split
- work on chains of different lengths
- join the network together again
- verify that getchaintips now returns two chain tips.
- invalidate the tip: its entry is "invalid"
- a side block that was never connected: "valid-headers"
"""

from test_framework.blocktools import create_block_yac, solve_block
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, disconnect_nodes, node_peers, wait_until

class GetChainTipsTest (BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4

    def run_test(self):
        tips = self.nodes[0].getchaintips()
        assert_equal(len(tips), 1)
        assert_equal(tips[0]['branchlen'], 0)
        assert_equal(tips[0]['height'], 41)
        assert_equal(tips[0]['status'], 'active')

        # Split the network and build two chains of different lengths.
        self.split_network()
        self.nodes[0].generatetoaddress(5, self.nodes[0].get_deterministic_priv_key().address)
        self.nodes[2].generatetoaddress(10, self.nodes[2].get_deterministic_priv_key().address)
        self.sync_all(self.nodes[:2])
        self.sync_all(self.nodes[2:])

        tips = self.nodes[1].getchaintips ()
        assert_equal (len (tips), 1)
        shortTip = tips[0]
        assert_equal (shortTip['branchlen'], 0)
        assert_equal (shortTip['height'], 46)
        assert_equal (tips[0]['status'], 'active')

        tips = self.nodes[3].getchaintips ()
        assert_equal (len (tips), 1)
        longTip = tips[0]
        assert_equal (longTip['branchlen'], 0)
        assert_equal (longTip['height'], 51)
        assert_equal (tips[0]['status'], 'active')

        # Join the network halves and check that we now have two tips
        # (at least at the nodes that previously had the short chain).
        self.join_network ()

        tips = self.nodes[0].getchaintips ()
        assert_equal (len (tips), 2)
        assert_equal (tips[0], longTip)

        assert_equal (tips[1]['branchlen'], 5)
        assert_equal (tips[1]['status'], 'valid-fork')
        tips[1]['branchlen'] = 0
        tips[1]['status'] = 'active'
        assert_equal (tips[1], shortTip)

        node = self.nodes[0]
        disconnect_nodes(node, 1)
        wait_until(lambda: node_peers(node) == [])

        self.log.info("An invalidated tip is listed as invalid")
        node.invalidateblock(longTip['hash'])
        hash50 = node.getblockhash(50)
        assert_equal(node.getbestblockhash(), hash50)

        self.log.info("A side block that was never connected is listed as valid-headers")
        # On block 48: less work than the active chain, so it stays a side block.
        side = solve_block(node, create_block_yac(node, prev=node.getblockhash(48)))
        assert_equal(node.submitblock(side.serialize().hex()), "inconclusive")

        expected = [
            {'height': 51, 'hash': longTip['hash'], 'branchlen': 1, 'status': 'invalid'},
            {'height': 50, 'hash': hash50, 'branchlen': 0, 'status': 'active'},
            {'height': 49, 'hash': side.hash, 'branchlen': 1, 'status': 'valid-headers'},
            {'height': 46, 'hash': shortTip['hash'], 'branchlen': 5, 'status': 'valid-fork'},
        ]
        assert_equal(sorted(node.getchaintips(), key=lambda t: (-t['height'], t['hash'])), expected)

if __name__ == '__main__':
    GetChainTipsTest ().main ()
