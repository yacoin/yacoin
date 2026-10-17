#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A banned node can't connect; -whitelist lets it.

YACoin shows -whitelist as getpeerinfo's `whitelisted` flag (Core: the
`noban` permission).
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, p2p_port, peers, wait_until


class SetBanTests(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.setup_nodes()

    def inbound_whitelisted(self):
        """The whitelisted flag of node1's only peer (node0)."""
        peer, = peers(self.nodes[1])
        assert_equal(peer['inbound'], True)
        return peer['whitelisted']

    def run_test(self):
        self.log.info("Node 0 connects to node 1, not whitelisted")
        connect_nodes(self.nodes[0], 1)
        assert_equal(self.inbound_whitelisted(), False)

        self.log.info("Node 1 bans node 0, which then can't reconnect")
        self.nodes[1].setban("127.0.0.1", "add")
        wait_until(lambda: peers(self.nodes[0]) == [] and peers(self.nodes[1]) == [], timeout=10)
        with self.nodes[1].assert_debug_log(["connection from 127.0.0.1:", "dropped (banned)"], timeout=10):
            self.restart_node(1, [])
            self.nodes[0].addnode("127.0.0.1:%d" % p2p_port(1), "onetry")
        wait_until(lambda: peers(self.nodes[0]) == [], timeout=10)
        assert_equal(peers(self.nodes[1]), [])

        self.log.info("Whitelisted, node 0 can connect while banned")
        self.restart_node(1, ["-whitelist=127.0.0.1"])
        assert_equal([b['address'] for b in self.nodes[1].listbanned()], ["127.0.0.1/32"])
        connect_nodes(self.nodes[0], 1)
        assert_equal(self.inbound_whitelisted(), True)

        self.log.info("Without the ban, node 0 connects without the whitelist")
        self.nodes[1].setban("127.0.0.1", "remove")
        self.restart_node(1, [])
        connect_nodes(self.nodes[0], 1)
        assert_equal(self.inbound_whitelisted(), False)


if __name__ == '__main__':
    SetBanTests().main()
