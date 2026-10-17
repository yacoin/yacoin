#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test connection limits, -addnode, -connect and the addnode RPC.

- Inbound slots are -maxconnections minus min(16, -maxconnections)
  outbound slots minus 1 feeler slot: -maxconnections 17, 8 and 0 accept
  no inbound peer at all, 18 accepts one and 19 two. With fewer than 21 inbound peers every peer is
  protected from eviction, so the new connection is dropped, whitelisted
  or not. Manual outbound connections still work.
- -addnode connects at startup and is listed by getaddednodeinfo; the
  addnode RPC refuses a second add and a remove of an unknown node; an
  added name that isn't connected.
- -connect connects only to the given node and reconnects after a
  disconnect; -connect=0 starts no automatic-connection thread, so
  -seednode is not used either.
"""

from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    p2p_port,
    peers,
    wait_until,
)


class ProbePeer(P2PInterface):
    """Records whether the TCP connection was opened and closed."""
    def __init__(self):
        super().__init__()
        self.opened = False
        self.closed = False

    def on_open(self):
        self.opened = True

    def on_close(self):
        self.closed = True


class ConnectionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()

    def assert_inbound_refused(self, node):
        with node.assert_debug_log(["failed to find an eviction candidate - connection dropped (full)"]):
            peer = node.add_p2p_connection(ProbePeer(), wait_for_verack=False)
            wait_until(lambda: peer.opened and peer.closed, timeout=10, lock=mininode_lock)

    def run_test(self):
        self.addr1 = "127.0.0.1:%d" % p2p_port(1)
        self.test_inbound_limit()
        self.test_addnode()
        self.test_connect()

    def test_inbound_limit(self):
        node = self.nodes[0]
        # Card iQg6oeoK item 3: with 16 outbound slots and 1 feeler slot,
        # -maxconnections of 17 or less leaves no inbound slot.
        for max_connections in [17, 8, 0]:
            self.log.info("-maxconnections=%d: no inbound connection" % max_connections)
            self.restart_node(0, ["-maxconnections=%d" % max_connections])
            self.assert_inbound_refused(node)
            assert_equal(peers(node), [])

        for max_connections in [18, 19]:
            slots = max_connections - 17
            self.log.info("-maxconnections=%d: %d inbound slot(s)" % (max_connections, slots))
            self.restart_node(0, ["-maxconnections=%d" % max_connections])
            for _ in range(slots):
                node.add_p2p_connection(P2PInterface())
            # Too few peers for eviction: all of them are protected.
            self.assert_inbound_refused(node)
            assert_equal(len(peers(node)), slots)
            node.disconnect_p2ps()

        self.log.info("Whitelisted peers get no inbound slot either")
        self.restart_node(0, ["-maxconnections=17", "-whitelist=127.0.0.1"])
        self.assert_inbound_refused(node)

        self.log.info("Manual outbound connections work at -maxconnections=0")
        self.restart_node(0, ["-maxconnections=0"])
        # onetry connects within the RPC call
        node.addnode(self.addr1, "onetry")
        peer = peers(node)
        assert_equal(len(peer), 1)
        assert_equal((peer[0]['addr'], peer[0]['inbound']), (self.addr1, False))
        # A onetry connection isn't marked as an addnode connection.
        assert_equal(peer[0]['addnode'], False)

    def test_addnode(self):
        node = self.nodes[0]
        self.log.info("-addnode connects at startup")
        self.restart_node(0, ["-addnode=%s" % self.addr1])
        wait_until(lambda: len(peers(node)) == 1, timeout=10)
        peer = peers(node)[0]
        assert_equal((peer['addr'], peer['inbound'], peer['addnode']), (self.addr1, False, True))
        assert_equal(node.getaddednodeinfo(), [{
            'addednode': self.addr1,
            'connected': True,
            'addresses': [{'address': self.addr1, 'connected': 'outbound'}],
        }])
        assert_equal(node.getaddednodeinfo(self.addr1), node.getaddednodeinfo())

        self.log.info("addnode add/remove errors")
        assert_raises_rpc_error(-23, "Error: Node already added", node.addnode, self.addr1, "add")
        assert_equal(node.addnode(self.addr1, "remove"), None)
        assert_equal(node.getaddednodeinfo(), [])
        # Removing it from the list keeps the connection.
        assert_equal(len(peers(node)), 1)
        assert_raises_rpc_error(-24, "Error: Node has not been added.", node.addnode, self.addr1, "remove")

        self.log.info("An added name that isn't connected")
        # Nothing listens on this port, so the name stays unconnected.
        name = "localhost:%d" % p2p_port(2)
        node.addnode(name, "add")
        assert_equal(node.getaddednodeinfo(), [{'addednode': name, 'connected': False, 'addresses': []}])
        node.addnode(name, "remove")

    def test_connect(self):
        node = self.nodes[0]
        self.log.info("-connect connects only to the given node")
        self.restart_node(0, ["-connect=%s" % self.addr1])
        wait_until(lambda: len(peers(node)) == 1, timeout=10)
        peer = peers(node)[0]
        assert_equal((peer['addr'], peer['inbound'], peer['addnode']), (self.addr1, False, False))
        assert_equal(node.getaddednodeinfo(), [])

        self.log.info("-connect reconnects after a disconnect")
        node.disconnectnode(nodeid=peer['id'])
        wait_until(lambda: [p['id'] for p in peers(node)] not in ([], [peer['id']]), timeout=10)
        assert_equal([(p['addr'], p['inbound']) for p in peers(node)], [(self.addr1, False)])

        self.log.info("-connect still listens (bind=127.0.0.1 in yacoin.conf)")
        # The framework's yacoin.conf has bind=127.0.0.1, which sets
        # -listen=1 before -connect could turn it off.
        node.add_p2p_connection(P2PInterface())
        assert_equal(peers(node)[-1]['inbound'], True)
        node.disconnect_p2ps()

        self.log.info("-connect=0 starts no automatic connections, so -seednode is unused")
        with node.assert_debug_log(["addcon thread start"], unexpected_msgs=["opencon thread start"]):
            self.restart_node(0, ["-connect=0", "-seednode=%s" % self.addr1])
        assert_equal(peers(node), [])


if __name__ == '__main__':
    ConnectionsTest().main()
