#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test inbound eviction when all inbound slots are taken.

Adapted from Bitcoin Core's p2p_eviction.py. With -maxconnections=40 the
node has 23 inbound slots (16 outbound and 1 feeler slot). When a 24th
peer connects, the node protects 4 peers by network group, 8 by lowest
minimum ping, 4 that last sent a transaction, 4 that last sent a block
and half of the rest by connection time, and evicts one of the others.

All peers are on loopback, so they share one network group and the 4
protected by it are arbitrary; the test only checks that the evicted peer
is none of the block, transaction and fast-ping peers.
"""

from decimal import Decimal
import time

from test_framework.blocktools import blocks_from_node
from test_framework.messages import CTransaction, FromHex, msg_block, msg_pong, msg_tx
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
    peers,
    wait_until,
)

INBOUND_SLOTS = 40 - 16 - 1


class SlowP2PInterface(P2PInterface):
    def on_ping(self, message):
        time.sleep(0.1)
        self.send_message(msg_pong(message.nonce))


class EvictionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-maxconnections=40"], []]

    def setup_network(self):
        # node1 is a donor of blocks, connected only to share the chain.
        self.setup_nodes()

    def run_test(self):
        node, donor = self.nodes
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        wait_until(lambda: node.getconnectioncount() == 0)
        blocks = blocks_from_node(donor, donor.generate(4))

        # Transactions from node0's wallet, signed but not broadcast.
        txs = []
        address = node.getnewaddress()
        for utxo in node.listunspent()[:4]:
            raw = node.createrawtransaction([{"txid": utxo['txid'], "vout": utxo['vout']}],
                                            {address: utxo['amount'] - Decimal('0.1')})
            txs.append(FromHex(CTransaction(), node.signrawtransaction(raw)['hex']))

        protected = set()
        self.log.info("4 peers that send a block")
        for block in blocks:
            peer = node.add_p2p_connection(SlowP2PInterface())
            peer.send_and_ping(msg_block(block))
            protected.add(len(node.p2ps) - 1)
        assert_equal(node.getbestblockhash(), blocks[-1].hash)

        self.log.info("5 slow-pinging peers, eviction candidates")
        for _ in range(5):
            node.add_p2p_connection(SlowP2PInterface())

        self.log.info("4 peers that send a transaction")
        for tx in txs:
            peer = node.add_p2p_connection(SlowP2PInterface())
            peer.send_and_ping(msg_tx(tx))
            protected.add(len(node.p2ps) - 1)
        assert_equal(len(node.getrawmempool()), 4)

        self.log.info("8 peers with fast pings")
        for _ in range(8):
            peer = node.add_p2p_connection(P2PInterface())
            wait_until(lambda: "ping" in peer.last_message, timeout=10, lock=mininode_lock)

        self.log.info("Fill the remaining inbound slots with slow peers")
        while len(node.p2ps) < INBOUND_SLOTS:
            node.add_p2p_connection(SlowP2PInterface())
        peer_info = peers(node)
        assert_equal(len(peer_info), INBOUND_SLOTS)

        # The 8 lowest minimum pings, as the node sees them (getpeerinfo
        # lists the peers in connection order). A peer without a pong yet
        # counts as the slowest.
        pings = [p.get('minping', Decimal(10 ** 6)) for p in peer_info]
        for i in sorted(range(len(pings)), key=lambda i: pings[i])[:8]:
            protected.add(i)

        self.log.info("One more peer: one unprotected peer is evicted")
        with node.assert_debug_log([], unexpected_msgs=["failed to find an eviction candidate"]):
            node.add_p2p_connection(SlowP2PInterface())
        wait_until(lambda: len([p for p in node.p2ps if not p.is_connected]) == 1, timeout=10)
        evicted = [i for i, p in enumerate(node.p2ps) if not p.is_connected]
        self.log.debug("evicted peer %s, protected peers %s" % (evicted, sorted(protected)))
        assert evicted[0] not in protected, (evicted, sorted(protected))
        assert_equal(len(peers(node)), INBOUND_SLOTS)


if __name__ == '__main__':
    EvictionTest().main()
