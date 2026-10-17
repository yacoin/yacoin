#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test addr relay, the addresses the node stores, getaddr and -seednode.

On node2:
- Stored addresses: a time of 0 is replaced by 5 days ago, addresses
  without NODE_NETWORK are dropped, and every time gets the 2 hour
  penalty for addresses learnt from a peer.
- Relay: of the addresses in an addr message with at most 10 entries,
  the routable ones younger than 10 minutes go to (at most) 2 peers; with
  only the sender and one other peer, the other peer gets all of them.
  The relayed set is checked exactly.
- A second getaddr on a connection is ignored.
- An addr message with more than 1000 entries scores 20 (Bitcoin Core's
  checks of this script are kept).
- peers.dat keeps the addresses across a restart; a corrupt peers.dat or
  banlist.dat is replaced by an empty one.
On node0 and node1 at the same time:
- -seednode: node0 connects to node1, gets addresses, and disconnects.

The node sends addr messages to a peer at random intervals (30 s on
average, not affected by mocktime), so the waits for them allow 300 s.
The nodes run with -discover=0 (no machine-dependent local addresses to
advertise) and never dial the addresses they learn: node1 and node2 with
-connect=0, node0 with a -connect to a closed local port (the one-shot
-seednode connection is still made).
"""

import os
import time

from test_framework.messages import (
    CAddress,
    NODE_NETWORK,
    msg_addr,
    msg_getaddr,
)
from test_framework.mininode import (
    P2PInterface,
    mininode_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
    peers,
    wait_until,
)

# Seconds; the node's addr timer can't be mocked.
ADDR_TIMEOUT = 300


def make_addr(ip, t, services=NODE_NETWORK, port=7688):
    addr = CAddress()
    addr.time = t
    addr.nServices = services
    addr.ip = ip
    addr.port = port
    return addr


def addr_msg(addrs):
    msg = msg_addr()
    msg.addrs = addrs
    return msg


def key(addr):
    return "%s:%d" % (addr.ip, addr.port)


class AddrReceiver(P2PInterface):
    def __init__(self):
        super().__init__()
        self.received = []

    def on_addr(self, message):
        for addr in message.addrs:
            assert_equal(addr.nServices, 1)
            self.received.append(key(addr))


class AddrTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        # The ports are known only now.
        self.extra_args = [
            ["-discover=0", "-connect=127.0.0.1:%d" % p2p_port(3)],
            ["-discover=0", "-connect=0"],
            ["-discover=0", "-connect=0"],
        ]
        self.setup_nodes()

    def run_test(self):
        self.set_mocktime(int(time.time()))
        self.now = self.mocktime
        self.start_seednode()
        self.test_stored()
        self.test_relay()
        self.test_getaddr()
        self.test_core_checks()
        self.test_persistence()
        self.finish_seednode()

    def start_seednode(self):
        node0, node1 = self.nodes[0], self.nodes[1]
        self.log.info("-seednode: node0 connects to node1 for addresses")
        source = node1.add_p2p_connection(P2PInterface())
        source.send_and_ping(addr_msg([make_addr("99.88.%d.%d" % (i // 100 + 1, i % 100 + 1), self.now - 60) for i in range(30)]))
        node1.disconnect_p2ps()
        wait_until(lambda: peers(node1) == [])
        with node1.assert_debug_log(["received: getaddr (0 bytes) peer="], timeout=30):
            self.restart_node(0, node0.extra_args + ["-seednode=127.0.0.1:%d" % p2p_port(1)])

    def finish_seednode(self):
        node0, node1 = self.nodes[0], self.nodes[1]
        self.log.info("-seednode: node0 gets addresses and disconnects")
        # node1 answers getaddr with a part of its addresses.
        wait_until(lambda: [a for a in node0.getaddrmaninfo() if a.get('address', '').startswith('99.88.')],
                   timeout=ADDR_TIMEOUT)
        wait_until(lambda: peers(node1) == [] and peers(node0) == [], timeout=30)

    def test_stored(self):
        node = self.nodes[2]
        self.log.info("Stored addresses: time 0 clamped, services 0 dropped, 2 hour penalty")
        self.src = node.add_p2p_connection(AddrReceiver())
        self.src.send_and_ping(addr_msg([
            make_addr("34.1.78.1", 0),
            make_addr("34.2.78.1", self.now - 60, services=0),
            make_addr("34.3.78.1", self.now - 600),
            make_addr("10.0.0.1", self.now - 60),
        ]))

        def stored(t):
            return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t - 2 * 60 * 60))
        result = node.getaddrmaninfo()
        assert_equal(sorted(result[:-1], key=lambda a: a['address']), [
            {'address': '34.1.78.1:7688', 'chance': 1, 'type': 'ipv4', 'time': stored(self.now - 5 * 24 * 60 * 60)},
            {'address': '34.3.78.1:7688', 'chance': 1, 'type': 'ipv4', 'time': stored(self.now - 600)},
        ])
        # The non-routable 10.0.0.1 is neither listed nor counted.
        assert_equal(result[-1], {"size: ": 2})

    def test_relay(self):
        node = self.nodes[2]
        self.log.info("Relay to the only other peer")
        recv = node.add_p2p_connection(AddrReceiver())
        # Exactly two relay candidates: the sender, which knows the
        # addresses already, and recv.
        assert_equal(len(peers(node)), 2)
        # Not relayed: more than 10 entries
        self.src.send_and_ping(addr_msg([make_addr("23.%d.67.1" % i, self.now - 60) for i in range(1, 12)]))
        # Not relayed: time 0, 10 minutes old, not routable, services 0.
        # Relayed: younger than 10 minutes.
        self.src.send_and_ping(addr_msg([
            make_addr("45.1.1.1", 0),
            make_addr("45.2.1.1", self.now - 600),
            make_addr("10.0.0.2", self.now - 60),
            make_addr("45.3.1.1", self.now - 60, services=0),
            make_addr("45.4.1.1", self.now - 599),
        ]))
        fresh = [make_addr("12.%d.34.1" % (100 + i), self.now - 60) for i in range(10)]
        self.src.send_and_ping(addr_msg(fresh))
        expected = set(key(a) for a in fresh)
        wait_until(lambda: expected <= set(recv.received), timeout=ADDR_TIMEOUT, lock=mininode_lock)
        # The queue is sent in order, so anything relayed from the earlier
        # messages would have arrived by now.
        with mininode_lock:
            assert_equal(sorted(recv.received), sorted(expected | {"45.4.1.1:7688"}))
            assert_equal(self.src.received, [])
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [])

    def test_getaddr(self):
        node = self.nodes[2]
        self.log.info("A second getaddr on a connection is ignored")
        peer = node.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_getaddr())
        with node.assert_debug_log(['Ignoring repeated "getaddr". peer=']):
            peer.send_and_ping(msg_getaddr())
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [])

    def test_core_checks(self):
        node = self.nodes[2]
        addrs = []
        for i in range(10):
            addrs.append(make_addr("123.123.123.{}".format(i % 256), self.now - 60 - i, port=8333 + i))

        self.log.info('Create connection that sends addr messages')
        addr_source = node.add_p2p_connection(P2PInterface())
        source_id = peers(node)[-1]['id']

        self.log.info('Send too large addr message')
        with node.assert_debug_log(['message addr size() = 1010']):
            addr_source.send_and_ping(addr_msg(addrs * 101))
        assert_equal(peers(node)[-1]['banscore'], 20)

        self.log.info('Check that addr message content is added to addrman')
        node.add_p2p_connection(AddrReceiver())
        with node.assert_debug_log([
                'Added 10 addresses from 127.0.0.1: 0 tried',
                'received: addr (301 bytes) peer=%d' % source_id,
        ]):
            addr_source.send_and_ping(addr_msg(addrs))
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [])

    def test_persistence(self):
        node = self.nodes[2]
        self.log.info("peers.dat keeps the addresses across a restart")
        before = sorted(a['address'] for a in node.getaddrmaninfo()[:-1])
        self.restart_node(2)
        assert_equal(sorted(a['address'] for a in node.getaddrmaninfo()[:-1]), before)

        self.log.info("A corrupt peers.dat or banlist.dat is replaced")
        node.setban("99.99.99.99", "add")
        self.stop_node(2)
        for name in ["peers.dat", "banlist.dat"]:
            with open(os.path.join(node.datadir, name), "wb") as f:
                f.write(b"junk" * 10)
        with node.assert_debug_log(["Invalid or missing peers.dat; recreating",
                                    "Invalid or missing banlist.dat; recreating"]):
            self.start_node(2)
        assert_equal(node.getaddrmaninfo(), [{"size: ": 0}])
        assert_equal(node.listbanned(), [])


if __name__ == '__main__':
    AddrTest().main()
