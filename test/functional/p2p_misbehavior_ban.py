#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bans for misbehaving peers.

The node never bans loopback peers, only disconnects them. So the peer
connects through the address of a non-loopback interface; without a usable
one, only the loopback case runs and the test is skipped.

- Loopback: the ban score reaches the threshold, the peer is disconnected,
  nothing is banned.
- A non-local peer: scores add up (addr with more than 1000 entries, +20),
  the peer is banned for -bantime ("node misbehaving") and disconnected;
  new connections from its address are dropped; the ban survives a restart.
- -whitelist: a whitelisted peer can connect while its address is banned,
  and its misbehaviour (filterload, +100) is counted but not punished.
- -banscore lowers the threshold.
"""
import socket
import time

from test_framework.messages import CAddress, msg_addr, msg_generic
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, non_loopback_ipv4, peers

BANTIME = 600


def usable_ipv4():
    """A non-loopback IPv4 address of this host that a connection to it
    really comes from, or None."""
    try:
        ip = non_loopback_ipv4()  # Linux-only ioctl
    except (ImportError, OSError):
        return None
    if ip is None:
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind((ip, 0))
            server.listen(1)
            with socket.create_connection(server.getsockname(), timeout=5):
                accepted, source = server.accept()
                accepted.close()
    except OSError:
        return None
    return ip if source[0] == ip else None


def big_addr(t):
    """An addr message with 1001 entries (the limit is 1000): +20."""
    msg = msg_addr()
    for i in range(1001):
        addr = CAddress()
        addr.time = t
        addr.ip = "10.0.%d.%d" % (i // 250, i % 250 + 1)
        addr.port = 7688
        msg.addrs.append(addr)
    return msg


# filterload while the node doesn't offer NODE_BLOOM: +100.
FILTERLOAD = msg_generic(b"filterload", b"\x01\x00" + b"\x00" * 9)


class MisbehaviorBanTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False
        self.ip = usable_ipv4()
        self.base_args = ["-bind=127.0.0.1", "-bantime=%d" % BANTIME]
        if self.ip is not None:
            self.base_args.append("-bind=%s" % self.ip)
        self.extra_args = [self.base_args]

    def connect(self, dstaddr='127.0.0.1'):
        node = self.nodes[0]
        before = {p['id'] for p in peers(node)}
        conn = node.add_p2p_connection(P2PInterface(), dstaddr=dstaddr)
        new = [p for p in peers(node) if p['id'] not in before]
        assert_equal(len(new), 1)
        conn.peer_id = new[0]['id']
        conn.addr = new[0]['addr']
        return conn

    def peer_info(self, conn):
        for p in peers(self.nodes[0]):
            if p['id'] == conn.peer_id:
                return p
        raise AssertionError("peer=%d is not connected" % conn.peer_id)

    def banscore(self, conn):
        return self.peer_info(conn)['banscore']

    def ban_entry(self, reason):
        return {"address": self.ip + "/32", "banned_until": self.mocktime + BANTIME,
                "ban_created": self.mocktime, "ban_reason": reason}

    def misbehave_until_banned(self, conn, n):
        """n addr messages of +20; the last one crosses the threshold."""
        node = self.nodes[0]
        for i in range(1, n):
            conn.send_and_ping(big_addr(self.mocktime))
            assert_equal(self.banscore(conn), 20 * i)
        with node.assert_debug_log(["peer=%d (%d -> %d) BAN THRESHOLD EXCEEDED" % (conn.peer_id, 20 * (n - 1), 20 * n)], timeout=10):
            conn.send_message(big_addr(self.mocktime))
            conn.wait_for_disconnect(timeout=10)

    def run_test(self):
        node = self.nodes[0]
        self.set_mocktime(int(time.time()))

        self.log.info("A loopback peer is disconnected, not banned")
        conn = self.connect()
        with node.assert_debug_log(["Warning: not banning local peer %s!" % conn.addr], timeout=10):
            self.misbehave_until_banned(conn, 5)
        assert_equal(node.listbanned(), [])

        if self.ip is None:
            raise SkipTest("no usable non-loopback IPv4 address")
        ip = self.ip
        conn = self.connect(ip)
        if not conn.addr.startswith(ip + ":"):
            raise SkipTest("connection to %s comes from %s" % (ip, conn.addr))

        self.log.info("A non-local peer is banned for -bantime when its score reaches 100")
        self.misbehave_until_banned(conn, 5)
        assert_equal(node.listbanned(), [self.ban_entry("node misbehaving")])

        self.log.info("New connections from a banned address are dropped")
        with node.assert_debug_log(["connection from %s:" % ip, "dropped (banned)"], timeout=10):
            refused = node.add_p2p_connection(P2PInterface(), dstaddr=ip, wait_for_verack=False)
        refused.wait_for_disconnect(timeout=10)
        with mininode_lock:
            assert_equal(refused.message_count['version'], 0)
        self.connect().peer_disconnect()  # loopback still works

        self.log.info("The ban survives a restart")
        banned = node.listbanned()
        self.restart_node(0)
        assert_equal(node.listbanned(), banned)

        self.log.info("A whitelisted peer connects while banned, and isn't punished")
        self.restart_node(0, self.base_args + ["-whitelist=%s" % ip])
        conn = self.connect(ip)
        with node.assert_debug_log(["Warning: not punishing whitelisted peer %s!" % conn.addr], timeout=10):
            conn.send_and_ping(FILTERLOAD)
        info = self.peer_info(conn)
        # The score is counted, only the punishment is skipped.
        assert_equal((info['whitelisted'], info['banscore']), (True, 100))
        assert_equal(node.listbanned(), banned)
        node.disconnect_p2ps()

        self.log.info("-banscore lowers the threshold")
        node.clearbanned()
        self.set_mocktime(self.mocktime + 10)  # a new entry, not the old one
        self.restart_node(0, self.base_args + ["-banscore=40"])
        self.misbehave_until_banned(self.connect(ip), 2)
        assert_equal(node.listbanned(), [self.ban_entry("node misbehaving")])


if __name__ == '__main__':
    MisbehaviorBanTest().main()
