#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""The version handshake and malformed messages.

- The node's own version message.
- A duplicate version (reject, ban score 1); versions below 31800 (reject,
  disconnect); version messages that end early after any of the optional
  fields; one cut inside a mandatory field (reject, and the peer can still
  send a full one); a 256-byte subversion is kept, a 257-byte one refused.
- fRelay=0 in the version: the node doesn't announce transactions to the
  peer.
- Messages between version and verack each add 1 to the ban score and get
  no answer.
- A connection to itself is dropped.
- Malformed payloads (non-canonical or oversized compact sizes, short
  messages) get a reject without a ban score; incoming reject messages are
  only logged.
"""
import random
import struct
import time

from test_framework.messages import (
    CAddress,
    CInv,
    MSG_TX,
    REJECT_DUPLICATE,
    REJECT_MALFORMED,
    REJECT_OBSOLETE,
    msg_generic,
    msg_inv,
    msg_ping,
    msg_verack,
    msg_version,
    ser_string,
)
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, peers, wait_until


class NoVerackPeer(P2PInterface):
    """Answers the node's version without a verack."""
    def on_version(self, message):
        self.nServices = message.nServices


class VersionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # Whitelisted peers get inventory on every send loop, so the fRelay=0
        # peer's missing inv can be checked without waiting for a trickle.
        self.extra_args = [["-whitelist=127.0.0.1"]]

    def raw_peer(self, peer=None):
        """A connected peer that hasn't sent its version, with its node id."""
        node = self.nodes[0]
        before = {p['id'] for p in peers(node)}
        conn = node.add_p2p_connection(peer or P2PInterface(), send_version=False, wait_for_verack=False)
        wait_until(lambda: conn.is_connected, timeout=10, lock=mininode_lock)
        wait_until(lambda: len([p for p in peers(node) if p['id'] not in before]) == 1, timeout=10)
        conn.peer_id = [p['id'] for p in peers(node) if p['id'] not in before][0]
        return conn

    def peer_info(self, conn):
        for p in peers(self.nodes[0]):
            if p['id'] == conn.peer_id:
                return p
        raise AssertionError("peer=%d is not connected" % conn.peer_id)

    def rejects(self, conn):
        with mininode_lock:
            return [(r.message, r.code, r.reason) for r in conn.rejects]

    def close(self, conn):
        conn.peer_disconnect()
        conn.wait_for_disconnect()

    def version_payload(self, *, version=70015, end=None, subver=b"/n1:1/", relay=None):
        """A version message's payload, cut after the field named by end
        (addrMe, nonce, subver, height); relay=None leaves fRelay out."""
        addr_me = CAddress()
        addr_me.ip = "127.0.0.1"
        addr_me.port = p2p_port(0)
        r = struct.pack("<iQq", version, 1, int(time.time())) + addr_me.serialize(False)
        if end == "addrMe":
            return r
        r += CAddress().serialize(False) + struct.pack("<Q", random.getrandbits(64))
        if end == "nonce":
            return r
        r += ser_string(subver)
        if end == "subver":
            return r
        r += struct.pack("<i", self.nodes[0].getblockcount())
        if relay is not None:
            r += struct.pack("<b", relay)
        return r

    def handshake(self, payload, peer=None):
        conn = self.raw_peer(peer)
        conn.send_message(msg_generic(b"version", payload))
        conn.wait_for_verack()
        conn.sync_with_ping()
        return conn

    def run_test(self):
        self.test_node_version()
        self.test_duplicate_version()
        self.test_obsolete_version()
        self.test_short_versions()
        self.test_relay()
        self.test_cut_version()
        self.test_messages_before_verack()
        self.test_self_connection()
        self.test_malformed_payloads()
        self.test_incoming_reject()
        self.test_subversion_length()

    def test_node_version(self):
        node = self.nodes[0]
        self.log.info("The node's version message")
        conn = node.add_p2p_connection(P2PInterface())
        with mininode_lock:
            version = conn.last_message['version']
        assert_equal(version.nVersion, 70015)
        assert_equal(version.nServices, 1)  # NODE_NETWORK only
        assert_equal(version.nStartingHeight, node.getblockcount())
        assert_equal(version.nRelay, 1)
        assert version.strSubVer.startswith(b"/Yacoin-WM:"), version.strSubVer
        node.disconnect_p2ps()

    def test_duplicate_version(self):
        node = self.nodes[0]
        self.log.info("A second version message: reject, ban score 1")
        before = {p['id'] for p in peers(node)}
        conn = node.add_p2p_connection(P2PInterface())
        conn.peer_id = [p['id'] for p in peers(node) if p['id'] not in before][0]
        version = msg_version()
        version.nStartingHeight = node.getblockcount()
        conn.send_and_ping(version)
        assert_equal(self.rejects(conn), [(b"version", REJECT_DUPLICATE, b"Duplicate version message")])
        assert_equal(self.peer_info(conn)['banscore'], 1)
        self.close(conn)

    def test_obsolete_version(self):
        node = self.nodes[0]
        # 10300 is refused too: the check comes before the 10300 -> 300 remap.
        for version in (31799, 10300):
            self.log.info("Version %d: reject, disconnect" % version)
            conn = self.raw_peer()
            with node.assert_debug_log(["peer=%d using obsolete version %d; disconnecting" % (conn.peer_id, version)], timeout=10):
                conn.send_message(msg_generic(b"version", self.version_payload(version=version)))
                conn.wait_for_disconnect(timeout=10)
            assert_equal(self.rejects(conn), [(b"version", REJECT_OBSOLETE, b"Version must be 31800 or greater")])

    def test_short_versions(self):
        self.log.info("Version messages that end after addrMe, the nonce or the subversion")
        for end, subver in (("addrMe", ""), ("nonce", ""), ("subver", "/n1:1/")):
            conn = self.handshake(self.version_payload(end=end))
            info = self.peer_info(conn)
            # Absent fields keep their defaults.
            assert_equal((info['version'], info['subver'], info['startingheight'], info['relaytxes'], info['banscore']),
                         (70015, subver, -1, True, 0))
            self.close(conn)

    def test_relay(self):
        node = self.nodes[0]
        self.log.info("fRelay=0: the node doesn't announce transactions to the peer")
        quiet = self.handshake(self.version_payload(relay=0))
        assert_equal(self.peer_info(quiet)['relaytxes'], False)
        loud = self.handshake(self.version_payload(relay=1))
        assert_equal(self.peer_info(loud)['relaytxes'], True)
        txid = int(node.sendtoaddress(address=node.getnewaddress(), amount=1), 16)
        wait_until(lambda: loud.last_message.get('inv') and loud.last_message['inv'].inv[0].hash == txid,
                   timeout=30, lock=mininode_lock)
        # The tx was queued for both peers at once; two more rounds of the
        # send loop have passed for the quiet one after these pings.
        quiet.sync_with_ping()
        quiet.sync_with_ping()
        with mininode_lock:
            assert_equal(quiet.message_count['inv'], 0)
        self.close(quiet)
        self.close(loud)

    def test_cut_version(self):
        node = self.nodes[0]
        self.log.info("A version cut inside addrMe: reject, and a full version still works")
        conn = self.raw_peer()
        with node.assert_debug_log(["ProcessMessages(version, 30 bytes): Exception",
                                    "caught, normally caused by a message being shorter than its stated length"], timeout=10):
            conn.send_message(msg_generic(b"version", self.version_payload(end="addrMe")[:30]))
            conn.wait_for_reject(message=b"version", code=REJECT_MALFORMED, reason=b"error parsing message", timeout=10)
        assert_equal(self.peer_info(conn)['version'], 0)
        conn.send_message(msg_generic(b"version", self.version_payload()))
        conn.wait_for_verack()
        conn.sync_with_ping()
        info = self.peer_info(conn)
        assert_equal((info['version'], info['subver'], info['banscore']), (70015, "/n1:1/", 0))
        self.close(conn)

    def test_messages_before_verack(self):
        self.log.info("Messages between version and verack: ban score 1 each, no answer")
        conn = self.raw_peer(NoVerackPeer())
        conn.send_message(msg_generic(b"version", self.version_payload()))
        wait_until(lambda: conn.message_count['verack'] == 1, timeout=10, lock=mininode_lock)
        conn.send_message(msg_ping(nonce=1000))
        conn.send_message(msg_inv([CInv(MSG_TX, 1)]))
        wait_until(lambda: self.peer_info(conn)['banscore'] == 2, timeout=10)
        conn.send_message(msg_verack())
        conn.sync_with_ping()
        with mininode_lock:
            # Only the ping sent after verack was answered.
            assert_equal(conn.message_count['pong'], 1)
        assert_equal(self.peer_info(conn)['banscore'], 2)
        self.close(conn)

    def test_self_connection(self):
        node = self.nodes[0]
        self.log.info("A connection to itself is dropped")
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [], timeout=10)
        with node.assert_debug_log(["connected to self at 127.0.0.1:"], timeout=10):
            node.addnode("127.0.0.1:%d" % p2p_port(0), "onetry")
        wait_until(lambda: peers(node) == [], timeout=10)

    def test_malformed_payloads(self):
        node = self.nodes[0]
        self.log.info("Malformed payloads: reject, no ban score")
        conn = node.add_p2p_connection(P2PInterface())
        conn.peer_id = peers(node)[0]['id']
        inv_entry = struct.pack("<I", MSG_TX) + b"\x00" * 32
        cases = [
            (b"inv", b"\xfd\x01\x00" + inv_entry, "non-canonical ReadCompactSize()"),
            (b"inv", b"\xfe\x01\x00\x00\x02", "size too large"),
            (b"inv", b"\x02" + inv_entry, "normally caused by a message being shorter than its stated length"),
            (b"ping", b"", "normally caused by a message being shorter than its stated length"),
        ]
        for command, payload, log in cases:
            with node.assert_debug_log([log]):
                conn.send_and_ping(msg_generic(command, payload))
            assert_equal(self.rejects(conn), [(command, REJECT_MALFORMED, b"error parsing message")])
            with mininode_lock:
                conn.rejects.clear()
        assert_equal(self.peer_info(conn)['banscore'], 0)
        self.conn = conn

    def test_incoming_reject(self):
        node = self.nodes[0]
        self.log.info("Incoming reject messages are logged only")
        conn = self.conn
        with node.assert_debug_log(["Unparseable reject message received"]):
            conn.send_and_ping(msg_generic(b"reject", ser_string(b"tx")))
        reject = ser_string(b"tx") + b"\x10" + ser_string(b"bad-txns-x") + b"\x11" * 32
        with node.assert_debug_log(["Reject tx code 16: bad-txns-x: hash " + "11" * 32]):
            conn.send_and_ping(msg_generic(b"reject", reject))
        assert_equal(self.rejects(conn), [])
        assert_equal(self.peer_info(conn)['banscore'], 0)
        node.disconnect_p2ps()

    def test_subversion_length(self):
        node = self.nodes[0]
        self.log.info("A 256-byte subversion is kept, a 257-byte one refused")
        conn = self.handshake(self.version_payload(subver=b"s" * 256))
        assert_equal(self.peer_info(conn)['subver'], "s" * 256)
        self.close(conn)

        conn = self.raw_peer()
        conn.send_message(msg_generic(b"version", self.version_payload(subver=b"s" * 257)))
        conn.wait_for_reject(message=b"version", code=REJECT_MALFORMED, reason=b"error parsing message", timeout=10)
        assert_equal(self.peer_info(conn)['version'], 0)
        # The exception is printed to stderr. Its first lines depend on the
        # C++ library, so only the stable parts are checked.
        def read_stderr():
            node.stderr.seek(0)
            return node.stderr.read().decode('utf-8').strip()
        wait_until(lambda: "in ProcessMessages()" in read_stderr(), timeout=10)
        stderr = read_stderr()
        assert "String length limit exceeded" in stderr, stderr
        self.stop_node(0, expected_stderr=stderr)


if __name__ == '__main__':
    VersionTest().main()
