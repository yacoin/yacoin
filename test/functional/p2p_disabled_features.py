#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test what is left of the P2P features YACoin disabled.

Compact blocks (BIP152) and bloom filters (BIP37) are switched off, but
some of their code still runs:
- A peer that sent sendcmpct version 1 is asked for a single new block
  with a getdata of type MSG_CMPCT_BLOCK, which the node can't take an
  answer to (card iQg6oeoK item 1, known failure). While that request is
  in flight, another peer announcing the block gets no request. When the
  first peer sends the full block, the node accepts it and asks that peer
  to announce blocks with cmpctblock. With sendcmpct version 2 the
  request is a plain block request.
- getdata for filtered or compact blocks is ignored, and the compact
  block and merkleblock messages are unknown commands.
- filterload from a peer below version 70011 disconnects it without a
  misbehaviour score; filteradd from a newer peer scores 100.
- filterclear turns transaction relay on for a peer that asked for none
  (card iQg6oeoK item 5).
"""

from test_framework.blocktools import blocks_from_node
from test_framework.messages import (
    CInv,
    MSG_BLOCK,
    msg_block,
    msg_generic,
    msg_getdata,
    msg_inv,
    msg_sendcmpct,
)
from test_framework.mininode import P2PDataStore, P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
    peers,
    wait_until,
)

MSG_FILTERED_BLOCK = 3
MSG_CMPCT_BLOCK = 4


class BlockStore(P2PDataStore):
    """Serves the blocks given to it (type MSG_BLOCK only) and records the
    node's requests and sendcmpct messages."""
    def __init__(self):
        super().__init__()
        self.getdata_types = []
        self.getheaders_count = 0
        self.sendcmpcts = []

    def add_block(self, block):
        """Add the block after connecting: the node's first getheaders
        would otherwise fetch it at once."""
        with mininode_lock:
            self.block_store[block.sha256] = block
            self.last_block_hash = block.sha256

    def on_getdata(self, message):
        for inv in message.inv:
            self.getdata_types.append(inv.type)
        super().on_getdata(message)

    def on_getheaders(self, message):
        self.getheaders_count += 1
        super().on_getheaders(message)

    def on_sendcmpct(self, message):
        self.sendcmpcts.append((message.announce, message.version))


class VersionPeer(P2PInterface):
    """Sends a version message with the given protocol version or relay flag."""
    def __init__(self, version=None, relay=None):
        super().__init__()
        self.version = version
        self.relay = relay

    def peer_connect(self, *args, **kwargs):
        create_conn = super().peer_connect(*args, **kwargs)
        if self.version is not None:
            self.on_connection_send_msg.nVersion = self.version
        if self.relay is not None:
            self.on_connection_send_msg.nRelay = self.relay
        return create_conn


def sendcmpct(version):
    msg = msg_sendcmpct()
    msg.announce = False
    msg.version = version
    return msg


class DisabledFeaturesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        # node1 is a donor of blocks, connected only to share the chain.
        self.setup_nodes()

    def run_test(self):
        node, donor = self.nodes
        self.mine_with_mocktime(node, 3, sync=False)
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        wait_until(lambda: node.getconnectioncount() == 0)
        hashes = self.mine_with_mocktime(donor, 2, sync=False)
        self.blocks = blocks_from_node(donor, hashes)

        self.test_compact_block_request()
        self.test_sendcmpct_version_2()
        self.test_unserved_types()
        self.test_bloom()

    def test_compact_block_request(self):
        node = self.nodes[0]
        block = self.blocks[0]
        self.log.info("sendcmpct version 1, then a block announcement")
        peer = node.add_p2p_connection(BlockStore())
        peer_id = peers(node)[-1]['id']
        peer.send_and_ping(sendcmpct(1))
        peer.add_block(block)
        height = node.getblockcount() + 1
        # The node answers the inv with getheaders, the peer with the
        # header, and the node then requests the block.
        peer.send_message(msg_inv([CInv(MSG_BLOCK, block.sha256)]))

        def check():
            wait_until(lambda: len(peer.getdata_types) > 0, timeout=10, lock=mininode_lock)
            with mininode_lock:
                assert_equal(peer.getdata_types[0], MSG_BLOCK)
        self.known_failure("compact-block getdata (iQg6oeoK item 1)", check, expected="not(4 == 2)")

        # Today the type-4 request keeps the block in flight, so another
        # peer's announcement isn't followed up and the tip doesn't move
        # until the peer sends the block; these asserts change with the fix.
        assert_equal([p['inflight'] for p in peers(node) if p['id'] == peer_id], [[height]])

        self.log.info("A second peer announcing the block gets no request while it is in flight")
        other = node.add_p2p_connection(BlockStore())
        other.add_block(block)
        with mininode_lock:
            other.getheaders_count = 0
        other.send_and_ping(msg_inv([CInv(MSG_BLOCK, block.sha256)]))
        other.sync_with_ping()
        with mininode_lock:
            assert_equal((other.getheaders_count, other.getdata_types), (0, []))
        assert_equal(node.getblockcount(), height - 1)

        self.log.info("The full block from the first peer is accepted")
        peer.send_and_ping(msg_block(block))
        assert_equal(node.getbestblockhash(), block.hash)
        # Independent of the request type: the peer's sendcmpct makes
        # BlockChecked ask it to announce with cmpctblock.
        wait_until(lambda: peer.sendcmpcts == [(True, 1)], timeout=10, lock=mininode_lock)
        assert_equal([p['inflight'] for p in peers(node)], [[], []])
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [])

    def test_sendcmpct_version_2(self):
        node = self.nodes[0]
        block = self.blocks[1]
        self.log.info("sendcmpct version 2: a plain block request")
        peer = node.add_p2p_connection(BlockStore())
        peer.send_and_ping(sendcmpct(2))
        peer.add_block(block)
        peer.send_message(msg_inv([CInv(MSG_BLOCK, block.sha256)]))
        wait_until(lambda: node.getbestblockhash() == block.hash, timeout=10)
        peer.sync_with_ping()
        with mininode_lock:
            assert_equal(peer.getdata_types, [MSG_BLOCK])
            assert_equal(peer.sendcmpcts, [])
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [])

    def test_unserved_types(self):
        node = self.nodes[0]
        tip = int(node.getbestblockhash(), 16)
        self.log.info("getdata for compact and filtered blocks is ignored")
        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(["ProcessGetData, unknown inv type 4", "ProcessGetData, unknown inv type 3"]):
            peer.send_and_ping(msg_getdata([CInv(MSG_CMPCT_BLOCK, tip), CInv(MSG_FILTERED_BLOCK, tip)]))
        with mininode_lock:
            assert_equal((peer.message_count['block'], peer.message_count['notfound']), (0, 0))

        self.log.info("The compact block and merkleblock messages are unknown commands")
        commands = [b"cmpctblock", b"getblocktxn", b"blocktxn", b"merkleblock"]
        with node.assert_debug_log(['Unknown command "%s" from peer=' % c.decode() for c in commands]):
            for command in commands:
                peer.send_message(msg_generic(command, b"\x00" * 10))
            peer.sync_with_ping()
        assert_equal(peers(node)[0]['banscore'], 0)
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [])

    def test_bloom(self):
        node = self.nodes[0]
        filterload = msg_generic(b"filterload", b"\x01\x00" + b"\x00" * 9)
        self.log.info("filterload from a peer below version 70011: disconnected, no score")
        peer = node.add_p2p_connection(VersionPeer(version=70010))
        with node.assert_debug_log(["ProcessMessages(filterload, 11 bytes) FAILED"], unexpected_msgs=["Misbehaving:"]):
            peer.send_message(filterload)
            peer.wait_for_disconnect()

        self.log.info("filteradd from a newer peer: score 100, disconnected")
        peer = node.add_p2p_connection(P2PInterface())
        with node.assert_debug_log(["Misbehaving: 127.0.0.1:", "(0 -> 100) BAN THRESHOLD EXCEEDED"]):
            peer.send_message(msg_generic(b"filteradd", b"\x01\x00"))
            peer.wait_for_disconnect()

        self.log.info("filterclear turns transaction relay on")
        peer = node.add_p2p_connection(VersionPeer(relay=0))
        assert_equal(peers(node)[0]['relaytxes'], False)
        peer.send_and_ping(msg_generic(b"filterclear", b""))
        # Card iQg6oeoK item 5: although bloom filters are off, filterclear
        # still sets the peer's relay flag (same in Bitcoin Core 0.15).
        assert_equal(peers(node)[0]['relaytxes'], True)


if __name__ == '__main__':
    DisabledFeaturesTest().main()
