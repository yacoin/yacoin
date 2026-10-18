#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test how the node announces new blocks: inv, headers or the full block.

Two peers, X without and Y with sendheaders:
- before they told the node about any header, a new block is announced
  with an inv;
- once a peer has the parent (here after a getheaders), the node sends it
  the full block, to both;
- a one-block reorg: X gets an inv, Y the new header; the next block goes
  to Y in full, to X as an inv;
- a reorg to 8 new blocks: Y gets all 8 headers in one message, X an inv of
  the tip; a reorg to 9 new blocks: both get an inv of the tip; a reorg to
  3 new blocks: Y gets the 3 headers;
- blocks a mininode delivers through headers direct fetch ("Downloading
  blocks toward") are sent in full to Y, as invs to X and to a peer that
  never sent anything;
- an inv for an unknown block gets a getheaders with that hashstop, then a
  getdata; a second inv for it gets nothing.

Competing branches are mined by a donor node and submitted with submitblock.
"""

from test_framework.blocktools import blocks_from_node
from test_framework.messages import MSG_BLOCK, CInv, msg_getheaders, msg_inv, msg_sendheaders
from test_framework.mininode import P2PDataStore, P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, disconnect_nodes, wait_until


class Announcements(P2PInterface):
    """Records block invs, headers and blocks (hashes as ints), in order."""
    def __init__(self):
        super().__init__()
        self.seq = []

    def on_inv(self, message):
        blocks = [inv.hash for inv in message.inv if inv.type == MSG_BLOCK]
        if blocks:
            self.seq.append(('inv', blocks))

    def on_headers(self, message):
        for header in message.headers:
            header.calc_sha256()
        self.seq.append(('headers', [header.sha256 for header in message.headers]))

    def on_block(self, message):
        message.block.calc_sha256()
        self.seq.append(('block', [message.block.sha256]))


class Store(P2PDataStore):
    def __init__(self):
        super().__init__()
        self.getheaders_stops = []

    def on_getheaders(self, message):
        self.getheaders_stops.append(message.hashstop)
        super().on_getheaders(message)


def ints(hashes):
    return [int(h, 16) for h in hashes]


class SendHeadersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Node 1 is a donor that mines unconnected.
        self.setup_nodes()

    def expect(self, peer, expected):
        """Wait for len(expected) announcements; then two more rounds of the
        send loop to see that nothing else comes; compare."""
        wait_until(lambda: len(peer.seq) >= len(expected), timeout=30, lock=mininode_lock)
        peer.sync_with_ping()
        peer.sync_with_ping()
        with mininode_lock:
            seq, peer.seq = peer.seq, []
        assert_equal(seq, expected)

    def drain(self, peers, block_hash):
        """Wait until every peer heard of block_hash, then forget everything."""
        x = int(block_hash, 16)
        for peer in peers:
            wait_until(lambda: any(x in hashes for _, hashes in peer.seq), timeout=30, lock=mininode_lock)
            peer.sync_with_ping()
            with mininode_lock:
                peer.seq = []

    def getheaders_tip(self, peer):
        request = msg_getheaders()
        request.locator.vHave = [int(self.nodes[0].getbestblockhash(), 16)]
        peer.send_message(request)
        self.expect(peer, [('headers', [])])

    def mine(self, n):
        return self.mine_with_mocktime(self.nodes[0], n, sync=False)

    def sync_donor(self):
        node, donor = self.nodes
        count = node.getconnectioncount()
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        wait_until(lambda: node.getconnectioncount() == count)

    def run_test(self):
        node = self.nodes[0]
        self.set_mocktime(1600000000)
        self.mine(20)
        self.x = x = node.add_p2p_connection(Announcements())
        self.y = y = node.add_p2p_connection(Announcements())
        y.send_and_ping(msg_sendheaders())

        self.log.info("Peers that told the node nothing get an inv")
        tip = self.mine(1)
        self.expect(x, [('inv', ints(tip))])
        self.expect(y, [('inv', ints(tip))])

        self.log.info("After a getheaders, both get new blocks in full")
        self.getheaders_tip(x)
        self.getheaders_tip(y)
        tip = self.mine(1)
        self.expect(x, [('block', ints(tip))])
        self.expect(y, [('block', ints(tip))])
        tips = self.mine(3)
        self.expect(x, [('block', [t]) for t in ints(tips)])
        self.expect(y, [('block', [t]) for t in ints(tips)])

        self.log.info("One-block reorg: X gets an inv, Y the header; the next block: X an inv, Y the block")
        assert_equal(node.getblockcount(), 25)
        node.invalidateblock(node.getbestblockhash())
        self.expect(x, [])
        self.expect(y, [])
        tip = self.mine(1)
        self.expect(x, [('inv', ints(tip))])
        self.expect(y, [('headers', ints(tip))])
        tip = self.mine(1)
        self.expect(x, [('inv', ints(tip))])
        self.expect(y, [('block', ints(tip))])
        self.drain([x, y], self.mine(4)[-1])

        self.log.info("Reorg to 8 new blocks: Y gets the 8 headers, X an inv of the tip")
        branch = self.reorg(30, 7, 8)
        self.expect(x, [('inv', branch[-1:])])
        self.expect(y, [('headers', branch)])
        self.drain([x, y], self.mine(2)[-1])

        self.log.info("Reorg to 9 new blocks: both get an inv of the tip")
        branch = self.reorg(40, 8, 9)
        self.expect(x, [('inv', branch[-1:])])
        self.expect(y, [('inv', branch[-1:])])
        self.drain([x, y], self.mine(1)[-1])

        self.log.info("Reorg to 3 new blocks: Y gets the 3 headers")
        branch = self.reorg(50, 2, 3)
        self.expect(x, [('inv', branch[-1:])])
        self.expect(y, [('headers', branch)])

        self.test_direct_fetch()
        self.test_inv_announcement()

    def reorg(self, height, own, longer):
        """node0 mines own blocks on height, the peers ask for headers, then
        a donor branch of longer blocks is submitted. Returns its hashes."""
        node, donor = self.nodes
        assert_equal(node.getblockcount(), height)
        self.sync_donor()
        self.drain([self.x, self.y], self.mine(own)[-1])
        self.getheaders_tip(self.x)
        self.getheaders_tip(self.y)
        hashes = self.mine_with_mocktime(donor, longer, sync=False)
        results = [node.submitblock(block.serialize().hex()) for block in blocks_from_node(donor, hashes)]
        assert_equal(results, ["inconclusive"] * own + [None] * (longer - own))
        assert_equal(node.getbestblockhash(), hashes[-1])
        return ints(hashes)

    def test_direct_fetch(self):
        node, donor = self.nodes
        self.log.info("A mininode's headers: direct fetch; Y gets the blocks, X and a silent peer W invs")
        assert_equal(node.getblockcount(), 53)
        w = node.add_p2p_connection(Announcements())
        self.sync_donor()
        hashes = self.mine_with_mocktime(donor, 2, sync=False)
        self.z = Store()
        node.add_p2p_connection(self.z)
        with node.assert_debug_log(["Downloading blocks toward %s (55) via headers direct fetch" % hashes[-1]]):
            self.z.send_blocks_and_test(blocks_from_node(donor, hashes), node)
        self.expect(self.x, [('inv', [h]) for h in ints(hashes)])
        self.expect(self.y, [('block', [h]) for h in ints(hashes)])
        self.expect(w, [('inv', [h]) for h in ints(hashes)])

    def test_inv_announcement(self):
        node, donor = self.nodes
        self.log.info("A mininode's inv for an unknown block: getheaders with that hashstop, then getdata")
        [block] = blocks_from_node(donor, self.mine_with_mocktime(donor, 1, sync=False))
        z = self.z
        with mininode_lock:
            z.block_store[block.sha256] = block
            z.last_block_hash = block.sha256
            z.getheaders_stops = []
            z.getdata_requests = []
        z.send_message(msg_inv([CInv(MSG_BLOCK, block.sha256)]))
        wait_until(lambda: node.getbestblockhash() == block.hash, timeout=30)
        with mininode_lock:
            assert_equal((z.getheaders_stops, z.getdata_requests), ([block.sha256], [block.sha256]))
        self.log.info("A second inv for it gets nothing")
        z.send_and_ping(msg_inv([CInv(MSG_BLOCK, block.sha256)]))
        z.sync_with_ping()
        with mininode_lock:
            assert_equal((z.getheaders_stops, z.getdata_requests), ([block.sha256], [block.sha256]))


if __name__ == '__main__':
    SendHeadersTest().main()
