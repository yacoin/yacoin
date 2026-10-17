#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test blocks a peer sends without being asked for them.

- A block with the same work as the tip is stored but doesn't become the
  tip (getchaintips "valid-headers"); its child has more work and does.
- A block with less work than the tip is not stored, only its header
  ("headers-only", getblock fails); once headers make its branch the best,
  the node asks for it with the rest of the branch and reorgs.
- A block more than 288 blocks above the tip is not stored, even with its
  header known; after the tip has caught up within 288 it is stored, and
  connected once its parent arrives.

Side blocks are built in Python on the node's chain; the long chain comes
from a donor node that mines it unconnected.
"""

from test_framework.blocktools import blocks_from_node, create_block_yac, solve_block
from test_framework.messages import CBlockHeader, msg_block, msg_headers
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, connect_nodes, disconnect_nodes, wait_until


class Requests(P2PInterface):
    """Records getdata hashes; never answers."""
    def __init__(self):
        super().__init__()
        self.requests = []

    def on_getdata(self, message):
        self.requests.extend(inv.hash for inv in message.inv)


class UnrequestedBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Node 1 is a donor that mines unconnected.
        self.setup_nodes()

    def tip_status(self, block_hash):
        return [(t['height'], t['status']) for t in self.nodes[0].getchaintips() if t['hash'] == block_hash]

    def assert_not_stored(self, block):
        assert_raises_rpc_error(-1, "Block not found on disk", self.nodes[0].getblock, block.hash)

    def run_test(self):
        self.set_mocktime(1600000000)
        self.mine_with_mocktime(self.nodes[0], 12, sync=False)
        self.test_side_blocks()
        self.test_too_far_ahead()

    def test_side_blocks(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(Requests())
        base = node.getblockhash(12)
        [own] = self.mine_with_mocktime(node, 1, sync=False)

        self.log.info("Same work as the tip: stored, no reorg")
        f1 = solve_block(node, create_block_yac(node, prev=base))
        f2 = solve_block(node, create_block_yac(node, prev=f1, height=14))
        peer.send_and_ping(msg_block(f1))
        assert_equal(node.getbestblockhash(), own)
        assert_equal(self.tip_status(f1.hash), [(13, 'valid-headers')])
        assert_equal(node.getblock(f1.hash)['height'], 13)

        self.log.info("Its child has more work: reorg")
        peer.send_and_ping(msg_block(f2))
        assert_equal(node.getbestblockhash(), f2.hash)
        assert_equal(self.tip_status(own), [(13, 'valid-fork')])

        self.log.info("Less work than the tip: only the header is kept")
        g1 = solve_block(node, create_block_yac(node, prev=node.getblockhash(11)))
        peer.send_and_ping(msg_block(g1))
        self.assert_not_stored(g1)
        assert_equal(node.getblockheader(g1.hash)['height'], 12)
        assert_equal(self.tip_status(g1.hash), [(12, 'headers-only')])

        self.log.info("Headers make its branch the best: the node asks for all of it and reorgs")
        branch = [g1]
        for height in (13, 14, 15):
            branch.append(solve_block(node, create_block_yac(node, prev=branch[-1], height=height)))
        peer.send_message(msg_headers([CBlockHeader(b) for b in branch]))
        wait_until(lambda: len(peer.requests) == 4, timeout=30, lock=mininode_lock)
        with mininode_lock:
            assert_equal(peer.requests, [b.sha256 for b in branch])
        for block in branch:
            peer.send_message(msg_block(block))
        peer.sync_with_ping()
        assert_equal(node.getbestblockhash(), branch[-1].hash)
        assert_equal(self.tip_status(f2.hash), [(14, 'valid-fork')])
        node.disconnect_p2ps()
        wait_until(lambda: node.getconnectioncount() == 0)

    def test_too_far_ahead(self):
        node, donor = self.nodes
        self.log.info("A 290-block chain from the donor; a peer without NODE_NETWORK announces its headers")
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        wait_until(lambda: node.getconnectioncount() == 0)
        base = node.getblockcount()
        blocks = blocks_from_node(donor, self.mine_with_mocktime(donor, 290, sync=False))
        # The mocktime is now 290 minutes past the tip's time: the node
        # doesn't fetch announced blocks directly, and never from this peer.
        peer = node.add_p2p_connection(Requests(), services=0)
        peer.send_and_ping(msg_headers([CBlockHeader(b) for b in blocks]))
        assert_equal(node.getblockheader(blocks[-1].hash)['height'], base + 290)

        self.log.info("Blocks 289 and 290 above the tip: not stored")
        for block in blocks[-1:-3:-1]:
            peer.send_and_ping(msg_block(block))
            self.assert_not_stored(block)

        self.log.info("Blocks 1-288: the tip follows")
        for block in blocks[:288]:
            peer.send_message(msg_block(block))
        peer.sync_with_ping()
        assert_equal(node.getblockcount(), base + 288)

        self.log.info("Block 290 again: within 288 now, stored but not connected; block 289 connects both")
        peer.send_and_ping(msg_block(blocks[-1]))
        assert_equal(node.getblock(blocks[-1].hash)['height'], base + 290)
        assert_equal(node.getblockcount(), base + 288)
        assert_equal(self.tip_status(blocks[-1].hash), [(base + 290, 'headers-only')])
        peer.send_and_ping(msg_block(blocks[-2]))
        assert_equal(node.getbestblockhash(), blocks[-1].hash)
        with mininode_lock:
            assert_equal(peer.requests, [])


if __name__ == '__main__':
    UnrequestedBlocksTest().main()
