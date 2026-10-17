#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test block download from mininodes: stalling, in-flight limits, direct fetch.

The node runs with -initSyncMaximumBlocksInDownloadPerPeer=2 and
-initSyncBlockDownloadWindow=4.
- A peer without NODE_NETWORK is never asked for blocks while the tip is
  old.
- A peer that doesn't deliver the first two blocks of a 12-block chain
  stalls the download window: a second peer gets blocks 3-4, the first one is
  disconnected ("is stalling block download") and the second gets 1-2 and
  the rest. getpeerinfo's inflight shows the requested heights.
- When the tip is recent, the blocks a peer announces with headers are
  fetched from it directly, even from a peer without NODE_NETWORK.
- Headers of a branch that forks more blocks back than a peer may have in
  flight aren't fetched directly ("Large reorg"); the branch is downloaded
  through the normal block requests and becomes the tip.

Valid blocks come from a donor node that mines them unconnected.
"""

from test_framework.blocktools import blocks_from_node
from test_framework.messages import MSG_BLOCK, CBlockHeader, msg_headers
from test_framework.mininode import P2PDataStore, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, disconnect_nodes, peers, wait_until


class BlockRequests(P2PDataStore):
    """Records every block getdata (a list of hashes per message) and
    answers it only if serve is True."""
    def __init__(self, serve=True):
        super().__init__()
        self.serve = serve
        self.requests = []

    def on_getdata(self, message):
        assert all(inv.type == MSG_BLOCK for inv in message.inv)
        self.requests.append([inv.hash for inv in message.inv])
        if self.serve:
            super().on_getdata(message)

    def store(self, blocks):
        with mininode_lock:
            for block in blocks:
                self.block_store[block.sha256] = block
            self.last_block_hash = blocks[-1].sha256


def headers_of(blocks):
    return msg_headers([CBlockHeader(block) for block in blocks])


class BlockSyncTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-initSyncMaximumBlocksInDownloadPerPeer=2", "-initSyncBlockDownloadWindow=4"], []]

    def setup_network(self):
        # Node 1 is a donor that mines unconnected.
        self.setup_nodes()

    def run_test(self):
        self.set_mocktime(1600000000)
        self.hashes = self.mine_with_mocktime(self.nodes[1], 12, sync=False)
        self.blocks = blocks_from_node(self.nodes[1], self.hashes)
        self.ints = [block.sha256 for block in self.blocks]
        self.test_client_old_tip()
        self.test_stalling()
        self.test_client_recent_tip()
        self.test_large_reorg()

    def close_peers(self):
        node = self.nodes[0]
        node.disconnect_p2ps()
        wait_until(lambda: node.getconnectioncount() == 0)

    def test_client_old_tip(self):
        node = self.nodes[0]
        self.log.info("Old tip: a peer without NODE_NETWORK announces 12 headers and gets no getdata")
        client = node.add_p2p_connection(BlockRequests(serve=False), services=0)
        assert_equal([p['services'] for p in peers(node)], ["0000000000000000"])
        client.send_and_ping(headers_of(self.blocks))
        client.sync_with_ping()
        assert_equal(node.getblockheader(self.hashes[-1])['height'], 12)
        assert_equal(node.getblockcount(), 0)
        with mininode_lock:
            assert_equal(client.requests, [])
        self.close_peers()

    def test_stalling(self):
        node = self.nodes[0]
        self.log.info("A peer that doesn't deliver blocks 1-2 gets them in flight")
        staller = node.add_p2p_connection(BlockRequests(serve=False))
        staller.send_message(headers_of(self.blocks))
        wait_until(lambda: staller.requests, timeout=30, lock=mininode_lock)
        with mininode_lock:
            assert_equal(staller.requests, [self.ints[0:2]])
        [info] = peers(node)
        staller_id = info['id']
        assert_equal((info['inflight'], info['synced_headers'], info['synced_blocks']), ([1, 2], 12, 0))

        self.log.info("A second peer gets blocks 3-4; the first one stalls the window and is disconnected")
        server = BlockRequests()
        server.store(self.blocks)
        with node.assert_debug_log(["Stall started peer=%d" % staller_id,
                                    "Peer=%d is stalling block download, disconnecting" % staller_id], timeout=10):
            node.add_p2p_connection(server)
            server.send_message(headers_of(self.blocks))
            staller.wait_for_disconnect(timeout=10)
            wait_until(lambda: node.getblockcount() == 12, timeout=30)
        assert_equal(node.getbestblockhash(), self.hashes[-1])
        with mininode_lock:
            assert_equal(server.requests[0:2], [self.ints[2:4], self.ints[0:2]])
            assert_equal(staller.requests, [self.ints[0:2]])
        self.close_peers()

    def test_client_recent_tip(self):
        node, donor = self.nodes
        self.log.info("Recent tip: the blocks a peer without NODE_NETWORK announces are fetched from it directly")
        hashes = self.mine_with_mocktime(donor, 2, sync=False)
        blocks = blocks_from_node(donor, hashes)
        client = node.add_p2p_connection(BlockRequests(serve=False), services=0)
        client.send_message(headers_of(blocks))
        wait_until(lambda: client.requests, timeout=30, lock=mininode_lock)
        with mininode_lock:
            assert_equal(client.requests, [[block.sha256 for block in blocks]])
        assert_equal([p['inflight'] for p in peers(node)], [[13, 14]])
        self.close_peers()
        node.add_p2p_connection(P2PDataStore()).send_blocks_and_test(blocks, node)
        assert_equal(node.getblockcount(), 14)
        self.close_peers()

    def test_large_reorg(self):
        node, donor = self.nodes
        self.log.info("Headers of a 4-block branch: no direct fetch, the branch is downloaded and becomes the tip")
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        wait_until(lambda: node.getconnectioncount() == 0)
        assert_equal(node.getblockcount(), 14)
        self.mine_with_mocktime(node, 3, sync=False)
        hashes = self.mine_with_mocktime(donor, 4, sync=False)
        branch = blocks_from_node(donor, hashes)
        peer = node.add_p2p_connection(BlockRequests())
        peer.store(branch)
        with node.assert_debug_log(["Large reorg, won't direct fetch to %s (18)" % hashes[-1]]):
            peer.send_message(headers_of(branch))
            wait_until(lambda: node.getbestblockhash() == hashes[-1], timeout=30)
        with mininode_lock:
            assert_equal(peer.requests[0], [block.sha256 for block in branch[0:2]])
        assert_equal(node.getblockcount(), 18)


if __name__ == '__main__':
    BlockSyncTest().main()
