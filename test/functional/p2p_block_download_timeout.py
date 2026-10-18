#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the block download timeout (-initSyncDownloadTimeout).

The only peer announces one block and never delivers it. The node runs with
-initSyncDownloadTimeout=2.

Known bug: the node multiplies the option by the block spacing (60 s) for
block downloads, so the default 900 means 15 hours, and 2 means 120 s. The
help says the option is in seconds (2 s); Bitcoin Core's block timeout is
one block interval (60 s here). The marker checks that nothing is in flight
75 s after the getdata. Either fix (the option in seconds, or Core's one
block interval) makes the marker report itself; the 120 s step then fails
and must be replaced by the fixed timing.

Slow (about 122 s): in the extended list.
"""
import time

from test_framework.blocktools import blocks_from_node
from test_framework.messages import CBlockHeader, msg_headers
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, connect_nodes, disconnect_nodes, peers, wait_until


class Silent(P2PInterface):
    """Never answers getdata; remembers when the first one came."""
    def __init__(self):
        super().__init__()
        self.getdata_time = None
        self.requests = []

    def on_getdata(self, message):
        if self.getdata_time is None:
            self.getdata_time = time.time()
        self.requests.append([inv.hash for inv in message.inv])


class BlockDownloadTimeoutTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-initSyncDownloadTimeout=2"], []]

    def setup_network(self):
        # Node 1 is a donor that mines unconnected.
        self.setup_nodes()

    def run_test(self):
        node, donor = self.nodes
        self.set_mocktime(1600000000)
        self.mine_with_mocktime(node, 3, sync=False)
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        wait_until(lambda: node.getconnectioncount() == 0)
        [block] = blocks_from_node(donor, self.mine_with_mocktime(donor, 1, sync=False))

        self.log.info("The only peer announces block 4 and gets the getdata")
        peer = node.add_p2p_connection(Silent())
        peer.send_message(msg_headers([CBlockHeader(block)]))
        wait_until(lambda: peer.requests, timeout=30, lock=mininode_lock)
        with mininode_lock:
            assert_equal(peer.requests, [[block.sha256]])
            start = peer.getdata_time
        assert_equal([p['inflight'] for p in peers(node)], [[4]])

        self.log.info("-initSyncDownloadTimeout=2: nothing in flight 75 s after the getdata")

        def check():
            wait_until(lambda: not peer.is_connected or time.time() > start + 75, timeout=90)
            assert_equal([p['inflight'] for p in peers(node)], [])
        self.known_failure("download timeout ×60 (t2B49V3R item 1)", check, "not([[4]] == [])")

        self.log.info("Today the peer is disconnected after 120 s (the block spacing times the option)")
        with node.assert_debug_log(["Timeout downloading block %s from peer=" % block.hash], timeout=10):
            peer.wait_for_disconnect(timeout=90)
        elapsed = time.time() - start
        assert_greater_than(elapsed, 110)
        assert_greater_than(135, elapsed)
        assert_equal(node.getblockcount(), 3)


if __name__ == '__main__':
    BlockDownloadTimeoutTest().main()
