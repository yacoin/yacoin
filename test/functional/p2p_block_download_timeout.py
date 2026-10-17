#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the block download timeout (-initSyncDownloadTimeout).

The only peer announces one block and never delivers it. The help text says
the option is a timeout in seconds, so with -initSyncDownloadTimeout=1 the
block should no longer be in flight after 10 s.

Known bug: the node multiplies the option by the block spacing (60 s) for
block downloads, so the default 900 means 15 hours, and 1 means 60 s.
The marker checks the help's promise; a second step measures today's 60 s.
A fix must update both: if it makes the option seconds, the marker reports
itself and the 60 s step fails; if it keeps the block-interval scale and
corrects the help instead, the marker's check and the help text change.

Slow (about 65 s): in the extended list.
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
        self.extra_args = [["-initSyncDownloadTimeout=1"], []]

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

        self.log.info("-initSyncDownloadTimeout=1: nothing in flight 10 s later")

        def check():
            wait_until(lambda: not peer.is_connected or time.time() > start + 10, timeout=20)
            assert_equal([p['inflight'] for p in peers(node)], [])
        self.known_failure("download timeout ×60 (t2B49V3R item 1)", check, "not([[4]] == [])")

        self.log.info("Today the peer is disconnected after 60 s (the block spacing times the option)")
        with node.assert_debug_log(["Timeout downloading block %s from peer=" % block.hash], timeout=10):
            peer.wait_for_disconnect(timeout=90)
        elapsed = time.time() - start
        assert_greater_than(elapsed, 55)
        assert_greater_than(75, elapsed)
        assert_equal(node.getblockcount(), 3)


if __name__ == '__main__':
    BlockDownloadTimeoutTest().main()
