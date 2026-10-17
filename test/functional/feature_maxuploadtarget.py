#!/usr/bin/env python3
# Copyright (c) 2015-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -maxuploadtarget.

Adapted from Bitcoin Core's feature_maxuploadtarget.py, at a small scale:
the blocks are tiny, and "historical" blocks are made by mining them more
than a week in the past (mocktime) instead of uploading 800 MB.

- getnettotals' uploadtarget before any traffic.
- A block more than a week older than the best header is a historical
  block: while the target leaves no room for historical serving, a peer
  asking for one is disconnected; recent blocks are still served.
- Once the target is reached, recent blocks are still served.
- The buffer kept for historical serving is exactly
  floor(time_left_in_cycle / 600) * getblocktemplate's sizelimit: serving
  switches on one second after the buffer drops below the target.
- The cycle ends after the timeframe and restarts with the next bytes sent.
- Whitelisted peers are served historical blocks.
- -maxuploadtarget=0 and -maxuploadtarget=-1.
"""
import time

from test_framework.messages import CInv, MSG_BLOCK, msg_getdata
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, peers, wait_until

MiB = 1024 * 1024
TIMEFRAME = 24 * 60 * 60


class BlockReceiver(P2PInterface):
    def __init__(self):
        super().__init__()
        self.blocks = []

    def on_block(self, message):
        # Hashed only when asked for: the scrypt hash costs 10 ms in Python.
        self.blocks.append(message.block)

    def received(self, block_hash):
        with mininode_lock:
            for block in self.blocks:
                block.calc_sha256()
                if block.sha256 == int(block_hash, 16):
                    return True
        return False

    def request_block(self, block_hash):
        """Send a getdata for the block, sync, and return whether it arrived."""
        with mininode_lock:
            self.blocks = []
        self.send_and_ping(msg_getdata([CInv(MSG_BLOCK, int(block_hash, 16))]))
        return self.received(block_hash)


class MaxUploadTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-maxuploadtarget=1"]]

    def upload_target(self):
        return self.nodes[0].getnettotals()['uploadtarget']

    def run_test(self):
        node = self.nodes[0]
        now = int(time.time())

        self.log.info("Mine 10 blocks 10 days ago and 5 recent ones")
        self.set_mocktime(now - 10 * 24 * 60 * 60)
        self.old_hashes = self.mine_with_mocktime(node, 10)
        self.set_mocktime(now)
        self.new_hashes = self.mine_with_mocktime(node, 5)

        self.test_one_mib_target()
        self.test_exact_buffer()
        self.test_whitelisted()
        self.test_no_and_negative_target()

    def test_one_mib_target(self):
        node = self.nodes[0]
        self.log.info("Before any traffic: a 1 MiB target leaves no room for historical blocks")
        # The buffer (144 * sizelimit, about 52 MB) exceeds the target.
        assert_equal(self.upload_target(), {
            'timeframe': TIMEFRAME,
            'target': MiB,
            'target_reached': False,
            'serve_historical_blocks': False,
            'bytes_left_in_cycle': MiB,
            'time_left_in_cycle': TIMEFRAME,
        })

        self.log.info("A recent block is served")
        peer = node.add_p2p_connection(BlockReceiver())
        assert peer.request_block(self.new_hashes[0])

        self.log.info("A historical block request disconnects the peer")
        with node.assert_debug_log(["historical block serving limit reached, disconnect peer="]):
            peer.send_message(msg_getdata([CInv(MSG_BLOCK, int(self.old_hashes[0], 16))]))
            peer.wait_for_disconnect()
        assert not peer.received(self.old_hashes[0])

        self.log.info("Reach the target with recent blocks")
        peer = node.add_p2p_connection(P2PInterface())
        getdata = msg_getdata([CInv(MSG_BLOCK, int(self.new_hashes[-1], 16))] * 500)
        for _ in range(1000):
            if self.upload_target()['target_reached']:
                break
            peer.send_and_ping(getdata)
        target = self.upload_target()
        assert_equal(target['target_reached'], True)
        assert_equal(target['bytes_left_in_cycle'], 0)
        assert_equal(target['serve_historical_blocks'], False)

        self.log.info("Recent blocks are still served once the target is reached")
        peer = node.add_p2p_connection(BlockReceiver())
        assert peer.request_block(self.new_hashes[-1])
        assert peer.is_connected
        node.disconnect_p2ps()
        wait_until(lambda: peers(node) == [])

    def test_exact_buffer(self):
        node = self.nodes[0]
        self.log.info("Restart with a 50 MiB target; the buffer decides historical serving")
        self.restart_node(0, ["-maxuploadtarget=50"])
        limit = 50 * MiB
        start = self.mocktime
        # The first bytes sent start the cycle at the current mocktime.
        peer = node.add_p2p_connection(BlockReceiver())
        size_limit = node.getblocktemplate()['sizelimit']
        assert_equal(size_limit, 380257)
        # buffer = floor(time_left / 600) * size_limit; serving is off while
        # buffer >= limit (or the bytes sent reach limit - buffer).
        k = -(-limit // size_limit)
        sent = node.getnettotals()['totalbytessent']
        assert_greater_than(limit - sent - 1000, (k - 1) * size_limit)

        self.set_mocktime(start + TIMEFRAME - k * 600)
        target = self.upload_target()
        assert_equal(target['time_left_in_cycle'], k * 600)
        assert_equal(target['serve_historical_blocks'], False)

        self.set_mocktime(self.mocktime + 1)
        target = self.upload_target()
        assert_equal(target['time_left_in_cycle'], k * 600 - 1)
        assert_equal(target['serve_historical_blocks'], True)
        assert_equal(target['target_reached'], False)

        self.log.info("A historical block is served now, and the peer stays")
        assert peer.request_block(self.old_hashes[0])
        assert peer.is_connected

        self.log.info("The cycle ends after the timeframe and restarts with the next bytes")
        self.set_mocktime(start + TIMEFRAME)
        assert_equal(self.upload_target()['time_left_in_cycle'], 0)
        self.set_mocktime(start + TIMEFRAME + 1)
        peer.sync_with_ping()
        target = self.upload_target()
        assert_equal(target['time_left_in_cycle'], TIMEFRAME)
        assert_greater_than(target['bytes_left_in_cycle'], limit - 1000)
        assert_equal(target['serve_historical_blocks'], False)
        node.disconnect_p2ps()

    def test_whitelisted(self):
        node = self.nodes[0]
        self.log.info("A whitelisted peer is served historical blocks")
        self.restart_node(0, ["-maxuploadtarget=1", "-whitelist=127.0.0.1"])
        assert_equal(self.upload_target()['serve_historical_blocks'], False)
        peer = node.add_p2p_connection(BlockReceiver())
        assert_equal(peers(node)[0]['whitelisted'], True)
        assert peer.request_block(self.old_hashes[0])
        assert peer.is_connected
        node.disconnect_p2ps()

    def test_no_and_negative_target(self):
        self.log.info("-maxuploadtarget=0 means no target")
        self.restart_node(0, ["-maxuploadtarget=0"])
        no_target = {
            'timeframe': TIMEFRAME,
            'target': 0,
            'target_reached': False,
            'serve_historical_blocks': True,
            'bytes_left_in_cycle': 0,
            'time_left_in_cycle': 0,
        }
        assert_equal(self.upload_target(), no_target)

        self.log.info("-maxuploadtarget=-1 wraps to a huge target")
        # Card iQg6oeoK item 4: the negative value is multiplied into an
        # unsigned target (same in Bitcoin Core 0.15).
        self.restart_node(0, ["-maxuploadtarget=-1"])
        target = self.upload_target()
        assert_equal(target['target'], 18446744073708503040)
        assert_equal(target['bytes_left_in_cycle'], 18446744073708503040)
        assert_equal(target['target_reached'], False)
        assert_equal(target['serve_historical_blocks'], True)


if __name__ == '__main__':
    MaxUploadTest().main()
