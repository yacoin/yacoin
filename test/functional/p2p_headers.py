#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getheaders answers and a 2000-header sync.

- getheaders on a 2010-block chain: the first locator entry in the active
  chain is the start, at most 2000 headers, hashstop ends the answer (and is
  ignored below the start), an empty locator returns only the hashstop
  header, an unknown or stale-only locator starts at genesis, the tip gives
  an empty answer.
- Known bug: an empty locator also returns the header of a stale block more
  than a month old (getdata refuses that block).
- A second node with -hashcalcthreads=1 syncs 2013 blocks from a mininode:
  two getheaders rounds ("more getheaders (2000)"), the single-thread hash
  path ("Received header"), and "Already have header" for headers it knows.
"""

from test_framework.blocktools import block_hash_rpc, blocks_from_node, create_block_yac, solve_block
from test_framework.messages import CBlockHeader, msg_getheaders, msg_headers
from test_framework.mininode import P2PDataStore, P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, peers, wait_until

UNKNOWN = 0x12345


class HeadersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [[], ["-hashcalcthreads=1"]]

    def setup_network(self):
        # Node 1 syncs from a mininode only.
        self.setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        self.set_mocktime(1600000000)
        hashes = [node.getblockhash(0)] + self.mine_with_mocktime(node, 2010, sync=False)
        self.h = [int(h, 16) for h in hashes]
        # Header hashes aren't computed in Python (10 ms each): a header's
        # height follows from its parent, and the last one is checked by RPC.
        self.height_of = {x: i for i, x in enumerate(self.h)}
        self.peer = node.add_p2p_connection(P2PInterface())
        self.test_getheaders()
        self.test_stale_branch()
        self.test_sync()

    def getheaders(self, locator, hashstop=0):
        """The headers of the answer, or None if the node sent none."""
        with mininode_lock:
            self.peer.last_message.pop('headers', None)
        request = msg_getheaders()
        request.locator.vHave = locator
        request.hashstop = hashstop
        self.peer.send_and_ping(request)
        with mininode_lock:
            answer = self.peer.last_message.get('headers')
        return None if answer is None else answer.headers

    def heights(self, headers):
        """Heights of a consecutive list of headers; checks the chain."""
        heights = [self.height_of[header.hashPrevBlock] + 1 for header in headers]
        assert_equal(heights, list(range(heights[0], heights[0] + len(heights))) if heights else [])
        if headers:
            last = int(block_hash_rpc(self.nodes[0], headers[-1]), 16)
            assert_equal(self.height_of[last], heights[-1])
        return heights

    def assert_answer(self, locator, hashstop, first, last):
        heights = self.heights(self.getheaders(locator, hashstop))
        assert_equal((heights[0], heights[-1], len(heights)), (first, last, last - first + 1))

    def test_getheaders(self):
        h = self.h
        self.log.info("Locator [genesis]: 2000 headers, heights 1-2000")
        self.assert_answer([h[0]], 0, 1, 2000)
        self.log.info("hashstop below the start is ignored: 2000 headers from 11")
        self.assert_answer([h[10]], h[5], 11, 2010)
        self.log.info("hashstop ends the answer")
        self.assert_answer([h[5]], h[10], 6, 10)
        self.assert_answer([h[2005]], h[2008], 2006, 2008)
        self.log.info("The first locator entry the node has in its chain is the start")
        self.assert_answer([UNKNOWN, h[7], h[3]], h[12], 8, 12)
        self.assert_answer([h[3], h[7]], h[12], 4, 12)
        self.log.info("An unknown locator starts at genesis")
        self.assert_answer([UNKNOWN], h[12], 1, 12)
        self.log.info("Locator [tip]: an empty headers message")
        assert_equal(self.getheaders([h[2010]]), [])
        self.log.info("Empty locator: only the hashstop header, nothing for an unknown or zero hashstop")
        self.assert_answer([], h[5], 5, 5)
        assert_equal(self.getheaders([], UNKNOWN), None)
        assert_equal(self.getheaders([], 0), None)

    def test_stale_branch(self):
        node = self.nodes[0]
        self.log.info("A stale block: block A at 2011 loses against a 2-block branch")
        [stale] = self.mine_with_mocktime(node, 1, sync=False)
        b1 = solve_block(node, create_block_yac(node, prev=node.getblockhash(2010)))
        b2 = solve_block(node, create_block_yac(node, prev=b1, height=2012))
        assert_equal([node.submitblock(b.serialize().hex()) for b in (b1, b2)], ["inconclusive", None])
        assert_equal(node.getbestblockhash(), b2.hash)
        assert_equal([(t['height'], t['status']) for t in node.getchaintips() if t['hash'] == stale], [(2011, 'valid-fork')])
        self.height_of[b1.sha256] = 2011
        self.height_of[b2.sha256] = 2012
        stale_int = int(stale, 16)

        self.log.info("A locator with only the stale block starts at genesis, not at the fork")
        self.assert_answer([stale_int], self.h[12], 1, 12)
        self.assert_answer([stale_int, self.h[2005]], 0, 2006, 2012)
        self.log.info("Empty locator, hashstop A: the stale header")
        [header] = self.getheaders([], stale_int)
        assert_equal(block_hash_rpc(node, header), stale)

        self.log.info("31 days later the stale block's header is still served")
        self.set_mocktime(self.mocktime + 31 * 24 * 60 * 60)
        self.mine_with_mocktime(node, 1, sync=False)

        def check():
            headers = self.getheaders([], stale_int) or []
            assert_equal([int(block_hash_rpc(node, x), 16) for x in headers], [])
        self.known_failure("stale headers served (t2B49V3R item 2)", check, "not([%d] == [])" % stale_int)

    def test_sync(self):
        node, fresh = self.nodes
        self.log.info("Node 1 syncs 2013 blocks from a mininode with -hashcalcthreads=1")
        count = node.getblockcount()
        assert_equal(count, 2013)
        blocks = blocks_from_node(node, [node.getblockhash(i) for i in range(1, count + 1)])
        store = P2PDataStore()
        for block in blocks:
            store.block_store[block.sha256] = block
        store.last_block_hash = blocks[-1].sha256
        with fresh.assert_debug_log(["more getheaders (2000) to end to peer=", "Received header"],
                                    unexpected_msgs=["HashCalcThread"]):
            fresh.add_p2p_connection(store)
            wait_until(lambda: fresh.getblockcount() == count, timeout=120)
        assert_equal(fresh.getbestblockhash(), node.getbestblockhash())
        [info] = peers(fresh)
        assert_equal((info['synced_headers'], info['synced_blocks'], info['inflight']), (count, count, []))

        self.log.info("Known headers again: \"Already have header\", no getdata")
        with mininode_lock:
            requested = len(store.getdata_requests)
        assert_equal(requested, count)
        with fresh.assert_debug_log(["Already have header"]):
            store.send_and_ping(msg_headers([CBlockHeader(block) for block in blocks[-5:]]))
        with mininode_lock:
            assert_equal(len(store.getdata_requests), requested)


if __name__ == '__main__':
    HeadersTest().main()
