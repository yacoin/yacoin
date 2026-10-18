#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test submitblock's BIP22 results.

node1 takes node0's chain through submitblock only (the two nodes are never
connected), then gets blocks built in Python:
- accepted (null), "duplicate" (also with the BIP22 dummy argument);
- decode errors and a block without a coinbase;
- a block whose hash misses its target: a reject without a reason string
  today, not stored;
- "prev-blk-not-found";
- a side-branch block: "inconclusive", then "duplicate-inconclusive";
- a block that fails when connected: its reason, then "duplicate-invalid"
  (also from a proposal).
"""

import copy
import random

from test_framework.blocktools import create_block_yac, solve_block
from test_framework.messages import CBlock
from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class SubmitBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node0, node1 = self.nodes
        self.mine_with_mocktime(node0, 20, sync=False)

        self.log.info("Another node's blocks, in order")
        for height in range(1, 21):
            assert_equal(node1.submitblock(node0.getblock(node0.getblockhash(height), 0)), None)
        assert_equal(node1.getbestblockhash(), node0.getbestblockhash())

        self.log.info("Duplicates, with and without the dummy argument")
        tip_hex = node0.getblock(node0.getbestblockhash(), 0)
        assert_equal(node1.submitblock(tip_hex), "duplicate")
        assert_equal(node1.submitblock(tip_hex, 'x'), "duplicate")
        assert_equal(node1.submitblock(hexdata=tip_hex, dummy=1), "duplicate")

        self.log.info("Undecodable blocks, blocks without a coinbase, argument count")
        assert_raises_rpc_error(-22, "Block decode failed", node1.submitblock, '00')
        assert_raises_rpc_error(-22, "Block decode failed", node1.submitblock, 'zz')
        # getblocktemplate (create_block_yac) needs a peer
        node1.add_p2p_connection(P2PInterface())
        block = create_block_yac(node1)
        no_txs = CBlock(block)
        assert_raises_rpc_error(-22, "Block does not start with a coinbase", node1.submitblock, no_txs.serialize().hex())
        no_coinbase = CBlock(block)
        no_coinbase.vtx = copy.deepcopy(block.vtx)
        no_coinbase.vtx[0].vin[0].prevout.hash = 1
        no_coinbase.vtx[0].rehash()
        assert_raises_rpc_error(-22, "Block does not start with a coinbase", node1.submitblock, no_coinbase.serialize().hex())
        assert_raises_rpc_error(-1, 'submitblock "hexdata"', node1.submitblock)
        assert_raises_rpc_error(-1, 'submitblock "hexdata"', node1.submitblock, '00', 1, 2)

        self.log.info("Hash above the target: rejected, not stored")
        tip = node1.getbestblockhash()
        unsolved = solve_block(node1, copy.deepcopy(block), invalid=True)
        result = node1.submitblock(unsolved.serialize().hex())
        # The block validity tests own the exact string (today a reject
        # without a reason); here only that it is a reject.
        assert isinstance(result, str) and result, result
        assert result not in ("duplicate", "duplicate-invalid", "duplicate-inconclusive", "inconclusive"), result
        assert_equal(node1.getbestblockhash(), tip)
        assert_raises_rpc_error(-5, "Block not found", node1.getblockheader, unsolved.hash)
        assert_equal(node1.submitblock(unsolved.serialize().hex()), result)

        self.log.info("Unknown parent")
        orphan = copy.deepcopy(block)
        orphan.hashPrevBlock = random.getrandbits(256)
        solve_block(node1, orphan)
        assert_equal(node1.submitblock(orphan.serialize().hex()), "prev-blk-not-found")
        assert_equal(node1.getbestblockhash(), tip)

        self.log.info("A valid block")
        solve_block(node1, block)
        assert_equal(node1.submitblock(block.serialize().hex()), None)
        assert_equal(node1.getbestblockhash(), block.hash)
        assert_equal(node1.calculateblockhash(block.serialize().hex()), block.hash)

        self.log.info("A side-branch block: stored, not connected")
        side = solve_block(node1, create_block_yac(node1, prev='%064x' % block.hashPrevBlock))
        assert_equal(node1.submitblock(side.serialize().hex()), "inconclusive")
        assert_equal(node1.submitblock(side.serialize().hex()), "duplicate-inconclusive")
        assert_equal(node1.getbestblockhash(), block.hash)
        tips = {t['hash']: t for t in node1.getchaintips()}
        assert_equal((tips[side.hash]['status'], tips[side.hash]['branchlen']), ('valid-headers', 1))

        self.log.info("A block that fails when connected")
        tmpl = node1.getblocktemplate()
        bad = solve_block(node1, create_block_yac(node1, tmpl=tmpl, coinbase_value=tmpl['coinbasevalue'] + 1))
        assert_equal(node1.submitblock(bad.serialize().hex()), "bad-cb-amount")
        assert_equal(node1.submitblock(bad.serialize().hex()), "duplicate-invalid")
        assert_equal(node1.getblocktemplate({'mode': 'proposal', 'data': bad.serialize().hex()}), "duplicate-invalid")
        assert_equal(node1.getbestblockhash(), block.hash)
        tips = {t['hash']: t for t in node1.getchaintips()}
        assert_equal(tips[bad.hash]['status'], 'invalid')


if __name__ == '__main__':
    SubmitBlockTest().main()
