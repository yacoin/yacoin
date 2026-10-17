#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getblocks, getdata and oversize inv/getdata messages.

- getblocks on a 511-block chain: an inv of at most 500 blocks after the
  first locator entry in the active chain, ended by hashstop.
- After a 500-block answer, the getdata for the last block is followed by an
  inv of the tip (hashContinue), once.
- A getdata mixing transactions and blocks is answered in order; the
  unknown transactions get a notfound after each block.
- inv and getdata with 50001 entries are refused (+20 each); 50000 unknown
  transactions get one notfound with 50000 entries.
- A block on a stale branch is served while it is recent, and refused once
  the best chain is more than a month newer.
"""
import struct

from test_framework.blocktools import blocks_from_node
from test_framework.messages import (
    MSG_BLOCK,
    MSG_TX,
    CInv,
    msg_generic,
    msg_getblocks,
    msg_getdata,
    ser_compact_size,
)
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, disconnect_nodes, peers, wait_until


class Recorder(P2PInterface):
    """Keeps inv, block, tx and notfound messages in arrival order."""
    def __init__(self):
        super().__init__()
        self.seq = []

    def on_inv(self, message):
        self.seq.append(('inv', [(inv.type, inv.hash) for inv in message.inv]))

    def on_block(self, message):
        message.block.calc_sha256()
        self.seq.append(('block', message.block.sha256))

    def on_tx(self, message):
        message.tx.calc_sha256()
        self.seq.append(('tx', message.tx.sha256))

    def on_notfound(self, message):
        self.seq.append(('notfound', [(inv.type, inv.hash) for inv in message.vec]))

    def take(self):
        self.sync_with_ping()
        with mininode_lock:
            seq, self.seq = self.seq, []
        return seq


def oversize(command, count):
    """A getdata or inv with count MSG_TX entries, built as raw bytes."""
    return msg_generic(command, ser_compact_size(count) + (struct.pack("<I", MSG_TX) + b"\x07" * 32) * count)


class GetBlocksInvTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Whitelisted peers get transaction invs on every pass of the send loop.
        self.extra_args = [["-whitelist=127.0.0.1"], []]

    def setup_network(self):
        # Node 1 is a donor that mines unconnected.
        self.setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        self.set_mocktime(1600000000)
        self.h = [int(node.getblockhash(0), 16)] + [int(x, 16) for x in self.mine_with_mocktime(node, 511, sync=False)]
        self.peer = node.add_p2p_connection(Recorder())
        self.peer_id = peers(node)[0]['id']
        self.test_getblocks()
        self.test_hash_continue()
        self.test_mixed_getdata()
        self.test_oversize()
        self.test_stale_block()

    def wait_announced(self, block_hash):
        """Wait for the inv (or the block) the node sends for a block it mined."""
        x = int(block_hash, 16)
        wait_until(lambda: any(m == ('block', x) or (m[0] == 'inv' and (MSG_BLOCK, x) in m[1]) for m in self.peer.seq),
                   timeout=30, lock=mininode_lock)

    def getblocks(self, locator, hashstop=0):
        request = msg_getblocks()
        request.locator.vHave = locator
        request.hashstop = hashstop
        self.peer.send_message(request)
        return self.peer.take()

    def block_inv(self, first, last):
        return [('inv', [(MSG_BLOCK, x) for x in self.h[first:last + 1]])]

    def test_getblocks(self):
        node, h = self.nodes[0], self.h
        self.log.info("Locator [genesis]: blocks 1-500")
        with node.assert_debug_log(["getblocks 1 to end limit 500 from peer=%d" % self.peer_id,
                                    "getblocks stopping at limit 500 %064x" % h[500]]):
            assert_equal(self.getblocks([h[0]]), self.block_inv(1, 500))
        self.log.info("Locator [10]: blocks 11-510 (the log shows the height, not the limit)")
        with node.assert_debug_log(["getblocks stopping at limit 510 %064x" % h[510]]):
            assert_equal(self.getblocks([h[10]]), self.block_inv(11, 510))
        self.log.info("hashstop 10: blocks 1-9")
        with node.assert_debug_log(["getblocks stopping at 10 %064x" % h[10]]):
            assert_equal(self.getblocks([h[0]], h[10]), self.block_inv(1, 9))
        self.log.info("The first locator entry in the chain is the start; the tip gives nothing")
        assert_equal(self.getblocks([h[506], h[3]]), self.block_inv(507, 511))
        assert_equal(self.getblocks([h[511]]), [])
        self.log.info("An empty locator starts at genesis")
        assert_equal(self.getblocks([]), self.block_inv(1, 500))

    def test_hash_continue(self):
        h = self.h
        self.log.info("After a 500-block answer, the getdata for block 500 is followed by an inv of the tip, once")
        # The last getblocks above ended at block 500.
        self.peer.send_message(msg_getdata([CInv(MSG_BLOCK, h[510])]))
        assert_equal(self.peer.take(), [('block', h[510])])
        self.peer.send_message(msg_getdata([CInv(MSG_BLOCK, h[500])]))
        assert_equal(self.peer.take(), [('block', h[500]), ('inv', [(MSG_BLOCK, h[511])])])
        self.peer.send_message(msg_getdata([CInv(MSG_BLOCK, h[500])]))
        assert_equal(self.peer.take(), [('block', h[500])])

    def test_mixed_getdata(self):
        node, h = self.nodes[0], self.h
        self.log.info("Mixed getdata: answered in order, a notfound after each block")
        txid = int(node.sendtoaddress(address=node.getnewaddress(), amount=1), 16)
        # The announcement puts the transaction in the relay memory getdata serves.
        wait_until(lambda: ('inv', [(MSG_TX, txid)]) in self.peer.seq, timeout=30, lock=mininode_lock)
        self.peer.take()
        self.peer.send_message(msg_getdata([CInv(MSG_TX, txid), CInv(MSG_TX, 777), CInv(MSG_BLOCK, h[3]),
                                            CInv(MSG_TX, 888), CInv(MSG_BLOCK, h[4]), CInv(MSG_TX, txid)]))
        assert_equal(self.peer.take(), [('tx', txid), ('block', h[3]), ('notfound', [(MSG_TX, 777)]),
                                        ('block', h[4]), ('notfound', [(MSG_TX, 888)]), ('tx', txid)])
        [block] = self.mine_with_mocktime(node, 1, sync=False)
        assert_equal(node.getrawmempool(), [])
        self.wait_announced(block)
        self.peer.take()

    def test_oversize(self):
        node = self.nodes[0]
        self.log.info("getdata and inv with 50001 entries: refused, +20 each")
        with node.assert_debug_log(["message getdata size() = 50001"]):
            self.peer.send_message(oversize(b"getdata", 50001))
            assert_equal(self.peer.take(), [])
        assert_equal(peers(node)[0]['banscore'], 20)
        with node.assert_debug_log(["message inv size() = 50001"]):
            self.peer.send_message(oversize(b"inv", 50001))
            assert_equal(self.peer.take(), [])
        assert_equal(peers(node)[0]['banscore'], 40)
        self.log.info("getdata with 50000 unknown transactions: one notfound with all of them")
        with node.assert_debug_log(["received getdata (50000 invsz)"]):
            self.peer.send_message(oversize(b"getdata", 50000))
            seq = self.peer.take()
        assert_equal([(cmd, len(entries)) for cmd, entries in seq], [('notfound', 50000)])
        assert_equal(peers(node)[0]['banscore'], 40)

    def test_stale_block(self):
        node, donor = self.nodes
        self.log.info("A block on a stale branch is served while it is recent")
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        wait_until(lambda: node.getconnectioncount() == 1)
        assert_equal(node.getblockcount(), 512)
        [stale] = self.mine_with_mocktime(node, 1, sync=False)
        branch = blocks_from_node(donor, self.mine_with_mocktime(donor, 2, sync=False))
        assert_equal([node.submitblock(b.serialize().hex()) for b in branch], ["inconclusive", None])
        assert_equal([t['status'] for t in node.getchaintips() if t['hash'] == stale], ['valid-fork'])
        assert_equal(node.getrawmempool(), [])
        self.peer.take()
        self.peer.send_message(msg_getdata([CInv(MSG_BLOCK, int(stale, 16))]))
        assert_equal(self.peer.take(), [('block', int(stale, 16))])

        self.log.info("31 days later it is refused")
        self.set_mocktime(self.mocktime + 31 * 24 * 60 * 60)
        [tip] = self.mine_with_mocktime(node, 1, sync=False)
        self.wait_announced(tip)
        self.peer.take()
        with node.assert_debug_log(["ignoring request from peer=%d for old block that isn't in the main chain" % self.peer_id]):
            self.peer.send_message(msg_getdata([CInv(MSG_BLOCK, int(stale, 16))]))
            assert_equal(self.peer.take(), [])


if __name__ == '__main__':
    GetBlocksInvTest().main()
