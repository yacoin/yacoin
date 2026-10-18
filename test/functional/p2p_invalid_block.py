#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test invalid blocks sent by a peer.

- A copy of a block with its last transaction duplicated (same merkle root,
  CVE-2012-2459) and a copy whose coinbase doesn't match the merkle root are
  rejected (bad-txns-duplicate, bad-txnmrklroot) and the peer is
  disconnected, but the block isn't marked invalid: the genuine block is
  accepted afterwards.
- A block whose coinbase pays too much is rejected (bad-cb-amount) and marked
  invalid; the same block from another peer gets no reject and no penalty,
  a child of it is rejected (bad-prevblk).
- A block with a transaction spending one output twice is rejected
  (bad-txns-inputs-duplicate) without an index entry.

Valid blocks come from a donor node that mines them unconnected.
"""

from test_framework.blocktools import (
    blocks_from_node,
    create_block_yac,
    get_template,
    mutate_duplicate_last_tx,
    mutate_merkle_mismatch,
    solve_block,
)
from test_framework.messages import COIN, REJECT_INVALID, COutPoint, CTransaction, CTxIn, CTxOut, msg_block
from test_framework.mininode import P2PInterface
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, disconnect_nodes, node_peers, wait_until


class InvalidBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = False

    def setup_network(self):
        # Node 1 is the donor and stays unconnected.
        self.setup_nodes()

    def tip_entries(self, block_hash):
        return [tip['status'] for tip in self.nodes[0].getchaintips() if tip['hash'] == block_hash]

    def new_peer(self):
        self.nodes[0].disconnect_p2ps()
        return self.nodes[0].add_p2p_connection(P2PInterface())

    def send_rejected(self, peer, block, reason):
        """Send block; the node rejects it with reason and disconnects the peer."""
        peer.send_message(msg_block(block))
        peer.wait_for_reject(message=b"block", code=REJECT_INVALID, reason=reason, data=block.sha256)
        peer.wait_for_disconnect()

    def run_test(self):
        node, donor = self.nodes
        # The framework mined block 41 on node 0 only.
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        wait_until(lambda: node_peers(node) == [] and node_peers(donor) == [])

        self.log.info("The donor mines two blocks with three transactions each")
        hashes = []
        for _ in range(2):
            donor.sendtoaddress(address=donor.getnewaddress(), amount=1)
            donor.sendtoaddress(address=donor.getnewaddress(), amount=2)
            hashes += donor.generate(1)
        block_d, block_e = blocks_from_node(donor, hashes)
        assert_equal([len(block_d.vtx), len(block_e.vtx)], [3, 3])
        tip = node.getbestblockhash()

        self.log.info("The last transaction duplicated: bad-txns-duplicate, the peer is disconnected")
        peer = self.new_peer()
        with node.assert_debug_log(["not banning local peer"]):
            self.send_rejected(peer, mutate_duplicate_last_tx(block_d), b"bad-txns-duplicate")
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(self.tip_entries(block_d.hash), [])
        self.log.info("The genuine block is accepted")
        peer = self.new_peer()
        peer.send_message(msg_block(block_d))
        peer.sync_with_ping()
        assert_equal(node.getbestblockhash(), block_d.hash)

        self.log.info("A coinbase not matching the merkle root: bad-txnmrklroot")
        self.send_rejected(peer, mutate_merkle_mismatch(block_e), b"bad-txnmrklroot")
        assert_equal(node.getbestblockhash(), block_d.hash)
        assert_equal(self.tip_entries(block_e.hash), [])
        self.log.info("The genuine block is accepted")
        peer = self.new_peer()
        peer.send_message(msg_block(block_e))
        peer.sync_with_ping()
        assert_equal(node.getbestblockhash(), block_e.hash)

        self.log.info("A coinbase paying too much: bad-cb-amount, and the block is marked invalid")
        tmpl = get_template(node)
        bad = solve_block(node, create_block_yac(node, coinbase_value=tmpl['coinbasevalue'] + 1))
        self.send_rejected(peer, bad, b"bad-cb-amount")
        wait_until(lambda: self.tip_entries(bad.hash) == ['invalid'])
        assert_equal(node.getbestblockhash(), block_e.hash)

        self.log.info("The same block from another peer: no reject, no disconnect")
        peer = self.new_peer()
        peer.send_message(msg_block(bad))
        peer.sync_with_ping()
        assert_equal(peer.rejects, [])
        assert peer.is_connected

        self.log.info("A child of the invalid block: bad-prevblk")
        child = solve_block(node, create_block_yac(node, prev=bad, height=tmpl['height'] + 1, nbits=bad.nBits, ntime=bad.nTime))
        self.send_rejected(peer, child, b"bad-prevblk")
        assert_equal(self.tip_entries(child.hash), [])

        self.log.info("A transaction spending one output twice: bad-txns-inputs-duplicate, no index entry")
        peer = self.new_peer()
        utxo = node.listunspent()[0]
        tx = CTransaction()
        tx.nTime = node.getblockheader(node.getbestblockhash())['time']
        tx.vin = [CTxIn(COutPoint(int(utxo['txid'], 16), utxo['vout']))] * 2
        tx.vout = [CTxOut(COIN, CScript([OP_TRUE]))]
        tx.rehash()
        block = solve_block(node, create_block_yac(node, [tx]))
        self.send_rejected(peer, block, b"bad-txns-inputs-duplicate")
        assert_equal(self.tip_entries(block.hash), [])
        assert_equal(node.getbestblockhash(), block_e.hash)


if __name__ == '__main__':
    InvalidBlockTest().main()
