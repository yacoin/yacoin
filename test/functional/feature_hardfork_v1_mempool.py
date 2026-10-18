#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a version 1 transaction one block before the 1.0 fork.

Version 1 transactions are valid up to the block before the fork. One that
reaches the mempool when the next block is the fork block must not stop the
nodes from mining: either the mempool refuses it, or the fork block leaves
it out and it leaves the mempool.

The fork is at block 510 because before the fork a coinbase needs 500 blocks
to mature, so only then is there an output to spend. This is a separate
script because today the transaction stays in every mempool and no node can
mine afterwards.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, disconnect_nodes, node_peers, wait_until
from test_framework.yac_tx import key_from_wif, p2pkh_script, sign_p2pkh_input, to_v1

FORK = 510


class HardforkV1MempoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.block_fork_1_0 = FORK

    def v1_coinbase_spend(self, height):
        """A signed version 1 spend of the coinbase of block height."""
        node = self.nodes[0]
        coinbase = node.getblock(node.getblockhash(height), 2)['tx'][0]
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(coinbase['txid'], 16), 0))]
        tx.vout = [CTxOut(int(coinbase['vout'][0]['value'] * COIN) - COIN // 100, p2pkh_script(self.pubkey))]
        tx = to_v1(tx)
        sign_p2pkh_input(tx, 0, self.key)
        return tx

    def run_test(self):
        n0, n1 = self.nodes
        self.key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        self.pubkey = self.key.get_pubkey().get_bytes()
        self.set_mocktime(TIME_GENESIS_BLOCK)
        self.mine_with_mocktime(n0, FORK - 2, sync=False)
        self.sync_all()

        self.log.info("Two blocks before the fork a version 1 transaction is accepted and mined")
        v1a = self.v1_coinbase_spend(1)
        assert_equal(n0.sendrawtransaction(v1a.serialize().hex()), v1a.hash)
        block_hash = self.mine_with_mocktime(n0, 1, sync=False)[0]
        assert v1a.hash in n0.getblock(block_hash)['tx']
        self.sync_blocks()
        assert_equal(n0.getrawmempool(), [])

        self.log.info("One block before the fork a version 1 transaction must not block mining")
        assert_equal(n0.getblockcount(), FORK - 1)
        v1b = self.v1_coinbase_spend(2)

        def check():
            try:
                n0.sendrawtransaction(v1b.serialize().hex())
            except JSONRPCException:
                # Refused by the mempool.
                assert v1b.hash not in n0.getrawmempool()
                return
            # It reaches node 1 too.
            self.sync_mempools()
            disconnect_nodes(n0, 1)
            wait_until(lambda: node_peers(n0) == [] and node_peers(n1) == [])
            self.set_mocktime(self.mocktime + 60)
            for node in (n0, n1):
                block_hash = node.generate(1)[0]
                assert v1b.hash not in node.getblock(block_hash)['tx']
                assert_equal(node.getrawmempool(), [])

        self.known_failure("C-S1 (MbqE60TC item 1)", check, "ProcessNewBlock, block not accepted")


if __name__ == '__main__':
    HardforkV1MempoolTest().main()
