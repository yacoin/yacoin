#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool re-org scenarios.

Test re-org scenarios with a mempool that contains transactions
that spend (directly or indirectly) coinbase transactions.
"""

from test_framework.blocktools import create_raw_transaction
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MempoolCoinbaseTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    alert_filename = None  # Set by setup_network

    def run_test(self):
        # Start with a 41 block chain
        assert_equal(self.nodes[0].getblockcount(), 41)

        # Mine 8 blocks. After this, nodes[0] blocks
        # 41, 42, and 43 are spend-able.
        new_blocks = self.nodes[0].generate(8)
        self.sync_all()

        node0_address = self.nodes[0].getnewaddress()
        node1_address = self.nodes[1].getnewaddress()

        # Three scenarios for re-orging coinbase spends in the memory pool:
        # 1. Direct coinbase spend  :  spend_41
        # 2. Indirect (coinbase spend in chain, child in mempool) : spend_42 and spend_42_1
        # 3. Indirect (coinbase and child both in chain) : spend_43 and spend_43_1
        # Use invalidatblock to make all of the above coinbase spends invalid (immature coinbase),
        # and make sure the mempool code behaves correctly.
        b = [ self.nodes[0].getblockhash(n) for n in range(41, 45) ]
        coinbase_txids = [ self.nodes[0].getblock(h)['tx'][0] for h in b ]
        spend_41_raw = create_raw_transaction(self.nodes[0], coinbase_txids[1], node1_address, amount=2.1)
        spend_42_raw = create_raw_transaction(self.nodes[0], coinbase_txids[2], node0_address, amount=2.1)
        spend_43_raw = create_raw_transaction(self.nodes[0], coinbase_txids[3], node0_address, amount=2.1)

        # Create a transaction which is time-locked to two blocks in the future
        timelock_tx = self.nodes[0].createrawtransaction([{"txid": coinbase_txids[0], "vout": 0}], {node0_address: 2})
        # Set the time lock
        timelock_tx = timelock_tx.replace("ffffffff", "11111191", 1)
        timelock_tx = timelock_tx[:-8] + hex(self.nodes[0].getblockcount() + 2)[2:] + "000000"
        timelock_tx = self.nodes[0].signrawtransaction(timelock_tx)["hex"]
        # This will raise an exception because the timelock transaction is too immature to spend
        assert_raises_rpc_error(-26, "non-final", self.nodes[0].sendrawtransaction, timelock_tx)

        # Broadcast and mine spend_42 and 43:
        spend_42_id = self.nodes[0].sendrawtransaction(spend_42_raw)
        spend_43_id = self.nodes[0].sendrawtransaction(spend_43_raw)
        self.nodes[0].generate(1)
        # Time-locked transaction is still too immature to spend
        assert_raises_rpc_error(-26, 'non-final', self.nodes[0].sendrawtransaction, timelock_tx)

        # Create 42_1 and 43_1:
        spend_42_1_raw = create_raw_transaction(self.nodes[0], spend_42_id, node1_address, amount=2)
        spend_43_1_raw = create_raw_transaction(self.nodes[0], spend_43_id, node1_address, amount=2)

        # Broadcast and mine 43_1:
        spend_43_1_id = self.nodes[0].sendrawtransaction(spend_43_1_raw)
        last_block = self.nodes[0].generate(1)
        # Time-locked transaction can now be spent
        timelock_tx_id = self.nodes[0].sendrawtransaction(timelock_tx)

        # ... now put spend_41 and spend_42_1 in memory pools:
        spend_41_id = self.nodes[0].sendrawtransaction(spend_41_raw)
        spend_42_1_id = self.nodes[0].sendrawtransaction(spend_42_1_raw)

        self.sync_all(timeout=720)

        assert_equal(set(self.nodes[0].getrawmempool()), {spend_41_id, spend_42_1_id, timelock_tx_id})

        for node in self.nodes:
            node.invalidateblock(last_block[0])
        # Time-locked transaction is now too immature and has been removed from the mempool
        # spend_43_1 has been re-orged out of the chain and is back in the mempool
        assert_equal(set(self.nodes[0].getrawmempool()), {spend_41_id, spend_42_1_id, spend_43_1_id})

        # Use invalidateblock to re-org back and make all those coinbase spends
        # immature/invalid:
        for node in self.nodes:
            node.invalidateblock(new_blocks[0])

        self.sync_all(timeout=720)

        # mempool should be empty.
        assert_equal(set(self.nodes[0].getrawmempool()), set())


if __name__ == '__main__':
    MempoolCoinbaseTest().main()
