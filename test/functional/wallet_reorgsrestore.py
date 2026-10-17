#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet's transaction state after a reorg while it was not loaded.

Port of Bitcoin Core 0.19 wallet_reorgsrestore.py, adapted to YACoin.

- A transaction whose conflict is 9 blocks deep shows confirmations == -9,
  also after a restart (the conflict is stored with the transaction).
- Node 0's wallet file is then loaded on node 1, whose chain node 0 never
  saw: there the transaction and the conflicted transaction were mined in
  other blocks. The startup rescan from the wallet's stored best block
  (its fork point with node 1's chain) confirms both in their new blocks,
  and the transaction that won on node 0's chain becomes the conflicted one.
"""
from decimal import Decimal
import os
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, connect_nodes, disconnect_nodes


class ReorgsRestoreTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        n0, n1, n2 = self.nodes
        # Send a tx from which to conflict outputs later
        txid_conflict_from = n0.sendtoaddress(address=n0.getnewaddress(), amount=Decimal("10"))
        n0.generate(1)
        self.sync_blocks()

        # Disconnect node1 from others to reorg its chain later
        disconnect_nodes(n0, 1)
        disconnect_nodes(n1, 0)
        disconnect_nodes(n1, 2)
        disconnect_nodes(n2, 1)
        connect_nodes(n0, 2)

        # Keep the 10 YAC output for the conflicts: YACoin's coin selection
        # would otherwise spend it in the next send.
        nA = next(d["vout"] for d in n0.gettransaction(txid_conflict_from)["details"] if d["amount"] == Decimal("10"))
        assert n0.lockunspent(False, [{"txid": txid_conflict_from, "vout": nA}])

        # Send a tx to be unconfirmed later
        txid = n0.sendtoaddress(address=n0.getnewaddress(), amount=Decimal("10"))
        tx = n0.gettransaction(txid)
        n0.generate(4)
        self.sync_blocks([n0, n2])
        tx_before_reorg = n0.gettransaction(txid)
        assert_equal(tx_before_reorg["confirmations"], 4)

        # Disconnect node0 from node2 to broadcast a conflict on their respective chains
        disconnect_nodes(n0, 2)
        disconnect_nodes(n2, 0)
        inputs = [{"txid": txid_conflict_from, "vout": nA}]
        outputs_1 = {n0.getnewaddress(): Decimal("9.99")}
        outputs_2 = {n0.getnewaddress(): Decimal("9.99")}
        conflicted = n0.signrawtransaction(n0.createrawtransaction(inputs, outputs_1))
        conflicting = n0.signrawtransaction(n0.createrawtransaction(inputs, outputs_2))
        assert conflicted["complete"] and conflicting["complete"]

        conflicted_txid = n0.sendrawtransaction(conflicted["hex"])
        n0.generate(1)
        conflicting_txid = n2.sendrawtransaction(conflicting["hex"])
        n2.generate(9)

        # Reconnect node0 and node2 and check that conflicted_txid is effectively conflicted
        connect_nodes(n0, 2)
        self.sync_blocks([n0, n2])
        conflicted_tx = n0.gettransaction(conflicted_txid)
        conflicting_tx = n0.gettransaction(conflicting_txid)
        assert_equal(conflicted_tx["confirmations"], -9)
        assert_equal(conflicting_tx["confirmations"], 9)
        assert 'walletconflicts' not in conflicted_tx  # Core lists the conflict here; YACoin has no such field

        # Node0 wallet is shutdown
        self.stop_node(0)
        self.start_node(0)
        assert_equal(n0.gettransaction(conflicted_txid)["confirmations"], -9)

        # The block chain re-orgs and the tx is included in a different block
        n1.generate(9)
        n1.sendrawtransaction(tx["hex"])
        n1.generate(1)
        n1.sendrawtransaction(conflicted["hex"])
        n1.generate(1)

        # Node0 wallet file is loaded on node1, whose chain never had node0's blocks
        self.stop_node(1)
        n0.backupwallet(os.path.join(n0.datadir, 'wallet.bak'))
        shutil.copyfile(os.path.join(n0.datadir, 'wallet.bak'), os.path.join(n1.datadir, 'wallet.dat'))
        self.start_node(1)
        tx_after_reorg = n1.gettransaction(txid)
        # Check that normal confirmed tx is confirmed again but with different blockhash
        assert_equal(tx_after_reorg["confirmations"], 2)
        assert tx_before_reorg["blockhash"] != tx_after_reorg["blockhash"]
        conflicted_after_reorg = n1.gettransaction(conflicted_txid)
        # Check that conflicted tx is confirmed again with blockhash different than previously conflicting tx
        assert_equal(conflicted_after_reorg["confirmations"], 1)
        assert conflicting_tx["blockhash"] != conflicted_after_reorg["blockhash"]
        # The rescan finds the conflicted tx in node 1's chain and marks the
        # wallet's other spend of the same output as conflicted.
        assert_equal(n1.gettransaction(conflicting_txid)["confirmations"], -1)


if __name__ == '__main__':
    ReorgsRestoreTest().main()
