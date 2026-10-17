#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet accounts when a transaction is double spent
(adapted from Bitcoin Core's txn_doublespend.py).

Node 0 funds the accounts foo and bar, sends from both to node 1 (tx1, tx2)
and signs, without broadcasting, a transaction that spends both funding
outputs differently. The other half of the split network mines that double
spend; after the networks join, tx1 and tx2 are conflicted and the balances
of the wallet and of each account reflect only the double spend. With
--mineblock, node 0 mines tx1 and tx2 first.

Porting notes: mined coins belong to the 'coinbase' account; node 0's
mature coinbases don't change during the test (its next coinbase matures
only later), so Bitcoin Core's subsidy terms are dropped; tx1 and tx2 each
spend one known funding output (the other coins are locked), as in Core
where every coin was a 50 BTC coinbase.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
    find_output,
    sync_blocks,
)
from test_framework.wallet_util import mature_coinbase_total


def spend_only(node, txid, vout):
    """Lock every unspent output of node's wallet except txid:vout."""
    node.lockunspent(True)
    node.lockunspent(False, [{'txid': u['txid'], 'vout': u['vout']} for u in node.listunspent(0)
                             if (u['txid'], u['vout']) != (txid, vout)])


class TxnMallTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def add_options(self, parser):
        parser.add_argument("--mineblock", dest="mine_block", default=False, action="store_true",
                            help="Test double-spend of 1-confirmed transaction")

    def setup_network(self):
        # Start with split network:
        super().setup_network()
        disconnect_nodes(self.nodes[1], 2)
        disconnect_nodes(self.nodes[2], 1)

    def run_test(self):
        node0, node1, node2 = self.nodes[:3]
        coinbase_address = node0.get_deterministic_priv_key().address
        starting_balance = node0.getbalance()
        assert_equal(starting_balance, mature_coinbase_total(node0, coinbase_address))
        foo_amount = (starting_balance * Decimal('0.6')).quantize(Decimal('1'))
        bar_amount = (starting_balance * Decimal('0.2')).quantize(Decimal('1'))

        self.log.info("Fund foo and bar, sign a double spend of both")
        # Assign coins to foo and bar accounts:
        fund_foo_txid = node0.sendfrom('coinbase', node0.getnewaddress('foo'), foo_amount)
        fund_foo_tx = node0.gettransaction(fund_foo_txid)
        fund_bar_txid = node0.sendfrom('coinbase', node0.getnewaddress('bar'), bar_amount)
        fund_bar_tx = node0.gettransaction(fund_bar_txid)
        fund_fees = fund_foo_tx['fee'] + fund_bar_tx['fee']
        assert_equal(node0.getbalance('coinbase'), starting_balance - foo_amount - bar_amount + fund_fees)

        # Coins are sent to node1_address
        node1_address = node1.getnewaddress('from0')

        # First: use raw transaction API to send foo + bar - 2 to node1_address,
        # but don't broadcast:
        doublespend_fee = Decimal('-0.02')
        foo_vout = find_output(node0, fund_foo_txid, foo_amount)
        bar_vout = find_output(node0, fund_bar_txid, bar_amount)
        inputs = [{'txid': fund_foo_txid, 'vout': foo_vout}, {'txid': fund_bar_txid, 'vout': bar_vout}]
        doublespend_amount = foo_amount + bar_amount - 2
        outputs = {node1_address: doublespend_amount, node0.getnewaddress(): 2 + doublespend_fee}
        doublespend = node0.signrawtransaction(node0.createrawtransaction(inputs, outputs))
        assert_equal(doublespend['complete'], True)

        self.log.info("Send from foo and bar")
        # Create two spends using one funding output each
        spend_only(node0, fund_foo_txid, foo_vout)
        txid1 = node0.sendfrom('foo', node1_address, 4, True, 0)
        spend_only(node0, fund_bar_txid, bar_vout)
        txid2 = node0.sendfrom('bar', node1_address, 2, True, 0)
        node0.lockunspent(True)

        # Have node0 mine a block:
        if self.options.mine_block:
            node0.generate(1)
            sync_blocks(self.nodes[0:2])

        tx1 = node0.gettransaction(txid1)
        tx2 = node0.gettransaction(txid2)

        # Node0's balance should be the starting balance minus tx1 and tx2
        # amounts, and minus transaction fees:
        expected = starting_balance + fund_fees + tx1['amount'] + tx1['fee'] + tx2['amount'] + tx2['fee']
        assert_equal(node0.getbalance(), expected)

        # foo and bar accounts should be debited:
        assert_equal(node0.getbalance('foo', 0), foo_amount + tx1['amount'] + tx1['fee'])
        assert_equal(node0.getbalance('bar', 0), bar_amount + tx2['amount'] + tx2['fee'])

        if self.options.mine_block:
            assert_equal(tx1['confirmations'], 1)
            assert_equal(tx2['confirmations'], 1)
            # Node1's "from0" balance should be both transaction amounts:
            assert_equal(node1.getbalance('from0'), -(tx1['amount'] + tx2['amount']))
        else:
            assert_equal(tx1['confirmations'], 0)
            assert_equal(tx2['confirmations'], 0)

        self.log.info("Mine the double spend on the other half")
        # Now give doublespend and its parents to miner:
        node2.sendrawtransaction(fund_foo_tx['hex'])
        node2.sendrawtransaction(fund_bar_tx['hex'])
        doublespend_txid = node2.sendrawtransaction(doublespend['hex'])
        # ... mine a block...
        node2.generate(1)

        # Reconnect the split network, and sync chain:
        connect_nodes(node1, 2)
        node2.generate(1)  # Mine another block to make sure we sync
        sync_blocks(self.nodes)
        assert_equal(node0.gettransaction(doublespend_txid)['confirmations'], 2)

        # Re-fetch transaction info:
        tx1 = node0.gettransaction(txid1)
        tx2 = node0.gettransaction(txid2)

        # Both transactions should be conflicted
        assert_equal(tx1['confirmations'], -2)
        assert_equal(tx2['confirmations'], -2)

        # Node0's total balance should be the starting balance minus the
        # double-spend, plus fees (which are negative):
        assert_equal(mature_coinbase_total(node0, coinbase_address), starting_balance)
        expected = starting_balance - doublespend_amount + fund_fees + doublespend_fee
        assert_equal(node0.getbalance(), expected)
        assert_equal(node0.getbalance('*'), expected)

        # The conflicted spends no longer count against foo and bar; the
        # double spend has no account, so '' pays it
        assert_equal(node0.getbalance('foo'), foo_amount)
        assert_equal(node0.getbalance('bar'), bar_amount)
        assert_equal(node0.getbalance(''), doublespend_fee - doublespend_amount)
        assert_equal(node0.getbalance('coinbase'), starting_balance - foo_amount - bar_amount + fund_fees)

        # Node1's "from0" account balance should be just the doublespend:
        assert_equal(node1.getbalance('from0'), doublespend_amount)


if __name__ == '__main__':
    TxnMallTest().main()
