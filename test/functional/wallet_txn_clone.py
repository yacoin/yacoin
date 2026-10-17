#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet accounts when a transaction is replaced by a clone
(adapted from Bitcoin Core's txn_clone.py).

Node 0 funds the accounts foo and bar and sends from both to node 1 (tx1,
tx2). A clone of tx1 (same input, same outputs in the other order, freshly
signed) is mined on the other half of the split network, together with
tx2. After the networks join, tx1 is conflicted, the clone and tx2 are
confirmed, and the balances of the wallet and of each account follow. With
--mineblock, node 0 mines tx1 and tx2 first.

Porting notes: createrawtransaction gives the clone a new nTime and the
output order differs, so the wallet doesn't treat the clone as an
equivalent of tx1: the clone is debited from '' rather than from foo (Core
signs with ALL|ANYONECANPAY to get an equivalent clone). Mined coins belong
to the 'coinbase' account; node 0's mature coinbases don't change during
the test, so Core's subsidy terms are dropped; tx1 and tx2 each spend one
known funding output (the other coins are locked).
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

        self.log.info("Fund foo and bar, send from both")
        fund_foo_txid = node0.sendfrom('coinbase', node0.getnewaddress('foo'), foo_amount)
        fund_foo_tx = node0.gettransaction(fund_foo_txid)
        fund_bar_txid = node0.sendfrom('coinbase', node0.getnewaddress('bar'), bar_amount)
        fund_bar_tx = node0.gettransaction(fund_bar_txid)
        fund_fees = fund_foo_tx['fee'] + fund_bar_tx['fee']
        assert_equal(node0.getbalance('coinbase'), starting_balance - foo_amount - bar_amount + fund_fees)

        # Coins are sent to node1_address
        node1_address = node1.getnewaddress('from0')

        # Send tx1, and another transaction tx2 that won't be cloned
        spend_only(node0, fund_foo_txid, find_output(node0, fund_foo_txid, foo_amount))
        txid1 = node0.sendfrom('foo', node1_address, 4, True, 0)
        spend_only(node0, fund_bar_txid, find_output(node0, fund_bar_txid, bar_amount))
        txid2 = node0.sendfrom('bar', node1_address, 2, True, 0)
        node0.lockunspent(True)

        self.log.info("Build a clone of tx1")
        rawtx1 = node0.getrawtransaction(txid1, 1)
        clone_inputs = [{'txid': i['txid'], 'vout': i['vout']} for i in rawtx1['vin']]
        # The outputs in the other order
        clone_outputs = {o['scriptPubKey']['addresses'][0]: o['value'] for o in reversed(rawtx1['vout'])}
        clone_raw = node0.createrawtransaction(clone_inputs, clone_outputs, rawtx1['locktime'])
        assert_equal([o['value'] for o in node0.decoderawtransaction(clone_raw)['vout']],
                     [o['value'] for o in reversed(rawtx1['vout'])])
        # Fully signed; don't send the clone anywhere yet
        tx1_clone = node0.signrawtransaction(clone_raw)
        assert_equal(tx1_clone['complete'], True)

        # Have node0 mine a block, if requested:
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

        self.log.info("Mine the clone on the other half")
        # Send clone and its parent to miner
        node2.sendrawtransaction(fund_foo_tx['hex'])
        txid1_clone = node2.sendrawtransaction(tx1_clone['hex'])
        # ... mine a block...
        node2.generate(1)

        # Reconnect the split network, and sync chain:
        connect_nodes(node1, 2)
        node2.sendrawtransaction(fund_bar_tx['hex'])
        node2.sendrawtransaction(tx2['hex'])
        node2.generate(1)  # Mine another block to make sure we sync
        sync_blocks(self.nodes)

        # Re-fetch transaction info:
        tx1 = node0.gettransaction(txid1)
        tx1_clone = node0.gettransaction(txid1_clone)
        tx2 = node0.gettransaction(txid2)

        # Verify expected confirmations
        assert_equal(tx1['confirmations'], -2)
        assert_equal(tx1_clone['confirmations'], 2)
        assert_equal(tx2['confirmations'], 1)

        # Check node0's total balance; the clone costs the same as tx1
        assert_equal(mature_coinbase_total(node0, coinbase_address), starting_balance)
        assert_equal(node0.getbalance(), expected)
        assert_equal(node0.getbalance('*', 0), expected)

        # Check node0's individual account balances: the conflicted tx1 no
        # longer counts against foo, the clone is debited from ''
        assert_equal(node0.getbalance('foo'), foo_amount)
        assert_equal(node0.getbalance('bar', 0), bar_amount + tx2['amount'] + tx2['fee'])
        assert_equal(node0.getbalance('', 0), tx1['amount'] + tx1['fee'])
        assert_equal(node0.getbalance('coinbase'), starting_balance - foo_amount - bar_amount + fund_fees)

        # Node1's "from0" account balance
        assert_equal(node1.getbalance('from0', 0), -(tx1['amount'] + tx2['amount']))


if __name__ == '__main__':
    TxnMallTest().main()
