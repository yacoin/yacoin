#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet's transaction fees.

The wallet starts at -paytxfee / settxfee as a fee for the whole
transaction and raises it to size * paytxfee / 1000 or to the node's
minimum, size * MIN_TX_FEE / 1000, whichever is higher (see
wallet_util.expected_fee). Covered:

- the default 0.01 YAC for a small transaction; settxfee(0.05);
  settxfee rounding to 0.01 steps; settxfee(0) pays the node minimum and is
  relayed and mined; the size-based fee of large transactions at the default
  and at 0.05;
- settxfee argument errors; -paytxfee (not rounded), an invalid -paytxfee
  value, the warning for a very high -paytxfee;
- subtracting the fee from the amount: sendtoaddress, sendmany split between
  three recipients (the first pays the remainder), sweeping a wallet;
- sending the whole balance without subtracting the fee;
- known failure W-B6: subtracting a fee larger than the amount;
- a new address in a new account has received nothing (moved here from
  feature_set_min_fee.py).
"""
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.wallet_util import assert_yac_fee

HIGH_FEE_WARNING = "Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."


class WalletFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def mine(self, relay=True):
        """Mine a block on node 0. relay=False when node 0 created the new
        transactions itself (saves waiting for the transaction relay)."""
        if relay:
            self.sync_mempools()
        self.nodes[0].generate(1)
        self.sync_blocks()

    def size(self, node, txid):
        return len(node.getrawtransaction(txid)) // 2

    def restart_node1(self, extra_args=None, expected_stderr=''):
        self.stop_node(1, expected_stderr)
        self.start_node(1, extra_args)
        connect_nodes(self.nodes[1], 0)

    def run_test(self):
        node0, node1 = self.nodes
        node0.generate(30)
        self.sync_blocks()

        self.log.info("A new address in a new account has received nothing")
        address = node1.getnewaddress('test-node2')
        assert_equal(node1.getaccount(address), 'test-node2')
        assert_equal(node1.getreceivedbyaddress(address), 0)
        assert_equal(node1.getreceivedbyaccount('test-node2'), 0)
        assert_equal(node1.listaccounts()['test-node2'], 0)

        # Pins today's fee semantics: paytxfee is a fee for the whole
        # transaction and a per-kB rate above 1 kB; settxfee rounds down to
        # 0.01 steps, -paytxfee doesn't; the help texts say "per kB".
        # Under review in Trello XbGM5oTW item 2; update these values if the
        # semantics change.
        self.log.info("Default: a small transaction pays 0.01")
        assert_equal(node0.getwalletinfo()['paytxfee'], Decimal('0.01'))
        txid = node0.sendtoaddress(node1.getnewaddress(), 1)
        assert_greater_than(1000, self.size(node0, txid))
        assert_equal(node0.gettransaction(txid)['fee'], Decimal('-0.01'))
        assert_yac_fee(node0, txid)

        self.log.info("settxfee(0.05): a small transaction pays 0.05")
        assert_equal(node0.settxfee(0.05), True)
        assert_equal(node0.getwalletinfo()['paytxfee'], Decimal('0.05'))
        txid = node0.sendtoaddress(node1.getnewaddress(), 1)
        assert_equal(node0.gettransaction(txid)['fee'], Decimal('-0.05'))
        assert_yac_fee(node0, txid, Decimal('0.05'))

        self.log.info("settxfee rounds down to 0.01 steps")
        node0.settxfee(Decimal('0.015'))
        assert_equal(node0.getwalletinfo()['paytxfee'], Decimal('0.01'))
        node0.settxfee(Decimal('0.005'))
        assert_equal(node0.getwalletinfo()['paytxfee'], Decimal('0'))

        self.log.info("settxfee(0): the node's minimum fee, relayed and mined")
        txid = node0.sendtoaddress(node1.getnewaddress(), 1)
        assert_yac_fee(node0, txid, Decimal('0'))
        assert_greater_than(Decimal('0.01'), -node0.gettransaction(txid)['fee'])
        assert txid in node0.getrawmempool()
        # Node 1 must accept it too: mine() waits for the mempools to sync
        self.mine()
        assert_equal(node0.gettransaction(txid)['confirmations'], 1)
        node0.settxfee(Decimal('0.01'))

        self.log.info("A large transaction pays by size")
        node0.sendmany(fromaccount='coinbase', amounts={node1.getnewaddress(): 1 for _ in range(12)})
        self.mine(relay=False)
        # All of node 1's coins are worth 1, so every pass of the fee loop
        # selects 12 of them.
        assert_equal(set(u['amount'] for u in node1.listunspent()), {1})
        txid = node1.sendtoaddress(address=node0.getnewaddress(), amount=Decimal('11.5'))
        assert_greater_than(self.size(node1, txid), 1000)
        assert_yac_fee(node1, txid)
        assert_greater_than(-node1.gettransaction(txid)['fee'], Decimal('0.01'))
        self.mine()

        self.log.info("A large transaction at settxfee(0.05) pays 0.05 per kB")
        node0.sendmany(fromaccount='coinbase', amounts={node1.getnewaddress(): Decimal('0.5') for _ in range(24)})
        self.mine(relay=False)
        node1.settxfee(0.05)
        # A sweep, so every pass of the wallet's fee loop selects the same
        # coins. (With a partial amount, a pass may pick a larger coin set
        # than the final one, and the fee is never lowered again.)
        txid = node1.sendtoaddress(address=node0.getnewaddress(), amount=node1.getbalance(), subtractfeefromamount=True)
        assert_greater_than(self.size(node1, txid), 1000)
        assert_yac_fee(node1, txid, Decimal('0.05'))
        assert_greater_than(-node1.gettransaction(txid)['fee'], Decimal('0.05'))
        node1.settxfee(0.01)
        self.mine()
        assert_equal(node1.getbalance(), 0)
        node0.sendtoaddress(node1.getnewaddress(), 5)
        self.mine(relay=False)

        self.log.info("settxfee argument errors")
        assert_raises_rpc_error(-3, "Amount out of range", node0.settxfee, -1)
        assert_raises_rpc_error(-3, "Invalid amount", node0.settxfee, 'x')
        assert_raises_rpc_error(-3, "Invalid amount", node0.settxfee, Decimal('0.0000001'))
        assert_raises_rpc_error(-1, "settxfee amount", node0.settxfee)

        self.log.info("-paytxfee is not rounded")
        self.restart_node1(['-paytxfee=0.015'])
        node1 = self.nodes[1]
        assert_equal(node1.getwalletinfo()['paytxfee'], Decimal('0.015'))
        txid = node1.sendtoaddress(node0.getnewaddress(), 1)
        assert_equal(node1.gettransaction(txid)['fee'], Decimal('-0.015'))
        self.mine()

        self.log.info("Invalid and very high -paytxfee")
        self.stop_node(1)
        node1.assert_start_raises_init_error(['-paytxfee=abc'], "Error: Invalid amount for -paytxfee=<amount>: 'abc'")
        with node1.assert_debug_log([HIGH_FEE_WARNING]):
            self.start_node(1, ['-paytxfee=0.3'])
        assert_equal(node1.getwalletinfo()['paytxfee'], Decimal('0.3'))
        self.restart_node1(expected_stderr='Warning: ' + HIGH_FEE_WARNING)

        self.log.info("Subtract the fee from the amount")
        b = node1.getnewaddress()
        txid = node0.sendtoaddress(address=b, amount=1, subtractfeefromamount=True)
        assert_equal(node0.gettransaction(txid)['fee'], Decimal('-0.01'))

        x, y, z = node1.getnewaddress(), node1.getnewaddress(), node1.getnewaddress()
        txid = node0.sendmany(fromaccount='coinbase', amounts={x: 1, y: 1, z: 1}, subtractfeefrom=[x, y, z])
        assert_yac_fee(node0, txid)
        fee_units = int(-node0.gettransaction(txid)['fee'] * COIN)
        share, remainder = divmod(fee_units, 3)
        values = {}
        for out in node0.getrawtransaction(txid, 1)['vout']:
            values[out['scriptPubKey']['addresses'][0]] = out['value']
        # Equal shares; the first recipient (in object order) also pays the remainder
        assert_equal(values[x], 1 - Decimal(share + remainder) / COIN)
        assert_equal(values[y], 1 - Decimal(share) / COIN)
        assert_equal(values[z], 1 - Decimal(share) / COIN)
        self.mine(relay=False)
        assert_equal(node1.getreceivedbyaddress(b), Decimal('0.99'))

        self.log.info("Sweep a wallet by subtracting the fee")
        txid = node1.sendtoaddress(address=node0.getnewaddress(), amount=node1.getbalance(), subtractfeefromamount=True)
        assert_equal(len(node1.getrawtransaction(txid, 1)['vout']), 1)
        assert_yac_fee(node1, txid)
        self.mine()
        assert_equal(node1.getbalance(), 0)
        assert_equal(node1.listunspent(0), [])

        self.log.info("Sending the whole balance without subtracting the fee fails")
        assert_raises_rpc_error(-4, "Error: This transaction requires a transaction fee of at least 0.01",
                                node0.sendtoaddress, node1.getnewaddress(), node0.getbalance())

        self.test_fee_larger_than_amount()

    def test_fee_larger_than_amount(self):
        """W-B6. Runs last: today it leaves node 0's wallet unusable for listings."""
        self.log.info("Subtract a fee that is larger than the amount")
        node0, node1 = self.nodes
        txcount = node0.getwalletinfo()['txcount']
        balance = node0.getbalance()
        balance_all = node0.getbalance('*')
        try:
            node0.sendtoaddress(address=node1.getnewaddress(), amount=Decimal('0.005'), subtractfeefromamount=True)
            raise AssertionError("A send whose fee is larger than its amount was accepted")
        except JSONRPCException:
            pass

        def check_wallet_unchanged():
            node0.listtransactions('*', 1000)
            node0.listaccounts()
            node0.listsinceblock()
            assert_equal(node0.getwalletinfo()['txcount'], txcount)
            assert_equal(node0.getbalance(), balance)
            assert_equal(node0.getbalance('*'), balance_all)
        # Today the transaction gets a negative output, the mempool rejects it
        # and it stays in the wallet as abandoned; listing it fails.
        self.known_failure("W-B6 (ZZ9emfPE)", check_wallet_unchanged, expected="value out of range")


if __name__ == '__main__':
    WalletFeeTest().main()
