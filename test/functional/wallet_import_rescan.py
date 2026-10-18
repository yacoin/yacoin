#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the rescans of importaddress, importpubkey and importprivkey
(adapted from Bitcoin Core's import-rescan.py).

Node 0 pays an address of node 1 for each import variant (address, public
key or private key, with or without a rescan). Node 2 imports without
rescans, node 3 with rescans; getbalance, listtransactions, gettransaction
and listreceivedbyaddress show whether the earlier payment was found. Then
node 0 pays every address again: every importing node sees the new payment
without a rescan.

Not ported: importmulti and its timestamps, pruning (YACoin has neither).
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
)


class Variant:
    """One key import and the checks of the transactions it should find."""

    def __init__(self, data, rescan):
        self.data = data
        self.rescan = rescan

    def do_import(self):
        if self.data == 'address':
            response = self.node.importaddress(self.address, self.label, self.rescan)
        elif self.data == 'pub':
            response = self.node.importpubkey(self.pubkey, self.label, self.rescan)
        else:
            response = self.node.importprivkey(self.key, self.label, self.rescan)
        assert_equal(response, None)

    def check(self, txid=None, amount=None, confirmations=None):
        """Verify that getbalance/listtransactions return expected values."""
        assert_equal(self.node.getbalance(self.label, 0, True), self.expected_balance)
        txs = self.node.listtransactions(self.label, 10000, 0, True)
        assert_equal(len(txs), self.expected_txs)
        if txid is None:
            return
        tx, = [tx for tx in txs if tx['txid'] == txid]
        assert_equal((tx['account'], tx['address'], tx['amount'], tx['category'], tx['label'], tx['confirmations']),
                     (self.label, self.address, amount, 'receive', self.label, confirmations))
        assert 'trusted' not in tx
        # The inputs are never watch-only, so the flag comes from the output
        if self.data != 'priv':
            assert_equal(tx['involvesWatchonly'], True)
        else:
            assert 'involvesWatchonly' not in tx


class ImportRescanTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        for i in range(1, self.num_nodes):
            connect_nodes(self.nodes[i], 0)

    def run_test(self):
        node0, node1 = self.nodes[:2]
        node0.generate(30)
        self.sync_blocks()
        variants = [Variant(data, rescan) for data in ('address', 'pub', 'priv') for rescan in (False, True)]

        self.log.info("Pay an address for each variant")
        for i, variant in enumerate(variants):
            variant.label = "label {} {} {}".format(i, variant.data, variant.rescan)
            variant.address = node1.getnewaddress(variant.label)
            variant.pubkey = node1.validateaddress(variant.address)['pubkey']
            variant.key = node1.dumpprivkey(variant.address)['private_key']
            variant.node = self.nodes[3 if variant.rescan else 2]
            variant.initial_amount = 1 + Decimal(i) / 10
            variant.initial_txid = node0.sendtoaddress(variant.address, variant.initial_amount)
        node0.generate(2)
        assert_equal(node0.getrawmempool(), [])
        self.sync_blocks()

        self.log.info("Import, with and without a rescan")
        for variant in variants:
            variant.do_import()
            entry = [e for e in variant.node.listreceivedbyaddress(0, True, True) if e['address'] == variant.address]
            assert_equal(len(entry), 1)
            tx = variant.node.gettransaction(variant.initial_txid, True)
            if variant.rescan:
                variant.expected_balance = variant.initial_amount
                variant.expected_txs = 1
                variant.check(variant.initial_txid, variant.initial_amount, 2)
                assert_equal((entry[0]['amount'], entry[0]['txids']), (variant.initial_amount, [variant.initial_txid]))
                assert_equal(tx['details'][0]['amount'], variant.initial_amount)
            else:
                variant.expected_balance = 0
                variant.expected_txs = 0
                variant.check()
                assert_equal((entry[0]['amount'], entry[0]['txids']), (0, []))
                # Not in the wallet: gettransaction falls back to the txindex
                assert 'details' not in tx

        self.log.info("Payments after the import need no rescan")
        for i, variant in enumerate(variants):
            variant.sent_amount = 2 + Decimal(i) / 10
            variant.sent_txid = node0.sendtoaddress(variant.address, variant.sent_amount)
        node0.generate(1)
        assert_equal(node0.getrawmempool(), [])
        self.sync_blocks()
        for variant in variants:
            variant.expected_balance += variant.sent_amount
            variant.expected_txs += 1
            variant.check(variant.sent_txid, variant.sent_amount, 1)
            details = variant.node.gettransaction(variant.sent_txid)['details']
            # Without include_watchonly only the private key variants show details
            assert_equal(len(details), 1 if variant.data == 'priv' else 0)

        # Only the private keys count in the spendable balance
        for node, rescan in ((self.nodes[2], False), (self.nodes[3], True)):
            mine = [v for v in variants if v.rescan == rescan]
            assert_equal(node.getbalance(), sum(v.expected_balance for v in mine if v.data == 'priv'))
            assert_equal(node.getbalance('*', 1, True), sum(v.expected_balance for v in mine))
        assert_equal(node1.getbalance(), sum(v.initial_amount + v.sent_amount for v in variants))


if __name__ == '__main__':
    ImportRescanTest().main()
