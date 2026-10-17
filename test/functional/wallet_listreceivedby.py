#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test listreceivedbyaddress, listreceivedbyaccount and getreceivedby*
(adapted from Bitcoin Core's receivedby.py).

- the entry fields (account and label), minconf, the confirmations of the
  most recent payment, several payments to one address;
- include_empty: every address book entry, including the coinbase address
  (coinbases aren't tallied);
- the account totals and getreceivedbyaccount;
- argument errors;
- watch-only: entries need include_watchonly and carry involvesWatchonly;
  getreceivedby* count watch-only payments.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
)


class ReceivedByTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Relay transactions to peers without the inventory trickle delay
        self.extra_args = [['-whitelist=127.0.0.1']] * 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        # Node 1 connects to node 0, so node 1 is a whitelisted inbound peer
        connect_nodes(self.nodes[1], 0)

    def mine(self, n=1):
        self.nodes[0].generate(n)
        self.sync_blocks()

    def entry(self, entries, address):
        found = [e for e in entries if e['address'] == address]
        assert_equal(len(found), 1)
        return found[0]

    def run_test(self):
        node0, node1 = self.nodes
        self.mine(30)

        self.log.info("Entries, minconf and several payments")
        address = node1.getnewaddress('r')
        txid1 = node0.sendtoaddress(address, 2)
        self.sync_mempools()
        assert_equal([e for e in node1.listreceivedbyaddress() if e['address'] == address], [])
        self.mine()
        assert_equal(self.entry(node1.listreceivedbyaddress(), address),
                     {'address': address, 'account': 'r', 'label': 'r', 'amount': Decimal('2'),
                      'confirmations': 1, 'txids': [txid1]})

        txid2 = node0.sendtoaddress(address, 3)
        self.sync_mempools()
        e = self.entry(node1.listreceivedbyaddress(0), address)
        assert_equal((e['amount'], e['confirmations'], sorted(e['txids'])), (Decimal('5'), 0, sorted([txid1, txid2])))
        e = self.entry(node1.listreceivedbyaddress(1), address)
        assert_equal((e['amount'], e['confirmations'], e['txids']), (Decimal('2'), 1, [txid1]))
        assert_equal(node1.getreceivedbyaddress(address, 0), 5)
        assert_equal(node1.getreceivedbyaddress(address), 2)
        assert_equal(node1.listreceivedbyaccount(0), [{'account': 'r', 'amount': Decimal('5'), 'confirmations': 0}])
        assert_equal(node1.listreceivedbyaccount(1), [{'account': 'r', 'amount': Decimal('2'), 'confirmations': 1}])
        assert_equal(node1.getreceivedbyaccount('r', 0), 5)
        assert_equal(node1.getreceivedbyaccount('r'), 2)
        self.mine(2)
        # The confirmations of the most recent payment
        e = self.entry(node1.listreceivedbyaddress(), address)
        assert_equal((e['amount'], e['confirmations']), (Decimal('5'), 2))
        assert_equal(self.entry(node1.listreceivedbyaddress(3), address)['txids'], [txid1])
        assert_equal([x for x in node1.listreceivedbyaddress(4) if x['address'] == address], [])
        assert_equal(node1.listreceivedbyaccount(), [{'account': 'r', 'amount': Decimal('5'), 'confirmations': 2}])

        self.log.info("include_empty")
        empty = node1.getnewaddress('e')
        entries = node1.listreceivedbyaddress(0, True)
        assert_equal(self.entry(entries, empty),
                     {'address': empty, 'account': 'e', 'label': 'e', 'amount': 0, 'confirmations': 0, 'txids': []})
        book = [a for account in node1.listaccounts() for a in node1.getaddressesbyaccount(account)]
        assert_equal(sorted(e['address'] for e in entries), sorted(book))
        # Coinbases aren't tallied
        coinbase = node0.get_deterministic_priv_key().address
        assert_equal(self.entry(node0.listreceivedbyaddress(0, True), coinbase),
                     {'address': coinbase, 'account': 'coinbase', 'label': 'coinbase', 'amount': 0,
                      'confirmations': 0, 'txids': []})
        accounts = node1.listreceivedbyaccount(1, True)
        assert {'account': 'e', 'amount': 0, 'confirmations': 0} in accounts, accounts
        assert {'account': '', 'amount': 0, 'confirmations': 0} in accounts, accounts
        node1.getaccountaddress('mynewaccount')
        assert {'account': 'mynewaccount', 'amount': 0, 'confirmations': 0} in node1.listreceivedbyaccount(0, True)
        assert_equal(node1.getreceivedbyaccount('mynewaccount'), 0)

        self.log.info("Argument errors")
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", node1.listreceivedbyaddress, 'x')
        assert_raises_rpc_error(-1, "JSON value is not a boolean as expected", node1.listreceivedbyaddress, 1, 'x')
        assert_raises_rpc_error(-1, "JSON value is not a boolean as expected", node1.listreceivedbyaccount, 1, True, 'x')
        # A negative minconf is accepted
        self.entry(node1.listreceivedbyaddress(-1), address)

        self.log.info("Watch-only")
        watched = node0.getnewaddress()
        txid = node0.sendtoaddress(watched, 1)
        vout = [o['n'] for o in node0.decoderawtransaction(node0.gettransaction(txid)['hex'])['vout']
                if o['scriptPubKey']['addresses'] == [watched]][0]
        # Node 0 must not spend the watched coin
        node0.lockunspent(False, [{'txid': txid, 'vout': vout}])
        self.mine()
        node1.importaddress(watched, 'w')
        assert_equal(self.entry(node1.listreceivedbyaddress(0, False, True), watched),
                     {'involvesWatchonly': True, 'address': watched, 'account': 'w', 'label': 'w',
                      'amount': Decimal('1'), 'confirmations': 1, 'txids': [txid]})
        assert_equal([e for e in node1.listreceivedbyaddress(0, False, False) if e['address'] == watched], [])
        # With include_empty the address is listed, without its payment
        assert_equal(self.entry(node1.listreceivedbyaddress(0, True, False), watched)['amount'], 0)
        assert {'involvesWatchonly': True, 'account': 'w', 'amount': Decimal('1'), 'confirmations': 1} in \
            node1.listreceivedbyaccount(0, False, True)
        assert 'w' not in [e['account'] for e in node1.listreceivedbyaccount(0, False, False)]
        assert_equal(node1.getreceivedbyaddress(watched), 1)
        assert_equal(node1.getreceivedbyaccount('w'), 1)


if __name__ == '__main__':
    ReceivedByTest().main()
