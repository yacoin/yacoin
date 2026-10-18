#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test listtransactions (adapted from Bitcoin Core's listtransactions.py).

- coinbase entries: 'immature', 'generate' at depth 6, 'orphan' once the
  block is invalidated (the entry stays 'orphan' after the chain moves on);
  listsinceblock lists the orphan in 'removed';
- argument errors, count 0, an unknown account, paging with count and skip;
- send and receive entries with their fields, unconfirmed and confirmed;
- sendmany to the wallet itself: send and receive entries for one txid, and
  the account filter;
- a watch-only multisig script (importaddress with p2sh): its entries need
  include_watchonly and carry involvesWatchonly.

Not ported: the RBF / bip125-replaceable part (YACoin has no RBF).
Mining uses mine_with_mocktime: after invalidateblock a block mined in the
same second as the invalidated one would be the same, invalid block.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.wallet_util import coinbase_value


class ListTransactionsTest(BitcoinTestFramework):
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

    def mine(self, n=1, sync=True):
        self.mine_with_mocktime(self.nodes[0], n, sync=False)
        if sync:
            self.sync_blocks()

    def entries(self, node, txid, *args):
        return [e for e in node.listtransactions('*', 1000, *args) if e.get('txid') == txid]

    def run_test(self):
        self.test_coinbase_categories()
        self.test_arguments()
        self.test_send_receive()
        self.test_sendmany_to_self()
        self.test_watchonly()

    def test_coinbase_categories(self):
        self.log.info("Coinbase entries: immature, generate, orphan")
        node0 = self.nodes[0]
        block = self.mine_with_mocktime(node0, 1, sync=False)[0]
        coinbase = node0.getblock(block)['tx'][0]
        e = self.entries(node0, coinbase)
        assert_equal(len(e), 1)
        e = e[0]
        assert_equal((e['category'], e['account'], e['label'], e['confirmations'], e['generated'], e['amount']),
                     ('immature', 'coinbase', 'coinbase', 1, True, coinbase_value(node0, block)))
        self.mine(5, sync=False)
        assert_equal([x['category'] for x in self.entries(node0, coinbase)], ['generate'])

        self.mine(25)
        tip = node0.getbestblockhash()
        tip_coinbase = node0.getblock(tip)['tx'][0]
        assert_equal([x['category'] for x in self.entries(node0, tip_coinbase)], ['immature'])
        node0.invalidateblock(tip)
        assert_equal([(x['category'], x['confirmations']) for x in self.entries(node0, tip_coinbase)], [('orphan', 0)])
        assert_equal(node0.gettransaction(tip_coinbase)['details'][0]['category'], 'orphan')
        assert tip_coinbase in [x['txid'] for x in node0.listsinceblock(tip)['removed']]
        # Node 1 follows the longer branch; the orphan stays an orphan
        self.mine(2)
        assert_equal(self.nodes[1].getbestblockhash(), node0.getbestblockhash())
        assert_equal([(x['category'], x['confirmations']) for x in self.entries(node0, tip_coinbase)], [('orphan', 0)])

    def test_arguments(self):
        self.log.info("Arguments and paging")
        node0 = self.nodes[0]
        assert_raises_rpc_error(-8, "Negative count", node0.listtransactions, '*', -1)
        assert_raises_rpc_error(-8, "Negative from", node0.listtransactions, '*', 1, -1)
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", node0.listtransactions, '*', 'x')
        assert_equal(node0.listtransactions('*', 0), [])
        assert_equal(node0.listtransactions('nosuch'), [])
        assert_equal(node0.listtransactions('*', 5, 10000), [])
        full = node0.listtransactions('*', 1000)
        assert len(full) >= 5
        assert_equal(node0.listtransactions('*', 2, 1), full[-3:-1])
        assert_equal(node0.listtransactions(), full[-10:])

    def test_send_receive(self):
        self.log.info("Send and receive entries")
        node0, node1 = self.nodes
        address = node1.getnewaddress('r')
        txid = node0.sendtoaddress(address, 2)
        vout = [o['n'] for o in node0.decoderawtransaction(node0.gettransaction(txid)['hex'])['vout']
                if o['scriptPubKey']['addresses'] == [address]][0]
        self.sync_mempools()
        sent = self.entries(node0, txid)
        assert_equal(len(sent), 1)
        sent = sent[0]
        for key, value in [('account', ''), ('address', address), ('category', 'send'), ('amount', Decimal('-2')),
                           ('vout', vout), ('fee', Decimal('-0.01')), ('confirmations', 0), ('trusted', True),
                           ('abandoned', False)]:
            assert_equal((key, sent[key]), (key, value))
        received = self.entries(node1, txid)
        assert_equal(len(received), 1)
        received = received[0]
        for key, value in [('account', 'r'), ('label', 'r'), ('address', address), ('category', 'receive'),
                           ('amount', Decimal('2')), ('vout', vout), ('confirmations', 0), ('trusted', False)]:
            assert_equal((key, received[key]), (key, value))
        assert 'abandoned' not in received
        assert abs(received['time'] - self.mocktime) < 5

        self.mine()
        for node in (node0, node1):
            e = self.entries(node, txid)[0]
            assert_equal((e['confirmations'], e['blockhash']), (1, node0.getbestblockhash()))

    def test_sendmany_to_self(self):
        self.log.info("sendmany to the wallet itself, and the account filter")
        node0 = self.nodes[0]
        a1, a2 = node0.getnewaddress('self'), node0.getnewaddress('self')
        txid = node0.sendmany('coinbase', {a1: Decimal('0.33'), a2: Decimal('0.44')})
        assert_equal(sorted((e['category'], e['amount'], e['account']) for e in self.entries(node0, txid)),
                     [('receive', Decimal('0.33'), 'self'), ('receive', Decimal('0.44'), 'self'),
                      ('send', Decimal('-0.44'), 'coinbase'), ('send', Decimal('-0.33'), 'coinbase')])
        assert_equal(sorted((e['category'], e['amount']) for e in node0.listtransactions('self', 100)),
                     [('receive', Decimal('0.33')), ('receive', Decimal('0.44'))])
        coinbase_entries = [e for e in node0.listtransactions('coinbase', 1000) if e.get('txid') == txid]
        assert_equal(sorted(e['category'] for e in coinbase_entries), ['send', 'send'])

        b = node0.getnewaddress()
        txid = node0.sendfrom('coinbase', b, 1)
        assert txid in [e.get('txid') for e in node0.listtransactions('coinbase', 1000)]
        # b is in '', so only the send entry must be missing
        assert txid not in [e.get('txid') for e in node0.listtransactions('', 1000) if e['category'] == 'send']
        self.mine()

    def test_watchonly(self):
        self.log.info("Watch-only multisig")
        node0, node1 = self.nodes
        pubkey = node1.validateaddress(node1.getnewaddress())['pubkey']
        multisig = node1.createmultisig(1, [pubkey])
        node0.importaddress(multisig['redeemScript'], 'watchonly', False, True)
        info = node0.validateaddress(multisig['address'])
        assert_equal((info['iswatchonly'], info['ismine'], info['script'], info['account']),
                     (True, False, 'multisig', 'watchonly'))
        txid = node1.sendtoaddress(multisig['address'], Decimal('0.1'))
        self.sync_mempools()
        self.mine()
        e = self.entries(node0, txid, 0, True)
        assert_equal(len(e), 1)
        e = e[0]
        assert_equal((e['involvesWatchonly'], e['account'], e['category'], e['amount'], e['confirmations']),
                     (True, 'watchonly', 'receive', Decimal('0.1'), 1))
        assert_equal(self.entries(node0, txid), [])
        assert_equal([t['txid'] for t in node0.listsinceblock('', 1, True)['transactions']].count(txid), 1)


if __name__ == '__main__':
    ListTransactionsTest().main()
