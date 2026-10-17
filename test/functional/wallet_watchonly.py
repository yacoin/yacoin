#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test watch-only addresses and scripts, and key imports.

Node 1 watches coins that node 0 owns (node 0 locks them so that it never
spends them).

- importaddress of an address with a rescan: the balances with and without
  include_watchonly, getinfo, listunspent, listtransactions, gettransaction,
  listaccounts, listsinceblock, validateaddress;
- errors of importaddress, importpubkey, importprivkey, dumpprivkey;
  relabelling; abortrescan without a rescan;
- importpubkey without and with a rescan;
- a P2SH multisig script imported with the p2sh flag;
- watch-only state after a restart;
- removeaddress of an address, a script and its P2SH address, its errors,
  after a restart;
- importprivkey of a watched address makes it spendable; importprivkey
  without a rescan, and of a key the wallet already has (relabels, never
  rescans), then a -rescan restart.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
)


class WatchOnlyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Relay transactions to peers without the inventory trickle delay
        self.extra_args = [['-whitelist=127.0.0.1']] * 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[1], 0)

    def restart_node1(self, extra_args=None):
        self.restart_node(1, extra_args)
        connect_nodes(self.nodes[1], 0)
        self.sync_blocks()

    def fund(self, address, amount, lock=True):
        """Pay amount from node 0 to address, mine it, and keep node 0 from spending it."""
        node0 = self.nodes[0]
        txid = node0.sendtoaddress(address, amount)
        if lock:
            vout = [o['n'] for o in node0.getrawtransaction(txid, 1)['vout']
                    if o['scriptPubKey'].get('addresses') == [address]][0]
            node0.lockunspent(False, [{'txid': txid, 'vout': vout}])
        node0.generate(1)
        self.sync_blocks()
        return txid

    def watched(self):
        """The watch-only part of node 1's balance."""
        node1 = self.nodes[1]
        return node1.getbalance('*', 1, True) - node1.getbalance()

    def run_test(self):
        self.nodes[0].generate(30)
        self.sync_blocks()
        self.test_importaddress()
        self.test_errors()
        self.test_importpubkey()
        self.test_script()
        self.test_restart()
        self.test_removeaddress()
        self.test_importprivkey()

    def test_importaddress(self):
        self.log.info("importaddress with a rescan")
        node0, node1 = self.nodes
        self.a0 = node0.getnewaddress()
        txid = self.fund(self.a0, 2)
        assert_equal(node1.importaddress(self.a0, 'w'), None)
        assert_equal(node1.getbalance(), 0)
        assert_equal(node1.getbalance('*', 1, True), 2)
        assert_equal(node1.getbalance('w', 1, True), 2)
        info = node1.getinfo()
        assert_equal((info['balance'], info['unspendable']), (0, 2))
        unspent = [u for u in node1.listunspent() if u['address'] == self.a0]
        assert_equal(len(unspent), 1)
        # YACoin reports a watched address as solvable (Bitcoin Core 0.15:
        # not solvable without the public key)
        assert_equal((unspent[0]['spendable'], unspent[0]['solvable'], unspent[0]['safe'], unspent[0]['account']),
                     (False, True, True, 'w'))
        entries = [e for e in node1.listtransactions('*', 10, 0, True) if e['txid'] == txid]
        assert_equal([(e['category'], e['involvesWatchonly']) for e in entries], [('receive', True)])
        assert_equal(node1.listtransactions('*', 10, 0), [])
        details = node1.gettransaction(txid, True)['details']
        assert_equal([(d['category'], d['amount'], d['involvesWatchonly'], d['address']) for d in details],
                     [('receive', Decimal('2'), True, self.a0)])
        assert_equal(node1.gettransaction(txid)['details'], [])
        assert_equal(node1.listaccounts(1, True)['w'], 2)
        assert 'w' not in node1.listaccounts()
        assert_equal([t['txid'] for t in node1.listsinceblock('', 1, True)['transactions']].count(txid), 1)
        info = node1.validateaddress(self.a0)
        assert_equal((info['ismine'], info['iswatchonly'], info['account'], info['timestamp']), (False, True, 'w', 0))

    def test_errors(self):
        self.log.info("Import errors")
        node0, node1 = self.nodes
        own = node1.getnewaddress()
        assert_raises_rpc_error(-5, "Cannot use the p2sh flag with an address - use a script instead",
                                node1.importaddress, self.a0, '', False, True)
        assert_raises_rpc_error(-5, "Invalid Yacoin address or script", node1.importaddress, 'zz')
        already = "The wallet already contains the private key for this address or script"
        assert_raises_rpc_error(-4, already, node1.importaddress, own)
        assert_raises_rpc_error(-5, "Pubkey must be a hex string", node1.importpubkey, 'zz')
        assert_raises_rpc_error(-5, "Pubkey is not a valid public key", node1.importpubkey, '00' * 33)
        assert_raises_rpc_error(-4, already, node1.importpubkey, node1.validateaddress(own)['pubkey'])
        assert_raises_rpc_error(-4, "Private key for address %s is not known" % self.a0, node1.dumpprivkey, self.a0)
        assert_raises_rpc_error(-5, "Invalid private key encoding", node1.importprivkey, 'bad')
        assert_equal(node1.abortrescan(), False)
        # Importing again relabels
        node1.importaddress(self.a0, 'w2', False)
        assert_equal(node1.getaccount(self.a0), 'w2')

    def test_importpubkey(self):
        self.log.info("importpubkey without and with a rescan")
        node0, node1 = self.nodes
        a1 = node0.getnewaddress()
        self.fund(a1, 3)
        pubkey = node0.validateaddress(a1)['pubkey']
        watched = self.watched()
        node1.importpubkey(pubkey, 'p', False)
        assert_equal(self.watched(), watched)
        assert_equal(node1.validateaddress(a1)['iswatchonly'], True)
        node1.importpubkey(pubkey, 'p', True)
        assert_equal(self.watched(), watched + 3)

    def test_script(self):
        self.log.info("A P2SH script imported with the p2sh flag")
        node0, node1 = self.nodes
        pubkey = node0.validateaddress(node0.getnewaddress())['pubkey']
        self.multisig = node0.createmultisig(1, [pubkey])
        address = self.multisig['address']
        # Node 0 doesn't know the script, so it never spends the coin
        self.fund(address, 1, lock=False)
        watched = self.watched()
        node1.importaddress(self.multisig['redeemScript'], 's', True, True)
        info = node1.validateaddress(address)
        assert_equal((info['iswatchonly'], info['ismine'], info['account']), (True, False, 's'))
        unspent = [u for u in node1.listunspent() if u['address'] == address]
        assert_equal([(u['spendable'], u['solvable'], u['redeemScript']) for u in unspent],
                     [(False, True, self.multisig['redeemScript'])])
        assert_equal(self.watched(), watched + 1)

    def test_restart(self):
        self.log.info("Watch-only state after a restart")
        watched = self.watched()
        self.restart_node1()
        assert_equal(self.watched(), watched)
        assert_equal(self.nodes[1].validateaddress(self.a0)['iswatchonly'], True)

    def test_removeaddress(self):
        self.log.info("removeaddress")
        node1 = self.nodes[1]
        watched = self.watched()
        assert_equal(node1.removeaddress(self.a0), None)
        assert_equal(node1.validateaddress(self.a0)['iswatchonly'], False)
        assert_equal(self.watched(), watched - 2)
        assert_equal([u for u in node1.listunspent() if u['address'] == self.a0], [])
        # The address book entry stays
        assert_equal(node1.getaccount(self.a0), 'w2')
        assert_raises_rpc_error(-4, "The wallet does not contain this address or script", node1.removeaddress, self.a0)
        assert_raises_rpc_error(-4, "The wallet contains the private key for this address or script - can't remove it",
                                node1.removeaddress, node1.getnewaddress())
        assert_raises_rpc_error(-5, "Invalid Yacoin address or script", node1.removeaddress, 'zz')
        # The script and its P2SH address are separate watch-only entries
        node1.removeaddress(self.multisig['redeemScript'])
        node1.removeaddress(self.multisig['address'])
        assert_equal(node1.validateaddress(self.multisig['address'])['iswatchonly'], False)
        assert_equal(self.watched(), watched - 3)
        self.restart_node1()
        assert_equal(self.nodes[1].validateaddress(self.a0)['iswatchonly'], False)
        assert_equal(self.watched(), watched - 3)

    def test_importprivkey(self):
        self.log.info("importprivkey of a watched address")
        node0, node1 = self.nodes
        a2 = node0.getnewaddress()
        self.fund(a2, 4)
        node1.importaddress(a2, 'up')
        info = node1.validateaddress(a2)
        assert_equal((info['iswatchonly'], info['ismine']), (True, False))
        balance = node1.getbalance()
        node1.importprivkey(node0.dumpprivkey(a2)['private_key'], 'up2')
        info = node1.validateaddress(a2)
        assert_equal((info['iswatchonly'], info['ismine']), (False, True))
        assert_equal(node1.getbalance(), balance + 4)
        assert_equal(node1.getaccount(a2), 'up2')

        self.log.info("importprivkey without a rescan, and of a known key")
        a3 = node0.getnewaddress()
        self.fund(a3, 5)
        key = node0.dumpprivkey(a3)['private_key']
        balance = node1.getbalance()
        node1.importprivkey(key, 'lbl', False)
        assert_equal(node1.getbalance(), balance)
        # A known key is relabelled, and never rescanned
        node1.importprivkey(key, 'lbl2', False)
        assert_equal(node1.getaccount(a3), 'lbl2')
        node1.importprivkey(key, 'lbl3', True)
        assert_equal(node1.getbalance(), balance)
        self.restart_node1(['-rescan'])
        assert_equal(self.nodes[1].getbalance(), balance + 5)


if __name__ == '__main__':
    WatchOnlyTest().main()
