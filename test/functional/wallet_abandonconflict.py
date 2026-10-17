#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test abandontransaction and conflicted wallet transactions.

A rework of Bitcoin Core's abandonconflict.py: Core keeps transactions out
of the mempool with -minrelaytxfee, which YACoin doesn't have. Here node 1
restarts with -walletbroadcast=0 -persistmempool=0 (and without its old
mempool.dat, which would bring the transactions back and un-abandon them).

- a chain A -> B -> C of unconfirmed sends; abandontransaction errors;
- abandoning A frees its input and marks A and B abandoned (known failure:
  the grandchild C isn't marked); abandoned transactions don't return to
  the mempool after a normal restart; C can be abandoned by hand;
- A confirmed elsewhere is no longer abandoned;
- a send D and its child E conflicted by a double spend mined on node 0:
  confirmations -1, then -2, the balances exclude them; invalidating the
  conflicting block clears the conflict.
"""
import os
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    wait_until,
)

# A valid address that no test node owns
FOREIGN = TestNode.PRIV_KEYS[11].address


class AbandonConflictTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[1], 0)

    def disconnect(self):
        disconnect_nodes(self.nodes[0], 1)
        disconnect_nodes(self.nodes[1], 0)
        wait_until(lambda: self.nodes[0].getconnectioncount() == 0 and self.nodes[1].getconnectioncount() == 0)

    def restart_node1(self, extra_args=None):
        """Restart node 1 without its saved mempool."""
        self.stop_node(1)
        mempool = os.path.join(self.nodes[1].datadir, 'mempool.dat')
        if os.path.exists(mempool):
            os.remove(mempool)
        self.start_node(1, extra_args)

    def send_entry(self, txid):
        entries = [e for e in self.nodes[1].listtransactions('*', 1000) if e['txid'] == txid and e['category'] == 'send']
        assert_equal(len(entries), 1)
        return entries[0]

    def vin(self, node, txid):
        return [i['txid'] for i in node.decoderawtransaction(node.gettransaction(txid)['hex'])['vin']]

    def run_test(self):
        node0, node1 = self.nodes
        node0.generate(30)
        self.sync_blocks()
        utxo = self.single_utxo_wallet(node0, node1, Decimal('10'))
        self.disconnect()

        self.log.info("A chain of unconfirmed sends")
        a = node1.sendtoaddress(FOREIGN, 1)
        b = node1.sendtoaddress(FOREIGN, 1)
        c = node1.sendtoaddress(FOREIGN, 1)
        assert_equal(sorted(node1.getrawmempool()), sorted([a, b, c]))
        assert_equal(self.vin(node1, b), [a])
        assert_equal(self.vin(node1, c), [b])
        a_hex = node1.gettransaction(a)['hex']
        assert_equal(node1.getbalance(), Decimal('6.97'))

        assert_raises_rpc_error(-5, "Transaction not eligible for abandonment", node1.abandontransaction, a)
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", node1.abandontransaction, '00' * 32)
        assert_raises_rpc_error(-5, "Invalid or non-wallet transaction id", node1.abandontransaction, 'zz')

        self.log.info("Out of the mempool, the sends are untrusted")
        self.restart_node1(['-walletbroadcast=0', '-persistmempool=0'])
        node1 = self.nodes[1]
        assert_equal(node1.getrawmempool(), [])
        assert_equal(node1.getbalance(), 0)
        assert_equal(node1.getunconfirmedbalance(), 0)
        assert_equal(node1.listunspent(0), [])
        assert_equal(node1.gettransaction(a)['trusted'], False)

        self.log.info("Abandon A")
        assert_equal(node1.abandontransaction(a), None)
        assert_equal(node1.getbalance(), 10)
        assert_equal([(u['txid'], u['vout'], u['amount']) for u in node1.listunspent()],
                     [(utxo['txid'], utxo['vout'], Decimal('10'))])
        assert_equal(self.send_entry(a)['abandoned'], True)
        assert_equal(self.send_entry(b)['abandoned'], True)

        def check_grandchild():
            assert self.send_entry(c)['abandoned'], "grandchild not abandoned"
        # The descendant walk looks up the spends of A instead of the
        # transaction it is at (wallet.cpp AbandonTransaction)
        self.known_failure("abandon misses grandchildren (VKLzdLmd item 2)", check_grandchild,
                           expected="grandchild not abandoned")
        assert_equal(node1.abandontransaction(a), None)
        assert_equal(node1.abandontransaction(b), None)
        # The account balances still subtract the abandoned sends
        assert_equal(node1.getbalance('*'), Decimal('6.97'))
        assert_equal(node1.listaccounts()[''], Decimal('6.97'))

        self.log.info("Abandoned transactions stay out of the mempool after a restart")
        self.restart_node1()
        node1 = self.nodes[1]
        assert_equal(node1.getrawmempool(), [])
        assert_equal(node1.resendwallettransactions(), [])
        assert_equal(node1.abandontransaction(c), None)
        assert_equal(self.send_entry(c)['abandoned'], True)

        self.log.info("A confirmed elsewhere is no longer abandoned")
        node0.sendrawtransaction(a_hex)
        node0.generate(1)
        connect_nodes(node1, 0)
        self.sync_blocks()
        assert_equal(node1.gettransaction(a)['confirmations'], 1)
        assert_equal(self.send_entry(a)['abandoned'], False)
        assert_equal((self.send_entry(b)['abandoned'], node1.gettransaction(b)['confirmations']), (True, 0))
        assert_equal(node1.getbalance(), Decimal('8.99'))

        self.test_conflict()

    def test_conflict(self):
        self.log.info("A send and its child conflicted by a double spend")
        node0, node1 = self.nodes
        v_address = node1.getnewaddress()
        v_txid = node0.sendtoaddress(v_address, 5)
        node0.generate(1)
        self.sync_blocks()
        v_out = [o for o in node0.getrawtransaction(v_txid, 1)['vout'] if o['scriptPubKey']['addresses'] == [v_address]][0]
        v = {'txid': v_txid, 'vout': v_out['n']}
        balance = node1.getbalance()
        legacy = node1.getbalance('*', 0)
        self.disconnect()

        raw = node1.createrawtransaction([v], {node1.getnewaddress(): Decimal('4.98')})
        signed = node1.signrawtransaction(raw)
        assert signed['complete']
        d = node1.sendrawtransaction(signed['hex'])
        raw = node1.createrawtransaction([{'txid': d, 'vout': 0}], {node1.getnewaddress(): Decimal('4.96')})
        signed = node1.signrawtransaction(raw)
        assert signed['complete']
        e = node1.sendrawtransaction(signed['hex'])
        assert_equal([node1.gettransaction(t)['confirmations'] for t in (d, e)], [0, 0])
        assert_equal(node1.getbalance(), balance - Decimal('0.04'))

        # Node 0 spends V differently, with node 1's key
        key = node1.dumpprivkey(v_address)['private_key']
        raw = node0.createrawtransaction([v], {node0.getnewaddress(): Decimal('4.99')})
        signed = node0.signrawtransaction(raw, [dict(v, scriptPubKey=v_out['scriptPubKey']['hex'])], [key])
        assert signed['complete']
        node0.sendrawtransaction(signed['hex'])
        block = node0.generate(1)[0]
        connect_nodes(node1, 0)
        self.sync_blocks()
        assert_equal([node1.gettransaction(t)['confirmations'] for t in (d, e)], [-1, -1])
        assert d not in node1.getrawmempool() and e not in node1.getrawmempool()
        node0.generate(1)
        self.sync_blocks()
        assert_equal([node1.gettransaction(t)['confirmations'] for t in (d, e)], [-2, -2])
        # The balances exclude the conflicted transactions
        assert_equal(node1.getbalance(), balance - 5)
        assert_equal(node1.getbalance('*', 0), legacy - 5)
        assert_equal(node1.getunconfirmedbalance(), 0)
        assert v_txid not in [u['txid'] for u in node1.listunspent(0)]
        # Abandoning a conflicted transaction changes nothing
        assert_equal(node1.abandontransaction(d), None)
        assert_equal((self.send_entry(d)['abandoned'], node1.gettransaction(d)['confirmations']), (False, -2))

        self.log.info("Invalidating the conflicting block clears the conflict")
        # Last step
        node1.invalidateblock(block)
        assert_equal([node1.gettransaction(t)['confirmations'] for t in (d, e)], [0, 0])
        assert signed_txid(node0, signed['hex']) in node1.getrawmempool()


def signed_txid(node, tx_hex):
    return node.decoderawtransaction(tx_hex)['txid']


if __name__ == '__main__':
    AbandonConflictTest().main()
