#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test recovery from random crashes while the UTXO set is flushed.

Nodes 0-2 run with a small -dbbatchsize, so a flush writes many partial
batches, and with -dbcrashratio 8, 16 and 24, so they exit (simulating a
crash) after a partial batch with that inverse probability. node3 is the
reference; it creates and mines all transactions (fan-out transactions with
100 outputs and fan-in transactions with 100 inputs) and the blocks are
given to the others with submitblock. Each crash, also one during the
replay at startup, is followed by a restart. After every round each node
must match node3: best block, the outputs created in the last rounds,
money supply and the address index of tracked addresses; and every 10
rounds verifychain(4, 0) must pass.

Based on Bitcoin Core's feature_dbcrash.py.
"""

from decimal import Decimal
import http.client
import os
import random

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import FailedToStartError
from test_framework.util import assert_equal

BASE = ["-addressindex=1", "-tokenindex=1", "-tokenSupportBlockNumber=10", "-dbcache=4"]
ROUNDS = 25
FANOUT = 100
SMALL = Decimal('0.02')


class DBCrashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.block_fork_1_0 = 1
        self.crash_args = [["-dbcrashratio=%d" % r, "-dbbatchsize=2000"] for r in (8, 16, 24)]
        self.extra_args = [BASE] * 4

    def setup_network(self):
        self.setup_nodes()  # no connections: blocks go in with submitblock

    def debug_log_size(self, node):
        return os.path.getsize(os.path.join(node.datadir, 'debug.log'))

    def assert_crashed(self, node, offset):
        assert_equal(node.wait_for_exit(60), 0)
        with open(os.path.join(node.datadir, 'debug.log'), 'rb') as f:
            f.seek(offset)
            assert b"Simulating a crash. Goodbye." in f.read(), "node%d exited without a simulated crash" % node.index

    def restart_after_crash(self, i, offset):
        node = self.nodes[i]
        self.assert_crashed(node, offset)
        self.crashes[i] += 1
        for _ in range(50):
            offset = self.debug_log_size(node)
            try:
                self.start_node(i)
                return
            except FailedToStartError:
                self.assert_crashed(node, offset)
                self.startup_crashes[i] += 1
        raise AssertionError("node%d keeps crashing at startup" % i)

    def call(self, i, f):
        """Run f(node). Returns (True, result), or (False, None) after a crash and restart."""
        node = self.nodes[i]
        offset = self.debug_log_size(node)
        try:
            return True, f(node)
        except (OSError, http.client.HTTPException):
            self.restart_after_crash(i, offset)
            return False, None

    def sync_crash_node(self, i):
        node3 = self.nodes[3]
        while True:
            ok, height = self.call(i, lambda n: n.getblockcount())
            if not ok:
                continue
            assert_equal(self.nodes[i].getbestblockhash(), node3.getblockhash(height))
            if height == node3.getblockcount():
                return
            for h in range(height + 1, node3.getblockcount() + 1):
                block = node3.getblock(node3.getblockhash(h), False)
                ok, result = self.call(i, lambda n: n.submitblock(block))
                if not ok:
                    break
                assert_equal(result, None)

    def compare(self, i):
        node, node3 = self.nodes[i], self.nodes[3]
        assert_equal(node.getbestblockhash(), node3.getbestblockhash())
        results = [n.batch([n.gettxout.get_request(txid, vout, False) for txid, vout in self.outpoints])
                   for n in (node, node3)]
        assert_equal([r['result'] for r in results[0]], [r['result'] for r in results[1]])
        assert_equal(node.getinfo()['moneysupply'], node3.getinfo()['moneysupply'])
        for a in self.tracked:
            assert_equal(node.getaddressutxos({'addresses': [a]}), node3.getaddressutxos({'addresses': [a]}))
            assert_equal(node.getaddressbalance({'addresses': [a]}), node3.getaddressbalance({'addresses': [a]}))

    def mature_coinbases(self):
        node3 = self.nodes[3]
        coinbases = [node3.getblock(node3.getblockhash(h))['tx'][0] for h in range(1, node3.getblockcount() - 6)]
        return [txid for txid in coinbases if txid not in self.spent_coinbases and node3.gettxout(txid, 0) is not None]

    def send(self, inputs, outputs):
        node3 = self.nodes[3]
        raw = node3.createrawtransaction(inputs, outputs)
        signed = node3.signrawtransaction(raw)
        assert signed['complete']
        txid = node3.sendrawtransaction(signed['hex'])
        return txid, node3.decoderawtransaction(raw)['vout']

    def run_test(self):
        random.seed(20261016)
        self.crashes = [0, 0, 0]
        self.startup_crashes = [0, 0, 0]
        node3 = self.nodes[3]
        self.mine_with_mocktime(node3, 31, sync=False)
        pool = [node3.getnewaddress() for _ in range(FANOUT)]
        self.tracked = [node3.getnewaddress() for _ in range(3)]
        self.outpoints = []
        self.spent_coinbases = set()
        small = []

        self.log.info("Sync nodes 0-2, then turn on the crash options")
        for i in range(3):
            self.sync_crash_node(i)
            self.nodes[i].listtokens()
            self.stop_node(i)
            self.nodes[i].extra_args = BASE + self.crash_args[i]
            self.start_node(i)

        for rnd in range(ROUNDS):
            # Inputs come from tracked coinbase outpoints and small outputs.
            for txid in self.mature_coinbases()[:2]:
                self.spent_coinbases.add(txid)
                amount = node3.gettxout(txid, 0)['value']
                outputs = {a: SMALL for a in pool}
                outputs[self.tracked[rnd % 3]] = Decimal('0.05')
                outputs[node3.getrawchangeaddress()] = amount - SMALL * FANOUT - Decimal('0.05') - Decimal('0.1')
                txid, vout = self.send([{'txid': txid, 'vout': 0}], outputs)
                self.outpoints += [(txid, o['n']) for o in vout]
                small += [(txid, o['n']) for o in vout if o['value'] == SMALL]
            if len(small) > 3 * FANOUT:
                inputs, small = small[:FANOUT], small[FANOUT:]
                txid, _ = self.send([{'txid': t, 'vout': n} for t, n in inputs],
                                    {node3.getrawchangeaddress(): SMALL * FANOUT - Decimal('0.3')})
                self.outpoints.append((txid, 0))
            self.mine_with_mocktime(node3, random.randint(2, 4), sync=False)
            for i in range(3):
                self.sync_crash_node(i)
                self.call(i, lambda n: n.listtokens())  # forces a flush
                self.sync_crash_node(i)
                self.compare(i)
                if rnd % 10 == 9 or rnd == ROUNDS - 1:
                    assert_equal(self.nodes[i].verifychain(4, 0), True)
            self.outpoints = self.outpoints[-6 * (2 * FANOUT + 3):]
            self.log.info("Round %d: height %d, crashes %s, crashes at startup %s" % (
                rnd, node3.getblockcount(), self.crashes, self.startup_crashes))

        for i in range(3):
            if self.crashes[i] == 0:
                self.log.warning("node%d never crashed during a flush" % i)


if __name__ == '__main__':
    DBCrashTest().main()
