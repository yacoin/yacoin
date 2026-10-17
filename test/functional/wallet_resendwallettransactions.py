#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet's rebroadcast of unconfirmed transactions.

- resendwallettransactions returns the unconfirmed transactions in the
  order they were received, and [] once they are confirmed.
- The periodic rebroadcast (ResendWalletTransactions) runs at most every
  30 minutes, only after a new block, and only for transactions received
  at least 5 minutes before that block arrived. A peer that was already
  sent a transaction doesn't get it again.
"""
import time
from collections import defaultdict

from test_framework.messages import MSG_TX
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class TxInvStore(P2PInterface):
    """Counts the tx invs it receives and never asks for the transactions."""
    def __init__(self):
        super().__init__()
        self.tx_invs = defaultdict(int)

    def on_inv(self, message):
        for i in message.inv:
            if i.type == MSG_TX:
                self.tx_invs['%064x' % i.hash] += 1

    def count(self, txid):
        with mininode_lock:
            return self.tx_invs[txid]


class ResendWalletTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        # Node 1 mines the blocks that don't contain node 0's transactions.
        self.num_nodes = 2
        # Whitelisted peers get their tx invs without the trickle delay.
        self.extra_args = [['-whitelist=127.0.0.1'], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # No connections: node 1 must not see node 0's transactions.
        self.setup_nodes()
        self.copy_tip(self.nodes[0], self.nodes[1])

    def copy_tip(self, src, dst):
        tip = src.getbestblockhash()
        assert_equal(dst.submitblock(src.getblock(tip, 0)), None)
        assert_equal(dst.getbestblockhash(), tip)

    def handled(self, peer):
        # The rebroadcast runs in the first SendMessages after a mocktime
        # change, possibly for another peer later in the same pass; three
        # pongs prove that pass and this peer's next SendMessages are done.
        for _ in range(3):
            peer.sync_with_ping()

    def block_without_wallet_txs(self):
        n0, n1 = self.nodes
        n1.generate(1)
        self.copy_tip(n1, n0)

    def run_test(self):
        n0, n1 = self.nodes
        T = int(time.time())
        self.set_mocktime(T)

        self.log.info("resendwallettransactions returns unconfirmed transactions oldest first")
        a = n0.sendtoaddress(address=n0.getnewaddress(), amount=1)
        self.set_mocktime(T + 10)
        b = n0.sendtoaddress(address=n0.getnewaddress(), amount=1)
        assert_equal(n0.resendwallettransactions(), [a, b])
        self.set_mocktime(T + 20)
        n0.generate(1)
        assert_equal(n0.resendwallettransactions(), [])
        self.copy_tip(n0, n1)

        self.log.info("The first broadcast goes to the connected peer")
        T += 100
        self.set_mocktime(T)
        p1 = n0.add_p2p_connection(TxInvStore())
        t1 = n0.sendtoaddress(address=n0.getnewaddress(), amount=1)
        self.handled(p1)
        assert_equal(p1.count(t1), 1)
        p2 = n0.add_p2p_connection(TxInvStore())

        self.log.info("31 minutes later: the last block is older than t1, nothing is rebroadcast")
        with n0.assert_debug_log([], ['Relaying wtx']):
            self.set_mocktime(T + 31 * 60)
            self.handled(p2)
        assert_equal((p1.count(t1), p2.count(t1)), (1, 0))

        self.log.info("A block without t1 arrives; t2 is sent right after it")
        self.block_without_wallet_txs()
        t2 = n0.sendtoaddress(address=n0.getnewaddress(), amount=1)
        self.handled(p2)
        assert_equal((p1.count(t2), p2.count(t2)), (1, 1))

        self.log.info("31 minutes later t1 is rebroadcast, t2 (younger than block - 5 min) is not")
        with n0.assert_debug_log(['Relaying wtx ' + t1, 'rebroadcast 1 unconfirmed transactions'], ['Relaying wtx ' + t2]):
            self.set_mocktime(T + 62 * 60)
            self.handled(p2)
        self.handled(p1)
        # p1 already has t1
        assert_equal((p1.count(t1), p2.count(t1), p2.count(t2)), (1, 1, 1))

        self.log.info("No second rebroadcast without another block")
        with n0.assert_debug_log([], ['Relaying wtx']):
            self.set_mocktime(T + 93 * 60)
            self.handled(p2)
        assert_equal((p2.count(t1), p2.count(t2)), (1, 1))

        self.log.info("After the next block both are rebroadcast")
        self.block_without_wallet_txs()
        p3 = n0.add_p2p_connection(TxInvStore())
        with n0.assert_debug_log(['Relaying wtx ' + t1, 'Relaying wtx ' + t2, 'rebroadcast 2 unconfirmed transactions']):
            self.set_mocktime(T + 124 * 60)
            self.handled(p3)
        assert_equal((p3.count(t1), p3.count(t2)), (1, 1))

        self.log.info("Confirmed transactions are not rebroadcast")
        n0.generate(1)
        assert_equal(n0.getrawmempool(), [])
        self.copy_tip(n0, n1)
        self.block_without_wallet_txs()
        with n0.assert_debug_log([], ['Relaying wtx']):
            self.set_mocktime(T + 155 * 60)
            self.handled(p3)
        assert_equal((p3.count(t1), p3.count(t2)), (1, 1))
        assert_equal(n0.resendwallettransactions(), [])


if __name__ == '__main__':
    ResendWalletTransactionsTest().main()
