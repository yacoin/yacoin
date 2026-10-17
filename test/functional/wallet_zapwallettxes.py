#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test -zapwallettxes (adapted from Bitcoin Core's zapwallettxes.py).

- with -persistmempool=1 an unconfirmed transaction comes back from the
  saved mempool and so stays in the wallet; its metadata is gone with =2;
- without the mempool it is dropped: gettransaction finds nothing, its
  inputs are spendable again; the confirmed transaction stays;
- =1 keeps the comments of confirmed transactions;
- -zapwallettxes with several wallets is an init error;
- known failure: -zapwallettxes without a value deletes the wallet's
  transactions without the implied rescan.

wallet_basic.py covers =1 / =2 on a wallet with only confirmed
transactions.
"""
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    wait_until,
)

# A valid address that no test node owns
FOREIGN = TestNode.PRIV_KEYS[11].address


class ZapWalletTXesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def restart(self, extra_args):
        self.stop_node(0)
        self.start_node(0, extra_args)
        return self.nodes[0]

    def run_test(self):
        node = self.nodes[0]
        node.generate(30)
        tx1 = node.sendtoaddress(address=FOREIGN, amount=1, comment='c1', comment_to='t1')
        node.generate(1)
        tx2 = node.sendtoaddress(FOREIGN, 2)
        fee2 = -node.gettransaction(tx2)['fee']
        balance = node.getbalance()

        self.log.info("-zapwallettxes=2 with the saved mempool")
        node = self.restart(['-persistmempool=1', '-zapwallettxes=2'])
        wait_until(lambda: tx2 in node.getrawmempool())
        wait_until(lambda: tx2 in [e['txid'] for e in node.listtransactions('*', 1000)])
        assert_equal(node.gettransaction(tx2)['confirmations'], 0)
        assert 'comment' not in node.gettransaction(tx1)
        assert_equal(node.getbalance(), balance)

        self.log.info("-zapwallettxes=2 without the mempool")
        node = self.restart(['-zapwallettxes=2'])
        assert_equal(node.getrawmempool(), [])
        assert_raises_rpc_error(-5, "No information available about transaction", node.gettransaction, tx2)
        assert_equal(node.gettransaction(tx1)['confirmations'], 1)
        # tx2's inputs are free again
        assert_equal(node.getbalance(), balance + 2 + fee2)

        self.log.info("-zapwallettxes=1 keeps the comments")
        tx3 = node.sendtoaddress(address=FOREIGN, amount=1, comment='c3', comment_to='t3')
        node.generate(1)
        node = self.restart(['-zapwallettxes=1'])
        tx = node.gettransaction(tx3)
        assert_equal((tx['comment'], tx['to']), ('c3', 't3'))

        self.log.info("Only with a single wallet")
        self.stop_node(0)
        for mode in ('1', '2'):
            node.assert_start_raises_init_error(['-wallet=a', '-wallet=b', '-zapwallettxes=' + mode],
                                                "Error: -zapwallettxes is only allowed with a single wallet file")

        self.log.info("-zapwallettxes without a value")
        # The mempool saved earlier would bring old transactions back
        mempool = os.path.join(node.datadir, 'mempool.dat')
        if os.path.exists(mempool):
            os.remove(mempool)
        self.start_node(0)
        node = self.nodes[0]
        info = node.getwalletinfo()
        snapshot = (info['txcount'], node.getbalance())
        self.stop_node(0)
        self.start_node(0, ['-zapwallettxes'])
        node = self.nodes[0]

        def check_wallet_kept():
            state = (node.getwalletinfo()['txcount'], node.getbalance())
            assert state == snapshot, "bare -zapwallettxes emptied the wallet: %r" % (state,)
        # -zapwallettxes counts as set for zapping, but as 0 for the implied -rescan
        self.known_failure("bare -zapwallettxes (VKLzdLmd item 6)", check_wallet_kept,
                           expected="bare -zapwallettxes emptied the wallet")
        node = self.restart(['-rescan'])
        assert_equal((node.getwalletinfo()['txcount'], node.getbalance()), snapshot)


if __name__ == '__main__':
    ZapWalletTXesTest().main()
