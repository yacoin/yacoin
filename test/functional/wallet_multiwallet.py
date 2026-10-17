#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test several wallets in one node (adapted from Bitcoin Core's multiwallet.py).

- RPC routing: wallet RPCs need the /wallet/<name> endpoint when several
  wallets are loaded; an unknown wallet; listwallets; RPCs that don't need
  a wallet;
- separate balances; paytxfee is shared by all wallets;
- encrypting one wallet; dumpwallet and backupwallet of one wallet; a
  backup loads as a wallet of its own;
- init errors: duplicate names, a directory, a symlink, a path, invalid
  characters, a copy of a loaded wallet, -salvagewallet and
  -upgradewallet with several wallets.

The framework's setup imports the deterministic coinbase key through the
default wallet RPC endpoint, which doesn't exist with several wallets, so
setup_nodes is overridden and coins are mined to an address of w1.
"""
import os
import shutil
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import mature_coinbase_total

WALLETS = ['-wallet=w1', '-wallet=w2', '-wallet=w3']
NOT_SPECIFIED = "Wallet file not specified (must request wallet RPC through /wallet/<filename> uri-path)."


class MultiWalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [WALLETS]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def wallets(self):
        return [self.nodes[0].get_wallet_rpc(name) for name in ('w1', 'w2', 'w3')]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("RPC routing")
        for method in (node.getwalletinfo, node.getbalance, node.getnewaddress):
            assert_raises_rpc_error(-19, NOT_SPECIFIED, method)
        assert_raises_rpc_error(-18, "Requested wallet does not exist or is not loaded",
                                node.get_wallet_rpc('wx').getwalletinfo)
        assert_equal(node.listwallets(), ['w1', 'w2', 'w3'])
        w1, w2, w3 = self.wallets()
        assert_equal(w1.getwalletinfo()['walletname'], 'w1')
        # Without an endpoint, RPCs that don't need a wallet see none
        info = node.getinfo()
        assert 'balance' not in info and 'walletversion' not in info and 'keypoolsize' not in info, info
        assert_equal(node.validateaddress(w1.getnewaddress())['ismine'], False)
        assert node.help('getwalletinfo').startswith('getwalletinfo')

        self.log.info("Separate balances")
        address = w1.getnewaddress()
        node.generatetoaddress(10, address)
        assert_equal(w1.getbalance(), mature_coinbase_total(node, address))
        assert_equal((w2.getbalance(), w3.getbalance()), (0, 0))
        txid = w1.sendtoaddress(w2.getnewaddress(), 1)
        node.generatetoaddress(1, address)
        assert_equal(w2.getbalance(), 1)
        assert_equal(w2.gettransaction(txid)['amount'], 1)
        assert_equal(w3.getbalance(), 0)
        # w3 gets the transaction from the txindex
        assert 'details' not in w3.gettransaction(txid)
        balances = [w.getbalance() for w in (w1, w2, w3)]

        # nTransactionFee is global
        w1.settxfee(Decimal('0.05'))
        assert_equal(w2.getwalletinfo()['paytxfee'], Decimal('0.05'))
        w1.settxfee(Decimal('0.01'))

        self.log.info("Encrypt one wallet")
        w3.encryptwallet('p')
        node.wait_until_stopped()
        self.start_node(0, WALLETS)
        w1, w2, w3 = self.wallets()
        assert 'unlocked_until' in w3.getwalletinfo()
        assert 'unlocked_until' not in w1.getwalletinfo()
        assert_equal([w.getbalance() for w in (w1, w2, w3)], balances)
        dump = w1.dumpwallet(os.path.join(node.datadir, 'w1.dump'))['filename']
        assert_equal(dump, os.path.join(node.datadir, 'w1.dump'))
        w1.backupwallet(os.path.join(node.datadir, 'w1.bak'))

        self.log.info("Init errors")
        self.stop_node(0)
        datadir = node.datadir

        def init_error(args, message):
            node.assert_start_raises_init_error(args, message)

        init_error(['-wallet=w1', '-wallet=w1'], "Error: Error loading wallet w1. Duplicate -wallet filename specified.")
        os.mkdir(os.path.join(datadir, 'w11'))
        init_error(['-wallet=w11'], "Error: Error loading wallet w11. -wallet filename must be a regular file.")
        os.symlink('w1', os.path.join(datadir, 'w12'))
        init_error(['-wallet=w12'], "Error: Error loading wallet w12. -wallet filename must be a regular file.")
        for name in ('sub/w', os.path.join(datadir, 'abs'), './wallet.dat'):
            init_error(['-wallet=' + name],
                       "Error: Error loading wallet %s. -wallet parameter must only specify a filename (not a path)." % name)
        init_error(['-wallet=w*'], "Error: Error loading wallet w*. Invalid characters in -wallet filename.")
        init_error(WALLETS[:2] + ['-salvagewallet'], "Error: -salvagewallet is only allowed with a single wallet file")
        init_error(WALLETS[:2] + ['-upgradewallet'], "Error: -upgradewallet is only allowed with a single wallet file")
        # A copy of a loaded wallet has the same BDB file id
        shutil.copyfile(os.path.join(datadir, 'w2'), os.path.join(datadir, 'w22'))
        node.assert_start_raises_init_error(['-wallet=w2', '-wallet=w22'], 'duplicates fileid',
                                            match=ErrorMatch.PARTIAL_REGEX)

        self.log.info("A backup loads as a wallet of its own")
        self.start_node(0, ['-wallet=w1.bak'])
        assert_equal(node.getwalletinfo()['walletname'], 'w1.bak')
        assert_equal(node.getbalance(), balances[0])


if __name__ == '__main__':
    MultiWalletTest().main()
