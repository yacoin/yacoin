#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet startup options -upgradewallet, -salvagewallet and
-blocksonly, and the startup checks of a damaged wallet.dat and wallet
database environment.

- -upgradewallet=<n> below the wallet's version is an init error; with no
  value it keeps an HD wallet at 139900 and a non-HD wallet at 60000.
- -salvagewallet renames wallet.dat to wallet.dat.<time>.bak, keeps only
  the keys and rescans: keys, balance and transactions survive, labels and
  key metadata don't.
- A wallet.dat that fails the database check is salvaged automatically at
  startup (warning), or the start fails ("salvage failed").
- A damaged database environment is moved aside.
- -blocksonly turns wallet broadcasting off unless -walletbroadcast=1.
"""
import os
import re
import resource
import shutil
import struct
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch, FailedToStartError, describe_exit_code
from test_framework.util import assert_equal, assert_raises_rpc_error

HD_VERSION = 139900
NON_HD_VERSION = 60000
BTREE_MAGIC = 0x053162
PAGE_TYPE_LEAF = 5
PAGE_TYPE_META = 9


def no_core_dump():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class WalletStartupOptionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [[], ['-usehd=0']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

    def wallet_path(self, *name):
        return os.path.join(self.nodes[0].datadir, *name)

    def write_wallet(self, data):
        with open(self.wallet_path('wallet.dat'), 'wb') as f:
            f.write(data)

    def tick(self):
        # Every renamed file gets a fresh <name>.<mocktime>.bak name.
        self.set_mocktime(self.mocktime + 10)
        return self.mocktime

    def state(self, node):
        return (node.getbalance(), {t: node.gettransaction(t)['confirmations'] for t in self.txids},
                [node.dumpprivkey(a)['private_key'] for a in self.addrs])

    def run_test(self):
        n0, n1 = self.nodes
        self.set_mocktime(int(time.time()))

        self.log.info("-upgradewallet on an HD wallet")
        assert_equal(n0.getwalletinfo()['walletversion'], HD_VERSION)
        self.stop_node(0)
        for v in (1, NON_HD_VERSION, HD_VERSION - 1):
            n0.assert_start_raises_init_error(['-upgradewallet=%d' % v], "Error: Cannot downgrade wallet")
        for args in (['-upgradewallet'], ['-upgradewallet=%d' % HD_VERSION]):
            self.start_node(0, args)
            info = n0.getwalletinfo()
            assert_equal((info['walletversion'], info['keypoolsize_hd_internal']), (HD_VERSION, 100))
            self.stop_node(0)

        self.log.info("-upgradewallet on a non-HD wallet keeps it non-HD")
        self.stop_node(1)
        n1.assert_start_raises_init_error(['-usehd=0', '-upgradewallet=%d' % (NON_HD_VERSION - 1)], "Error: Cannot downgrade wallet")
        self.start_node(1, ['-usehd=0', '-upgradewallet'])
        info = n1.getwalletinfo()
        assert_equal(info['walletversion'], NON_HD_VERSION)
        assert 'hdmasterkeyid' not in info

        self.log.info("-salvagewallet on a healthy wallet")
        self.start_node(0)
        self.addrs = [n0.getnewaddress('label%d' % i) for i in range(3)]
        self_payment = n0.sendtoaddress(address=self.addrs[0], amount=3)
        n0.generate(1)
        self.txids = set(t['txid'] for t in n0.listtransactions('*', 1000))
        old_paths = [int(re.match(r"m/0'/0'/(\d+)'", n0.validateaddress(a)['hdkeypath']).group(1)) for a in self.addrs]
        before = self.state(n0)
        self.stop_node(0)
        t = self.tick()
        with n0.assert_debug_log(['parameter interaction: -salvagewallet=1 -> setting -rescan=1',
                                  'Renamed wallet.dat to wallet.dat.%d.bak' % t,
                                  'Rescanning last']):
            self.start_node(0, ['-salvagewallet'])
        assert os.path.isfile(self.wallet_path('wallet.dat.%d.bak' % t))
        assert_equal(self.state(n0), before)
        # Only keys are kept: labels and key metadata are gone.
        assert_equal([n0.getaccount(a) for a in self.addrs], ['', '', ''])
        assert 'hdkeypath' not in n0.validateaddress(self.addrs[1])
        # Pins today's behaviour: without its label the self-payment's output
        # counts as change, so listtransactions no longer shows it.
        assert self_payment not in [t['txid'] for t in n0.listtransactions('*', 1000)]
        # The HD counter survives, so no key is handed out twice.
        new_path = n0.validateaddress(n0.getnewaddress())['hdkeypath']
        assert int(re.match(r"m/0'/0'/(\d+)'", new_path).group(1)) > max(old_paths)
        self.restart_node(0)

        def hd_split_kept():
            info = n0.getwalletinfo()
            assert_equal(info['walletversion'], HD_VERSION)
            assert n0.validateaddress(n0.getrawchangeaddress())['hdkeypath'].startswith("m/0'/1'/")
        self.known_failure("salvage drops the HD chain split (YslI5Qz7 item 3)", hd_split_kept,
                           expected="not(%d == %d)" % (NON_HD_VERSION, HD_VERSION))
        healthy_txcount = n0.getwalletinfo()['txcount']
        self.stop_node(0)

        with open(self.wallet_path('wallet.dat'), 'rb') as f:
            healthy = f.read()
        magic = struct.unpack('<I', healthy[12:16])[0]
        ps = struct.unpack('<I', healthy[20:24])[0]
        # Page 1 is the master database's leaf, page 2 the meta page of "main".
        assert_equal((magic, healthy[ps + 25], healthy[2 * ps + 25]), (BTREE_MAGIC, PAGE_TYPE_LEAF, PAGE_TYPE_META))

        self.log.info("A wallet.dat with a damaged page is salvaged at startup")
        damaged = bytearray(healthy)
        for k in range(ps + 8, ps + 12):  # page 1's page number
            damaged[k] ^= 0xff
        self.write_wallet(bytes(damaged))
        t = self.tick()
        self.start_node(0)
        assert os.path.isfile(self.wallet_path('wallet.dat.%d.bak' % t))
        assert_equal(self.state(n0), before)
        # InitWarning adds a second "Warning: " (as for -paytxfee).
        self.stop_node(0, expected_stderr=(
            'Warning: Warning: Wallet file corrupt, data salvaged! Original wallet.dat saved as '
            'wallet.dat.%d.bak in "%s"; if your balance or transactions are incorrect you should '
            'restore from a backup.\n'
            'Warning: Error reading wallet.dat! All keys read correctly, but transaction data or '
            'address book entries might be missing or incorrect.') % (t, n0.datadir))

        self.log.info("A wallet.dat that is not a database: salvage fails and the file stays")
        junk = bytes(range(256)) * 16
        self.write_wallet(junk)
        t = self.tick()
        n0.assert_start_raises_init_error([], "Error: wallet.dat corrupt, salvage failed")
        assert not os.path.exists(self.wallet_path('wallet.dat.%d.bak' % t))
        with open(self.wallet_path('wallet.dat'), 'rb') as f:
            assert_equal(f.read(), junk)
        self.known_failure("silent -salvagewallet failure (YslI5Qz7 item 4)",
                           lambda: n0.assert_start_raises_init_error(['-salvagewallet'], r'\S', match=ErrorMatch.PARTIAL_REGEX),
                           expected='does not partially match stderr:\n""')

        self.log.info("A failed salvage moves wallet.dat away, also when it is restored afterwards")
        damaged = bytearray(healthy)
        damaged[2 * ps + 25] ^= 0xff  # page 2's page type
        self.write_wallet(bytes(damaged))
        t = self.tick()
        n0.assert_start_raises_init_error([], "Error: wallet.dat corrupt, salvage failed")
        assert os.path.isfile(self.wallet_path('wallet.dat.%d.bak' % t))
        assert not os.path.exists(self.wallet_path('wallet.dat'))
        # The user restores the healthy file.
        self.write_wallet(healthy)
        self.start_node(0)

        def restored_wallet_loaded():
            assert_equal(n0.getwalletinfo()['txcount'], healthy_txcount)
        self.known_failure("restored wallet.dat moved aside (YslI5Qz7 item 2)", restored_wallet_loaded,
                           expected="not(0 == %d)" % healthy_txcount)
        assert os.path.isfile(self.wallet_path('wallet.dat.%d.bak' % t))
        assert_raises_rpc_error(-4, "Wallet doesn't manage coins in this address", n0.dumpprivkey, self.addrs[0])
        self.stop_node(0)

        self.log.info("A regular file in place of the database directory")
        self.write_wallet(healthy)
        if os.path.isdir(self.wallet_path('database')):
            shutil.rmtree(self.wallet_path('database'))
        with open(self.wallet_path('database'), 'wb') as f:
            f.write(junk)
        self.known_failure("raw exception for a database file (YslI5Qz7 item 5)",
                           lambda: n0.assert_start_raises_init_error([], "Error initializing wallet database environment", match=ErrorMatch.PARTIAL_REGEX),
                           expected='EXCEPTION: N5boost10filesystem16filesystem_errorE')
        os.remove(self.wallet_path('database'))

        self.log.info("A damaged database environment is moved aside")
        os.makedirs(self.wallet_path('database'))
        # Any non-zero log content; BDB accepts an all-zero log as empty.
        with open(self.wallet_path('database', 'log.0000000001'), 'wb') as f:
            f.write(junk)
        t = self.tick()

        def env_retry():
            n0.start([], preexec_fn=no_core_dump)
            try:
                n0.wait_for_rpc_connection()
            except FailedToStartError:
                raise AssertionError("exit code %s" % describe_exit_code(n0.wait_for_exit()))
        # CDBEnv::Open closes the DbEnv on failure, and the retry reuses it.
        self.known_failure("segfault on damaged db log (YslI5Qz7 item 1)", env_retry,
                           expected="exit code -11 (SIGSEGV)")
        assert os.path.isdir(self.wallet_path('database.%d.bak' % t))

        self.log.info("-blocksonly turns wallet broadcasting off")
        with n0.assert_debug_log(['parameter interaction: -blocksonly=1 -> setting -walletbroadcast=0']):
            self.start_node(0, ['-blocksonly'])
        assert_equal(self.state(n0), before)
        txid = n0.sendtoaddress(address=n0.getnewaddress(), amount=1)
        assert_equal(n0.getrawmempool(), [])
        assert_equal(n0.gettransaction(txid)['confirmations'], 0)
        assert_raises_rpc_error(-4, "Error: Wallet transaction broadcasting is disabled with -walletbroadcast", n0.resendwallettransactions)
        self.stop_node(0)
        self.tick()
        self.start_node(0, ['-blocksonly', '-walletbroadcast=1'])
        assert_equal(n0.getrawmempool(), [txid])
        txid2 = n0.sendtoaddress(address=n0.getnewaddress(), amount=1)
        assert_equal(sorted(n0.getrawmempool()), sorted([txid, txid2]))
        assert_equal(n0.resendwallettransactions(), [txid, txid2])


if __name__ == '__main__':
    WalletStartupOptionsTest().main()
