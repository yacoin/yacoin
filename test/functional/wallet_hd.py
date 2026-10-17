#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Hierarchical Deterministic wallet function.

- -usehd can't be switched off on an HD wallet, nor on for a non-HD one;
  the wallet versions and keypool fields of both kinds;
- the internal (change) and external key paths; a non-HD key imported into
  an HD wallet; dumpwallet;
- a restored backup derives the same keys and finds the funds with -rescan;
- keypool top-up: restoring a backup over a wallet whose later keys were
  used marks the keypool keys up to the used one as used and refills the
  keypool.
"""

import os
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    connect_nodes,
)


class WalletHDTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-usehd=0'], ['-usehd=1', '-keypool=0']]
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        # Make sure can't switch off usehd after wallet creation
        self.stop_node(1)
        self.nodes[1].assert_start_raises_init_error(['-usehd=0'], 'already existing HD wallet', match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(1)

        # Versions and keypool fields: HD with chain split, and non-HD
        info0 = self.nodes[0].getwalletinfo()
        assert_equal(info0['walletversion'], 60000)
        assert 'keypoolsize_hd_internal' not in info0 and 'hdmasterkeyid' not in info0
        info1 = self.nodes[1].getwalletinfo()
        assert_equal(info1['walletversion'], 139900)
        # -keypool=0 still keeps one key of each kind
        assert_equal((info1['keypoolsize'], info1['keypoolsize_hd_internal']), (1, 1))

        # Make sure can't switch on usehd on a non-HD wallet
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(['-usehd=1'], "Error: Error loading wallet.dat: You can't enable HD on an already existing non-HD wallet")
        self.start_node(0)

        # Make sure we use hd, keep masterkeyid
        masterkeyid = self.nodes[1].getwalletinfo()['hdmasterkeyid']
        assert_equal(len(masterkeyid), 40)

        # create an internal key
        change_addr = self.nodes[1].getrawchangeaddress()
        change_addrV= self.nodes[1].validateaddress(change_addr)
        assert_equal(change_addrV["hdkeypath"], "m/0'/1'/0'") #first internal child key

        # Import a non-HD private key in the HD wallet
        non_hd_add = self.nodes[0].getnewaddress()
        self.nodes[1].importprivkey(self.nodes[0].dumpprivkey(non_hd_add)["private_key"])

        # This should be enough to keep the master key and the non-HD key
        self.nodes[1].backupwallet(os.path.join(self.nodes[1].datadir, "hd.bak"))
        dump = os.path.join(self.nodes[1].datadir, "hd.dump")
        assert_equal(self.nodes[1].dumpwallet(dump)['filename'], dump)

        # Derive some HD addresses and remember the last
        # Also send funds to each add
        self.nodes[0].generate(10)
        hd_add = None
        num_hd_adds = 10
        for i in range(num_hd_adds):
            hd_add = self.nodes[1].getnewaddress()
            hd_info = self.nodes[1].validateaddress(hd_add)
            assert_equal(hd_info["hdkeypath"], "m/0'/0'/"+str(i+1)+"'")
            assert_equal(hd_info["hdmasterkeyid"], masterkeyid)
            self.nodes[0].sendtoaddress(hd_add, 1)
            self.nodes[0].generate(1)
        self.nodes[0].sendtoaddress(non_hd_add, 1)
        self.nodes[0].generate(1)

        # create an internal key (again)
        change_addr = self.nodes[1].getrawchangeaddress()
        change_addrV= self.nodes[1].validateaddress(change_addr)
        assert_equal(change_addrV["hdkeypath"], "m/0'/1'/1'") #second internal child key

        connect_nodes(self.nodes[0], 1)
        self.sync_all()
        assert_equal(self.nodes[1].getbalance(), num_hd_adds + 1)

        self.log.info("Restore backup ...")
        self.stop_node(1)
        # we need to delete the complete chain directory
        # otherwise node1 would auto-recover all funds in flag the keypool keys as used
        shutil.rmtree(os.path.join(self.nodes[1].datadir, "blocks"))
        shutil.rmtree(os.path.join(self.nodes[1].datadir, "chainstate"))
        shutil.copyfile(os.path.join(self.nodes[1].datadir, "hd.bak"), os.path.join(self.nodes[1].datadir, "wallet.dat"))
        self.start_node(1)

        # Assert that derivation is deterministic
        hd_add_2 = None
        for _ in range(num_hd_adds):
            hd_add_2 = self.nodes[1].getnewaddress()
            hd_info_2 = self.nodes[1].validateaddress(hd_add_2)
            assert_equal(hd_info_2["hdkeypath"], "m/0'/0'/"+str(_+1)+"'")
            assert_equal(hd_info_2["hdmasterkeyid"], masterkeyid)
        assert_equal(hd_add, hd_add_2)
        connect_nodes(self.nodes[0], 1)
        self.sync_all()

        # Needs rescan
        self.stop_node(1)
        self.start_node(1, extra_args=self.extra_args[1] + ['-rescan'])
        assert_equal(self.nodes[1].getbalance(), num_hd_adds + 1)

        # send a tx and make sure its using the internal chain for the changeoutput
        txid = self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        outs = self.nodes[1].decoderawtransaction(self.nodes[1].gettransaction(txid)['hex'])['vout']
        keypath = ""
        for out in outs:
            if out['value'] != 1:
                keypath = self.nodes[1].validateaddress(out['scriptPubKey']['addresses'][0])['hdkeypath']

        assert_equal(keypath[0:7], "m/0'/1'")

        self.test_keypool_topup()

    def test_keypool_topup(self):
        self.log.info("Keypool top-up after restoring a backup")
        args = ['-usehd=1', '-keypool=20']
        self.restart_node(1, args)
        connect_nodes(self.nodes[0], 1)
        self.sync_blocks()
        node0, node1 = self.nodes
        info = node1.getwalletinfo()
        assert_equal((info['keypoolsize'], info['keypoolsize_hd_internal']), (20, 20))
        backup = os.path.join(node1.datadir, "topup.bak")
        node1.backupwallet(backup)

        addresses = [node1.getnewaddress() for _ in range(15)]
        first = int(node1.validateaddress(addresses[0])['hdkeypath'].split('/')[-1][:-1])
        node0.sendtoaddress(addresses[11], 1)
        node0.generate(1)
        self.sync_blocks()

        self.stop_node(1)
        shutil.copyfile(backup, os.path.join(node1.datadir, "wallet.dat"))
        self.start_node(1, args)
        connect_nodes(self.nodes[0], 1)
        self.sync_blocks()
        node1 = self.nodes[1]
        # (Not the balance: node 0 may spend the non-HD key's coin, which
        # both wallets own.)
        assert_equal([u['amount'] for u in node1.listunspent() if u['address'] == addresses[11]], [1])
        assert_equal(node1.getreceivedbyaddress(addresses[11]), 1)
        # The keys up to the used one were taken out, and the pool refilled
        info = node1.getwalletinfo()
        assert_equal((info['keypoolsize'], info['keypoolsize_hd_internal']), (20, 20))
        assert_equal(node1.validateaddress(node1.getnewaddress())['hdkeypath'], "m/0'/0'/%d'" % (first + 12))

if __name__ == '__main__':
    WalletHDTest().main ()
