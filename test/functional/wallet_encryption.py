#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet encryption.

- an unencrypted wallet rejects walletpassphrase, walletpassphrasechange,
  walletlock and an empty encryptwallet passphrase;
- encryptwallet: the node stops; a new HD master key is used afterwards;
- a locked wallet: unlocked_until, empty and wrong passphrases, every RPC
  that needs a private key reports that the wallet is locked, new
  addresses still come from the keypool;
- walletpassphrase: the timeout relocks the wallet, unlocked_until, a send
  while unlocked; walletlock; walletpassphrasechange;
- known failures: walletpassphrase accepts a negative and an overflowing
  timeout (and leaves the wallet locked); spendcsv reports a locked wallet
  with -1.
"""
import time
from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    wait_until,
)

UNLOCK_NEEDED = "Error: Please enter the wallet passphrase with walletpassphrase first."
INCORRECT = "Error: The wallet passphrase entered was incorrect."
# A valid address that no test node owns
FOREIGN = TestNode.PRIV_KEYS[11].address


class WalletEncryptionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        passphrase = "WalletPassphrase"
        passphrase2 = "SecondWalletPassphrase"
        node = self.nodes[0]
        node.generate(10)

        # Make sure the wallet isn't encrypted first
        address = node.getnewaddress()
        privkey = node.dumpprivkey(address)["private_key"]
        assert_equal(privkey[:1], "X")
        assert_equal(len(privkey), 52)
        assert_raises_rpc_error(-15, "Error: running with an unencrypted wallet, but walletpassphrase was called", node.walletpassphrase, 'ff', 1)
        assert_raises_rpc_error(-15, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.", node.walletpassphrasechange, 'ff', 'ff')
        assert_raises_rpc_error(-15, "Error: running with an unencrypted wallet, but walletlock was called.", node.walletlock)
        assert_raises_rpc_error(-1, "encryptwallet <passphrase>\nEncrypts the wallet with <passphrase>.", node.encryptwallet, '')
        assert 'unlocked_until' not in node.getwalletinfo()
        master = node.getwalletinfo()['hdmasterkeyid']

        # Encrypt the wallet
        node.encryptwallet(passphrase)
        self.stop_node(0)
        self.start_node(0)
        node = self.nodes[0]

        # Test that the wallet is encrypted
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", node.dumpprivkey, address)
        assert_raises_rpc_error(-15, "Error: running with an encrypted wallet, but encryptwallet was called.", node.encryptwallet, 'ff')

        self.log.info("Encryption replaces the HD master key")
        info = node.getwalletinfo()
        assert info['hdmasterkeyid'] != master
        new = node.validateaddress(node.getnewaddress())
        assert_equal((new['hdmasterkeyid'], new['hdkeypath']), (info['hdmasterkeyid'], "m/0'/0'/0'"))

        self.log.info("A locked wallet")
        assert_equal(info['unlocked_until'], 0)
        assert_raises_rpc_error(-1, "walletpassphrase <passphrase> <timeout>\nStores the wallet decryption key in memory for <timeout> seconds.",
                                node.walletpassphrase, '', 10)
        assert_raises_rpc_error(-14, INCORRECT, node.walletpassphrasechange, 'wrong', 'x')
        change_help = "walletpassphrasechange <oldpassphrase> <newpassphrase>\nChanges the wallet passphrase from <oldpassphrase> to <newpassphrase>."
        assert_raises_rpc_error(-1, change_help, node.walletpassphrasechange, '', 'x')
        assert_raises_rpc_error(-1, change_help, node.walletpassphrasechange, passphrase, '')
        for method, args in [
            (node.sendtoaddress, [FOREIGN, 1]),
            (node.sendmany, ['coinbase', {FOREIGN: 1}]),
            (node.sendfrom, ['coinbase', FOREIGN, 1]),
            (node.signmessage, [address, 'm']),
            (node.importprivkey, [TestNode.PRIV_KEYS[10].key]),
            (node.dumpprivkey, [address]),
            (node.keypoolrefill, [5]),
            (node.timelockcoins, [1, 10]),
        ]:
            assert_raises_rpc_error(-13, UNLOCK_NEEDED, method, *args)
        # The keypool still has keys
        node.getnewaddress()

        # Check that walletpassphrase works
        node.walletpassphrase(passphrase, 2)
        assert_equal(privkey, node.dumpprivkey(address)["private_key"])

        # Check that the timeout is right
        wait_until(lambda: node.getwalletinfo()['unlocked_until'] == 0, timeout=10)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", node.dumpprivkey, address)

        # Test wrong passphrase
        assert_raises_rpc_error(-14, "wallet passphrase entered was incorrect", node.walletpassphrase, passphrase + "wrong", 10)

        self.log.info("unlocked_until and a send while unlocked")
        now = int(time.time())
        node.walletpassphrase(passphrase, 60)
        unlocked_until = node.getwalletinfo()['unlocked_until']
        assert now + 55 <= unlocked_until <= now + 65, unlocked_until - now
        txid = node.sendtoaddress(FOREIGN, 1)
        assert_equal(node.gettransaction(txid)['fee'], Decimal('-0.01'))
        node.generate(1)
        assert_equal(node.gettransaction(txid)['confirmations'], 1)

        # Test walletlock
        node.walletpassphrase(passphrase, 84600)
        assert_equal(privkey, node.dumpprivkey(address)["private_key"])
        node.walletlock()
        assert_equal(node.getwalletinfo()['unlocked_until'], 0)
        assert_raises_rpc_error(-13, "Please enter the wallet passphrase with walletpassphrase first", node.dumpprivkey, address)

        # Test passphrase changes
        node.walletpassphrasechange(passphrase, passphrase2)
        assert_raises_rpc_error(-14, "wallet passphrase entered was incorrect", node.walletpassphrase, passphrase, 10)
        node.walletpassphrase(passphrase2, 10)
        assert_equal(privkey, node.dumpprivkey(address)["private_key"])
        node.walletlock()

        self.log.info("walletpassphrase timeouts out of range")

        def check_negative_timeout():
            assert_raises_rpc_error(None, None, node.walletpassphrase, passphrase2, -10)
        # The timeout isn't checked
        self.known_failure("walletpassphrase timeout (VKLzdLmd item 5)", check_negative_timeout,
                           expected="No exception raised")
        # ... and the wallet stays locked
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, node.dumpprivkey, address)

        def check_huge_timeout():
            try:
                node.walletpassphrase(passphrase2, 2**62)
            except JSONRPCException:
                return
            assert node.getwalletinfo()['unlocked_until'] > time.time(), "huge timeout ignored"
        # The relock timer's milliseconds overflow, so it fires at once
        self.known_failure("walletpassphrase timeout (VKLzdLmd item 5)", check_huge_timeout,
                           expected="huge timeout ignored")
        node.walletlock()

        self.log.info("spendcsv on a locked wallet")
        node.walletpassphrase(passphrase2, 60)
        csv_address = node.createcsvaddress(2, True)['csv address']
        node.sendtoaddress(csv_address, 1)
        node.walletlock()

        def check_spendcsv_locked():
            assert_raises_rpc_error(-13, UNLOCK_NEEDED, node.spendcsv, csv_address, FOREIGN, Decimal('0.5'))
        # spendcsv throws runtime_error (-1) where spendcltv uses -13
        self.known_failure("more -1 errors (DCjqQX73 item 4)", check_spendcsv_locked,
                           expected="Unexpected JSONRPC error code -1")


if __name__ == '__main__':
    WalletEncryptionTest().main()
