#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the keypool (adapted from Bitcoin Core's keypool.py).

- getwalletinfo's keypool fields; keypoolrefill argument errors;
- known failure: failing createcltvaddress / createcsvaddress calls use up
  a key (the next HD index is skipped);
- encryptwallet replaces the HD master key; new addresses use the new one;
- a locked wallet hands out the remaining keys, then reports that the
  keypool ran out (getnewaddress, getrawchangeaddress, createcltvaddress,
  getaccountaddress, setaccount); known failure: createcsvaddress uses the
  wrong error code; RPCs that need no key still work;
- keypoolrefill(n) while unlocked; exactly n external and n internal keys.

Not ported: draining the keypool by mining (generate pays the node's
deterministic key, not a keypool key).
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

KEYPOOL_RAN_OUT = "Error: Keypool ran out, please call keypoolrefill first"
UNLOCK_NEEDED = "Error: Please enter the wallet passphrase with walletpassphrase first."
FOREIGN = TestNode.PRIV_KEYS[11].address


class KeyPoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-keypool=3']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def index(self, address):
        path = self.nodes[0].validateaddress(address)['hdkeypath']
        assert path.startswith("m/0'/0'/") and path.endswith("'"), path
        return int(path[len("m/0'/0'/"):-1])

    def run_test(self):
        node = self.nodes[0]
        node.generate(10)
        info = node.getwalletinfo()
        assert_equal((info['keypoolsize'], info['keypoolsize_hd_internal'], info['walletversion']), (3, 3, 139900))
        assert_equal(len(info['hdmasterkeyid']), 40)
        assert 'unlocked_until' not in info

        self.log.info("Failing calls that use up a key")
        last = self.index(node.getnewaddress())
        for method, args, code, message in [
            (node.createcsvaddress, [0], -1, "<lock_time> must be between 1 and 1073741823"),
            (node.createcsvaddress, [10, 'x'], -1, "JSON value is not a boolean as expected"),
            (node.createcltvaddress, ['x'], -1, "JSON value is not an integer as expected"),
            (node.createcltvaddress, [100, '*'], -11, "Invalid account name"),
            (node.createcsvaddress, [1073741824], -1, "<lock_time> must be between 1 and 1073741823"),
        ]:
            assert_raises_rpc_error(code, message, method, *args)
            index = self.index(node.getnewaddress())

            def check_no_key_used():
                assert index == last + 1, "key burnt: index %d after %d" % (index, last)
            # The key is taken from the pool before the arguments are checked
            self.known_failure("failed call burns a key (VKLzdLmd item 3)", check_no_key_used,
                               expected="key burnt")
            last = index
        # getnewaddress checks the account first
        assert_raises_rpc_error(-11, "Invalid account name", node.getnewaddress, '*')
        assert_equal(self.index(node.getnewaddress()), last + 1)

        assert_raises_rpc_error(-8, "Invalid parameter, expected valid size.", node.keypoolrefill, -1)
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", node.keypoolrefill, 'x')

        self.log.info("encryptwallet replaces the HD master key")
        master = info['hdmasterkeyid']
        coinbase = node.get_deterministic_priv_key().address
        node.encryptwallet('test')
        node.wait_until_stopped()
        self.start_node(0)
        node = self.nodes[0]
        info = node.getwalletinfo()
        assert info['hdmasterkeyid'] != master
        assert_equal((info['unlocked_until'], info['keypoolsize'], info['keypoolsize_hd_internal']), (0, 3, 3))

        self.log.info("A locked wallet runs out of keys")
        addresses = [node.getnewaddress() for _ in range(3)]
        first = node.validateaddress(addresses[0])
        assert_equal((first['hdmasterkeyid'], first['hdkeypath']), (info['hdmasterkeyid'], "m/0'/0'/0'"))
        assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.getnewaddress)
        for _ in range(3):
            node.getrawchangeaddress()
        assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.getrawchangeaddress)
        assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.createcltvaddress, 100)

        def check_csv_code():
            assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.createcsvaddress, 10)
        # createcsvaddress throws runtime_error (-1) where createcltvaddress uses -12
        self.known_failure("more -1 errors (DCjqQX73 item 4)", check_csv_code,
                           expected="Unexpected JSONRPC error code -1")
        # The lock is checked first, so no key is needed
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, node.timelockcoins, 1, 10)
        assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.getaccountaddress, 'new')
        assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.getaccountaddress, '')
        # setaccount looks up the old account's current address, which needs a key
        assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.setaccount, coinbase, 'coinbase')
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, node.keypoolrefill, 5)
        assert_raises_rpc_error(-8, "Invalid parameter, expected valid size.", node.keypoolrefill, -1)
        assert_raises_rpc_error(-13, UNLOCK_NEEDED, node.sendtoaddress, FOREIGN, 1)
        # These need no key
        assert_equal(node.move('coinbase', 'x', 1), True)
        node.addmultisigaddress(1, [coinbase])

        self.log.info("keypoolrefill while unlocked")
        node.walletpassphrase('test', 60)
        node.keypoolrefill(6)
        info = node.getwalletinfo()
        assert_equal((info['keypoolsize'], info['keypoolsize_hd_internal']), (6, 6))
        node.walletlock()
        assert_equal(len({node.getnewaddress() for _ in range(6)}), 6)
        assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.getnewaddress)
        assert_equal(len({node.getrawchangeaddress() for _ in range(6)}), 6)
        assert_raises_rpc_error(-12, KEYPOOL_RAN_OUT, node.getrawchangeaddress)

        # Unlocking tops the pool up again (to -keypool=3)
        node.walletpassphrase('test', 60)
        info = node.getwalletinfo()
        assert_equal((info['keypoolsize'], info['keypoolsize_hd_internal']), (3, 3))
        node.getnewaddress()
        node.walletlock()


if __name__ == '__main__':
    KeyPoolTest().main()
