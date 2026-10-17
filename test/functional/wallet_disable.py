#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a node with the -disablewallet option.

- Wallet RPCs are not registered (-32601), and getinfo has no wallet fields.
- validateaddress, createmultisig (with public keys) and generatetoaddress
  work without a wallet; mining to an invalid address fails.
- No wallet.dat is created, and wallet startup options are ignored.
- describeredeemscript needs no wallet but is unavailable (known failure).
"""
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

# A valid public key
PUBKEY = '035a0f36ef803bf690c8aff41c603622db24aed6619b9d5b823fd63b356d0d1767'
# CLTV (lock time 1000) redeem script for PUBKEY
CLTV_SCRIPT = '02e803b175' + '21' + PUBKEY + 'ac'


class DisableWalletTest (BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-disablewallet"]]

    def run_test (self):
        node = self.nodes[0]
        # Make sure wallet is really disabled
        assert_raises_rpc_error(-32601, 'Method not found', node.getwalletinfo)
        for method in ('sendtoaddress', 'listwallets', 'timelockcoins', 'resendwallettransactions'):
            assert_raises_rpc_error(-32601, 'Method not found', getattr(node, method))
        assert_equal(sorted(node.getinfo()), sorted(['version', 'protocolversion', 'blocks', 'timeoffset', 'up-time',
            'moneysupply', 'connections', 'proxy', 'difficulty', 'testnet', 'paytxfee', 'errors']))
        assert not os.path.exists(os.path.join(node.datadir, 'wallet.dat'))

        x = node.validateaddress('YLreZ2kuvpjdHcwfF34PyX6GsLa7K7TMsc')
        assert x['isvalid'] == False
        x = node.validateaddress('YLreZ2kuvpjdHcwfF34PyX6GsLm7K7TMsc')
        assert x['isvalid'] == True
        assert_equal((x['ismine'], x['iswatchonly']), (False, False))

        assert_raises_rpc_error(-5, "Invalid address", node.generatetoaddress, 1, 'YLreZ2kuvpjdHcwfF34PyX6GsLa7K7TMsc')
        hashes = node.generatetoaddress(1, 'YLreZ2kuvpjdHcwfF34PyX6GsLm7K7TMsc')
        assert_equal(len(hashes), 1)
        assert_equal(node.getbestblockhash(), hashes[0])

        ms = node.createmultisig(1, [PUBKEY])
        assert_equal(ms['redeemScript'], '5121' + PUBKEY + '51ae')
        # Without a wallet, addresses can't stand in for public keys (the
        # wallet branch is in rpc_misc.py).
        assert_raises_rpc_error(-1, "Invalid public key: YLreZ2kuvpjdHcwfF34PyX6GsLm7K7TMsc", node.createmultisig, 1, ['YLreZ2kuvpjdHcwfF34PyX6GsLm7K7TMsc'])

        def describe_works():
            assert_equal(node.describeredeemscript(CLTV_SCRIPT)['LockType'], 'Block-based lock')
        self.known_failure("describeredeemscript without wallet (VKLzdLmd item 8)", describe_works, expected=-32601)

        self.log.info("Wallet startup options are ignored")
        self.restart_node(0, ['-disablewallet', '-salvagewallet', '-upgradewallet=1', '-zapwallettxes=2', '-wallet=a', '-wallet=b'])
        assert_raises_rpc_error(-32601, 'Method not found', node.getwalletinfo)
        assert_equal([f for f in os.listdir(node.datadir) if f.startswith('wallet') or f in ('a', 'b')], [])


if __name__ == '__main__':
    DisableWalletTest ().main ()
