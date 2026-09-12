#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a node with the -disablewallet option.

- Test that validateaddress RPC works when running with -disablewallet
- Test that it is not possible to mine to an invalid address.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_raises_rpc_error

class DisableWalletTest (BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-disablewallet"]]

    def run_test (self):
        # Make sure wallet is really disabled
        assert_raises_rpc_error(-32601, 'Method not found', self.nodes[0].getwalletinfo)
        x = self.nodes[0].validateaddress('YLreZ2kuvpjdHcwfF34PyX6GsLa7K7TMsc')
        assert x['isvalid'] == False
        x = self.nodes[0].validateaddress('YLreZ2kuvpjdHcwfF34PyX6GsLm7K7TMsc')
        assert x['isvalid'] == True

        assert_raises_rpc_error(-5, "Invalid address", self.nodes[0].generatetoaddress, 1, 'YLreZ2kuvpjdHcwfF34PyX6GsLa7K7TMsc')

if __name__ == '__main__':
    DisableWalletTest ().main ()
