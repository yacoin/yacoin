#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a new address in a new account has received nothing.

getnewaddress with an account, getaccount, getreceivedbyaddress,
getreceivedbyaccount and listaccounts. (Despite its name this script
tests no fees; wallet_fee.py is planned to replace it.)
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class NewAccountTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        self.log.info('Create a new address in account test-node2')
        address = node.getnewaddress('test-node2')
        assert_equal(node.getaccount(address), 'test-node2')

        self.log.info('The address and the account have received nothing')
        assert_equal(node.getreceivedbyaddress(address), Decimal('0'))
        assert_equal(node.getreceivedbyaccount('test-node2'), Decimal('0'))
        assert_equal(node.listaccounts()['test-node2'], Decimal('0'))


if __name__ == '__main__':
    NewAccountTest().main()
