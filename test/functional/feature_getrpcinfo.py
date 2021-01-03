#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify that uptime is reported as expected."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
import time
import re

class UptimeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False


    def run_test(self):
        rpcinfo_0 = self.nodes[0].getrpcinfo()
        rpcinfo_1 = self.nodes[1].getrpcinfo()
        self.log.info("RPC info node 0: "+str(rpcinfo_0))
        self.log.info("RPC info node 1: "+str(rpcinfo_1))
        assert_equal(int(rpcinfo_0['RPCport']),16000)
        assert_equal(int(rpcinfo_1['RPCport']),16001)


if __name__ == '__main__':
    UptimeTest().main()
