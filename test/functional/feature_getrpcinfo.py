#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that getrpcinfo reports the RPC port each node was configured with."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, rpc_port


class GetRpcInfoTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False

    def run_test(self):
        for i, node in enumerate(self.nodes):
            rpcinfo = node.getrpcinfo()
            self.log.info("RPC info node %d: %s", i, rpcinfo)
            assert_equal(int(rpcinfo['RPCport']), rpc_port(i))


if __name__ == '__main__':
    GetRpcInfoTest().main()
