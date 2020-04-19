    #!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mining RPCs

- getmininginfo
- getblocktemplate proposal mode
- submitblock"""

import copy
import time
from decimal import Decimal

from test_framework.blocktools import (
    create_coinbase,
    TIME_GENESIS_BLOCK,
)
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    BLOCK_HEADER_SIZE
)
from test_framework.mininode import (
    P2PDataStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.script import CScriptNum

class MiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.supports_cli = False

    def run_test(self):
#         1) CREATE NEW ADDRESS FOR NODE C
        self.log.info('Create new address')
        info = self.nodes[2].getnewaddress('test-node2')
        print("1 ===============>>>>>>>>>>")
        print(info)
        address = info
        self.log.info('Check new address')
        info = self.nodes[2].getaccount(address)
        assert_equal(info, 'test-node2')
        print("2 ===============>>>>>>>>>>")
        print(info)
        
#         2) CHECK BALANCE OF NODE C ACCOUNT
        self.log.info('Checking node 2')
        info = self.nodes[2].getreceivedbyaddress(address)
        print("3 ===============>>>>>>>>>>")
        print(info)
        assert_equal(info, Decimal(0.0000))
        info = self.nodes[2].getreceivedbyaccount('test-node2')
        print("4 ===============>>>>>>>>>>")
        print(info)
        assert_equal(info, Decimal(0.0000))
        info = self.nodes[2].listaccounts()
        print("5 ===============>>>>>>>>>>")
        print(info)

        assert_equal(info['test-node2'],Decimal(0.00000))
#       3) CHECK BALANCE OF MY NODE
#       4) SEND COIN TO NODE C
        self.nodes[0].setmocktime(TIME_GENESIS_BLOCK)
        self.nodes[0].generate(1)
        # self.nodes[0].sendtoaddress
        # self.nodes[0].generate(1)

if __name__ == '__main__':
    MiningTest().main()
