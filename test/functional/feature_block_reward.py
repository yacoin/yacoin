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


def assert_template(node, block, expect, rehash=True):
    if rehash:
        block.hashMerkleRoot = block.calc_merkle_root()
    rsp = node.getblocktemplate(template_request={'data': block.serialize().hex(), 'mode': 'proposal', 'rules': ['segwit']})
    assert_equal(rsp, expect)


class MiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False

    def run_test(self):
        self.log.info('Create 10 block')
        info = self.nodes[0].getinfo()
        print(info)
        blockreward= [Decimal('4.7327100000000000')]*9 + [Decimal('4.7327120000000000')]*10 + [Decimal('4.7327130000000000')]*10+[Decimal('4.7327150000000000')]
        moneysupply= [
            Decimal('124460825.506301'),
            Decimal('124460830.239011'),
            Decimal('124460834.971721'),
            Decimal('124460839.704431'),
            Decimal('124460844.437141'),
            Decimal('124460849.169851'),
            Decimal('124460853.902561'),
            Decimal('124460858.635271'),
            Decimal('124460863.367981'),
            Decimal('124460868.100693'),
            Decimal('124460872.833405'),
            Decimal('124460877.566117'),
            Decimal('124460882.298829'),
            Decimal('124460887.031541'),
            Decimal('124460891.764253'),
            Decimal('124460896.496965'),
            Decimal('124460901.229677'),
            Decimal('124460905.962389'),
            Decimal('124460910.695101'),
            Decimal('124460915.427814'),
            Decimal('124460920.160527'),
            Decimal('124460924.893240'),
            Decimal('124460929.625953'),
            Decimal('124460934.358666'),
            Decimal('124460939.091379'),
            Decimal('124460943.824092'),
            Decimal('124460948.556805'),
            Decimal('124460953.289518'),
            Decimal('124460958.022231'),
            Decimal('124460962.754946'),
            Decimal('124460967.487661')]

        for t in range(0,30):
            print("calculating block "+str(t+1))
            self.nodes[0].setmocktime(TIME_GENESIS_BLOCK+t*120)
            self.nodes[0].generate(1, 4294967295)
            mining_info = self.nodes[0].getmininginfo()
            assert_equal(mining_info['blocks'], t+1)
            # assert_equal(mining_info['powreward'], blockreward[t])
            print(mining_info['powreward'])
            print(blockreward[t])
            assert(abs(mining_info['powreward'] - blockreward[t]) < 0.0000001)
            info = self.nodes[0].getinfo()  
            print(info['moneysupply'])
            print(moneysupply[t])
            assert(abs(info['moneysupply'] - moneysupply[t])<.000001)

if __name__ == '__main__':
    MiningTest().main()
