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
        self.log.info('Create first block')
        self.nodes[0].setmocktime(TIME_GENESIS_BLOCK)
        self.nodes[0].generate(1)        
        mining_info = self.nodes[0].getmininginfo()
        assert_equal(mining_info['blocks'], 1)
        assert_equal(mining_info['currentblocktx'], 0)
        assert_equal(mining_info['difficulty']['proof-of-work'], Decimal('0.0002441371325370'))
        assert_equal(mining_info['currentblocksize'], 1000)
        assert_equal(mining_info['powreward'], Decimal('4.7327100000000000'))
        assert_equal(mining_info['Nfactor'], 4)
        assert_equal(mining_info['N'], 32)

if __name__ == '__main__':
    MiningTest().main()
