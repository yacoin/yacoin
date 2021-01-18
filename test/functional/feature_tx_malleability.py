#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test sending and receiving coins 
"""

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
    assert_approx,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.script import CScriptNum


def assert_template(node, block, expect, rehash=True):
    if rehash:
        block.hashMerkleRoot = block.calc_merkle_root()
    rsp = node.getblocktemplate(template_request={'data': block.serialize().hex(), 'mode': 'proposal', 'rules': ['segwit']})
    assert_equal(rsp, expect)


class TXMalleability_Test(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK
        self.block_fork_1_0 = 0
        
    def setmocktimeforallnodes(self, mocktime):
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks(self, nodeId, numberOfBlocksAtOnce):
        timeBetweenBlocks = 60
        self.setmocktimeforallnodes(self.mocktime)
        self.nodes[nodeId].generate(numberOfBlocksAtOnce)
        self.mocktime=self.mocktime+timeBetweenBlocks*numberOfBlocksAtOnce
        self.sync_all()

    def log_accounts(self, description):
        node_0_accounts = self.nodes[0].listaccounts()
        node_1_accounts = self.nodes[1].listaccounts()
        self.log.info('List accounts 0 '+description+': '+str(node_0_accounts))
        self.log.info('List accounts 1 '+description+': '+str(node_1_accounts))
        self.log.info('Balance 0: '+str(self.nodes[0].getbalance()))
        self.log.info('Balance 1: '+str(self.nodes[1].getbalance()))

    # The fault case in 0.4.x is reproduced in below test case
    # However it is not run since this would require to mine 500 blocks
    # which takes some time and is only relevanat for 0.4.x
    def check_tx_malleability_pre_1_0(self):
        # setup and mine some coins
        self.mine_blocks(0,510)
        address_tx = self.nodes[1].getnewaddress('account1')

        # create original transaction
        txid_original = self.nodes[0].sendtoaddress(address_tx, 10)
        self.log.info('Original transaction ID: '+str(txid_original))
        transaction_raw = self.nodes[0].getrawtransaction(txid_original)
        self.log.info('Original transaction raw: '+str(transaction_raw))
        transaction_details = self.nodes[0].gettransaction(txid_original)
        scriptSig = transaction_details['vin'][0]['scriptSig']['hex']
        self.log.info("Original transaction details: "+str(transaction_details))
        self.log.info("Original transaction scriptSig: "+str(scriptSig))
        
        # modifiy transaction
        index = transaction_raw.index(scriptSig)
        lengthbyte = transaction_raw[index-2:index]
        self.log.info('ScriptSig length byte: '+str(lengthbyte))
        newlengthbyte = hex(int(lengthbyte,16)+1)[2:]
        self.log.info('Increased scriptSig length byte: '+str(newlengthbyte))
        transaction_raw_modified = transaction_raw[:index-2]+newlengthbyte+'4c'+transaction_raw[index:]
        self.log.info('Modified raw transaction: '+str(transaction_raw_modified))
        assert(transaction_raw != transaction_raw_modified)

        # check that original transaction id not available on node 1
        assert_raises_rpc_error(-1, 'unknown!?', self.nodes[1].gettransaction, txid_original)
        # send transaction
        txid_modified = self.nodes[1].sendrawtransaction(transaction_raw_modified)
        self.log.info('Modified transaction ID: '+str(txid_original))

        assert(txid_original != txid_modified) # malleable !!!
        
        # mine it into the blockchain
        self.mine_blocks(1,10)

        # check if the modified txid is confirmed and synced across the network
        transaction_details = self.nodes[1].gettransaction(txid_modified)
        self.log.info('Modified transaction found on node 1: '+str(transaction_details))
        transaction_details = self.nodes[0].gettransaction(txid_modified)
        assert_equal(transaction_details['confirmations'],Decimal('10'))
        self.log.info('Modified transaction found on node 0: '+str(transaction_details))
        assert_equal(transaction_details['confirmations'],Decimal('10'))
        # check that coins have been transferred
        assert_equal(self.nodes[1].getreceivedbyaccount('account1'), Decimal('10.0'))

        # 2nd effect of malleability
        # check that the original transaction is still on node 0 but did not get confirmed 
        # or synced across the network
        transaction_details = self.nodes[0].gettransaction(txid_original)
        self.log.info('Original transaction still found on node 0: '+str(transaction_details))
        assert_equal(transaction_details['confirmations'],Decimal('0'))

        assert_raises_rpc_error(-1, 'unknown!?', self.nodes[1].gettransaction, txid_original)

    # Check that the issue has been fixed
    def check_tx_malleability_fixed_in_1_0(self):
        # setup and mine some coins
        self.mine_blocks(0,10)
        address_tx = self.nodes[1].getnewaddress('account2')

        # create original transaction
        txid_original = self.nodes[0].sendtoaddress(address_tx, 2.0)
        self.log.info('Original transaction ID: '+str(txid_original))
        transaction_raw = self.nodes[0].getrawtransaction(txid_original)
        self.log.info('Original transaction raw: '+str(transaction_raw))
        transaction_details = self.nodes[0].gettransaction(txid_original)
        scriptSig = transaction_details['vin'][0]['scriptSig']['hex']
        self.log.info("Original transaction details: "+str(transaction_details))
        self.log.info("Original transaction scriptSig: "+str(scriptSig))
        
        # modifiy transaction
        index = transaction_raw.index(scriptSig)
        lengthbyte = transaction_raw[index-2:index]
        self.log.info('ScriptSig length byte: '+str(lengthbyte))
        newlengthbyte = hex(int(lengthbyte,16)+1)[2:]
        self.log.info('Increased scriptSig length byte: '+str(newlengthbyte))
        transaction_raw_modified = transaction_raw[:index-2]+newlengthbyte+'4c'+transaction_raw[index:]
        self.log.info('Modified raw transaction: '+str(transaction_raw_modified))
        assert(transaction_raw != transaction_raw_modified)

        # check that original transaction id not available on node 1
        assert_raises_rpc_error(-1, 'unknown!?', self.nodes[1].gettransaction, txid_original)
        # send transaction
        txid_modified = self.nodes[1].sendrawtransaction(transaction_raw_modified)
        self.log.info('Modified transaction ID: '+str(txid_original))
        assert_equal(txid_original, txid_modified) # 1.0 tx malleability fix
        # mine it into the blockchain
        self.mine_blocks(1,10)

        # check if the modified txid is confirmed and synced across the network
        transaction_details = self.nodes[1].gettransaction(txid_modified)
        self.log.info('Modified transaction found on node 1: '+str(transaction_details))
        transaction_details = self.nodes[0].gettransaction(txid_modified)
        assert_equal(transaction_details['confirmations'],Decimal('10'))
        self.log.info('Modified transaction found on node 0: '+str(transaction_details))
        assert_equal(transaction_details['confirmations'],Decimal('10'))
        # check that coins have been transferred
        assert_equal(self.nodes[1].getreceivedbyaccount('account2'), Decimal('2.0'))


    def run_test(self):
        self.mine_blocks(0, 50)

        # The fault case in 0.4.x is reproduced in below test case
        # However it is not run since this would require to mine 500 blocks
        # which takes some time and is only relevanat for 0.4.x
        # self.check_tx_malleability_pre_1_0() 

        # test the fix
        self.check_tx_malleability_fixed_in_1_0()


if __name__ == '__main__':
    TXMalleability_Test().main()