#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test createcsvaddress, createcltvaddress and describeredeemscript.

For time-based and block-based CSV and CLTV locks: the new address is in
the given account, has received nothing, and describeredeemscript returns
the script, the address, the lock type and the encoded lock value.

describeredeemscript: the complete output for block-based locks, scripts
built outside the wallet, and the errors for invalid hex, non-standard
and non-CLTV/CSV scripts.
"""

import re
from decimal import Decimal

from test_framework.blocktools import (
    TIME_GENESIS_BLOCK,
)
from test_framework.script import CScript, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_DROP
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

SPEND_TEXT = (" After the lock time, if anyone has a signature signed by private key matching"
              " with public key then they can spend coins from this address")


class DescribeRedeemScriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK

    def setmocktimeforallnodes(self, mocktime):
        self.mocktime = mocktime
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        for i in range(numberOfBlocks):
            self.setmocktimeforallnodes(self.mocktime)
            self.mocktime=self.mocktime+timeBetweenBlocks      
            self.nodes[nodeId].generate(1)
        self.sync_all()

    def log_accounts(self, description):
        node_0_accounts = self.nodes[0].listaccounts()
        node_1_accounts = self.nodes[0].listaccounts()
        self.log.info('List accounts 0 '+description+': '+str(node_0_accounts))
        self.log.info('List accounts 1 '+description+': '+str(node_1_accounts))

    def run_test(self):
        self.setmocktimeforallnodes(TIME_GENESIS_BLOCK)
        csv_info = self.nodes[0].createcsvaddress(1200, False, 'csv_1')
        csv_address = csv_info['csv address']
        csv_redeemscript = csv_info['redeemScript']
        testaddress=self.nodes[0].getaddressesbyaccount('csv_1')[0]
        assert_equal(testaddress, csv_address)
        balance = self.nodes[0].getreceivedbyaccount('csv_1')
        assert_equal(balance, Decimal('0.0000'))
        description = self.nodes[0].describeredeemscript(csv_redeemscript)
        self.log.info(str(description))
        assert_equal(description['RedeemScriptHex'], csv_redeemscript)        
        assert_equal(description['CsvAddress'], csv_address)
        assert_equal(description['LockType'], 'Time-based lock')
        nlocktime = int(re.match('(\d+) ', description['RedeemScriptFormat']).groups()[0])
        assert_equal(nlocktime>>31,0)
        assert_equal(nlocktime>>30,1)
        assert_equal(nlocktime & 0x3fffffff, 1200)

        csv_info = self.nodes[0].createcsvaddress(100, True, 'csv_2')
        csv_address = csv_info['csv address']
        csv_redeemscript = csv_info['redeemScript']
        testaddress=self.nodes[0].getaddressesbyaccount('csv_2')[0]
        assert_equal(testaddress, csv_address)
        balance = self.nodes[0].getreceivedbyaccount('csv_2')
        assert_equal(balance, Decimal('0.0000'))
        description = self.nodes[0].describeredeemscript(csv_redeemscript)
        self.log.info(str(description))
        assert_equal(description['RedeemScriptHex'], csv_redeemscript)        
        assert_equal(description['CsvAddress'], csv_address)
        assert_equal(description['LockType'], 'Block-based lock')
        nlocktime = int(re.match('(\d+) ', description['RedeemScriptFormat']).groups()[0])
        assert_equal(nlocktime>>31,0)
        assert_equal(nlocktime>>30,0)
        assert_equal(nlocktime & 0x3fffffff, 100)

        cltv_info = self.nodes[0].createcltvaddress(TIME_GENESIS_BLOCK+1200, 'cltv_1')
        cltv_address = cltv_info['cltv address']
        cltv_redeemscript = cltv_info['redeemScript']
        testaddress=self.nodes[0].getaddressesbyaccount('cltv_1')[0]
        assert_equal(testaddress, cltv_address)
        balance = self.nodes[0].getreceivedbyaccount('cltv_1')
        assert_equal(balance, Decimal('0.0000'))
        description = self.nodes[0].describeredeemscript(cltv_redeemscript)
        self.log.info(str(description))        
        assert_equal(description['RedeemScriptHex'], cltv_redeemscript)
        assert_equal(description['CltvAddress'], cltv_address)
        assert_equal(description['LockType'], 'Time-based lock')
        nlocktime = int(re.match('(\d+) ', description['RedeemScriptFormat']).groups()[0])
        assert_equal(nlocktime, TIME_GENESIS_BLOCK+1200)

        cltv_info = self.nodes[0].createcltvaddress(1000, 'cltv_2')
        cltv_address = cltv_info['cltv address']
        cltv_redeemscript = cltv_info['redeemScript']
        testaddress=self.nodes[0].getaddressesbyaccount('cltv_2')[0]
        assert_equal(testaddress, cltv_address)
        balance = self.nodes[0].getreceivedbyaccount('cltv_2')
        assert_equal(balance, Decimal('0.0000'))
        description = self.nodes[0].describeredeemscript(cltv_redeemscript)
        self.log.info(str(description))
        assert_equal(description['RedeemScriptHex'], cltv_redeemscript)        
        assert_equal(description['CltvAddress'], cltv_address)
        assert_equal(description['LockType'], 'Block-based lock')
        nlocktime = int(re.match('(\d+) ', description['RedeemScriptFormat']).groups()[0])
        assert_equal(nlocktime, 1000)

        self.test_full_output()
        self.test_errors()

    def pubkey_of(self, script):
        return self.nodes[0].decodescript(script)['asm'].split()[3]

    def check_described(self, script, address, kind, lock, pubkey, lock_type, condition):
        assert_equal(self.nodes[0].describeredeemscript(script), {
            'RedeemScriptHex': script,
            'RedeemScriptFormat': '%s OP_%s OP_DROP %s OP_CHECKSIG' % (
                lock, 'CHECKLOCKTIMEVERIFY' if kind == 'Cltv' else 'CHECKSEQUENCEVERIFY', pubkey),
            'PublicKey': pubkey,
            'LockType': lock_type,
            kind + 'Address': address,
            'Description': 'This is a redeemscript of %sAddress. Any coins sent to this %sAddress will be %s.%s' % (
                kind, kind, condition, SPEND_TEXT),
        })

    def test_full_output(self):
        self.log.info("describeredeemscript: complete output")
        node = self.nodes[0]
        for lock in (17, 1000):
            info = node.createcltvaddress(lock)
            self.check_described(info['redeemScript'], info['cltv address'], 'Cltv', lock, self.pubkey_of(info['redeemScript']),
                       'Block-based lock', 'locked until block height %d' % lock)
        info = node.createcsvaddress(100, True)
        self.check_described(info['redeemScript'], info['csv address'], 'Csv', 100, self.pubkey_of(info['redeemScript']),
                   'Block-based lock', 'locked within 100 blocks')

        # Scripts made outside this wallet, with a foreign key; lock time 5
        # is the opcode OP_5 here (the wallet pushes it as one byte).
        pubkey = self.nodes[1].validateaddress(self.nodes[1].getnewaddress())['pubkey']
        for op, kind, condition in ((OP_CHECKLOCKTIMEVERIFY, 'Cltv', 'locked until block height 5'),
                                    (OP_CHECKSEQUENCEVERIFY, 'Csv', 'locked within 5 blocks')):
            script = CScript([5, op, OP_DROP, bytes.fromhex(pubkey), OP_CHECKSIG]).hex()
            self.check_described(script, node.decodescript(script)['p2sh'], kind, 5, pubkey, 'Block-based lock', condition)

    def test_errors(self):
        self.log.info("describeredeemscript: errors")
        node = self.nodes[0]
        assert_raises_rpc_error(-8, "redeemScript must be hexadecimal string (not 'zz')", node.describeredeemscript, 'zz')
        assert_raises_rpc_error(-8, "redeemScript must be hexadecimal string (not '')", node.describeredeemscript, '')
        assert_raises_rpc_error(-1, "This is non-standard redeemscript", node.describeredeemscript, '00')
        address = node.getnewaddress()
        multisig = node.createmultisig(1, [node.validateaddress(address)['pubkey']])['redeemScript']
        assert_raises_rpc_error(-1, "This is not CLTV/CSV redeemscript", node.describeredeemscript, multisig)
        p2pkh = node.validateaddress(address)['scriptPubKey']
        assert_raises_rpc_error(-1, "This is not CLTV/CSV redeemscript", node.describeredeemscript, p2pkh)
        # The CLTV P2PKH output script is no redeem script either.
        cltv_p2pkh = CScript([1000, OP_CHECKLOCKTIMEVERIFY, OP_DROP]).hex() + p2pkh
        assert_raises_rpc_error(-1, "This is not CLTV/CSV redeemscript", node.describeredeemscript, cltv_p2pkh)

if __name__ == '__main__':
    DescribeRedeemScriptTest().main()
