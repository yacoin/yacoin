#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the rawtranscation RPCs.

Test the following RPCs:
   - createrawtransaction (argument checks, sequence defaults, null data)
   - signrawtransaction (argument checks, prevtxs)
   - sendrawtransaction (missing inputs, already in the chain, invalid
     signature, decode errors)
   - decoderawtransaction
   - getrawtransaction

Null data outputs are decoded with a random reqSigs (known failure).
"""

import re

from test_framework.messages import CTransaction, FromHex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.yac_tx import key_from_wif, sign_p2pkh_input

# Create one-input, one-output, no-fee transaction:
class RawTransactionsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        super().setup_network()
        connect_nodes(self.nodes[0], 2)

    def run_test(self):
        self.log.info('prepare some coins for multiple *rawtransaction commands')
        #prepare some coins for multiple *rawtransaction commands
        self.nodes[2].generate(5)
        self.sync_all()
        self.nodes[0].generate(10)
        self.sync_all()
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(),1.5)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(),1.0)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(),5.0)
        self.sync_all()
        self.nodes[0].generate(5)
        self.sync_all()

        #########################################
        # sendrawtransaction with missing input #
        #########################################
        inputs  = [ {'txid' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'vout' : 1}] #won't exists
        outputs = { self.nodes[0].getnewaddress() : 4.998 }
        rawtx   = self.nodes[2].createrawtransaction(inputs, outputs)
        rawtx   = self.nodes[2].signrawtransaction(rawtx)

        # This will raise an exception since there are missing inputs
        assert_raises_rpc_error(-25, "Missing inputs", self.nodes[2].sendrawtransaction, rawtx['hex'])

        #########################
        # RAW TX MULTISIG TESTS #
        #########################
        # 2of2 test
        addr1 = self.nodes[2].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[2].validateaddress(addr1)
        addr2Obj = self.nodes[2].validateaddress(addr2)

        mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey']])
        mSigObjValid = self.nodes[2].validateaddress(mSigObj)

        #use balance deltas instead of absolute values
        bal = self.nodes[2].getbalance()

        # send 1.2 YAC to msig adr
        txId = self.nodes[0].sendtoaddress(mSigObj, 1.2)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(self.nodes[2].getbalance(), bal+Decimal('1.200000')) #node2 has both keys of the 2of2 ms addr., tx should affect the balance


        # 2of3 test from different nodes
        bal = self.nodes[2].getbalance()
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()
        addr3 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[1].validateaddress(addr1)
        addr2Obj = self.nodes[2].validateaddress(addr2)
        addr3Obj = self.nodes[2].validateaddress(addr3)

        mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey'], addr3Obj['pubkey']])
        mSigObjValid = self.nodes[2].validateaddress(mSigObj)

        txId = self.nodes[0].sendtoaddress(mSigObj, 2.2)
        decTx = self.nodes[0].gettransaction(txId)
        rawTx = self.nodes[0].decoderawtransaction(decTx['hex'])
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        #THIS IS A INCOMPLETE FEATURE
        #NODE2 HAS TWO OF THREE KEY AND THE FUNDS SHOULD BE SPENDABLE AND COUNT AT BALANCE CALCULATION
        assert_equal(self.nodes[2].getbalance(), bal) #for now, assume the funds of a 2of3 multisig tx are not marked as spendable

        txDetails = self.nodes[0].gettransaction(txId, True)
        rawTx = self.nodes[0].decoderawtransaction(txDetails['hex'])
        vout = False
        for outpoint in rawTx['vout']:
            if outpoint['value'] == Decimal('2.200000'):
                vout = outpoint
                break

        bal = self.nodes[1].getbalance()
        inputs = [{ "txid" : txId, "vout" : vout['n'], "scriptPubKey" : vout['scriptPubKey']['hex']}]
        outputs = { self.nodes[1].getnewaddress() : 2.19 }
        rawTx = self.nodes[2].createrawtransaction(inputs, outputs)
        rawTxPartialSigned = self.nodes[1].signrawtransaction(rawTx, inputs)
        assert_equal(rawTxPartialSigned['complete'], False) #node1 only has one key, can't comp. sign the tx

        rawTxSigned = self.nodes[2].signrawtransaction(rawTx, inputs)
        assert_equal(rawTxSigned['complete'], True) #node2 can sign the tx compl., own two of three keys
        self.nodes[2].sendrawtransaction(rawTxSigned['hex'])
        rawTx = self.nodes[0].decoderawtransaction(rawTxSigned['hex'])
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(self.nodes[1].getbalance(), bal+Decimal('2.190000'))

        # 2of2 test for combining transactions
        bal = self.nodes[2].getbalance()
        addr1 = self.nodes[1].getnewaddress()
        addr2 = self.nodes[2].getnewaddress()

        addr1Obj = self.nodes[1].validateaddress(addr1)
        addr2Obj = self.nodes[2].validateaddress(addr2)

        self.nodes[1].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey']])
        mSigObj = self.nodes[2].addmultisigaddress(2, [addr1Obj['pubkey'], addr2Obj['pubkey']])
        mSigObjValid = self.nodes[2].validateaddress(mSigObj)

        txId = self.nodes[0].sendtoaddress(mSigObj, 2.2)
        decTx = self.nodes[0].gettransaction(txId)
        rawTx2 = self.nodes[0].decoderawtransaction(decTx['hex'])
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        assert_equal(self.nodes[2].getbalance(), bal) # the funds of a 2of2 multisig tx should not be marked as spendable

        # getrawtransaction tests
        # 1. valid parameters - only supply txid
        txHash = rawTx["txid"]
        assert_equal(self.nodes[0].getrawtransaction(txHash), rawTxSigned['hex'])

        # 2. valid parameters - supply txid and 0 for non-verbose
        assert_equal(self.nodes[0].getrawtransaction(txHash, 0), rawTxSigned['hex'])

        # 3. valid parameters - supply txid and False for non-verbose
        assert_equal(self.nodes[0].getrawtransaction(txHash, False), rawTxSigned['hex'])

        # 4. valid parameters - supply txid and 1 for verbose.
        # We only check the "hex" field of the output so we don't need to update this test every time the output format changes.
        assert_equal(self.nodes[0].getrawtransaction(txHash, 1)["hex"], rawTxSigned['hex'])

        # 5. valid parameters - supply txid and True for non-verbose
        assert_equal(self.nodes[0].getrawtransaction(txHash, True)["hex"], rawTxSigned['hex'])

        # 6. invalid parameters - supply txid and string "Flase"
        if self.options.usecli:
            # yacoin-cli converts the verbose argument from JSON itself and
            # refuses it before sending.
            assert_raises_process_error(1, "Error parsing JSON:Flase", self.nodes[0].getrawtransaction, txHash, "Flase")
        else:
            assert_raises_rpc_error(-3,"Invalid type", self.nodes[0].getrawtransaction, txHash, "Flase")

        # 7. invalid parameters - supply txid and empty array
        assert_raises_rpc_error(-3,"Invalid type", self.nodes[0].getrawtransaction, txHash, [])

        # 8. invalid parameters - supply txid and empty dict
        assert_raises_rpc_error(-3,"Invalid type", self.nodes[0].getrawtransaction, txHash, {})

        inputs  = [ {'txid' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'vout' : 1, 'sequence' : 1000}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        rawtx   = self.nodes[0].createrawtransaction(inputs, outputs)
        decrawtx= self.nodes[0].decoderawtransaction(rawtx)
        assert_equal(decrawtx['vin'][0]['sequence'], 1000)

        # 9. invalid parameters - sequence number out of range
        inputs  = [ {'txid' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'vout' : 1, 'sequence' : -1}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        assert_raises_rpc_error(-8, 'Invalid parameter, sequence number is out of range', self.nodes[0].createrawtransaction, inputs, outputs)

        # 10. invalid parameters - sequence number out of range
        inputs  = [ {'txid' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'vout' : 1, 'sequence' : 4294967296}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        assert_raises_rpc_error(-8, 'Invalid parameter, sequence number is out of range', self.nodes[0].createrawtransaction, inputs, outputs)

        inputs  = [ {'txid' : "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000", 'vout' : 1, 'sequence' : 4294967294}]
        outputs = { self.nodes[0].getnewaddress() : 1 }
        rawtx   = self.nodes[0].createrawtransaction(inputs, outputs)
        decrawtx= self.nodes[0].decoderawtransaction(rawtx)
        assert_equal(decrawtx['vin'][0]['sequence'], 4294967294)

        self.test_createrawtransaction_checks()
        self.test_signrawtransaction_checks()
        self.test_sendrawtransaction_checks()
        # Last: it uses a coin nothing else spends.
        self.test_invalid_signature()

    def test_createrawtransaction_checks(self):
        self.log.info("createrawtransaction argument checks")
        node = self.nodes[0]
        txid = "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000"
        address = node.getnewaddress()
        assert_raises_rpc_error(-8, "Invalid parameter, missing vout key", node.createrawtransaction, [{'txid': txid}], {address: 1})
        assert_raises_rpc_error(-8, "Invalid parameter, vout must be positive", node.createrawtransaction, [{'txid': txid, 'vout': -1}], {address: 1})
        for locktime in [-1, 4294967296]:
            assert_raises_rpc_error(-8, "Invalid parameter, locktime out of range", node.createrawtransaction, [], {address: 1}, locktime)
        assert_raises_rpc_error(-8, "Invalid parameter, arguments 1 and 2 must be non-null", node.createrawtransaction, None, None)
        assert_raises_rpc_error(-5, "Invalid Yacoin address: xyz", node.createrawtransaction, [], {'xyz': 1})
        assert_raises_rpc_error(-3, "Invalid amount", node.createrawtransaction, [], {address: Decimal('0.0000001')})
        # A dict can't hold an address twice: send the JSON as text.
        status, _, body = raw_rpc(node, '{"method": "createrawtransaction", "params": [[], {"%s": 1, "%s": 2}], "id": 1}' % (address, address))
        assert_equal((status, json.loads(body.decode())['error']),
                     (500, {'code': -8, 'message': "Invalid parameter, duplicated address: " + address}))

        # With a locktime the default sequence is final - 1.
        raw = node.createrawtransaction([{'txid': txid, 'vout': 1}], {address: 1}, 1)
        assert_equal(node.decoderawtransaction(raw)['vin'][0]['sequence'], 4294967294)
        raw = node.createrawtransaction([{'txid': txid, 'vout': 1}], {address: 1})
        assert_equal(node.decoderawtransaction(raw)['vin'][0]['sequence'], 4294967295)

        self.log.info("A null data output")
        out = node.decoderawtransaction(node.createrawtransaction([], {'data': '00ff'}))['vout'][0]
        assert_equal((out['value'], out['scriptPubKey']['hex'], out['scriptPubKey']['type']), (0, '6a0200ff', 'nulldata'))
        script_pub_key = out['scriptPubKey']

        def check():
            assert 'reqSigs' not in script_pub_key and 'addresses' not in script_pub_key, "nulldata scriptPubKey: %r" % script_pub_key
        self.known_failure("uxP8YzbJ item 4", check, expected=re.compile(r"'reqSigs': -?\d+"))

    def test_signrawtransaction_checks(self):
        self.log.info("signrawtransaction argument checks")
        node = self.nodes[0]
        utxo = node.listunspent()[0]
        raw = node.createrawtransaction([{'txid': utxo['txid'], 'vout': utxo['vout']}], {node.getnewaddress(): 1})
        prevtx = {'txid': utxo['txid'], 'vout': utxo['vout'], 'scriptPubKey': utxo['scriptPubKey']}
        assert_raises_rpc_error(-5, "Invalid private key", node.signrawtransaction, raw, [], ['x'])
        assert_raises_rpc_error(-22, 'expected object with {"txid\'","vout","scriptPubKey"}', node.signrawtransaction, raw, [1])
        # The keys are checked in alphabetical order.
        assert_raises_rpc_error(-3, "Missing scriptPubKey", node.signrawtransaction, raw, [{}])
        assert_raises_rpc_error(-22, "vout must be positive", node.signrawtransaction, raw, [dict(prevtx, vout=-1)])
        assert_raises_rpc_error(-22, "Previous output scriptPubKey mismatch:\nOP_DUP OP_HASH160", node.signrawtransaction, raw, [dict(prevtx, scriptPubKey='51')])
        assert_raises_rpc_error(-8, "Invalid sighash param", node.signrawtransaction, raw, None, None, 'FOO')
        assert_equal(node.signrawtransaction(raw, [dict(prevtx, amount=utxo['amount'])])['complete'], True)

    def test_sendrawtransaction_checks(self):
        self.log.info("sendrawtransaction errors")
        node = self.nodes[0]
        coinbase = node.getblock(node.getblockhash(3))['tx'][0]
        assert_raises_rpc_error(-27, "transaction already in block chain", node.sendrawtransaction, node.getrawtransaction(coinbase))
        assert_raises_rpc_error(-22, "TX decode failed", node.sendrawtransaction, "00")
        assert_raises_rpc_error(-5, "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.",
                                node.getrawtransaction, "00" * 32)

    def test_invalid_signature(self):
        self.log.info("sendrawtransaction of a transaction signed with the wrong key")
        node = self.nodes[0]
        # The largest coin: change below the output's 1 YAC would fail first.
        utxo = max(node.listunspent(), key=lambda u: u['amount'])
        raw = node.createrawtransaction([{'txid': utxo['txid'], 'vout': utxo['vout']}], {node.getnewaddress(): 1})
        tx = FromHex(CTransaction(), raw)
        # A key of another node's wallet: it doesn't own the coin.
        wrong_key = key_from_wif(self.nodes[1].dumpprivkey(self.nodes[1].getnewaddress())['private_key'])
        sign_p2pkh_input(tx, 0, wrong_key, bytes.fromhex(utxo['scriptPubKey']))
        assert_raises_rpc_error(-26, "16: mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)",
                                node.sendrawtransaction, tx.serialize().hex())

if __name__ == '__main__':
    RawTransactionsTest().main()
