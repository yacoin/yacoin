#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test decoding scripts via decodescript RPC command."""

from test_framework.messages import CTransaction, sha256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, hex_str_to_bytes

from io import BytesIO

class DecodeScriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def decodescript_script_sig(self):
        signature = '3045022100d1722aa4cba5d80b22a3382a5b3340f0a4fbc3d1719265bb193adc132771946302205e45d9bd7c47ab2f585970512569d55cad860395efae5e1373d6e1efea68203d01'
        push_signature = '48' + signature
        public_key = '0273ab4878e664d8a1d622b2318c657c82e27644a49118e7b02d39e60c6ded1fb5'
        push_public_key = '21' + public_key

        # below are test cases for all of the standard transaction types

        # 1) P2PK scriptSig
        # the scriptSig of a public key scriptPubKey simply pushes a signature onto the stack
        rpc_result = self.nodes[0].decodescript(push_signature)
        assert_equal(signature, rpc_result['asm'])

        # 2) P2PKH scriptSig
        rpc_result = self.nodes[0].decodescript(push_signature + push_public_key)
        assert_equal(signature + ' ' + public_key, rpc_result['asm'])

        # 3) multisig scriptSig
        # this also tests the leading portion of a P2SH multisig scriptSig
        # OP_0 <A sig> <B sig>
        rpc_result = self.nodes[0].decodescript('00' + push_signature + push_signature)
        assert_equal('0 ' + signature + ' ' + signature, rpc_result['asm'])

        # 4) P2SH scriptSig
        # an empty P2SH redeemScript is valid and makes for a very simple test case.
        # thus, such a spending scriptSig would just need to pass the outer redeemScript
        # hash test and leave true on the top of the stack.
        rpc_result = self.nodes[0].decodescript('5100')
        assert_equal('1 0', rpc_result['asm'])

        # 5) null data scriptSig - no such thing because null data scripts can not be spent.
        # thus, no test case for that standard transaction type is here.

    def decodescript_script_pub_key(self):
        public_key = '0273ab4878e664d8a1d622b2318c657c82e27644a49118e7b02d39e60c6ded1fb5'
        push_public_key = '21' + public_key
        public_key_hash = '8b7e5850baf602dbb51d9570e89e9a5617b1fafd'
        push_public_key_hash = '14' + public_key_hash
        uncompressed_public_key = '0422216e8f48b47ae985af4f5231b95c90b87fd7e415a21c75d0b22a25001167f6b53e7cd01a4eddbbc748e0715a3ca9f078e10611939aa5d90ef37817fea01375'
        push_uncompressed_public_key = '41' + uncompressed_public_key

        # below are test cases for all of the standard transaction types

        # 1) P2PK scriptPubKey
        # <pubkey> OP_CHECKSIG
        rpc_result = self.nodes[0].decodescript(push_public_key + 'ac')
        assert_equal(public_key + ' OP_CHECKSIG', rpc_result['asm'])

        # 2) P2PKH scriptPubKey
        # OP_DUP OP_HASH160 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        rpc_result = self.nodes[0].decodescript('76a9' + push_public_key_hash + '88ac')
        assert_equal('OP_DUP OP_HASH160 ' + public_key_hash + ' OP_EQUALVERIFY OP_CHECKSIG', rpc_result['asm'])

        # 3) multisig scriptPubKey
        # <m> <A pubkey> <B pubkey> <C pubkey> <n> OP_CHECKMULTISIG
        # just imagine that the pub keys used below are different.
        # for our purposes here it does not matter that they are the same even though it is unrealistic.
        multisig_script = '52' + push_public_key + push_public_key + push_public_key + '53ae'
        rpc_result = self.nodes[0].decodescript(multisig_script)
        assert_equal('2 ' + public_key + ' ' + public_key + ' ' + public_key +  ' 3 OP_CHECKMULTISIG', rpc_result['asm'])

        # 4) P2SH scriptPubKey
        # OP_HASH160 <Hash160(redeemScript)> OP_EQUAL.
        # push_public_key_hash here should actually be the hash of a redeem script.
        # but this works the same for purposes of this test.
        rpc_result = self.nodes[0].decodescript('a9' + push_public_key_hash + '87')
        assert_equal('OP_HASH160 ' + public_key_hash + ' OP_EQUAL', rpc_result['asm'])

        # 5) null data scriptPubKey
        # use a signature look-alike here to make sure that we do not decode random data as a signature.
        # this matters if/when signature sighash decoding comes along.
        # would want to make sure that no such decoding takes place in this case.
        signature_imposter = '48304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001'
        # OP_RETURN <data>
        rpc_result = self.nodes[0].decodescript('6a' + signature_imposter)
        assert_equal('OP_RETURN ' + signature_imposter[2:], rpc_result['asm'])

        # 6) a CLTV redeem script. redeem scripts are in-effect scriptPubKey scripts, so adding a test here.
        # OP_NOP2 is also known as OP_CHECKLOCKTIMEVERIFY.
        # just imagine that the pub keys used below are different.
        # for our purposes here it does not matter that they are the same even though it is unrealistic.
        #
        # OP_IF
        #   <receiver-pubkey> OP_CHECKSIGVERIFY
        # OP_ELSE
        #   <lock-until> OP_CHECKLOCKTIMEVERIFY OP_DROP
        # OP_ENDIF
        # <sender-pubkey> OP_CHECKSIG
        #
        # lock until block 500,000
        cltv_script = '63' + push_public_key + 'ad670320a107b17568' + push_public_key + 'ac'
        rpc_result = self.nodes[0].decodescript(cltv_script)
        assert_equal('OP_IF ' + public_key + ' OP_CHECKSIGVERIFY OP_ELSE 500000 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_ENDIF ' + public_key + ' OP_CHECKSIG', rpc_result['asm'])

        # 7) P2PK scriptPubKey
        # <pubkey> OP_CHECKSIG
        rpc_result = self.nodes[0].decodescript(push_uncompressed_public_key + 'ac')
        assert_equal(uncompressed_public_key + ' OP_CHECKSIG', rpc_result['asm'])

        # 8) multisig scriptPubKey with an uncompressed pubkey
        # <m> <A pubkey> <B pubkey> <n> OP_CHECKMULTISIG
        # just imagine that the pub keys used below are different.
        # the purpose of this test is to check that a segwit script is not returned for bare multisig scripts
        # with an uncompressed pubkey in them.
        rpc_result = self.nodes[0].decodescript('52' + push_public_key + push_uncompressed_public_key +'52ae')
        assert_equal('2 ' + public_key + ' ' + uncompressed_public_key + ' 2 OP_CHECKMULTISIG', rpc_result['asm'])

    def decoderawtransaction_asm_sighashtype(self):
        """Test decoding scripts via RPC command "decoderawtransaction".

        This test is in with the "decodescript" tests because they are testing the same "asm" script decodes.
        """

        # this test case uses a random plain vanilla mainnet transaction with a single P2PKH input and output
        tx = '020000003e2a676800000000019accf234f5628ae24fbd9b50fbd7dde2208def3e015b1abc786e809759c832d2000000006a473044022033f229e579ec50cb3dcaaa44ba4364992ee35d82ce1d056d85f916321bf9dedb0220792487ef39cc8179f296e545b218746c9a8b2e0c7d3669bb0eb97976481ab7940121021d7ddbdefad260498a2c02defbad20a846bef7442b3da3e15a49a72f5a9d7ab6ffffffff027255ed53020000001976a914bcccd077e69dc02bf4cf833e06f056c3f376acfc88ac80841e00000000001976a9148b7e5850baf602dbb51d9570e89e9a5617b1fafd88ac00000000'
        rpc_result = self.nodes[0].decoderawtransaction(tx)
        assert_equal('3044022033f229e579ec50cb3dcaaa44ba4364992ee35d82ce1d056d85f916321bf9dedb0220792487ef39cc8179f296e545b218746c9a8b2e0c7d3669bb0eb97976481ab794[ALL] 021d7ddbdefad260498a2c02defbad20a846bef7442b3da3e15a49a72f5a9d7ab6', rpc_result['vin'][0]['scriptSig']['asm'])

        # this test case uses a mainnet transaction that has 2 P2SH inputs and 2 P2PKH outputs.
        tx = '02000000e39c85620000000002678fe9d6a7baee573cb3f0b78dffee08d6dbd6e7670c93cf047026ca278285f100000000754930460221008d648b76391aa8654fd1d652a1b1bd9a1c1c902ea602ba927db68d5f3547d19a022100c49e7f5f042df2bde0624ac3518f8eff6d90c9e0c795c3aa6d822de12d0c79ad012a0490968562b1752103876057ae65923aaf9e8e61ad622be45dcf26c65ebe32b6eff8c4a4f73ac55d4aac00000000f2bd29431378d44cea5b4fa0040b36a79480b574cee4ed6dfb4170fdebb712990000000074483045022100a41cd34ea73798ce1b86c60a9767b595f9f49c3ee651e49e87b4053387c88f3b0220603960001b91b49a495630ffb887e24c27612a1c2ba6adc10e6af44afe60b563012a0490968562b1752103876057ae65923aaf9e8e61ad622be45dcf26c65ebe32b6eff8c4a4f73ac55d4aac0000000002705d1e00000000001976a9141c625874500a870998e0d6a5d91cd7611e5da9ca88acc0c62d00000000001976a914c9fe3eef14c1c2408ed25d4a3273cbc03656691288ac90968562'
        rpc_result = self.nodes[0].decoderawtransaction(tx)
        assert_equal('db8850390b429a43ab31ebbf42bc7fbfcb44cbc4fc3922ec2e0c57ef39d1e6a1', rpc_result['txid'])
        assert_equal('30460221008d648b76391aa8654fd1d652a1b1bd9a1c1c902ea602ba927db68d5f3547d19a022100c49e7f5f042df2bde0624ac3518f8eff6d90c9e0c795c3aa6d822de12d0c79ad[ALL] 0490968562b1752103876057ae65923aaf9e8e61ad622be45dcf26c65ebe32b6eff8c4a4f73ac55d4aac', rpc_result['vin'][0]['scriptSig']['asm'])
        assert_equal('3045022100a41cd34ea73798ce1b86c60a9767b595f9f49c3ee651e49e87b4053387c88f3b0220603960001b91b49a495630ffb887e24c27612a1c2ba6adc10e6af44afe60b563[ALL] 0490968562b1752103876057ae65923aaf9e8e61ad622be45dcf26c65ebe32b6eff8c4a4f73ac55d4aac', rpc_result['vin'][1]['scriptSig']['asm'])
        assert_equal('OP_DUP OP_HASH160 1c625874500a870998e0d6a5d91cd7611e5da9ca OP_EQUALVERIFY OP_CHECKSIG', rpc_result['vout'][0]['scriptPubKey']['asm'])
        assert_equal('OP_DUP OP_HASH160 c9fe3eef14c1c2408ed25d4a3273cbc036566912 OP_EQUALVERIFY OP_CHECKSIG', rpc_result['vout'][1]['scriptPubKey']['asm'])
        txSave = CTransaction()
        txSave.deserialize(BytesIO(hex_str_to_bytes(tx)))

        # Test a scriptSig that contains more than push operations.
        # in fact, it contains an OP_RETURN with data specially crafted to cause improper decode if the code does not catch it.
        txSave.vin[0].scriptSig = hex_str_to_bytes('6a143011020701010101010101020601010101010101')
        rpc_result = self.nodes[0].decoderawtransaction(txSave.serialize().hex())
        assert_equal('OP_RETURN 3011020701010101010101020601010101010101', rpc_result['vin'][0]['scriptSig']['asm'])

    def run_test(self):
        self.decodescript_script_sig()
        self.decodescript_script_pub_key()
        self.decoderawtransaction_asm_sighashtype()

if __name__ == '__main__':
    DecodeScriptTest().main()
