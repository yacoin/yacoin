#!/usr/bin/env python3
# Copyright (c) 2016-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC commands for signing and verifying messages.

- signmessagewithprivkey and signmessage signatures verify; another
  address's signature doesn't.
- verifymessage errors: an invalid address, a P2SH address, a signature
  of a wrong base64 length; a wrong message gives false.
- signmessagewithprivkey with an invalid key.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

class SignMessagesTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        message = 'This is just a test message'

        self.log.info('test signing with priv_key')
        priv_key = 'XRQYQFJ6He3xR3G48r5gMaZHE11wB4WervUy5PxtMzZaE3nbREFL'
        address = 'Y775oeGCciuHraME7Zbw1LYVPbvz6KkWYf'
        expected_signature = 'IGhMZ6jLUj/FDXJyOcJ7BiVLNm3ltj0YkKEFb8+oDzYccaOsAhLmJE/oFJ1fAAW+2yZtVJkCU983bAqURwxLZiE='
        signature = self.nodes[0].signmessagewithprivkey(priv_key, message)
        assert_equal(expected_signature, signature)
        assert self.nodes[0].verifymessage(address, signature, message)

        self.log.info('test signing with an address with wallet')
        address = self.nodes[0].getnewaddress()
        signature = self.nodes[0].signmessage(address, message)
        assert self.nodes[0].verifymessage(address, signature, message)

        self.log.info('test verifying with another address should not work')
        other_address = self.nodes[0].getnewaddress()
        other_signature = self.nodes[0].signmessage(other_address, message)
        assert not self.nodes[0].verifymessage(other_address, signature, message)
        assert not self.nodes[0].verifymessage(address, other_signature, message)

        self.log.info('test verifymessage and signmessagewithprivkey errors')
        node = self.nodes[0]
        assert_equal(node.verifymessage(address, signature, message + 'x'), False)
        assert_raises_rpc_error(-3, "Invalid address", node.verifymessage, 'xyz', signature, message)
        p2sh = node.createmultisig(1, [node.validateaddress(address)['pubkey']])['address']
        assert_raises_rpc_error(-3, "Address does not refer to key", node.verifymessage, p2sh, signature, message)
        # Decoding stops at the first character outside base64; only a
        # wrong length of what came before is an error.
        assert_raises_rpc_error(-5, "Malformed base64 encoding", node.verifymessage, address, 'abcde', message)
        assert_equal(node.verifymessage(address, '!!!', message), False)
        assert_raises_rpc_error(-5, "Invalid private key", node.signmessagewithprivkey, 'bad', message)

if __name__ == '__main__':
    SignMessagesTest().main()
