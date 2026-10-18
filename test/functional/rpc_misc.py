#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test miscellaneous control and util RPCs.

- getmemoryinfo: the locked-memory statistics, mallocinfo, a bad mode.
- logging: turning categories off and on changes what is logged; bad
  categories; a non-array argument is ignored; the values are booleans
  (known failure).
- setmocktime with a string.
- getinfo agrees with the other RPCs.
- createmultisig (adapted from Core's rpc_createmultisig.py): the same
  address and script as addmultisigaddress, from public keys or wallet
  addresses; the address can be funded and spent; argument errors.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    peers,
)


class RpcMiscTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        # yacoin-cli refuses setmocktime("x") itself.
        self.supports_cli = False

    def run_test(self):
        self.test_getmemoryinfo()
        self.test_logging()
        self.test_setmocktime()
        self.test_getinfo()
        self.test_createmultisig()

    def test_getmemoryinfo(self):
        node = self.nodes[0]
        self.log.info("getmemoryinfo")
        locked = node.getmemoryinfo()['locked']
        assert_equal(sorted(locked), ['chunks_free', 'chunks_used', 'free', 'locked', 'total', 'used'])
        assert all(isinstance(v, int) for v in locked.values())
        assert_equal(locked['used'] + locked['free'], locked['total'])
        assert node.getmemoryinfo('mallocinfo').startswith('<malloc version="1">')
        assert_raises_rpc_error(-8, "unknown mode foo", node.getmemoryinfo, 'foo')

    def test_logging(self):
        node = self.nodes[0]
        self.log.info("logging")
        state = node.logging()
        for category in ['net', 'rpc', 'http', 'libevent', 'leveldb']:
            assert category in state
        # The framework starts nodes with -debug -debugexclude=libevent -debugexclude=leveldb.
        assert_equal((state['rpc'], state['http'], state['libevent'], state['leveldb']), (1, 1, 0, 0))
        self.known_failure("uxP8YzbJ item 5", lambda: assert_equal(type(node.logging()['rpc']), bool),
                           expected="<class 'int'>")

        # The http line shows that the request was logged at all.
        with node.assert_debug_log(expected_msgs=['Received a POST request for / from'],
                                   unexpected_msgs=['ThreadRPCServer method=getblockcount']):
            assert_equal(node.logging([], ['rpc'])['rpc'], 0)
            node.getblockcount()
        with node.assert_debug_log(expected_msgs=['ThreadRPCServer method=getblockcount']):
            assert_equal(node.logging(['rpc'])['rpc'], 1)
            node.getblockcount()

        assert_raises_rpc_error(-8, "unknown logging category foo", node.logging, ['foo'])
        assert_raises_rpc_error(-8, "unknown logging category foo", node.logging, [], ['foo'])
        assert_equal(node.logging(['libevent'])['libevent'], 1)
        assert_equal(node.logging([], ['libevent'])['libevent'], 0)
        # Arguments that aren't arrays are ignored.
        assert_equal(node.logging('rpc', 'net'), state)
        everything = node.logging(['all'])
        assert all(everything.values()), everything
        assert_equal(node.logging([], ['libevent', 'leveldb']), state)

    def test_setmocktime(self):
        self.log.info("setmocktime takes a number")
        assert_raises_rpc_error(-3, "Expected type number, got string", self.nodes[0].setmocktime, "x")

    def test_getinfo(self):
        node = self.nodes[0]
        self.log.info("getinfo agrees with the other RPCs")
        info = node.getinfo()
        assert_equal(info['blocks'], node.getblockcount())
        assert_equal(info['moneysupply'], node.getblock(node.getbestblockhash())['money supply'])
        assert_equal(info['testnet'], False)
        assert_equal(info['errors'], '')
        # Not len(getpeerinfo()): it ends with a size element.
        assert_equal(info['connections'], len(peers(node)))
        assert_equal(info['connections'], 1)

    def test_createmultisig(self):
        node0, node1 = self.nodes
        self.log.info("createmultisig from public keys equals addmultisigaddress")
        addresses = [node1.getnewaddress() for _ in range(3)]
        pubkeys = [node1.validateaddress(a)['pubkey'] for a in addresses]
        msig = node0.createmultisig(2, pubkeys)
        assert_equal(sorted(msig), ['address', 'redeemScript'])
        assert_equal(node1.addmultisigaddress(2, pubkeys), msig['address'])
        assert_equal(node1.validateaddress(msig['address'])['hex'], msig['redeemScript'])
        assert_equal(node0.decodescript(msig['redeemScript'])['p2sh'], msig['address'])

        self.log.info("With wallet addresses instead of public keys")
        assert_equal(node1.createmultisig(2, addresses), msig)
        assert_equal(node1.createmultisig(2, [addresses[0], pubkeys[1], addresses[2]]), msig)

        self.log.info("The address can be funded and spent")
        txid = node0.sendtoaddress(address=msig['address'], amount=10)
        tx = node0.getrawtransaction(txid, 1)
        vout = [o['n'] for o in tx['vout'] if o['scriptPubKey'].get('addresses') == [msig['address']]][0]
        node0.generate(1)
        self.sync_all()
        destination = node0.getnewaddress()
        raw = node1.createrawtransaction([{'txid': txid, 'vout': vout}], {destination: Decimal('9.99')})
        prevtxs = [{'txid': txid, 'vout': vout, 'scriptPubKey': tx['vout'][vout]['scriptPubKey']['hex'],
                    'redeemScript': msig['redeemScript'], 'amount': 10}]
        signed = node1.signrawtransaction(raw, prevtxs)
        assert_equal(signed['complete'], True)
        spend = node1.sendrawtransaction(signed['hex'])
        node1.generate(1)
        self.sync_all()
        assert_equal(node0.gettransaction(spend)['confirmations'], 1)
        assert_equal(node0.getreceivedbyaddress(destination), Decimal('9.99'))

        self.log.info("Argument errors")
        assert_raises_rpc_error(-1, "a multisignature address must require at least one key to redeem",
                                node0.createmultisig, 0, pubkeys)
        assert_raises_rpc_error(-1, "not enough keys supplied (got 2 keys, but need at least 3 to redeem)",
                                node0.createmultisig, 3, pubkeys[:2])
        assert_raises_rpc_error(-1, "Number of addresses involved in the multisignature address creation > 16\nReduce the number",
                                node0.createmultisig, 2, [pubkeys[0]] * 17)
        assert_raises_rpc_error(-1, " Invalid public key: xyz", node0.createmultisig, 1, ['xyz'])
        assert_raises_rpc_error(-1, "%s does not refer to a key" % msig['address'],
                                node1.createmultisig, 1, [msig['address']])
        # node0's wallet doesn't have the public key of node1's address.
        assert_raises_rpc_error(-1, "no full public key for address %s" % addresses[0],
                                node0.createmultisig, 1, [addresses[0]])


if __name__ == '__main__':
    RpcMiscTest().main()
