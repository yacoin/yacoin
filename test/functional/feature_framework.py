#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Self-checks of the YACoin parts of the test framework.

Later tests rely on these helpers, so check them against a real node:
- node exit codes and the signal helpers (TestNode.wait_until_stopped,
  send_signal, wait_for_exit).
- connect_nodes returns only when both sides finished the handshake, and
  peers() drops YACoin's extra getpeerinfo element.
- CTransaction computes the node's txids (scriptSigs ignored from version 2
  on, except for coinbases) and CBlock the merkle root.
- mininode connections announce the node's height and can use another
  loopback source address.
- set_mocktime / mine_with_mocktime keep one forward-only clock on all
  nodes, also across restarts.
- raw_rpc, rpcauth_value, the wallet fee rule and single_utxo_wallet.
- known_failure passes while its check fails and fails once it passes.
"""

from decimal import Decimal
import re
import signal

from test_framework.authproxy import JSONRPCException
from test_framework.messages import COIN, CBlock, CTransaction, FromHex, TX_VERSION
from test_framework.mininode import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises,
    connect_nodes,
    non_loopback_ipv4,
    p2p_port,
    peers,
    raw_rpc,
    rpcauth_value,
)
from test_framework.wallet_util import assert_yac_fee, expected_fee


class FrameworkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # The connection checks connect the nodes themselves.
        self.setup_nodes()

    def run_test(self):
        self.test_exit_codes()
        self.test_connect_nodes()
        self.test_txid()
        self.test_mininode_options()
        self.test_mocktime()
        self.test_raw_rpc()
        self.test_wallet_helpers()
        self.test_known_failure()

    def test_exit_codes(self):
        node = self.nodes[1]

        self.log.info("SIGTERM shuts the node down cleanly (exit code 0)")
        node.send_signal(signal.SIGTERM)
        assert_equal(node.wait_for_exit(), 0)
        assert_equal(node.read_stderr(), "")
        assert not node.running
        self.start_node(1)

        self.log.info("wait_until_stopped accepts the expected exit code")
        node.send_signal(signal.SIGKILL)
        node.wait_until_stopped(expected_ret_code=-signal.SIGKILL)
        self.start_node(1)

        self.log.info("wait_until_stopped fails on an unexpected exit code, and the node can be restarted")
        node.send_signal(signal.SIGKILL)
        try:
            node.wait_until_stopped()
        except AssertionError as e:
            assert "Node returned exit code -9 (SIGKILL), expected 0" in str(e), str(e)
        else:
            raise AssertionError("wait_until_stopped did not fail on exit code -9")
        assert not node.running
        self.start_node(1)
        assert_equal(node.getblockcount(), 0)

    def test_connect_nodes(self):
        self.log.info("peers() drops the extra getpeerinfo element")
        assert_equal(len(self.nodes[0].getpeerinfo()), 1)
        assert_equal(peers(self.nodes[0]), [])

        self.log.info("connect_nodes returns when both sides finished the handshake")
        connect_nodes(self.nodes[0], 1)
        # No waiting here: both sides must already agree.
        outbound = peers(self.nodes[0])
        inbound = peers(self.nodes[1])
        assert_equal(len(outbound), 1)
        assert_equal(len(inbound), 1)
        assert_equal(outbound[0]['addr'], "127.0.0.1:%d" % p2p_port(1))
        assert not outbound[0]['inbound']
        assert inbound[0]['inbound']
        assert outbound[0]['version'] != 0 and inbound[0]['version'] != 0
        assert 'verack' in inbound[0]['bytesrecv_per_msg']
        assert 'pong' in outbound[0]['bytesrecv_per_msg']

    def check_txid(self, txid):
        raw = self.nodes[0].getrawtransaction(txid)
        tx = FromHex(CTransaction(), raw)
        assert_equal(tx.serialize().hex(), raw)
        assert_equal(tx.rehash(), txid)
        return tx

    def test_txid(self):
        node = self.nodes[0]
        node.generate(12)
        self.sync_blocks()

        self.log.info("Coinbase txid: full serialization")
        coinbase = self.check_txid(node.getblock(node.getbestblockhash())['tx'][0])
        assert coinbase.is_coinbase()
        assert_equal(coinbase.nVersion, TX_VERSION)

        self.log.info("Wallet transaction txids: scriptSigs ignored")
        one_input = self.check_txid(node.sendtoaddress(address=node.getnewaddress(), amount=Decimal('1.5')))
        assert_equal(len(one_input.vin), 1)
        # COIN matches the node's unit.
        for n, txout in enumerate(node.getrawtransaction(one_input.hash, 1)['vout']):
            assert_equal(Decimal(one_input.vout[n].nValue) / COIN, txout['value'])
        self.fee_txids = [one_input.hash]
        many_inputs = self.check_txid(node.sendtoaddress(address=node.getnewaddress(), amount=node.getbalance() - 1))
        assert len(many_inputs.vin) > 1
        assert not many_inputs.is_coinbase()
        self.fee_txids.append(many_inputs.hash)

        self.log.info("Merkle root of a block with these transactions")
        block_hash = node.generate(1)[0]
        assert_equal(len(node.getblock(block_hash)['tx']), 3)
        block = FromHex(CBlock(), node.getblock(block_hash, False))
        assert_equal(block.calc_merkle_root(), int(node.getblock(block_hash)['merkleroot'], 16))

        self.log.info("Version 1 transaction: full serialization")
        v1 = CTransaction(one_input)
        v1.nVersion = 1
        v1.rehash()
        assert_equal(node.decoderawtransaction(v1.serialize().hex())['txid'], v1.hash)
        assert v1.hash != one_input.hash

        self.log.info("Signing doesn't change a version 2 txid")
        utxo = node.listunspent()[0]
        unsigned = node.createrawtransaction([{"txid": utxo['txid'], "vout": utxo['vout']}], {node.getnewaddress(): Decimal('0.5')})
        signed = node.signrawtransaction(unsigned)['hex']
        assert_equal(FromHex(CTransaction(), unsigned).rehash(), FromHex(CTransaction(), signed).rehash())
        assert_equal(FromHex(CTransaction(), signed).rehash(), node.decoderawtransaction(signed)['txid'])

    def test_mininode_options(self):
        node = self.nodes[0]
        self.log.info("A mininode announces the node's height")
        node.add_p2p_connection(P2PInterface())
        info = peers(node)[-1]
        assert_equal(info['subver'], "/python-mininode-tester:0.0.3/")
        assert_equal(info['startingheight'], node.getblockcount())

        self.log.info("local_addr gives a mininode its own source address")
        node.add_p2p_connection(P2PInterface(), local_addr=("127.0.0.2", 0))
        assert peers(node)[-1]['addr'].startswith("127.0.0.2:")
        node.disconnect_p2ps()

    def test_mocktime(self):
        node = self.nodes[0]
        self.log.info("mine_with_mocktime spaces blocks by the given time")
        height = node.getblockcount()
        hashes = self.mine_with_mocktime(node, 3, spacing=90)
        assert_equal(node.getblockcount(), height + 3)
        times = [node.getblockheader(h)['time'] for h in hashes]
        assert_equal([times[1] - times[0], times[2] - times[1]], [90, 90])
        assert_equal(times[2], self.mocktime)
        assert_equal(self.nodes[1].getbestblockhash(), hashes[-1])

        self.log.info("set_mocktime refuses to move the clock back")
        assert_raises(AssertionError, self.set_mocktime, self.mocktime - 1)

        self.log.info("A node stopped while the clock moves comes back with the current mocktime")
        self.stop_node(1)
        self.mine_with_mocktime(node, 2)
        self.start_node(1)
        connect_nodes(self.nodes[1], 0)
        self.sync_blocks()
        block = self.nodes[1].getblockheader(self.nodes[1].generate(1)[0])
        assert_equal(block['time'], self.mocktime)
        self.sync_blocks()

    def test_raw_rpc(self):
        node = self.nodes[0]
        self.log.info("raw_rpc returns status and body as sent by the node")
        status, headers, body = raw_rpc(node, {"method": "getblockcount", "params": [], "id": 1})
        assert_equal(status, 200)
        assert_equal(headers['Content-Type'], 'application/json')
        assert body.startswith(b'{"result":%d,' % node.getblockcount())
        assert_equal(raw_rpc(node, {"method": "getblockcount"}, auth=False)[0], 401)

        self.log.info("rpcauth_value gives a working -rpcauth entry")
        self.restart_node(1, extra_args=["-rpcauth=" + rpcauth_value("alice", "secret")])
        connect_nodes(self.nodes[1], 0)
        assert_equal(raw_rpc(self.nodes[1], {"method": "getblockcount"}, auth=("alice", "secret"))[0], 200)
        assert_equal(raw_rpc(self.nodes[1], {"method": "getblockcount"}, auth=("alice", "wrong"))[0], 401)

        address = non_loopback_ipv4()
        self.log.info("non_loopback_ipv4: %s", address)
        assert address is None or not address.startswith("127.")

    def test_wallet_helpers(self):
        self.log.info("expected_fee matches the wallet's fees, for a small and a large transaction")
        for txid in self.fee_txids:
            assert_yac_fee(self.nodes[0], txid)
        assert_equal(-self.nodes[0].gettransaction(self.fee_txids[0])['fee'], Decimal('0.01'))
        large_size = len(self.nodes[0].getrawtransaction(self.fee_txids[1])) // 2
        assert large_size > 1000
        assert expected_fee(large_size) > Decimal('0.01')

        self.log.info("single_utxo_wallet leaves exactly one UTXO")
        utxo = self.single_utxo_wallet(self.nodes[0], self.nodes[1], Decimal('2.5'))
        assert_equal(utxo['confirmations'], 1)

    def test_known_failure(self):
        node = self.nodes[0]
        out_of_range = lambda: node.getblockhash(100000)

        self.log.info("known_failure passes while the check fails with the expected symptom")
        self.known_failure("example bug", lambda: assert_equal(1, 2), "not(1 == 2)")
        self.known_failure("example bug", lambda: assert_equal(1, 2), re.compile(r"not\(1 == \d\)"))
        self.known_failure("example bug", out_of_range, "Block height out of range")
        self.known_failure("example bug", out_of_range, -8)

        self.log.info("known_failure fails once the check passes")
        try:
            self.known_failure("example bug", lambda: assert_equal(1, 1), "not(1 == 2)")
        except AssertionError as e:
            assert_equal(str(e), "example bug no longer fails; remove the known-failure marker")
        else:
            raise AssertionError("known_failure did not fail on a passing check")

        self.log.info("known_failure raises an unexpected failure unchanged")
        try:
            self.known_failure("example bug", lambda: assert_equal(1, 2), "not(1 == 3)")
        except AssertionError as e:
            assert_equal(str(e), "not(1 == 2)")
        else:
            raise AssertionError("known_failure accepted the wrong assertion")
        for expected in ("Method not found", -5):
            try:
                self.known_failure("example bug", out_of_range, expected)
            except JSONRPCException as e:
                assert_equal(e.error['code'], -8)
            else:
                raise AssertionError("known_failure accepted the wrong RPC error")
        try:
            self.known_failure("example bug", lambda: assert_equal(1, 2), -8)
        except AssertionError as e:
            assert_equal(str(e), "not(1 == 2)")
        else:
            raise AssertionError("known_failure matched an error code against an assertion")


if __name__ == '__main__':
    FrameworkTest().main()
