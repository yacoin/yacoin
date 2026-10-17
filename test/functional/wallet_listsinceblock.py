#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test listsinceblock (adapted from Bitcoin Core's listsinceblock.py).

Bitcoin Core's scenarios:
- without a block hash: all wallet transactions, no removed ones;
- unknown and invalid block hashes;
- a block that is no longer in the main chain after a reorg: the
  transactions from the fork point on are listed;
- a UTXO spent differently on two branches: the losing spend is listed in
  'removed', and include_removed=false drops the key;
- the same transaction mined on both branches: listed in 'transactions'
  and 'removed', with the confirmations of the winning branch.
Added: target_confirmations and lastblock, and the listing at the tip.

Porting notes: the cached chain instead of 101 blocks; amounts with 6
decimals and a 0.01 fee; signrawtransaction; the winning branch is always
strictly longer. In YACoin listtransactions orders by insertion and
listsinceblock by txid, so the 'no block hash' comparison sorts both.
"""
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

FEE = Decimal('0.01')


def entry_key(e):
    return (e['txid'], e['category'], e.get('vout'), e.get('address'))


class ListSinceBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.test_no_blockhash()
        self.test_invalid_blockhash()
        self.test_target_confirmations()
        self.test_reorg()
        self.test_double_spend()
        self.test_double_send()

    def raw_spend(self, signer, utxo, outputs):
        raw = signer.createrawtransaction([{'txid': utxo['txid'], 'vout': utxo['vout']}], outputs)
        signed = signer.signrawtransaction(raw)
        assert signed['complete']
        return signed['hex']

    def test_no_blockhash(self):
        self.log.info("Without a block hash")
        node0, node2 = self.nodes[0], self.nodes[2]
        txid = node2.sendtoaddress(node0.getnewaddress(), 1)
        blockhash = node2.generate(1)[0]
        self.sync_all()
        txs = node0.listtransactions('*', 1000)
        entry = [e for e in txs if e['txid'] == txid]
        assert_equal(len(entry), 1)
        assert_equal((entry[0]['category'], entry[0]['amount'], entry[0]['blockhash'], entry[0]['confirmations']),
                     ('receive', Decimal('1'), blockhash, 1))
        result = node0.listsinceblock()
        assert_equal((result['lastblock'], result['removed']), (blockhash, []))
        assert_equal(sorted(result['transactions'], key=entry_key), sorted(txs, key=entry_key))
        assert_equal(node0.listsinceblock(''), result)

    def test_invalid_blockhash(self):
        self.log.info("Unknown and invalid block hashes")
        node0 = self.nodes[0]
        for blockhash in ["42759cde25462784395a337460bde75f58e73d3f08bd31fdc3507cbac856a2c4",
                          "00" * 32, "invalid-hex"]:
            assert_raises_rpc_error(-5, "Block not found", node0.listsinceblock, blockhash)
        assert_raises_rpc_error(-8, "Invalid parameter", node0.listsinceblock, '', 0)

    def test_target_confirmations(self):
        self.log.info("target_confirmations and lastblock")
        node0 = self.nodes[0]
        height = node0.getblockcount()
        assert_equal(node0.listsinceblock('', 3)['lastblock'], node0.getblockhash(height - 2))
        # No check against the chain height
        assert_equal(node0.listsinceblock('', 10**6)['lastblock'], '00' * 32)
        # Since the tip: only transactions without a block
        assert all(e['confirmations'] <= 0 for e in node0.listsinceblock(node0.getbestblockhash())['transactions'])

    def test_reorg(self):
        self.log.info("A block that is no longer in the main chain")
        node0, node1, node2 = self.nodes[:3]
        self.split_network()
        senttx = node2.sendtoaddress(node0.getnewaddress(), 1)
        lastblockhash = node1.generate(6)[5]
        node2.generate(7)
        self.sync_all(self.nodes[:2])
        self.sync_all(self.nodes[2:])
        self.join_network()
        result = node0.listsinceblock(lastblockhash)
        assert senttx in [e['txid'] for e in result['transactions']]

    def test_double_spend(self):
        self.log.info("A UTXO spent differently on two branches")
        node0, node1, node2, node3 = self.nodes
        self.sync_all()
        self.split_network()
        utxo = node2.listunspent()[0]
        node1.importprivkey(node2.dumpprivkey(utxo['address'])['private_key'])
        change = utxo['amount'] - 1 - FEE
        txid1 = node1.sendrawtransaction(self.raw_spend(node1, utxo, {
            node0.getnewaddress(): 1, node1.getnewaddress(): change}))
        node2.sendrawtransaction(self.raw_spend(node2, utxo, {
            node3.getnewaddress(): 1, node2.getnewaddress(): change}))
        lastblockhash = node1.generate(3)[2]
        node2.generate(4)
        self.join_network()
        self.sync_all()

        tx = node0.gettransaction(txid1)
        assert_equal(tx['txid'], txid1)
        assert tx['confirmations'] < 0
        result = node0.listsinceblock(lastblockhash)
        assert txid1 in [e['txid'] for e in result['removed']]
        # A conflicted receive isn't listed with a minimum depth of 0
        assert txid1 not in [e['txid'] for e in result['transactions']]
        assert 'removed' not in node0.listsinceblock(blockhash=lastblockhash, include_removed=False)

    def test_double_send(self):
        self.log.info("The same transaction mined on two branches")
        node0, node1, node2 = self.nodes[:3]
        self.sync_all()
        self.split_network()
        utxo = node2.listunspent()[0]
        signed = self.raw_spend(node2, utxo, {
            node0.getnewaddress(): 1, node2.getnewaddress(): utxo['amount'] - 1 - FEE})
        txid1 = node1.sendrawtransaction(signed)
        node2.generate(2)
        txid2 = node2.sendrawtransaction(signed)
        assert_equal(txid1, txid2)
        lastblockhash = node1.generate(3)[2]
        node2.generate(2)
        self.join_network()
        self.sync_all()

        blockhash = node0.gettransaction(txid1)['blockhash']
        result = node0.listsinceblock(lastblockhash)
        for key in ('transactions', 'removed'):
            entries = [e for e in result[key] if e['txid'] == txid1]
            assert_equal([(e['confirmations'], e['blockhash']) for e in entries], [(2, blockhash)])


if __name__ == '__main__':
    ListSinceBlockTest().main()
