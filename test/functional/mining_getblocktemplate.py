#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getblocktemplate: template fields, transactions, proposals, arguments.

- Without a peer the template call fails; proposal mode works anyway.
- Every field of a template on an empty mempool, and the next block's bits.
- The template cache (rebuilt only after the tip moved, or after the mempool
  changed and more than 5 s passed), a parent and a child transaction with
  depends, fee and sigops, and a coinbase value without the fees.
- Proposal results: valid, duplicate, not on the tip, one consensus reject.
- Argument errors of the template request.
"""

import copy
import random
from decimal import Decimal

from test_framework.blocktools import create_block_yac, txs_from_template
from test_framework.messages import COIN, uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
)

BUG_CARD = "IvbXjqbT"


class GetBlockTemplateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]
        self.mine_with_mocktime(node, 20)

        self.log.info("Without a peer: no template, but proposals work")
        disconnect_nodes(node, 1)
        assert_raises_rpc_error(-9, "Yacoin is not connected!", node.getblocktemplate)
        tip = node.getbestblockhash()
        assert_equal(node.getblocktemplate({'mode': 'proposal', 'data': node.getblock(tip, 0)}), "duplicate")
        connect_nodes(node, 1)

        self.test_template_fields(node)
        self.test_transactions(node)
        self.test_proposals(node)
        self.test_arguments(node)

    def proposal(self, node, block):
        return node.getblocktemplate({'mode': 'proposal', 'data': block.serialize().hex()})

    def test_template_fields(self, node):
        self.log.info("Template fields on an empty mempool")
        tip = node.getbestblockhash()
        t = node.getblocktemplate()
        assert_equal(t['capabilities'], ['proposal'])
        assert_equal(t['version'], 7)
        assert_equal(t['rules'], [])
        assert_equal(t['vbavailable'], {})
        assert_equal(t['vbrequired'], 0)
        assert_equal(t['previousblockhash'], tip)
        assert_equal(t['height'], node.getblockcount() + 1)
        assert_equal(t['transactions'], [])
        # "/P2SH/" with its push byte
        assert_equal(t['coinbaseaux'], {'flags': '062f503253482f'})
        subsidy = node.getsubsidy()
        assert_equal(t['coinbasevalue'], subsidy)
        # the tip's hash followed by the mempool's update counter
        assert t['longpollid'].startswith(tip)
        assert t['longpollid'][len(tip):].isdigit()
        assert_equal(int(t['target'], 16), uint256_from_compact(int(t['bits'], 16)))
        assert_equal(t['mintime'], node.getblockheader(tip)['mediantime'] + 1)
        assert_equal(t['curtime'], self.mocktime)
        assert_equal(t['mutable'], ['time', 'transactions', 'prevblock'])
        assert_equal(t['noncerange'], '00000000ffffffff')
        # GetMaxSize: the size limit follows the reward (MIN_TX_FEE 0.01 YAC),
        # the sigop limit is a 50th of it, at least of the 1 MB genesis size.
        assert_equal(t['sizelimit'], subsidy * 1000 // 10000)
        assert_equal(t['sigoplimit'], max(t['sizelimit'], 1000000) // 50)

        h = self.mine_with_mocktime(node, 1)[0]
        assert_equal(node.getblockheader(h)['bits'], t['bits'])

    def test_transactions(self, node):
        self.log.info("Template cache: the mempool counts only after more than 5 s")
        assert_equal(node.getblocktemplate()['transactions'], [])
        address = node.getnewaddress()
        txa = node.sendtoaddress(address, 10)
        assert_equal(node.getblocktemplate()['transactions'], [])
        self.set_mocktime(self.mocktime + 5)
        assert_equal(node.getblocktemplate()['transactions'], [])
        self.set_mocktime(self.mocktime + 1)
        assert_equal([e['txid'] for e in node.getblocktemplate()['transactions']], [txa])

        self.log.info("A parent and a child: order, depends, fee, sigops")
        vout = [o['n'] for o in node.getrawtransaction(txa, 1)['vout'] if o['value'] == Decimal('10')][0]
        raw = node.createrawtransaction([{'txid': txa, 'vout': vout}], {node.getnewaddress(): Decimal('9.95')})
        txb = node.sendrawtransaction(node.signrawtransaction(raw)['hex'])
        self.set_mocktime(self.mocktime + 6)
        t = node.getblocktemplate()
        assert_equal([e['txid'] for e in t['transactions']], [txa, txb])
        entry_a, entry_b = t['transactions']
        assert_equal(entry_a['depends'], [])
        # 1-based index of the parent in 'transactions'
        assert_equal(entry_b['depends'], [1])
        assert_equal(entry_a['fee'], int(-node.gettransaction(txa)['fee'] * COIN))
        assert_equal(entry_b['fee'], 50000)
        for entry in t['transactions']:
            assert_equal(entry['data'], node.getrawtransaction(entry['txid']))
            assert_equal(entry['hash'], entry['txid'])
        # legacy count: one per P2PKH output
        assert_equal([e['sigops'] for e in t['transactions']], [2, 1])

        self.log.info("The coinbase value doesn't include the fees")
        assert_equal(t['coinbasevalue'], node.getsubsidy())
        help_line = [l for l in node.help('getblocktemplate').split('\n') if '"coinbasevalue"' in l][0]
        self.known_failure("R-23 (%s)" % BUG_CARD,
                           lambda: self.assert_no_fees_in_help(help_line),
                           expected="transaction fees")
        self.template = t

    @staticmethod
    def assert_no_fees_in_help(help_line):
        assert 'transaction fees' not in help_line, "help says the coinbase value includes transaction fees: " + help_line

    def test_proposals(self, node):
        self.log.info("Proposals (no proof of work needed)")
        t = self.template
        block = create_block_yac(node, txs_from_template(t), tmpl=t)
        assert_equal(self.proposal(node, block), None)
        assert_equal(node.getblocktemplate({'mode': 'proposal', 'data': node.getblock(node.getbestblockhash(), 0)}),
                     "duplicate")

        other_parent = copy.deepcopy(block)
        other_parent.hashPrevBlock = random.getrandbits(256)
        other_parent.sha256 = None
        assert_equal(self.proposal(node, other_parent), "inconclusive-not-best-prevblk")

        # One consensus reject reason, to show that it comes through; the
        # block validity tests own the others.
        bad_merkle = copy.deepcopy(block)
        bad_merkle.hashMerkleRoot += 1
        bad_merkle.sha256 = None
        assert_equal(self.proposal(node, bad_merkle), "bad-txnmrklroot")

    def test_arguments(self, node):
        self.log.info("Argument errors")
        block_hex = create_block_yac(node).serialize().hex()
        assert_raises_rpc_error(-3, "Missing data String key for proposal", node.getblocktemplate, {'mode': 'proposal'})
        assert_raises_rpc_error(-3, "Missing data String key for proposal", node.getblocktemplate, {'mode': 'proposal', 'data': 1})
        assert_raises_rpc_error(-22, "Block decode failed", node.getblocktemplate, {'mode': 'proposal', 'data': block_hex[:-4]})
        assert_raises_rpc_error(-22, "Block decode failed", node.getblocktemplate, {'mode': 'proposal', 'data': 'zz'})
        assert_raises_rpc_error(-8, "Invalid mode", node.getblocktemplate, {'mode': 123})
        assert_raises_rpc_error(-8, "Invalid mode", node.getblocktemplate, {'mode': 'foo'})
        assert_raises_rpc_error(-1, "JSON value is not a string as expected", node.getblocktemplate, {'rules': [1]})
        assert_raises_rpc_error(-1, "JSON value is not an object as expected", node.getblocktemplate, 'foo')
        assert_raises_rpc_error(-1, "getblocktemplate ( TemplateRequest )", node.getblocktemplate, {}, 1)
        height = node.getblockcount() + 1
        # accepted and ignored
        for request in ({'mode': 'template'}, {'rules': ['segwit']}, {'rules': 'x'},
                        {'capabilities': ['longpoll', 'proposal']}, None):
            assert_equal(node.getblocktemplate(request)['height'], height)


if __name__ == '__main__':
    GetBlockTemplateTest().main()
