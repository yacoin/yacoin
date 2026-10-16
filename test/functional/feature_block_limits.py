#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the block size and signature operation limits.

From the 1.0 fork on the block size limit follows the reward, and so the
money supply: reward * 1000 / MIN_TX_FEE bytes (GetMaxSize). The sigop limit
is max(size limit, 1 MB) / 50. Checks:
- getblocktemplate's sizelimit and sigoplimit;
- a block of exactly the size limit is accepted, one byte more is not;
- 20000 legacy sigops are accepted (20001 is in feature_block.py), P2SH
  sigops count when the block is connected;
- burning a large fee lowers the money supply, and the next epoch's reward
  and size limit with it;
- the miner fills a block up to the limit and leaves the rest in the mempool.
"""

from test_framework.blocktools import (
    TIME_GENESIS_BLOCK,
    assert_block_accepted,
    assert_block_rejected,
    create_block_yac,
    epoch_reward,
    get_template,
    solve_block,
)
from test_framework.messages import COIN, MIN_TX_FEE, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.mininode import P2PInterface
from test_framework.script import CScript, OP_CHECKSIG, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, assert_greater_than
from test_framework.yac_tx import key_from_wif, p2pkh_script, p2sh_script, sign_p2pkh_input

FORK = 30


class BlockLimitsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.block_fork_1_0 = FORK
        self.extra_args = [["-par=1"]]

    def money_supply(self, height):
        return int(self.node.getblock(self.node.getblockhash(height))['money supply'] * COIN)

    def reward(self, height):
        return epoch_reward(self.node, height, FORK)

    def coinbase_output(self, height):
        """(txid as int, value) of the P2PKH coinbase output of a node-mined block."""
        block = self.node.getblock(self.node.getblockhash(height), 2)
        out = block['tx'][0]['vout'][0]
        assert_equal(out['scriptPubKey']['hex'], p2pkh_script(self.pubkey).hex())
        return int(block['tx'][0]['txid'], 16), int(out['value'] * COIN)

    def padded_block(self, size):
        """A template block whose serialization is exactly size bytes: the
        coinbase gets an OP_RETURN output with a push of zero bytes (no
        OP_CHECKSIG bytes, which would count as sigops)."""
        block = create_block_yac(self.node)
        pad = size - len(block.serialize())
        for _ in range(4):
            block.vtx[0].vout[1:] = [CTxOut(0, CScript([OP_RETURN, b"\x00" * pad]))]
            block.vtx[0].rehash()
            block.hashMerkleRoot = block.calc_merkle_root()
            if len(block.serialize()) == size:
                return solve_block(self.node, block)
            # Take off the output's own overhead (value, lengths, opcodes).
            pad -= len(block.serialize()) - size
        raise AssertionError("no padding gives %d bytes" % size)

    def run_test(self):
        self.node = node = self.nodes[0]
        self.key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        self.pubkey = self.key.get_pubkey().get_bytes()
        node.add_p2p_connection(P2PInterface())
        self.set_mocktime(TIME_GENESIS_BLOCK)
        self.mine_with_mocktime(node, FORK + 1)

        self.log.info("getblocktemplate: the size limit follows the reward, the sigop limit is 20000")
        self.set_mocktime(self.mocktime + 60)
        tmpl = get_template(node)
        size_limit = tmpl['sizelimit']
        assert_equal(tmpl['coinbasevalue'], self.reward(tmpl['height']))
        assert_equal(size_limit, tmpl['coinbasevalue'] * 1000 // MIN_TX_FEE)
        assert_equal(tmpl['sigoplimit'], max(size_limit, 1000000) // 50)
        assert_equal(tmpl['sigoplimit'], 20000)

        self.log.info("A block one byte above the size limit: bad-blk-length; exactly the limit is accepted")
        assert_block_rejected(node, self.padded_block(size_limit + 1), "bad-blk-length")
        block = self.padded_block(size_limit)
        assert_block_accepted(node, block)
        assert_equal(node.getblock(block.hash)['size'], size_limit)

        self.log.info("20000 legacy sigops are accepted")
        self.set_mocktime(self.mocktime + 60)
        block = solve_block(node, create_block_yac(node, script_pubkey=CScript([OP_CHECKSIG] * 20000)))
        assert_block_accepted(node, block)

        self.log.info("P2SH sigops count when the block is connected: bad-blk-sigops")
        redeem_script = CScript([OP_CHECKSIG] * 520)
        txid, value = self.coinbase_output(1)
        fund = CTransaction()
        fund.nTime = self.mocktime
        fund.vin = [CTxIn(COutPoint(txid, 0))]
        fund.vout = [CTxOut(COIN, p2sh_script(redeem_script)) for _ in range(40)]
        sign_p2pkh_input(fund, 0, self.key)
        self.set_mocktime(self.mocktime + 60)
        assert_block_accepted(node, solve_block(node, create_block_yac(node, [fund])))
        spend = CTransaction()
        spend.nTime = self.mocktime
        # 39 * 520 = 20280 sigops; the legacy count of these pushes is 0.
        spend.vin = [CTxIn(COutPoint(fund.sha256, n), CScript([bytes(redeem_script)])) for n in range(39)]
        spend.vout = [CTxOut(30 * COIN, CScript([OP_TRUE]))]
        spend.rehash()
        assert_block_rejected(node, solve_block(node, create_block_yac(node, [spend])), "bad-blk-sigops")

        self.log.info("A burned fee lowers the money supply")
        self.set_mocktime(self.mocktime + 60)
        burn = CTransaction()
        burn.nTime = self.mocktime
        inputs = [self.coinbase_output(height) for height in range(2, 22)]
        burn.vin = [CTxIn(COutPoint(txid, 0)) for txid, _ in inputs]
        burn.vout = [CTxOut(10 * COIN, p2pkh_script(self.pubkey))]
        for n in range(len(inputs)):
            sign_p2pkh_input(burn, n, self.key)
        fee = sum(value for _, value in inputs) - 10 * COIN
        tmpl = get_template(node)
        block = solve_block(node, create_block_yac(node, [burn], tmpl=tmpl))
        assert_block_accepted(node, block)
        height = node.getblockcount()
        assert_equal(int(node.getblock(block.hash)['mint'] * COIN), tmpl['coinbasevalue'])
        assert_equal(self.money_supply(height), self.money_supply(height - 1) + tmpl['coinbasevalue'] - fee)

        self.log.info("The next epoch's reward and size limit follow the lower money supply")
        while node.getblockcount() < 39:
            self.mine_with_mocktime(node, 1)
        self.set_mocktime(self.mocktime + 60)
        tmpl = get_template(node)
        assert_equal(tmpl['height'], 40)
        assert_equal(tmpl['coinbasevalue'], self.reward(40))
        assert_equal(tmpl['sizelimit'], tmpl['coinbasevalue'] * 1000 // MIN_TX_FEE)
        assert_greater_than(size_limit, tmpl['sizelimit'])
        assert_block_rejected(node, self.padded_block(size_limit), "bad-blk-length")
        assert_block_rejected(node, self.padded_block(tmpl['sizelimit'] + 1), "bad-blk-length")
        assert_block_accepted(node, self.padded_block(tmpl['sizelimit']))
        size_limit = tmpl['sizelimit']

        self.log.info("The miner fills a block up to the limit and leaves the rest in the mempool")
        self.set_mocktime(self.mocktime + 60)
        txids = []
        for height in range(22, 27):
            txid, value = self.coinbase_output(height)
            tx = CTransaction()
            tx.nTime = self.mocktime
            tx.vin = [CTxIn(COutPoint(txid, 0))]
            # About 90 kB each, so four fit below the limit and five don't.
            tx.vout = [CTxOut(value - COIN, p2pkh_script(self.pubkey)), CTxOut(0, CScript([OP_RETURN, b"\x01" * 89800]))]
            sign_p2pkh_input(tx, 0, self.key)
            txids.append(node.sendrawtransaction(tx.serialize().hex()))
        assert_equal(sorted(node.getrawmempool()), sorted(txids))
        block = node.getblock(self.mine_with_mocktime(node, 1)[0])
        assert_greater_than(size_limit, block['size'])
        assert_equal(len(block['tx']), 5)
        left = node.getrawmempool()
        assert_equal(len(left), 1)
        assert_equal(sorted(block['tx'][1:] + left), sorted(txids))
        block = node.getblock(self.mine_with_mocktime(node, 1)[0])
        assert_equal(block['tx'][1:], left)
        assert_equal(node.getrawmempool(), [])


if __name__ == '__main__':
    BlockLimitsTest().main()
