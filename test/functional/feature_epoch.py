#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the epoch block reward.

Mine 39 blocks with epochinterval=10 and check, after every block, that the
coinbase pays the reward computed from the money supply at the end of the
previous epoch, the block value (getmininginfo, which should equal
getsubsidy, the next block's reward), the difficulty, and the money supply
after each epoch. Then a transaction fee is burned: the coinbase doesn't claim it
and the money supply grows by the reward minus the fee.
"""

from test_framework.blocktools import TIME_GENESIS_BLOCK, epoch_reward
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_approx,
    assert_equal,
)
from test_framework.yac_tx import key_from_wif, p2pkh_script, sign_p2pkh_input


class EpochTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.block_fork_1_0 = 1

    def money_supply(self, height):
        node = self.nodes[0]
        return int(node.getblock(node.getblockhash(height))['money supply'] * COIN)

    def expected_reward(self, height):
        return epoch_reward(self.nodes[0], height, self.block_fork_1_0)

    def coinbase_value(self, block_hash):
        coinbase = self.nodes[0].getblock(block_hash, 2)['tx'][0]
        return sum(int(out['value'] * COIN) for out in coinbase['vout'])

    def mine_blocks(self, n, blockvalue, moneysupply_at_end, difficulty):
        node = self.nodes[0]
        for _ in range(n):
            block_hash = self.mine_with_mocktime(node, 1, spacing=120, sync=False)[0]
            height = node.getblockcount()
            reward = self.expected_reward(height)
            assert_equal(self.coinbase_value(block_hash), reward)
            assert_equal(int(node.getblock(block_hash)['mint'] * COIN), reward)
            assert_equal(self.money_supply(height), self.money_supply(height - 1) + reward)
            mininginfo = node.getmininginfo()
            if self.expected_reward(height + 1) == reward:
                assert_equal(mininginfo['blockvalue'], blockvalue)
                assert_equal(mininginfo['blockvalue'], node.getsubsidy())
            else:
                # Last block of an epoch: blockvalue shows the tip's reward
                # today, getsubsidy and the miner the next block's.
                subsidy = node.getsubsidy()
                assert_equal(subsidy, self.expected_reward(height + 1))
                self.known_failure("C-S11 (VUi4Bd6T)",
                                   lambda: assert_equal(mininginfo['blockvalue'], subsidy),
                                   "not(%d == %d)" % (reward, subsidy))
            assert_approx(mininginfo['difficulty'], difficulty, vspan=1E-12)
        assert_equal(int(node.getinfo()['moneysupply'] * COIN), moneysupply_at_end)
        self.sync_all()

    def run_test(self):
        # The first block is mined at the genesis time (the difficulty values
        # below depend on the block times).
        self.set_mocktime(TIME_GENESIS_BLOCK - 120)
        self.mine_blocks(9, 3802570, 100000034223130, 5.96046448E-8)
        self.mine_blocks(10, 3802571, 100000072248840, 3.80457032E-8)
        self.mine_blocks(10, 3802573, 100000110274570, 1.98682149E-8)
        self.mine_blocks(10, 3802574, 100000148300310, 1.98682149E-8)

        self.log.info("A transaction fee is burned: the coinbase pays the reward only")
        node = self.nodes[0]
        key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        coinbase = node.getblock(node.getblockhash(1), 2)['tx'][0]
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(coinbase['txid'], 16), 0))]
        tx.vout = [CTxOut(int(coinbase['vout'][0]['value'] * COIN) - COIN, p2pkh_script(key.get_pubkey().get_bytes()))]
        sign_p2pkh_input(tx, 0, key)
        assert_equal(node.sendrawtransaction(tx.serialize().hex()), tx.hash)
        subsidy = node.getsubsidy()
        supply_39 = self.money_supply(39)
        block_hash = self.mine_with_mocktime(node, 1, spacing=120)[0]
        block = node.getblock(block_hash)
        assert_equal(block['tx'], [block['tx'][0], tx.hash])
        assert_equal(self.coinbase_value(block_hash), subsidy)
        assert_equal(subsidy, self.expected_reward(40))
        assert_equal(self.money_supply(40), supply_39 + subsidy - COIN)
        for n in self.nodes:
            assert_equal(int(n.getinfo()['moneysupply'] * COIN), supply_39 + subsidy - COIN)


if __name__ == '__main__':
    EpochTest().main()
