#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test coinbase maturity before and after the 1.0 hardfork.

Before the fork, consensus lets a coinbase be spent at depth 500
(COINBASE_MATURITY_BEFORE_HARDFORK), while the wallet adds 20 blocks and
reports it as immature until depth 520. From the fork block on, both use 6.

The test chain forks at height 600. Pre-fork blocks must be mined with a
clock near the genesis time (the proof-of-work N-factor grows with the
block time), so the blocks are mined with mine_with_mocktime.

- Up to depth 499 a raw spend of block 1's coinbase is rejected; at depth
  500 it is accepted, while the wallet still calls the coinbase immature
  until depth 520.
- Known failure (XbGM5oTW item 3): after that spend, immature_balance still
  counts the spent coinbase.
- At the fork height every coinbase of depth 6 or more becomes mature at
  once.
"""
from test_framework.messages import COINBASE_MATURITY, COINBASE_MATURITY_BEFORE_HARDFORK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import coinbase_value

FORK_HEIGHT = 600
WALLET_OFFSET = 20  # GetCoinbaseMaturityOffset() before the fork


class WalletCoinbaseMaturityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.block_fork_1_0 = FORK_HEIGHT

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_to(self, height):
        node = self.nodes[0]
        self.hashes += self.mine_with_mocktime(node, height - node.getblockcount())
        assert_equal(node.getblockcount(), height)

    def value(self, height):
        """Coinbase value of the block at height."""
        node = self.nodes[0]
        if height not in self.values:
            self.values[height] = coinbase_value(node, self.hashes[height - 1])
        return self.values[height]

    def values_sum(self, first, last):
        return sum(self.value(h) for h in range(first, last + 1))

    def category(self, txid):
        return self.nodes[0].gettransaction(txid)['details'][0]['category']

    def run_test(self):
        node = self.nodes[0]
        self.hashes = []
        self.values = {}

        self.log.info("Mine block 1")
        self.mine_to(1)
        cb1 = node.getblock(self.hashes[0])['tx'][0]
        r1 = self.value(1)
        assert_equal(self.category(cb1), 'immature')

        # The 20-block wallet offset before the fork is intended (as in old
        # Bitcoin versions); Trello XbGM5oTW item 3 reviews its side effects.
        self.log.info("Depth 499: consensus still rejects spending block 1's coinbase")
        self.mine_to(COINBASE_MATURITY_BEFORE_HARDFORK - 1)
        info = node.getwalletinfo()
        assert_equal((info['balance'], info['immature_balance']), (0, self.values_sum(1, 499)))
        raw = node.createrawtransaction([{'txid': cb1, 'vout': 0}], {node.getnewaddress(): r1 - 1})
        signed = node.signrawtransaction(raw)
        assert signed['complete']
        assert_raises_rpc_error(-26, "bad-txns-premature-spend-of-coinbase/coinstake", node.sendrawtransaction, signed['hex'])

        self.log.info("Depth 500: consensus accepts the spend, the wallet still calls the coinbase immature")
        self.mine_to(COINBASE_MATURITY_BEFORE_HARDFORK)
        assert_equal(node.getbalance(), 0)
        assert_equal(self.category(cb1), 'immature')
        spend = node.sendrawtransaction(signed['hex'])
        # The spend is the wallet's own, in the mempool, so it is trusted
        assert_equal(node.gettransaction(spend)['trusted'], True)
        assert_equal(node.getbalance(), r1 - 1)

        self.mine_to(COINBASE_MATURITY_BEFORE_HARDFORK + 1)
        assert_equal(node.gettransaction(spend)['confirmations'], 1)
        assert_equal(node.getbalance(), r1 - 1)
        assert_equal(self.category(cb1), 'immature')

        def check_immature_without_spent_coinbase():
            immature = node.getwalletinfo()['immature_balance']
            expected = self.values_sum(2, 501)
            assert immature == expected, "immature_balance counts the spent coinbase: %s != %s" % (immature, expected)
        # GetImmatureCredit doesn't check whether the coinbase was spent
        self.known_failure("XbGM5oTW item 3", check_immature_without_spent_coinbase,
                           expected="immature_balance counts the spent coinbase")

        self.log.info("Depth 520: the wallet calls the coinbase mature")
        wallet_maturity = COINBASE_MATURITY_BEFORE_HARDFORK + WALLET_OFFSET
        self.mine_to(wallet_maturity - 1)
        assert_equal(self.category(cb1), 'immature')
        self.mine_to(wallet_maturity)
        assert_equal(self.category(cb1), 'generate')
        assert_equal(node.getbalance(), r1 - 1)
        self.mine_to(wallet_maturity + 1)
        assert_equal(node.getbalance(), r1 - 1 + self.value(2))

        self.log.info("Before the fork, coinbases of depth 520 or more are mature in the wallet")
        self.mine_to(FORK_HEIGHT - 1)
        last_mature = FORK_HEIGHT - 1 - wallet_maturity + 1
        assert_equal(node.getbalance(), r1 - 1 + self.values_sum(2, last_mature))

        self.log.info("At the fork height every coinbase of depth 6 or more is mature")
        self.mine_to(FORK_HEIGHT)
        last_mature = FORK_HEIGHT - COINBASE_MATURITY + 1
        info = node.getwalletinfo()
        assert_equal(info['balance'], r1 - 1 + self.values_sum(2, last_mature))
        assert_equal(info['immature_balance'], self.values_sum(last_mature + 1, FORK_HEIGHT))


if __name__ == '__main__':
    WalletCoinbaseMaturityTest().main()
