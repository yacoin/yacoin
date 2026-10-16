#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the 1.0 hard fork, here at block 30 (-testnetNewLogicBlockNumber).

- Before the fork: version 6 blocks, version 1 coinbases, coinbases mature
  after 500 blocks (also for the fork block itself), the old subsidy, the
  time-based scrypt N-factor.
- The fork block: version 7, nBits reset to the proof-of-work limit, a
  version 2 coinbase paying the reward that follows from the money supply,
  N-factor from -nFactorAtHardfork; coinbases mature after 6 blocks.
- After the fork a version 1 transaction is refused.
- A reorg back below the fork: the 500-block maturity applies again, so a
  mempool spend of a pre-fork coinbase leaves the mempool; the longer branch
  wins on the other node; -reindex keeps the result.
- A fresh node syncs across the fork; wallet transactions are version 2.

(A version 1 transaction one block before the fork is in
feature_hardfork_v1_mempool.py.)
"""

from test_framework.blocktools import (
    assert_block_accepted,
    block_hash_rpc,
    create_block_yac,
    epoch_reward,
    solve_block,
)
from test_framework.messages import COIN, CBlockHeader, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.scrypt_jane import block_nfactor
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    NFACTOR_AT_HARDFORK,
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    node_peers,
    wait_until,
)
from test_framework.yac_tx import key_from_wif, p2pkh_script, sign_p2pkh_input, to_v1

FORK = 30
# Inside the mainnet N-factor table's second step (N-factor 5, block.h), so
# the switch to -nFactorAtHardfork (4) at the fork is visible.
START_TIME = 1368516000
PREMATURE = "16: bad-txns-premature-spend-of-coinbase/coinstake"


class HardforkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.supports_cli = False
        self.block_fork_1_0 = FORK

    def setup_network(self):
        # Node 2 starts unconnected with an empty chain.
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def money_supply(self, node, height):
        return int(node.getblock(node.getblockhash(height))['money supply'] * COIN)

    def coinbase_spend(self, height, fee=COIN // 100):
        """A signed version 2 spend of the coinbase of block height (paid to PRIV_KEYS[0])."""
        node = self.nodes[0]
        coinbase = node.getblock(node.getblockhash(height), 2)['tx'][0]
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(coinbase['txid'], 16), 0))]
        tx.vout = [CTxOut(int(coinbase['vout'][0]['value'] * COIN) - fee, p2pkh_script(self.pubkey))]
        sign_p2pkh_input(tx, 0, self.key)
        return tx

    def check_blockvalue(self, node, reward):
        """getmininginfo's blockvalue at tip 29 should be the fork block's reward,
        like getsubsidy; today it is the tip's (the old subsidy)."""
        self.known_failure("C-S11 (VUi4Bd6T)",
                           lambda: assert_equal(node.getmininginfo()['blockvalue'], reward),
                           "not(56120000 == %d)" % reward)

    def mine(self, node, n, sync=None):
        """Mine with mocktime and sync nodes 0 and 1 (node 2 is unconnected until the end)."""
        return self.mine_with_mocktime(node, n, sync=self.nodes[:2] if sync is None else sync)

    def run_test(self):
        n0, n1, n2 = self.nodes
        self.key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        self.pubkey = self.key.get_pubkey().get_bytes()
        self.set_mocktime(START_TIME)

        self.log.info("Before the fork: version 6 blocks with version 1 coinbases")
        self.mine(n0, FORK - 2)
        assert_equal(n0.getblock(n0.getblockhash(FORK - 2))['version'], 6)
        for height in (14, 15):
            assert_equal(n0.getblock(n0.getblockhash(height), 2)['tx'][0]['version'], 1)
        assert_equal(n0.getbalance(), 0)

        self.log.info("Before the fork coinbases need 500 blocks to mature")
        coinbase1 = n0.getblock(n0.getblockhash(1))['tx'][0]
        wallet_tx = n0.gettransaction(coinbase1)
        assert_equal(wallet_tx['confirmations'], FORK - 2)
        assert_equal(wallet_tx['details'][0]['category'], 'immature')
        spend1 = self.coinbase_spend(1)
        assert_raises_rpc_error(-26, PREMATURE, n0.sendrawtransaction, spend1.serialize().hex())
        self.mine(n0, 1)
        # The fork block is still checked with the old rule.
        assert_raises_rpc_error(-26, PREMATURE, n0.sendrawtransaction, spend1.serialize().hex())
        supply29 = self.money_supply(n0, FORK - 1)
        reward = epoch_reward(n0, FORK, FORK)
        # The next block is the fork block, with the new reward.
        assert_equal(n0.getsubsidy(), reward)
        self.check_blockvalue(n0, reward)
        hash29 = n0.getbestblockhash()
        time29 = n0.getblockheader(hash29)['time']
        assert_equal(n0.getmininginfo()['Nfactor'], block_nfactor(6, time29))
        assert_equal(n0.getmininginfo()['Nfactor'], 5)
        self.log.info("The node's hash of a pre-fork (80-byte) header is the block's hash")
        fields = n0.getblockheader(n0.getblockhash(28))
        header = CBlockHeader()
        header.nVersion = fields['version']
        header.hashPrevBlock = int(fields['previousblockhash'], 16)
        header.hashMerkleRoot = int(fields['merkleroot'], 16)
        header.nTime = fields['time']
        header.nBits = int(fields['bits'], 16)
        header.nNonce = fields['nonce']
        assert_equal(len(header.serialize()), 80)
        assert_equal(block_hash_rpc(n0, header), fields['hash'])

        self.log.info("The fork block: version 7, nBits at the limit, version 2 coinbase, new reward")
        self.mine(n0, 1)
        assert_equal(n0.getblockcount(), FORK)
        assert_equal(n1.getblockcount(), FORK)
        hash30 = n0.getbestblockhash()
        block30 = n0.getblock(hash30, 2)
        assert_equal(block30['version'], 7)
        assert_equal(block30['bits'], '201fffff')
        assert_equal(n0.getblockheader(hash29)['bits'], '2000ffff')
        assert_equal(block30['tx'][0]['version'], 2)
        assert_equal(int(block30['mint'] * COIN), reward)
        assert_equal(n0.getmininginfo()['blockvalue'], reward)
        assert_equal(n0.getmininginfo()['Nfactor'], NFACTOR_AT_HARDFORK)

        self.log.info("From the fork on coinbases mature after 6 blocks")
        assert_equal(n0.sendrawtransaction(spend1.serialize().hex()), spend1.hash)
        self.sync_mempools(self.nodes[:2])

        self.log.info("After the fork a version 1 transaction is refused")
        v1 = to_v1(self.coinbase_spend(2))
        sign_p2pkh_input(v1, 0, self.key)
        self.known_failure("C-S2 (MbqE60TC item 2)",
                           lambda: assert_raises_rpc_error(-26, "16: bad-txns-version", n0.sendrawtransaction, v1.serialize().hex()),
                           "Unexpected JSONRPC error code -25")
        assert v1.hash not in n0.getrawmempool()

        branch_a = self.mine(n0, 3)
        assert spend1.hash in n0.getblock(branch_a[0])['tx']
        assert_equal(n0.getblock(branch_a[0], 2)['tx'][0]['version'], 2)
        for k, block_hash in enumerate([hash30] + branch_a, start=1):
            assert_equal(n0.getblockheader(block_hash)['time'], time29 + 60 * k)
        hash33 = branch_a[-1]

        self.log.info("A reorg back below the fork: a mempool spend of a pre-fork coinbase becomes premature")
        disconnect_nodes(n0, 1)
        wait_until(lambda: node_peers(n0) == [] and node_peers(n1) == [])
        spend5 = self.coinbase_spend(5)
        assert_equal(n1.sendrawtransaction(spend5.serialize().hex()), spend5.hash)
        n1.invalidateblock(hash30)
        assert_equal(n1.getblockcount(), FORK - 1)
        # Both spends of pre-fork coinbases (spend5, and spend1 from the
        # disconnected block 31) are out of the mempool, though their inputs
        # are still unspent.
        assert_equal(n1.getrawmempool(), [])
        assert n1.gettxout('%064x' % spend5.vin[0].prevout.hash, 0) is not None
        assert_raises_rpc_error(-26, PREMATURE, n1.sendrawtransaction, spend5.serialize().hex())
        # The next block is the fork block again.
        assert_equal(n1.getsubsidy(), reward)
        self.check_blockvalue(n1, reward)
        assert {'height': 33, 'hash': hash33, 'branchlen': 4, 'status': 'invalid'} in n1.getchaintips()

        self.log.info("Node 1 builds a longer branch from block 29; node 0 reorgs to it")
        self.set_mocktime(time29 + 300)
        nbits = int(n0.getblockheader(hash30)['bits'], 16)
        branch_b = []
        for k in range(1, 6):
            if branch_b:
                block = create_block_yac(n1, prev=branch_b[-1], height=FORK - 1 + k, ntime=time29 + 60 * k,
                                         coinbase_value=reward)
            else:
                block = create_block_yac(n1, prev=hash29, nbits=nbits, ntime=time29 + 60, coinbase_value=reward)
            solve_block(n1, block)
            assert_block_accepted(n1, block)
            branch_b.append(block)
        for block in branch_b[:-1]:
            assert_equal(n0.submitblock(block.serialize().hex()), "inconclusive")
        assert_block_accepted(n0, branch_b[-1])
        # spend1 is back from the disconnected block 31, valid again under the
        # 6-block rule.
        assert_equal(n0.getrawmempool(), [spend1.hash])
        assert {'height': 33, 'hash': hash33, 'branchlen': 4, 'status': 'valid-fork'} in n0.getchaintips()
        expected_supply = supply29 + 5 * reward
        for node in (n0, n1):
            assert_equal(int(node.getinfo()['moneysupply'] * COIN), expected_supply)
        self.mine(n0, 1, sync=False)
        assert_equal(n0.getrawmempool(), [])

        self.log.info("-reindex on node 1 keeps the chain; it no longer marks the old branch invalid")
        tip_b = branch_b[-1].hash
        self.restart_node(1, extra_args=["-reindex"])
        wait_until(lambda: n1.getbestblockhash() == tip_b, timeout=60)
        assert_equal(int(n1.getinfo()['moneysupply'] * COIN), expected_supply)
        assert {'height': 33, 'hash': hash33, 'branchlen': 4, 'status': 'valid-fork'} in n1.getchaintips()

        self.log.info("A fresh node syncs across the fork")
        connect_nodes(n2, 0)
        connect_nodes(n1, 0)
        self.sync_blocks()
        for height in (FORK - 1, FORK, FORK + 1):
            block_hash = n0.getblockhash(height)
            assert_equal(n2.getblockheader(block_hash), n0.getblockheader(block_hash))

        self.log.info("Wallet transactions are version 2; coinbases mature after 6 blocks")
        address_1 = n1.getaccountaddress('')
        txid = n0.sendtoaddress(address_1, 2.0)
        assert_equal(n0.gettransaction(txid)['version'], 2)
        self.mine(n0, 1, sync=True)
        assert_equal(n1.getbalance(), 2)
        first = self.mine(n1, 5, sync=True)[0]
        assert_equal(n1.getbalance(), 2)
        self.mine(n1, 1, sync=True)
        first_reward = n1.getblock(first, 2)['tx'][0]['vout'][0]['value']
        assert_equal(n1.getbalance(), 2 + first_reward)


if __name__ == '__main__':
    HardforkTest().main()
