#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the node's enforcement of CLTV, CSV and BIP68 for YAC P2SH outputs.

Spends of the wallet's CLTV and CSV P2SH scripts (createcltvaddress,
createcsvaddress), built and signed in Python, against the mempool:
- CLTV by height and by time: the script check (non-mandatory flag) and
  the nLockTime finality check, at their exact boundaries;
- CSV by height and by time: the script check and the BIP68 sequence lock,
  at their exact boundaries. YACoin's type flag is 1 << 30 and time locks
  count seconds (no 512 s granularity);
- after a reorg, a spend whose relative lock no longer holds leaves the
  mempool and one with a margin stays; when the funding block is
  disconnected, the funding tx returns to the mempool and the spend, whose
  lock now counts from the next block, leaves.

The opcodes are not enforced in blocks on the suite's chain parameters
(BIP65/BIP68 heights); BIP68 sequence locks in blocks are in
feature_block.py.
"""

from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.yac_tx import (
    cltv_p2sh_redeem_script,
    csv_p2sh_redeem_script,
    key_from_wif,
    p2pkh_script,
    p2sh_script,
    sign_p2pkh_input,
    sign_p2sh_input,
)

# primitives/transaction.h (YACoin's values)
SEQUENCE_FINAL = 0xffffffff
SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 30

AMOUNT = COIN // 5
FEE = COIN // 100
LOCKTIME_FAILED = "64: non-mandatory-script-verify-flag (Locktime requirement not satisfied)"
NON_FINAL = "64: non-final"
NON_BIP68_FINAL = "64: non-BIP68-final"


class CltvCsvEnforcementTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.block_fork_1_0 = 1

    def fund(self, coinbase_height, redeem_scripts):
        """Pay AMOUNT to each redeem script's P2SH address from the coinbase
        of block coinbase_height, and mine it. Returns the funding tx."""
        node = self.node
        coinbase = node.getblock(node.getblockhash(coinbase_height), 2)['tx'][0]
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(coinbase['txid'], 16), 0))]
        tx.vout = [CTxOut(AMOUNT, p2sh_script(script)) for script in redeem_scripts]
        tx.vout.append(CTxOut(int(coinbase['vout'][0]['value'] * COIN) - len(redeem_scripts) * AMOUNT - FEE,
                              p2pkh_script(self.pubkey)))
        sign_p2pkh_input(tx, 0, self.key)
        assert_equal(node.sendrawtransaction(tx.serialize().hex()), tx.hash)
        self.mine_with_mocktime(node, 1)
        assert tx.hash in node.getblock(node.getbestblockhash())['tx']
        return tx

    def spend(self, fund_tx, n, redeem_script, *, locktime=0, sequence=0xfffffffe):
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.nLockTime = locktime
        tx.vin = [CTxIn(COutPoint(fund_tx.sha256, n), b"", sequence)]
        tx.vout = [CTxOut(AMOUNT - FEE, p2pkh_script(self.pubkey))]
        sign_p2sh_input(tx, 0, redeem_script, [self.key])
        return tx

    def assert_rejected(self, tx, message):
        assert_raises_rpc_error(-26, message, self.node.sendrawtransaction, tx.serialize().hex())

    def assert_accepted(self, tx):
        assert_equal(self.node.sendrawtransaction(tx.serialize().hex()), tx.hash)

    def mine_to(self, height):
        while self.node.getblockcount() < height:
            self.mine_with_mocktime(self.node, 1)

    def run_test(self):
        self.node = node = self.nodes[0]
        self.key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        self.pubkey = self.key.get_pubkey().get_bytes()
        self.set_mocktime(1600000000)
        self.mine_with_mocktime(node, 20)

        lock_height = node.getblockcount() + 5
        lock_time = self.mocktime + 1000
        cltv_height = cltv_p2sh_redeem_script(lock_height, self.pubkey)
        cltv_time = cltv_p2sh_redeem_script(lock_time, self.pubkey)
        csv_height = csv_p2sh_redeem_script(10, self.pubkey)
        fund = self.fund(1, [cltv_height, cltv_height, cltv_time, cltv_time, csv_height, csv_height])
        fund_height = node.getblockcount()

        self.log.info("CLTV by height: the script needs nLockTime >= the lock and a non-final input")
        self.assert_rejected(self.spend(fund, 0, cltv_height, locktime=0), LOCKTIME_FAILED)
        self.assert_rejected(self.spend(fund, 0, cltv_height, locktime=lock_height, sequence=SEQUENCE_FINAL), LOCKTIME_FAILED)
        self.log.info("CLTV by height: non-final until the tip reaches the lock height")
        self.assert_rejected(self.spend(fund, 0, cltv_height, locktime=lock_height), NON_FINAL)
        self.mine_to(lock_height - 1)
        self.assert_rejected(self.spend(fund, 0, cltv_height, locktime=lock_height), NON_FINAL)
        self.mine_to(lock_height)
        self.assert_rejected(self.spend(fund, 1, cltv_height, locktime=lock_height - 1), LOCKTIME_FAILED)
        self.assert_accepted(self.spend(fund, 0, cltv_height, locktime=lock_height))

        self.log.info("CLTV by time: non-final until the node's time passes the lock")
        assert self.mocktime < lock_time
        self.assert_rejected(self.spend(fund, 2, cltv_time, locktime=lock_time), NON_FINAL)
        self.set_mocktime(lock_time)
        self.assert_rejected(self.spend(fund, 2, cltv_time, locktime=lock_time), NON_FINAL)
        self.set_mocktime(lock_time + 1)
        self.assert_accepted(self.spend(fund, 2, cltv_time, locktime=lock_time))
        self.log.info("CLTV by time: a height nLockTime doesn't satisfy a time lock")
        self.assert_rejected(self.spend(fund, 3, cltv_time, locktime=node.getblockcount()), LOCKTIME_FAILED)

        self.log.info("CSV by height: the BIP68 lock holds until the input is 10 blocks deep")
        self.mine_to(fund_height + 8)  # depth 9
        self.assert_rejected(self.spend(fund, 4, csv_height, sequence=10), NON_BIP68_FINAL)
        self.mine_with_mocktime(node, 1)  # depth 10
        self.log.info("CSV by height: the script needs nSequence >= the lock, a height lock, not disabled")
        for sequence in (9, SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG | 10):
            self.assert_rejected(self.spend(fund, 5, csv_height, sequence=sequence), LOCKTIME_FAILED)
        self.assert_accepted(self.spend(fund, 4, csv_height, sequence=10))

        self.log.info("createcsvaddress uses the same script and type flag")
        created = node.createcsvaddress(1024, False)
        redeem = bytes.fromhex(created['redeemScript'])
        wallet_pubkey = list(CScript(redeem))[3]
        assert_equal(redeem, csv_p2sh_redeem_script(SEQUENCE_LOCKTIME_TYPE_FLAG | 1024, wallet_pubkey))

        self.log.info("CSV by time: locked until the tip's time is 1024 s past the block before the input's")
        self.mine_with_mocktime(node, 1)
        csv_time = csv_p2sh_redeem_script(SEQUENCE_LOCKTIME_TYPE_FLAG | 1024, self.pubkey)
        fund_t = self.fund(3, [csv_time] * 3)
        start = node.getblockheader(node.getblockhash(node.getblockcount() - 1))['time']
        time_lock = SEQUENCE_LOCKTIME_TYPE_FLAG | 1024
        self.assert_rejected(self.spend(fund_t, 0, csv_time, sequence=time_lock), NON_BIP68_FINAL)
        self.set_mocktime(start + 1023)
        node.generate(1)
        assert_equal(node.getblockheader(node.getbestblockhash())['time'], start + 1023)
        self.assert_rejected(self.spend(fund_t, 0, csv_time, sequence=time_lock), NON_BIP68_FINAL)
        self.set_mocktime(start + 1024)
        node.generate(1)
        self.assert_accepted(self.spend(fund_t, 0, csv_time, sequence=time_lock))
        self.log.info("CSV by time: a shorter lock fails the script, a height lock or a longer one isn't final")
        self.assert_rejected(self.spend(fund_t, 1, csv_time, sequence=SEQUENCE_LOCKTIME_TYPE_FLAG | 1023), LOCKTIME_FAILED)
        self.assert_rejected(self.spend(fund_t, 1, csv_time, sequence=1024), NON_BIP68_FINAL)
        self.assert_rejected(self.spend(fund_t, 1, csv_time, sequence=SEQUENCE_LOCKTIME_TYPE_FLAG | 1025), NON_BIP68_FINAL)

        self.log.info("Reorg: a spend at its exact lock leaves the mempool, one with a margin stays")
        self.mine_with_mocktime(node, 1)
        assert_equal(node.getrawmempool(), [])
        fund_r = self.fund(4, [csv_height] * 3)
        fund_block = node.getbestblockhash()
        fund_r_height = node.getblockcount()
        self.mine_to(fund_r_height + 9)  # depth 10
        exact = self.spend(fund_r, 0, csv_height, sequence=10)
        self.assert_accepted(exact)
        node.invalidateblock(node.getbestblockhash())
        assert_equal(node.getrawmempool(), [])
        self.mine_to(fund_r_height + 11)  # depth 12
        margin = self.spend(fund_r, 1, csv_height, sequence=10)
        self.assert_accepted(margin)
        node.invalidateblock(node.getbestblockhash())
        assert_equal(node.getrawmempool(), [margin.hash])
        self.log.info("Reorg: invalidating the funding block brings the funding tx back and drops the spend")
        node.invalidateblock(fund_block)
        assert_equal(node.getrawmempool(), [fund_r.hash])


if __name__ == '__main__':
    CltvCsvEnforcementTest().main()
