#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the life cycle of CLTV/CSV timelock addresses in the wallet.

- createcltvaddress / createcsvaddress (block-height locks) return the
  documented warning texts.
- The redeem scripts survive a restart: the wallet still recognises the
  addresses, their accounts and the coins received on them.
- A height lock can't be spent one block before it expires, and can be spent
  from the first block on which it has expired: a CLTV lock L when the tip is
  at least L, a CSV lock of n blocks funded at height F when the tip is at
  least F + n - 1. The spends set nLockTime / nSequence accordingly.
- A wallet restored from a backupwallet copy into an empty datadir still
  knows its timelock addresses and can spend from them after expiry.
"""
import os
import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.wallet_util import wipe_chain

NOT_SPENDABLE_YET = "Error: Transaction creation failed: Insufficient funds"


class WalletTimelockRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def mine_to(self, height):
        """Mine on node 0 until the tip is at height, and sync."""
        node0 = self.nodes[0]
        node0.generate(height - node0.getblockcount())
        self.sync_blocks()

    def funding_outpoint(self, txid, address):
        tx = self.nodes[0].getrawtransaction(txid, 1)
        vout = [o['n'] for o in tx['vout'] if o['scriptPubKey'].get('addresses') == [address]]
        assert_equal(len(vout), 1)
        return txid, vout[0]

    def decode(self, node, txid):
        return node.decoderawtransaction(node.gettransaction(txid)['hex'])

    def run_test(self):
        node0, node1 = self.nodes
        node0.generate(10)
        self.sync_blocks()
        h = node0.getblockcount()

        self.log.info("Create CLTV and CSV addresses with block-height locks")
        cl = node1.createcltvaddress(h + 5, 'c')
        assert_equal(cl['Warning'], "Any coins sent to this cltv address will be locked until block height %d" % (h + 5))
        cs = node1.createcsvaddress(3, True, 's')
        assert_equal(cs['Warning'], "Any coins sent to this csv address will be locked within 3 blocks")
        cl2 = node1.createcltvaddress(h + 8, 'c2')
        cl_addr, cs_addr, cl2_addr = cl['cltv address'], cs['csv address'], cl2['cltv address']

        fund = {}
        for addr in (cl_addr, cs_addr, cl2_addr):
            fund[addr] = self.funding_outpoint(node0.sendtoaddress(addr, 5), addr)
        self.mine_to(h + 1)
        funding_height = h + 1

        self.log.info("Restart node 1: the redeem scripts are loaded from the wallet file")
        self.restart_node(1)
        node1 = self.nodes[1]
        connect_nodes(node1, 0)
        expected = [
            (cl_addr, 'CLTV_P2SH_timelock', cl['redeemScript'], 'c'),
            (cs_addr, 'CSV_P2SH_timelock', cs['redeemScript'], 's'),
            (cl2_addr, 'CLTV_P2SH_timelock', cl2['redeemScript'], 'c2'),
        ]
        for addr, script_type, redeem_script, account in expected:
            info = node1.validateaddress(addr)
            assert_equal((info['ismine'], info['script'], info['hex'], info['account']),
                         (True, script_type, redeem_script, account))
            assert_equal(node1.getreceivedbyaddress(addr), 5)
        described = node1.describeredeemscript(cl['redeemScript'])
        assert_equal((described['LockType'], described['CltvAddress']), ('Block-based lock', cl_addr))

        dest = node0.getnewaddress()

        self.log.info("CSV: can't spend before the lock expires, can spend from the expiry block on")
        csv_expiry = funding_height + 3 - 1
        self.mine_to(csv_expiry - 1)
        assert_raises_rpc_error(-4, NOT_SPENDABLE_YET, node1.spendcsv, cs_addr, dest, 4)
        self.mine_to(csv_expiry)
        tx_csv = node1.spendcsv(cs_addr, dest, 4)
        vin = self.decode(node1, tx_csv)['vin']
        assert_equal(len(vin), 1)
        assert_equal((vin[0]['txid'], vin[0]['vout'], vin[0]['sequence']), fund[cs_addr] + (3,))
        self.sync_mempools()

        self.log.info("CLTV: can't spend before the lock expires, can spend from the expiry block on")
        self.mine_to(h + 4)
        assert_raises_rpc_error(-4, NOT_SPENDABLE_YET, node1.spendcltv, cl_addr, dest, 4)
        self.mine_to(h + 5)
        tx_cltv = node1.spendcltv(cl_addr, dest, 4)
        decoded = self.decode(node1, tx_cltv)
        assert_equal(decoded['locktime'], h + 5)
        assert_equal(len(decoded['vin']), 1)
        assert_equal((decoded['vin'][0]['txid'], decoded['vin'][0]['vout'], decoded['vin'][0]['sequence']),
                     fund[cl_addr] + (0,))

        self.sync_mempools()
        self.mine_to(h + 6)
        assert_equal(node0.getreceivedbyaddress(dest), 8)
        assert_equal(node1.gettransaction(tx_cltv)['confirmations'], 1)
        assert_equal(node1.gettransaction(tx_csv)['confirmations'], 3)

        self.log.info("Restore node 1's wallet from a backup into an empty datadir")
        backup = os.path.join(self.options.tmpdir, 'node1.bak')
        node1.backupwallet(backup)
        self.stop_node(1)
        wipe_chain(node1, wallet=True)
        assert not os.path.exists(os.path.join(node1.datadir, 'blocks'))
        shutil.copyfile(backup, os.path.join(node1.datadir, 'wallet.dat'))
        self.start_node(1)
        node1 = self.nodes[1]
        connect_nodes(node1, 0)
        self.sync_blocks()
        for addr, script_type, redeem_script, account in expected:
            info = node1.validateaddress(addr)
            assert_equal((info['ismine'], info['hex'], info['account']), (True, redeem_script, account))

        self.log.info("Spend from the restored wallet's CLTV address after expiry")
        self.mine_to(h + 7)
        assert_raises_rpc_error(-4, NOT_SPENDABLE_YET, node1.spendcltv, cl2_addr, dest, 4)
        self.mine_to(h + 8)
        tx_cltv2 = node1.spendcltv(cl2_addr, dest, 4)
        assert_equal(self.decode(node1, tx_cltv2)['vin'][0]['txid'], fund[cl2_addr][0])
        self.sync_mempools()
        self.mine_to(h + 9)
        assert_equal(node0.getreceivedbyaddress(dest), 12)


if __name__ == '__main__':
    WalletTimelockRPCTest().main()
