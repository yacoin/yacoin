#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the wallet backup features.

4 nodes. Nodes 0, 1 and 2 send coins to each other (a seeded random
schedule), node 3 is the miner.

The clock starts a day in the past (mocktime, set before the nodes start, so
the wallet keys are older than the first coins). Nodes 0-2 mine 2 blocks
each and node 3 mines 10; node 3 pays 1 YAC to a fresh address of node 0;
one round of sends. Then the clock jumps to now. So part of every wallet's
funds is more than 2 hours older than the tip.

Wallets are backed up with backupwallet and dumpwallet, then one more round
of sends, and node 3 mines 10 more blocks.

Sanity check: the balances plus the immature balances of all 4 nodes equal
the sum of all coinbase values minus the fees paid (YACoin burns fees).

Restore 1: nodes 0-2 are stopped, their wallets erased, node 2 also loses its
chain; the wallet.dat backups are copied back. All balances are as before.

Restore 2: the same, but the wallets are restored with importwallet from the
dumps. Known failure W-B2: importwallet rescans only the last 2 hours, so the
old funds are missing. After a restart with -rescan all balances are as
before.

Also: backupwallet into a directory, onto a missing path, and onto the
wallet file itself.
"""
from decimal import Decimal
import filecmp
import os
import random
import shutil
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.wallet_util import coinbase_value, wipe_chain


class WalletBackupTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        # nodes 0, 1 and 2 are the spenders; give them keypool=100
        self.extra_args = [["-keypool=100"], ["-keypool=100"], ["-keypool=100"], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        # Start a day in the past, before the nodes create their keys, so the
        # keys are older than the coins they receive, as in real use.
        self.set_mocktime(int(time.time()) - 86400)
        self.start_nodes()
        self.import_deterministic_coinbase_privkeys()
        connect_nodes(self.nodes[0], 3)
        connect_nodes(self.nodes[1], 3)
        connect_nodes(self.nodes[2], 3)
        connect_nodes(self.nodes[2], 0)
        self.sync_all()

    def mine(self, node_index, n):
        self.mined[node_index] += self.nodes[node_index].generate(n)
        self.sync_blocks()

    def mature_coinbase_value(self, node_index):
        node = self.nodes[3]
        tip = node.getblockcount()
        return sum(coinbase_value(node, h) for h in self.mined[node_index]
                   if tip - node.getblock(h)['height'] + 1 >= 6)

    def one_send(self, from_node, to_address):
        if (self.rng.randint(1,2) == 1):
            amount = Decimal(self.rng.randint(1,10)) / Decimal(10)
            txid = self.nodes[from_node].sendtoaddress(to_address, amount)
            self.sends.append((from_node, txid))

    def do_one_round(self):
        a0 = self.nodes[0].getnewaddress()
        a1 = self.nodes[1].getnewaddress()
        a2 = self.nodes[2].getnewaddress()

        self.one_send(0, a1)
        self.one_send(0, a2)
        self.one_send(1, a0)
        self.one_send(1, a2)
        self.one_send(2, a0)
        self.one_send(2, a1)

        # Have the miner (node3) mine a block.
        # Must sync mempools before mining.
        self.sync_mempools()
        self.mine(3, 1)

    # As above, this mirrors the original bash test.
    def start_three(self, extra_args=None):
        self.start_node(0, extra_args)
        self.start_node(1, extra_args)
        self.start_node(2, extra_args)
        connect_nodes(self.nodes[0], 3)
        connect_nodes(self.nodes[1], 3)
        connect_nodes(self.nodes[2], 3)
        connect_nodes(self.nodes[2], 0)

    def stop_three(self):
        self.stop_node(0)
        self.stop_node(1)
        self.stop_node(2)

    def erase_three(self):
        os.remove(os.path.join(self.nodes[0].datadir, 'wallet.dat'))
        os.remove(os.path.join(self.nodes[1].datadir, 'wallet.dat'))
        os.remove(os.path.join(self.nodes[2].datadir, 'wallet.dat'))

    def assert_balances(self, balances):
        for node, balance in zip(self.nodes, balances):
            assert_equal(node.getbalance(), balance)

    def run_test(self):
        self.rng = random.Random(1)
        self.mined = [[], [], [], []]
        self.sends = []

        self.log.info("Generating initial blockchain (a day ago)")
        self.mine(0, 2)
        self.mine(1, 2)
        self.mine(2, 2)
        self.mine(3, 10)
        for i in range(4):
            assert_equal(self.nodes[i].getbalance(), self.mature_coinbase_value(i))

        self.log.info("Old funds: node 3 pays 1 YAC to a fresh address of node 0")
        addr_old = self.nodes[0].getnewaddress('old')
        self.sends.append((3, self.nodes[3].sendtoaddress(addr_old, 1)))
        self.sync_mempools()
        self.mine(3, 1)

        self.log.info("Creating transactions")
        # Sending each other transactions.
        self.do_one_round()

        self.log.info("Move the clock to now")
        self.set_mocktime(int(time.time()))
        self.mine(3, 1)

        self.log.info("Backing up")

        self.nodes[0].backupwallet(os.path.join(self.nodes[0].datadir, 'wallet.bak'))
        self.nodes[0].dumpwallet(os.path.join(self.nodes[0].datadir, 'wallet.dump'))
        self.nodes[1].backupwallet(os.path.join(self.nodes[1].datadir, 'wallet.bak'))
        self.nodes[1].dumpwallet(os.path.join(self.nodes[1].datadir, 'wallet.dump'))
        self.nodes[2].backupwallet(os.path.join(self.nodes[2].datadir, 'wallet.bak'))
        self.nodes[2].dumpwallet(os.path.join(self.nodes[2].datadir, 'wallet.dump'))

        self.log.info("More transactions")
        self.do_one_round()

        # Generate 10 more blocks
        self.mine(3, 10)
        self.sync_all()

        balances = [node.getbalance() for node in self.nodes]
        assert_equal(self.nodes[0].getreceivedbyaddress(addr_old), 1)

        self.log.info("Sanity check: balances = coinbases - fees")
        total = sum(node.getbalance() + node.getwalletinfo()['immature_balance'] for node in self.nodes)
        tip = self.nodes[3].getblockcount()
        minted = sum(coinbase_value(self.nodes[3], self.nodes[3].getblockhash(h)) for h in range(1, tip + 1))
        fees = sum(-self.nodes[sender].gettransaction(txid)['fee'] for sender, txid in self.sends)
        assert_equal(total, minted - fees)

        ##
        # Test restoring spender wallets from backups
        ##
        self.log.info("Restoring using wallet.dat")
        self.stop_three()
        self.erase_three()

        # Start node2 with no chain
        wipe_chain(self.nodes[2])

        # Restore wallets from backup
        shutil.copyfile(os.path.join(self.nodes[0].datadir, 'wallet.bak'), os.path.join(self.nodes[0].datadir, 'wallet.dat'))
        shutil.copyfile(os.path.join(self.nodes[1].datadir, 'wallet.bak'), os.path.join(self.nodes[1].datadir, 'wallet.dat'))
        shutil.copyfile(os.path.join(self.nodes[2].datadir, 'wallet.bak'), os.path.join(self.nodes[2].datadir, 'wallet.dat'))

        self.log.info("Re-starting nodes")
        self.start_three()
        self.sync_blocks()

        self.assert_balances(balances)

        self.log.info("Restoring using dumped wallet")
        self.stop_three()
        self.erase_three()

        #start node2 with no chain
        wipe_chain(self.nodes[2])

        self.start_three()
        # Let node 2 have the whole chain before it imports, so all three
        # nodes import with the same chain.
        self.sync_blocks()

        assert_equal(self.nodes[0].getbalance(), 0)
        assert_equal(self.nodes[1].getbalance(), 0)
        assert_equal(self.nodes[2].getbalance(), 0)

        self.nodes[0].importwallet(os.path.join(self.nodes[0].datadir, 'wallet.dump'))
        self.nodes[1].importwallet(os.path.join(self.nodes[1].datadir, 'wallet.dump'))
        self.nodes[2].importwallet(os.path.join(self.nodes[2].datadir, 'wallet.dump'))

        self.sync_blocks()

        def check_import_finds_old_funds():
            assert_equal(self.nodes[0].getreceivedbyaddress(addr_old), 1)
            self.assert_balances(balances)
        # importwallet never applies the key birth times from the dump (its
        # parser waits for '@' section headers; dumpwallet writes '#'), so it
        # rescans only from the tip time minus 2 hours.
        self.known_failure("W-B2 (FrgyyrOz)", check_import_finds_old_funds, expected="not(0.000000 == 1)")

        self.log.info("Restart the restored nodes with -rescan")
        self.stop_three()
        self.start_three(['-rescan'])
        self.sync_blocks()
        assert_equal(self.nodes[0].getreceivedbyaddress(addr_old), 1)
        self.assert_balances(balances)

        self.log.info("Backup into a directory and onto a missing path")
        backup_dir = os.path.join(self.nodes[0].datadir, 'backupdir')
        os.mkdir(backup_dir)
        self.nodes[0].backupwallet(backup_dir)
        backup_file = os.path.join(self.nodes[0].datadir, 'plain.bak')
        self.nodes[0].backupwallet(backup_file)
        assert filecmp.cmp(os.path.join(backup_dir, 'wallet.dat'), backup_file, shallow=False)
        assert_raises_rpc_error(-4, "Error: Wallet backup failed!", self.nodes[0].backupwallet,
                                os.path.join(self.options.tmpdir, 'nonexistent', 'wallet.bak'))

        # Backup to source wallet file must fail
        sourcePaths = [
            os.path.join(self.nodes[0].datadir, 'wallet.dat'),
            os.path.join(self.nodes[0].datadir, '.', 'wallet.dat'),
            os.path.join(self.nodes[0].datadir, ''),
            os.path.join(self.nodes[0].datadir)]

        for sourcePath in sourcePaths:
            assert_raises_rpc_error(-4, "backup failed", self.nodes[0].backupwallet, sourcePath)


if __name__ == '__main__':
    WalletBackupTest().main()
