#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test token holdings in the wallet.

- Restoring an older wallet backup, -rescan, and dumpwallet/importwallet into
  an empty wallet all give the current token holdings, including transfers
  received and sent after the backup.
- issue, transfer, reissue and transferfromaddress need an unlocked wallet;
  listmytokens doesn't.
- Token transfers without YAC for the fee, with too few tokens, of a token the
  wallet doesn't hold, and of an owner token with an amount other than 1.
- Abandoning an unbroadcast token transfer returns the tokens.

Only token holdings are compared, no YAC balances.
"""

import os
import shutil

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    wait_until,
)


def holdings(verbose):
    """listmytokens(..., True) without the account labels, outpoints sorted."""
    return {name: {"balance": data["balance"], "token_type": data["token_type"],
                   "outpoints": sorted((o["txid"], o["vout"], o["address"], o["amount"])
                                       for o in data["outpoints"])}
            for name, data in verbose.items()}


class WalletTokensTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        # Fork at 1, like the other token scripts.
        self.block_fork_1_0 = 1
        self.extra_args = [["-tokenindex=1", "-tokenSupportBlockNumber=10"]] * 3

    def reconnect(self):
        connect_nodes(self.nodes[1], 0)
        connect_nodes(self.nodes[2], 1)
        self.sync_all()

    def run_test(self):
        n0, n1, n2 = self.nodes
        self.set_mocktime(TIME_GENESIS_BLOCK)
        a0 = n0.getnewaddress()

        self.log.info("Node 0 issues tokens and transfers some to node 1")
        self.mine_with_mocktime(n0, 30)
        n0.issue(token_name="WTK", qty=1000, units=2, reissuable=True)
        n0.issue(token_name="WTK2", qty=10, units=0, reissuable=True)
        self.mine_with_mocktime(n0, 1)
        n0.issue(token_name="WTK/SUB", qty=5)
        n0.issue(token_name="WTK#U1")
        self.mine_with_mocktime(n0, 1)
        n0.transfer("WTK", 100, n1.getnewaddress())
        n0.transfer("WTK#U1", 1, n1.getnewaddress())
        n0.transfer("WTK/SUB", 2, n1.getnewaddress())
        self.mine_with_mocktime(n0, 1)
        assert_equal(n1.listmytokens(), {"WTK": "100.00", "WTK#U1": "1", "WTK/SUB": "2"})

        self.log.info("A token transfer needs YAC for the fee")
        assert_raises_rpc_error(-6, "This wallet doesn't contain any YAC, transfering an token requires a network fee",
                                n1.transfer, "WTK", 1, a0)
        n0.sendtoaddress(n1.getnewaddress(), 20)
        self.mine_with_mocktime(n0, 1)

        self.log.info("Restore an older wallet backup")
        backup = os.path.join(n1.datadir, "wallet.bak")
        n1.backupwallet(backup)
        n0.transfer("WTK", 5, n1.getnewaddress())
        n0.transfer("WTK2", 3, n1.getnewaddress())
        spend = n1.transfer("WTK", 30, a0)
        # Node 0 mines; it must have node 1's transfer first.
        wait_until(lambda: spend in n0.getrawmempool())
        self.mine_with_mocktime(n0, 1)
        current = holdings(n1.listmytokens("*", True))
        expected = {"WTK": "75.00", "WTK#U1": "1", "WTK/SUB": "2", "WTK2": "3"}
        assert_equal(n1.listmytokens(), expected)
        self.stop_node(1)
        shutil.copyfile(backup, os.path.join(n1.datadir, "wallet.dat"))
        # The wallet rescans from the backup's best block at startup, without
        # -rescan. Addresses created after the backup lose their labels.
        self.start_node(1)
        self.reconnect()
        assert_equal(holdings(n1.listmytokens("*", True)), current)

        self.log.info("Restart with -rescan")
        self.restart_node(1, self.extra_args[1] + ["-rescan"])
        self.reconnect()
        assert_equal(holdings(n1.listmytokens("*", True)), current)

        self.log.info("Import node 1's wallet dump into node 2")
        assert_equal(n2.listmytokens(), {})
        dump = os.path.join(self.options.tmpdir, "node1.dump")
        n1.dumpwallet(dump)
        n2.importwallet(dump)
        assert_equal(n2.listmytokens(), expected)
        assert_equal(holdings(n2.listmytokens("*", True)), current)

        self.log.info("Token RPCs with a locked wallet")
        n1.encryptwallet("pass")
        n1.wait_until_stopped()
        self.start_node(1)
        self.reconnect()
        wtk_address = n1.listmytokens("WTK", True)["WTK"]["outpoints"][0]["address"]
        unlock = "Error: Please enter the wallet passphrase with walletpassphrase first."
        assert_raises_rpc_error(-13, unlock, n1.issue, "LOCKD")
        assert_raises_rpc_error(-13, unlock, n1.transfer, "WTK", 1, a0)
        assert_raises_rpc_error(-13, unlock, n1.reissue, "WTK", 1)
        assert_raises_rpc_error(-13, unlock, n1.transferfromaddress, "WTK", wtk_address, 1, a0)
        assert_equal(n1.listmytokens(), expected)
        n1.walletpassphrase("pass", 100000)
        n1.transfer("WTK", 1, a0)
        # Node 0 mines; it must have the transactions first.
        self.sync_mempools([n0, n1])
        self.mine_with_mocktime(n0, 1)
        assert_equal(n1.listmytokens()["WTK"], "74.00")

        self.log.info("Token transfer errors")
        assert_raises_rpc_error(-25, "Insufficient token funds", n1.transfer, "WTK", 1000, a0)
        assert_raises_rpc_error(-32600, "Wallet doesn't have token: NOTMINE", n1.transfer, "NOTMINE", 1, a0)
        assert_raises_rpc_error(-32602, "When transferring an 'Ownership Token' the amount must always be 1. Please try again with the amount of 1",
                                n0.transfer, "WTK!", 2, n1.getnewaddress())

        self.log.info("Abandon an unbroadcast token transfer")
        disconnect_nodes(n1, 0)
        disconnect_nodes(n1, 2)
        before = n1.listmytokens()
        txid = n1.transfer("WTK", 2, a0)
        assert_equal(n1.listmytokens()["WTK"], "72.00")
        # Drop the saved mempool and turn wallet broadcast off, so the
        # transfer is neither reloaded nor resubmitted at startup.
        self.stop_node(1)
        os.remove(os.path.join(n1.datadir, "mempool.dat"))
        self.start_node(1, self.extra_args[1] + ["-walletbroadcast=0"])
        assert txid not in n1.getrawmempool()
        # abandontransaction doesn't need the passphrase.
        n1.abandontransaction(txid)
        assert_equal(n1.listmytokens(), before)

        self.restart_node(1)
        self.reconnect()
        n1.walletpassphrase("pass", 100000)
        txid2 = n1.transfer("WTK", 2, a0)
        # Node 0 mines; it must have the transactions first.
        self.sync_mempools([n0, n1])
        self.mine_with_mocktime(n0, 1)
        assert_equal(n1.gettransaction(txid2)["confirmations"], 1)
        # The new transfer spent the inputs the abandoned one had used.
        assert_equal(n1.gettransaction(txid)["confirmations"], -1)
        assert_equal(n1.listmytokens()["WTK"], "72.00")


if __name__ == "__main__":
    WalletTokensTest().main()
