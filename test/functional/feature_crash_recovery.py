#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test recovery from a crash in the middle of a UTXO flush.

node0 runs with -dbcrashratio=1 -dbbatchsize=1, so the next flush of the
coins database exits the process right after writing its first partial batch
(which already marks the database as being between two tips). listtokens
forces such a flush. On the next start ReplayBlocks has to bring the UTXO set
to the new tip. After each recovery node0 is compared with node1 (best block,
money supply, tracked outputs, address index of tracked addresses):

- roll forward over blocks with payments;
- roll back a branch of coinbase-only blocks and roll forward the new branch;
- roll back a branch that contains a transaction (known bug xNZNUbVx: the
  node segfaults in ReplayBlocks on every start), then repair with -reindex.
"""

import http.client

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import FailedToStartError, describe_exit_code
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
)

BASE = ["-addressindex=1", "-tokenindex=1", "-tokenSupportBlockNumber=10"]
CRASH = ["-dbcrashratio=1", "-dbbatchsize=1"]


class CrashRecoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.block_fork_1_0 = 1
        self.extra_args = [BASE, BASE, []]

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def state(self, node):
        return {
            'tip': node.getbestblockhash(),
            'moneysupply': node.getinfo()['moneysupply'],
            'txouts': [node.gettxout(txid, n, False) for txid, n in self.tracked],
            'balances': [node.getaddressbalance({'addresses': [a]}) for a in self.addresses],
            'utxos': [node.getaddressutxos({'addresses': [a]}) for a in self.addresses],
        }

    def assert_same_state(self):
        assert_equal(self.state(self.nodes[0]), self.state(self.nodes[1]))

    def pay(self, address, amount):
        """node1 pays address; the output is tracked."""
        node1 = self.nodes[1]
        txid = node1.sendtoaddress(address=address, amount=amount)
        vout = [o['n'] for o in node1.decoderawtransaction(node1.gettransaction(txid)['hex'])['vout']
                if o['scriptPubKey'].get('addresses') == [address]]
        assert_equal(len(vout), 1)
        self.tracked.append((txid, vout[0]))

    def crash_at_flush(self):
        """node0 runs with CRASH: force a flush and expect the simulated crash."""
        node0 = self.nodes[0]
        with node0.assert_debug_log(["Simulating a crash. Goodbye."]):
            try:
                node0.listtokens()
            except (OSError, http.client.HTTPException):
                pass
            else:
                raise AssertionError("listtokens returned; node0 should have crashed")
            assert_equal(node0.wait_for_exit(30), 0)

    def start_ok(self, i, args):
        """Start node i; a failed start becomes an AssertionError with the exit code."""
        try:
            self.start_node(i, args, no_core_dump=True)
        except FailedToStartError:
            rc = self.nodes[i].wait_for_exit()
            raise AssertionError("node%d failed to start, exit code %s: %s" % (
                i, describe_exit_code(rc), self.nodes[i].read_stderr()))

    def blocks(self, node, first, last):
        return [node.getblockhash(h) for h in range(first, last + 1)]

    def submit_branch(self, first, last):
        """Submit node1's blocks first..last to the unconnected node0."""
        node0, node1 = self.nodes[0], self.nodes[1]
        for h in range(first, last + 1):
            node0.submitblock(node1.getblock(node1.getblockhash(h), False))
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())

    def run_test(self):
        node0, node1, node2 = self.nodes
        # node2 only provides receive-only addresses.
        self.addresses = [node2.getnewaddress() for _ in range(3)]
        self.stop_node(2)
        self.tracked = []

        self.mine_with_mocktime(node0, 8)
        self.mine_with_mocktime(node1, 12)
        for a in self.addresses:
            self.pay(a, 1)
        self.mine_with_mocktime(node1, 1)
        node0.listtokens()  # flush without a crash
        self.assert_same_state()

        self.log.info("Crash during a flush, then roll forward over 3 blocks")
        self.restart_node(0, BASE + CRASH)
        connect_nodes(node0, 1)
        start = node1.getblockcount() + 1
        for i in range(3):
            self.pay(self.addresses[i], 2 + i)
            self.mine_with_mocktime(node1, 1)
        self.crash_at_flush()
        new_blocks = self.blocks(node1, start, start + 2)
        with node0.assert_debug_log(["Replaying blocks"] +
                                    ["Rolling forward %s (%d)" % (h, start + i) for i, h in enumerate(new_blocks)]):
            self.start_node(0, BASE)
        connect_nodes(node0, 1)
        self.assert_same_state()
        assert_equal(node0.verifychain(4, 0), True)

        self.log.info("Crash during a reorg flush, roll back 2 coinbase-only blocks")
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        fork = node0.getblockcount()
        old_blocks = self.mine_with_mocktime(node0, 2, sync=False)
        node0.listtokens()
        self.restart_node(0, BASE + CRASH)
        self.pay(self.addresses[2], 3)
        self.mine_with_mocktime(node1, 3, sync=False)
        self.submit_branch(fork + 1, fork + 3)
        self.crash_at_flush()
        new_blocks = self.blocks(node1, fork + 1, fork + 3)
        with node0.assert_debug_log(["Rolling back %s (%d)" % (old_blocks[1], fork + 2),
                                     "Rolling back %s (%d)" % (old_blocks[0], fork + 1)] +
                                    ["Rolling forward %s (%d)" % (h, fork + 1 + i) for i, h in enumerate(new_blocks)]):
            self.start_node(0, BASE)
        connect_nodes(node0, 1)
        self.assert_same_state()
        assert_equal(node0.verifychain(4, 0), True)

        self.log.info("Crash during a reorg flush, roll back a branch with a transaction")
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        fork = node0.getblockcount()
        node0.sendtoaddress(address=node0.getnewaddress(), amount=1)
        self.mine_with_mocktime(node0, 2, sync=False)
        node0.listtokens()
        self.restart_node(0, BASE + CRASH)
        self.pay(self.addresses[1], 4)
        self.mine_with_mocktime(node1, 3, sync=False)
        self.submit_branch(fork + 1, fork + 3)
        self.crash_at_flush()
        self.known_failure("R-B1 (xNZNUbVx)", lambda: self.start_ok(0, BASE), "SIGSEGV")

        self.log.info("-reindex repairs node0")
        self.start_node(0, BASE + ["-reindex"])
        connect_nodes(node0, 1)
        self.sync_blocks(self.nodes[:2])
        self.assert_same_state()
        assert_equal(node0.verifychain(4, 0), True)


if __name__ == '__main__':
    CrashRecoveryTest().main()
