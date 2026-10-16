#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test block verification at startup and verifychain, and -checkblockindex.

The chain (60 blocks, fork at 20, epoch interval 10) has pre-fork blocks, a
token issue, reissue and transfer, a 2-block reorg, and a block whose 200 YAC fee
lowers the reward of the following epochs below the one before. Both nodes
run with -checkblockindex=1 while it is built.

- verifychain at levels 0-4. Level 4 checks each coinbase against the reward
  of the block after the tip (known bug NA3GuKv0), so it fails for pre-fork
  blocks and for the epoch with the higher reward; also -checklevel=4 at
  startup.
- -checkblocks/-checklevel at startup, and the number of blocks checked.
- Corrupted undo data: init error at -checklevel=2, not at 1; -reindex
  recovers.
- -checkblockindex=1: the first block after a restart aborts the node (known
  bug uF3zsEiV).
- The -help defaults of -checkblocks/-checklevel, and debug options missing
  from -help (yacoind has no -help-debug) (VdCO5Ac4).
"""

import http.client
import os
import subprocess

from test_framework.messages import COIN
from test_framework.mininode import MAGIC_BYTES
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch, FailedToStartError, describe_exit_code
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
    read_block_file,
)

BASE = ["-tokenindex=1", "-tokenSupportBlockNumber=25"]
CBI = ["-checkblockindex=1"]


class VerifyDBTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.block_fork_1_0 = 20
        self.extra_args = [BASE + CBI, BASE + CBI]

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def debug_log_size(self):
        return os.path.getsize(os.path.join(self.nodes[0].datadir, 'debug.log'))

    def debug_log_errors(self, offset):
        with open(os.path.join(self.nodes[0].datadir, 'debug.log'), encoding='utf-8') as f:
            f.seek(offset)
            return [line for line in f.read().splitlines() if 'ERROR:' in line]

    def verifychain_ok(self, level, depth):
        offset = self.debug_log_size()
        if not self.nodes[0].verifychain(level, depth):
            raise AssertionError("verifychain(%d, %d) returned false: %s" % (level, depth, self.debug_log_errors(offset)))

    def start_ok(self, args, **kwargs):
        """Start node0; a failed start becomes an AssertionError with the debug log errors."""
        offset = self.debug_log_size()
        try:
            self.start_node(0, args, **kwargs)
        except FailedToStartError:
            rc = self.nodes[0].wait_for_exit()
            raise AssertionError("node0 failed to start, exit code %s: %s %s" % (
                describe_exit_code(rc), self.nodes[0].read_stderr(), self.debug_log_errors(offset)))

    def mint(self, height):
        node = self.nodes[0]
        return int(node.getblock(node.getblockhash(height))['mint'] * COIN)

    def help_entry(self, text, option):
        """The description of option in -help output."""
        lines = text.splitlines()
        start = [i for i, line in enumerate(lines) if line.startswith("  %s" % option)][0]
        entry = []
        for line in lines[start + 1:]:
            if not line.startswith("       "):
                break
            entry.append(line.strip())
        return " ".join(entry)

    def run_test(self):
        node0, node1 = self.nodes

        self.log.info("Build the chain")
        self.mine_with_mocktime(node0, 30)
        node0.issue("VERIFYTOK", 1000, 0, True, False, "", node0.getnewaddress(), "")
        self.mine_with_mocktime(node0, 1)
        node0.reissue("VERIFYTOK", 500)
        self.mine_with_mocktime(node0, 1)
        node0.transfer("VERIFYTOK", 100, node1.getnewaddress())
        self.mine_with_mocktime(node0, 1)
        disconnect_nodes(node0, 1)
        disconnect_nodes(node1, 0)
        self.mine_with_mocktime(node0, 2, sync=False)
        self.mine_with_mocktime(node1, 3, sync=False)
        connect_nodes(node0, 1)
        self.sync_blocks()
        self.mine_with_mocktime(node0, 44 - node0.getblockcount())
        # Block 45 burns a 200 YAC fee, spending four pre-fork coinbases.
        inputs = []
        total = 0
        for h in range(1, 20):
            txid = node0.getblock(node0.getblockhash(h))['tx'][0]
            txout = node0.gettxout(txid, 0)
            if txout is not None and len(inputs) < 4:
                inputs.append({'txid': txid, 'vout': 0})
                total += txout['value']
        assert_equal(len(inputs), 4)
        raw = node0.createrawtransaction(inputs, {node0.getnewaddress(): total - 200})
        node0.sendrawtransaction(node0.signrawtransaction(raw)['hex'])
        self.mine_with_mocktime(node0, 16)
        assert_equal(node0.getblockcount(), 60)
        assert self.mint(49) > self.mint(50)
        assert self.mint(49) > node0.getsubsidy()
        tip = node0.getbestblockhash()
        mint_pre_fork, mint_49 = self.mint(1), self.mint(49)

        self.log.info("verifychain at all levels")
        for level in range(4):
            self.verifychain_ok(level, 0)
        # verifychain(4, n) checks n + 1 blocks: 50-60 here, all paying at most
        # the reward of block 61.
        self.verifychain_ok(4, 10)
        self.known_failure("C-S3 (NA3GuKv0)", lambda: self.verifychain_ok(4, 0),
                           "coinbase pays too much (actual=%d " % mint_pre_fork)
        self.known_failure("C-S3 (NA3GuKv0)", lambda: self.verifychain_ok(4, 11),
                           "coinbase pays too much (actual=%d " % mint_49)

        self.log.info("-checklevel/-checkblocks at startup")
        self.stop_node(0)
        self.known_failure("C-S3 (NA3GuKv0)", lambda: self.start_ok(BASE + ["-checklevel=4", "-checkblocks=0"]),
                           "coinbase pays too much (actual=%d " % mint_pre_fork)
        with node0.assert_debug_log(["Verifying last 10 blocks at level 4",
                                     "No coin database inconsistencies in last 11 blocks"]):
            self.start_node(0, BASE + ["-checklevel=4", "-checkblocks=10"])
        self.stop_node(0)
        with node0.assert_debug_log(["Verifying last 1 blocks at level 3"]):
            self.start_node(0, BASE + ["-checkblocks=1"])
        self.stop_node(0)
        # The test config sets checkblocks=8.
        with node0.assert_debug_log(["Verifying last 8 blocks at level 0"]):
            self.start_node(0, BASE + ["-checklevel=0"])
        assert_equal(node0.getbestblockhash(), tip)
        self.stop_node(0)

        self.log.info("Corrupted undo data")
        rev = os.path.join(node0.datadir, 'blocks', 'rev00000.dat')
        data, records = read_block_file(rev, MAGIC_BYTES['mainnet'], checksum_size=32)
        data = bytearray(data)
        # Overwrite the middle of the tip's undo record and checksum (written last).
        pos, size = records[-1]
        middle = pos + 8 + (size + 32) // 2 - 16
        data[middle:middle + 32] = b'\xff' * 32
        with open(rev, 'wb') as f:
            f.write(bytes(data))
        with node0.assert_debug_log(["found bad undo data at 60"]):
            node0.assert_start_raises_init_error(BASE + ["-checklevel=2", "-checkblocks=5"],
                                                 "Corrupted block database detected", match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, BASE + ["-checklevel=1", "-checkblocks=5"])
        self.stop_node(0)
        self.start_node(0, BASE + ["-reindex"])
        assert_equal(node0.getbestblockhash(), tip)
        self.verifychain_ok(3, 0)

        self.log.info("-checkblockindex=1 after a restart")
        self.stop_node(0)
        self.start_node(0, BASE + CBI, no_core_dump=True)

        def mine_one():
            try:
                self.mine_with_mocktime(node0, 1, sync=False)
            except (OSError, http.client.HTTPException):
                rc = node0.wait_for_exit(10)
                raise AssertionError("node0 exited with code %s: %s" % (describe_exit_code(rc), node0.read_stderr()))
        self.known_failure("C-S10 (uF3zsEiV)", mine_one, "setBlockIndexCandidates.count(pindex) == 0")
        self.start_node(0, BASE)
        assert_equal(node0.getbestblockhash(), tip)

        self.log.info("-help text")
        help_text = subprocess.run([node0.binary, "-help"], stdout=subprocess.PIPE,
                                   universal_newlines=True, check=True).stdout
        checkblocks = self.help_entry(help_text, "-checkblocks=<n>")
        checklevel = self.help_entry(help_text, "-checklevel=<n>")

        def help_default(entry, text):
            assert text in entry, "help says: %s" % entry
        self.known_failure("R-24 (VdCO5Ac4)", lambda: help_default(checkblocks, "(default: 60"), "(default: 750)")
        self.known_failure("R-24 (VdCO5Ac4)", lambda: help_default(checklevel, "(0-4, default: 3)"), "(0-6, default: 1)")

        options = ["-checkblockindex", "-dbbatchsize", "-stopafterblockimport", "-persistmempool"]

        def help_lists():
            missing = [o for o in options if "  %s" % o not in help_text]
            assert not missing, "missing from -help (yacoind has no -help-debug): %s" % missing
        self.known_failure("help options (VdCO5Ac4)", help_lists,
                           "missing from -help (yacoind has no -help-debug): %s" % options)


if __name__ == '__main__':
    VerifyDBTest().main()
