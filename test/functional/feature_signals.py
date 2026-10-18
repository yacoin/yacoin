#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the node's signal handling.

- SIGTERM and SIGINT: clean shutdown with exit code 0, pid file removed, the
  mempool written to mempool.dat and loaded again on the next start.
- SIGHUP: debug.log is reopened, so a renamed log file is replaced by a new
  one that receives the new lines.
- SIGTERM during -reindex: the reindex should stop; today it runs to the end
  (known bug VdCO5Ac4). A junk blk00001.dat makes the reindex last a few
  seconds.
"""

from datetime import datetime, timezone
import os
import signal

from test_framework.mininode import MAGIC_BYTES
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    get_rpc_proxy,
    rpc_url,
    wait_until,
)

MAGIC = MAGIC_BYTES['mainnet']


class SignalsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.block_fork_1_0 = 1

    def debug_log(self, name='debug.log'):
        with open(os.path.join(self.nodes[0].datadir, name), encoding='utf-8') as f:
            return f.read()

    def run_test(self):
        node = self.nodes[0]
        pid_file = os.path.join(node.datadir, 'yacoind.pid')
        self.mine_with_mocktime(node, 12)

        for sig in (signal.SIGTERM, signal.SIGINT):
            self.log.info("%s" % sig.name)
            txid = node.sendtoaddress(address=node.getnewaddress(), amount=1)
            tip = node.getbestblockhash()
            with open(pid_file, encoding='utf-8') as f:
                assert_equal(f.read().strip(), str(node.process.pid))
            with node.assert_debug_log(["Shutdown: In progress...", "Yacoin exited"]):
                node.send_signal(sig)
                assert_equal(node.wait_for_exit(60), 0)
            assert not os.path.exists(pid_file)
            with node.assert_debug_log(["Imported mempool transactions from disk: 1 successes"]):
                self.start_node(0)
            assert_equal(node.getbestblockhash(), tip)
            assert_equal(node.getrawmempool(), [txid])
            assert_equal(node.gettransaction(txid)['confirmations'], 0)
            self.mine_with_mocktime(node, 1)

        self.log.info("SIGHUP")
        log_file = os.path.join(node.datadir, 'debug.log')
        os.rename(log_file, log_file + '.1')
        node.send_signal(signal.SIGHUP)
        block_hash = self.mine_with_mocktime(node, 1)[0]
        wait_until(lambda: os.path.exists(log_file))
        update_tip = "UpdateTip: new best=%s" % block_hash[:20]
        wait_until(lambda: update_tip in self.debug_log())
        assert update_tip not in self.debug_log('debug.log.1')
        assert_equal(node.getbestblockhash(), block_hash)

        self.log.info("SIGTERM during -reindex")
        tip = node.getbestblockhash()
        self.stop_node(0)
        # 128 MiB of record headers whose size check fails: the reindex scans
        # them byte by byte.
        junk = os.path.join(node.datadir, 'blocks', 'blk00001.dat')
        with open(junk, 'wb') as f:
            f.write((MAGIC + b'\xff\xff\xff\xff') * (128 * 131072))
        start = len(self.debug_log())
        node.start(["-reindex"])
        wait_until(lambda: "Reindexing block file blk00001.dat..." in self.debug_log()[start:])
        rpc = get_rpc_proxy(rpc_url(node.datadir, node.index, node.chain, node.rpchost), node.index, timeout=60)
        assert_raises_rpc_error(-28, "Reindexing block index and chainstate in slow mode", rpc.getblockcount)
        signal_time = datetime.now(timezone.utc).replace(tzinfo=None)
        node.send_signal(signal.SIGTERM)
        exit_code = node.wait_for_exit(120)
        finished = [line for line in self.debug_log()[start:].splitlines() if "Reindexing finished" in line]

        def reindex_stopped():
            assert not finished, "the reindex ran to the end: %s" % finished
        self.known_failure("R-19 (VdCO5Ac4)", reindex_stopped, "Reindexing finished")
        finished_time = datetime.strptime(finished[0][:26], "%Y-%m-%d %H:%M:%S.%f")
        assert signal_time < finished_time, "SIGTERM was sent after the reindex had finished"
        # A shutdown request during init ends with exit code 1.
        assert_equal(exit_code, 1)
        os.remove(junk)
        self.start_node(0)
        assert_equal(node.getbestblockhash(), tip)


if __name__ == '__main__':
    SignalsTest().main()
