#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the internal miner: setgenerate, getgenerate, gethashespersec, -gen.

- Defaults and argument errors.
- setgenerate(true, 1) mines blocks paying a wallet key (P2PK) and reserves
  that key; setgenerate(false) stops the thread before it returns.
- The coinbase key goes back to the keypool (known failure R-4).
- A processor limit of 0 switches generation off; a later setgenerate(true)
  then reports generation on with no thread (known failure M-B3).
- -gen=1 at startup mines; the node stops cleanly while mining.
- Locked wallet: the miner mines nothing until the wallet is unlocked.
- Locked wallet with an empty keypool: the node crashes (known failure R-2).
- -disablewallet: after setgenerate(true) the miner thread never ends, so
  setgenerate(false) and stopping hang (known failure R-3).
"""

import os
import re

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    get_rpc_proxy,
    try_rpc,
    wait_until,
)

BUG_CARD = "IvbXjqbT"
# the timeout code AuthServiceProxy gives a call that got no answer
RPC_TIMEOUT_CODE = -344


class SetGenerateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        # node2: a small keypool, so that the locked wallet's pool can be emptied
        self.extra_args = [[], [], ['-keypool=1'], ['-disablewallet']]

    def setup_network(self):
        # node2 and node3 mine alone: the miner needs no peers.
        self.setup_nodes()
        connect_nodes(self.nodes[1], 0)

    def run_test(self):
        node = self.nodes[0]
        self.mine_with_mocktime(node, 10, sync=self.nodes[:2])

        self.test_defaults(node)
        self.test_mining(node)
        self.test_zero_limit(node)
        self.test_gen_option()
        self.test_locked_wallet()
        self.test_empty_keypool()
        self.test_disablewallet()

    def test_defaults(self, node):
        self.log.info("Defaults and argument errors")
        assert_equal(node.getgenerate(), False)
        info = node.getmininginfo()
        assert_equal((info['generate'], info['genproclimit']), (False, -1))
        # measured only after 60 s of mining
        assert_equal(node.gethashespersec(), 0)
        assert_raises_rpc_error(-1, "gethashespersec\n", node.gethashespersec, 1)
        assert_raises_rpc_error(-1, "getgenerate\n", node.getgenerate, 1)
        assert_raises_rpc_error(-1, "setgenerate generate ( genproclimit )", node.setgenerate)
        assert_raises_rpc_error(-1, "setgenerate generate ( genproclimit )", node.setgenerate, True, 1, 2)
        assert_raises_rpc_error(-1, "JSON value is not a boolean as expected", node.setgenerate, 'yes')
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", node.setgenerate, True, '1')

    def test_mining(self, node):
        self.log.info("Mining with one thread")
        # The miner stamps its blocks with the node's time (or the median
        # time past + 1); a small step ahead keeps the chain's clock in line.
        self.set_mocktime(self.mocktime + 60)
        height = node.getblockcount()
        keypool = node.getwalletinfo()['keypoolsize']
        result = node.setgenerate(True, 1)
        assert re.fullmatch(r"1 of \d+", result), result
        assert_equal(node.getgenerate(), True)
        assert_equal(node.getmininginfo()['genproclimit'], 1)
        wait_until(lambda: node.getblockcount() >= height + 2, timeout=120)
        # reserved by the miner thread, which is running (it found a block)
        assert_equal(node.getwalletinfo()['keypoolsize'], keypool - 1)

        self.log.info("Stopping: the thread has ended when the call returns")
        assert_equal(node.setgenerate(False), result)
        new_height = node.getblockcount()
        assert_equal(node.getgenerate(), False)
        assert_equal(node.getmininginfo()['generate'], False)
        self.sync_blocks(self.nodes[:2])
        assert_equal(node.getblockcount(), new_height)

        addresses = set()
        for h in range(height + 1, new_height + 1):
            txid = node.getblock(node.getblockhash(h))['tx'][0]
            script = node.getrawtransaction(txid, 1)['vout'][0]['scriptPubKey']
            assert_equal(script['type'], 'pubkey')
            addresses.update(script['addresses'])
            # in the wallet; 'generate' once 6 deep (the miner may find more
            # blocks before it is stopped)
            assert node.gettransaction(txid)['details'][0]['category'] in ('immature', 'generate')
        # one key per thread
        assert_equal(len(addresses), 1)
        coinbase_address = addresses.pop()

        self.log.info("The coinbase key goes back to the keypool")
        address = node.getnewaddress()
        self.known_failure("R-4 (%s)" % BUG_CARD,
                           lambda: self.assert_not_coinbase_address(address, coinbase_address),
                           expected="returned the coinbase address")

    @staticmethod
    def assert_not_coinbase_address(address, coinbase_address):
        assert address != coinbase_address, "getnewaddress returned the coinbase address " + address

    def test_zero_limit(self, node):
        self.log.info("A processor limit of 0")
        result = node.setgenerate(True, 0)
        assert re.fullmatch(r"0 of \d+", result), result
        assert_equal(node.getgenerate(), False)
        assert_equal(node.getmininginfo()['genproclimit'], 0)
        # without a limit argument the stored limit 0 applies
        result = node.setgenerate(True)
        self.known_failure("M-B3 (%s)" % BUG_CARD,
                           lambda: self.assert_not_on_without_threads(node, result),
                           expected="0 threads")
        node.setgenerate(False)

    @staticmethod
    def assert_not_on_without_threads(node, result):
        assert not (node.getgenerate() and result.startswith("0 of")), \
            "generate is on with 0 threads (%s)" % result

    def test_gen_option(self):
        self.log.info("-gen=1 at startup")
        node1 = self.nodes[1]
        height = node1.getblockcount()
        self.restart_node(1, ['-gen=1', '-genproclimit=1'])
        assert_equal(node1.getgenerate(), True)
        wait_until(lambda: node1.getblockcount() > height, timeout=120)
        # stops cleanly while mining (exit code 0)
        self.stop_node(1)

    def test_locked_wallet(self):
        self.log.info("Locked wallet: the miner mines nothing until unlocked")
        node2 = self.nodes[2]
        node2.encryptwallet('pass')
        node2.wait_until_stopped()
        self.start_node(2)
        height = node2.getblockcount()
        with node2.assert_debug_log(["Starting mining loop"], timeout=10):
            node2.setgenerate(True, 1)
        assert_equal(node2.getblockcount(), height)
        node2.walletpassphrase('pass', 60)
        wait_until(lambda: node2.getblockcount() > height, timeout=60)
        node2.setgenerate(False)
        node2.walletlock()
        # A process that crashes writes no coverage data: the restart keeps
        # what this one covered.
        self.restart_node(2)

    def test_empty_keypool(self):
        self.log.info("Locked wallet with an empty keypool")
        node2 = self.nodes[2]
        for _ in range(5):
            try:
                node2.getnewaddress()
            except JSONRPCException:
                break
        assert_raises_rpc_error(-12, "Error: Keypool ran out, please call keypoolrefill first", node2.getnewaddress)
        self.known_failure("R-2 (%s)" % BUG_CARD,
                           lambda: node2.crash_check(lambda: self.start_miner_and_wait(node2)),
                           expected="exit code -11")

    @staticmethod
    def start_miner_and_wait(node):
        """setgenerate(true, 1), then wait for the miner thread to end (a
        miner without a coinbase script ends at once) or the node to exit."""
        log_path = os.path.join(node.datadir, 'debug.log')
        start = os.path.getsize(log_path)

        def miner_ended():
            with open(log_path, encoding='utf-8') as f:
                f.seek(start)
                return "YacoinMiner stopped for proof-of-work" in f.read()

        node.setgenerate(True, 1)
        wait_until(lambda: node.process.poll() is not None or miner_ended(), timeout=10)
        node.getblockcount()

    def test_disablewallet(self):
        self.log.info("-disablewallet: the miner thread never ends")
        node3 = self.nodes[3]

        def check():
            # an RPC error would be a fix as well
            try_rpc(None, None, node3.setgenerate, True, 1)
            # setgenerate(false) joins the miner thread. node3.rpc would wait
            # 600 s for it.
            proxy = get_rpc_proxy(node3.url, node3.index, timeout=5, coveragedir=node3.coverage_dir)
            try:
                proxy.setgenerate(False)
            except JSONRPCException as e:
                if e.error['code'] == RPC_TIMEOUT_CODE:
                    raise AssertionError("setgenerate(false) hung for 5 s")
                raise

        try:
            self.known_failure("R-3 (%s)" % BUG_CARD, check, expected="hung")
        finally:
            # A node with that thread can't be stopped (only killed).
            if node3.running:
                node3.process.kill()
                node3.wait_for_exit()


if __name__ == '__main__':
    SetGenerateTest().main()
