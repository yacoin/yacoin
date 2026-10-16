#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test getwork.

- No peer: error. The work: 128 bytes of data, each 32-bit word byte-swapped,
  holding the 84-byte version 7 header (64-bit nTime) and SHA-256 padding;
  the target in little-endian order; the constant hash1.
- A solution (found through calculatescrypthash) is accepted: the stored
  header has the submitted nonce and time, the coinbase pays the wallet's
  key (P2PK) and the block is signed. A rolled nTime is accepted too.
- False for a stale solution, a hash above the target and unknown work;
  argument errors.
- Two solutions of the same work submitted at the same time.
- The coinbase key goes back to the keypool (known failure R-4).
- -disablewallet: getwork is unavailable.
- Locked wallet: submitting fails (known failure R-5) until it is unlocked.
- Locked wallet with an empty keypool: the node crashes (known failure R-1).
"""

import copy
import threading

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import solve_block
from test_framework.messages import CBlock, CBlockHeader, FromHex, uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    get_rpc_proxy,
)

BUG_CARD = "IvbXjqbT"
# SHA-256 padding of a 32-byte hash, word-swapped (deprecated field)
HASH1 = '00' * 32 + '00000080' + '00' * 24 + '00010000'
# 0x80, zeros, then the bit length of the 84-byte header (672 = 0x2a0)
HEADER_PADDING = b'\x80' + b'\x00' * 39 + b'\x00\x00\x02\xa0'


def swap_words(data):
    return b''.join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


def work_to_header(data_hex):
    """The CBlockHeader in getwork data."""
    return FromHex(CBlockHeader(), swap_words(bytes.fromhex(data_hex))[:84].hex())


def header_to_work(header, data_hex):
    """getwork data with header's fields (nTime, nNonce) written in."""
    padding = swap_words(bytes.fromhex(data_hex))[84:]
    return swap_words(CBlockHeader.serialize(header) + padding).hex()


def solve_work(node, data_hex, start_nonce=0, invalid=False):
    """A solution for getwork data: (header, data), nonce counting up from
    start_nonce; with invalid=True a nonce whose hash misses the target."""
    header = work_to_header(data_hex)
    header.nNonce = start_nonce
    solve_block(node, header, invalid=invalid)
    return header, header_to_work(header, data_hex)


class GetWorkTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        # a small keypool, so that the locked wallet's pool can be emptied
        self.extra_args = [['-keypool=1'], [], ['-disablewallet']]

    def run_test(self):
        node = self.nodes[0]
        self.mine_with_mocktime(node, 20)

        self.log.info("Without a peer")
        disconnect_nodes(node, 1)
        assert_raises_rpc_error(-9, "Yacoin is not connected!", node.getwork)
        connect_nodes(self.nodes[1], 0)

        self.test_work_format(node)
        self.test_submit(node)
        self.test_concurrent_submits(node)

        self.log.info("-disablewallet")
        assert_raises_rpc_error(-32601, "Method not found (wallet method is disabled because no wallet is loaded)",
                                self.nodes[2].getwork)

        self.test_locked_wallet()
        self.test_empty_keypool()

    def test_work_format(self, node):
        self.log.info("The work")
        keypool = node.getwalletinfo()['keypoolsize']
        w = node.getwork()
        assert_equal([len(w[k]) for k in ('midstate', 'data', 'hash1', 'target')], [64, 256, 128, 64])
        assert_equal(w['hash1'], HASH1)
        header = work_to_header(w['data'])
        assert_equal(header.nVersion, 7)
        assert_equal(header.hashPrevBlock, int(node.getbestblockhash(), 16))
        assert_equal(header.nTime, self.mocktime)
        assert_equal(header.nBits, int(node.getblocktemplate()['bits'], 16))
        assert_equal(header.nNonce, 0)
        assert_equal(swap_words(bytes.fromhex(w['data']))[84:], HEADER_PADDING)
        assert_equal(int.from_bytes(bytes.fromhex(w['target']), 'little'), uint256_from_compact(header.nBits))
        # the coinbase key is reserved and given back within the call
        assert_equal(node.getwalletinfo()['keypoolsize'], keypool)
        # new work per call (extra nonce), on the same block
        assert work_to_header(node.getwork()['data']).hashMerkleRoot != header.hashMerkleRoot
        self.work = w

    def test_submit(self, node):
        self.log.info("A solution is accepted")
        w = self.work
        height = node.getblockcount()
        header, solution = solve_work(node, w['data'])
        _, second_solution = solve_work(node, w['data'], start_nonce=header.nNonce + 1)
        assert_equal(node.getwork(solution), True)
        assert_equal(node.getblockcount(), height + 1)
        tip = node.getbestblockhash()
        assert_equal(tip, header.hash)
        stored = node.getblockheader(tip)
        assert_equal((stored['nonce'], stored['time']), (header.nNonce, header.nTime))
        self.sync_blocks()
        coinbase = node.getrawtransaction(node.getblock(tip)['tx'][0], 1)
        assert_equal(coinbase['vout'][0]['scriptPubKey']['type'], 'pubkey')
        assert_equal(node.gettransaction(coinbase['txid'])['details'][0]['category'], 'immature')
        # signed with the coinbase key
        assert FromHex(CBlock(), node.getblock(tip, 0)).vchBlockSig

        self.log.info("A second solution of the same work is stale")
        # Only while no getwork() call has been made since the block: such a
        # call drops the old work, and the answer is then "no saved block".
        with node.assert_debug_log(["generated block is stale"]):
            assert_equal(node.getwork(second_solution), False)
        assert_equal(node.getbestblockhash(), tip)

        self.log.info("A hash above the target, unknown work, a rolled nTime")
        w = node.getwork()
        _, unsolved = solve_work(node, w['data'], invalid=True)
        with node.assert_debug_log(["proof-of-work not meeting target"]):
            assert_equal(node.getwork(unsolved), False)
        unknown = work_to_header(w['data'])
        unknown.hashMerkleRoot ^= 1
        with node.assert_debug_log(["No saved block"]):
            assert_equal(node.getwork(header_to_work(unknown, w['data'])), False)
        rolled = work_to_header(w['data'])
        rolled.nTime += 1
        rolled, rolled_solution = solve_work(node, header_to_work(rolled, w['data']))
        assert_equal(node.getwork(rolled_solution), True)
        assert_equal(node.getblockheader(node.getbestblockhash())['time'], rolled.nTime)
        assert_equal(node.getbestblockhash(), rolled.hash)

        self.log.info("Argument errors")
        for data in (rolled_solution[:-2], rolled_solution + '00', 'zz' * 128):
            assert_raises_rpc_error(-8, "Invalid parameter", node.getwork, data)
        assert_raises_rpc_error(-1, "getwork [data]", node.getwork, rolled_solution, 1)

        self.log.info("The coinbase key goes back to the keypool")
        coinbase = node.getrawtransaction(node.getblock(node.getbestblockhash())['tx'][0], 1)
        coinbase_address = coinbase['vout'][0]['scriptPubKey']['addresses'][0]
        address = node.getnewaddress()
        self.known_failure("R-4 (%s)" % BUG_CARD,
                           lambda: self.assert_not_coinbase_address(address, coinbase_address),
                           expected="returned the coinbase address")

    @staticmethod
    def assert_not_coinbase_address(address, coinbase_address):
        assert address != coinbase_address, "getnewaddress returned the coinbase address " + address

    def test_concurrent_submits(self, node):
        self.log.info("Two solutions of the same work at the same time")
        w = node.getwork()
        first, first_solution = solve_work(node, w['data'])
        second, second_solution = solve_work(node, w['data'], start_nonce=first.nNonce + 1)
        results = [None, None]

        def submit(i, solution):
            proxy = get_rpc_proxy(node.url, node.index, timeout=60, coveragedir=node.coverage_dir)
            results[i] = proxy.getwork(solution)

        threads = [threading.Thread(target=submit, args=(i, s)) for i, s in enumerate((first_solution, second_solution))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        # Both may pass the stale check before either becomes the tip; then
        # the second is stored as a side block and is True as well.
        assert all(r in (True, False) for r in results), results
        assert True in results, results
        tip = node.getbestblockhash()
        assert tip in (first.hash, second.hash), tip
        # the stored bytes are those of the block in the index
        assert_equal(node.calculateblockhash(node.getblock(tip, 0)), tip)
        self.sync_blocks()

    def restart_locked(self):
        self.start_node(0)
        connect_nodes(self.nodes[1], 0)

    def test_locked_wallet(self):
        self.log.info("Locked wallet: work, but no submission until unlocked")
        node = self.nodes[0]
        node.encryptwallet('pass')
        node.wait_until_stopped()
        self.restart_locked()
        w = node.getwork()
        header, solution = solve_work(node, w['data'])
        self.known_failure("R-5 (%s)" % BUG_CARD,
                           lambda: assert_equal(node.getwork(solution), True),
                           expected=-100)
        node.walletpassphrase('pass', 60)
        assert_equal(node.getwork(solution), True)
        assert_equal(node.getbestblockhash(), header.hash)
        node.walletlock()
        # A process that crashes writes no coverage data: the restart keeps
        # what this one covered.
        self.stop_node(0)

    def test_empty_keypool(self):
        self.log.info("Locked wallet with an empty keypool")
        node = self.nodes[0]
        self.restart_locked()
        # Before the first getwork() of this process, which builds a new
        # block with a key from the pool.
        for _ in range(5):
            try:
                node.getnewaddress()
            except JSONRPCException:
                break
        assert_raises_rpc_error(-12, "Error: Keypool ran out, please call keypoolrefill first", node.getnewaddress)
        self.known_failure("R-1 (%s)" % BUG_CARD,
                           lambda: node.crash_check(lambda: assert_raises_rpc_error(None, None, node.getwork)),
                           expected="exit code -11")


if __name__ == '__main__':
    GetWorkTest().main()
