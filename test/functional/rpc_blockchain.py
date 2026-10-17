#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPCs related to blockchainstate.

Test the following RPCs:
    - gettimechaininfo
    - getbestblockhash, getbestblockhashsha256
    - getblockhash
    - getblock (verbosity, money supply), getblockbynumber
    - getblockheader (verbose and hex)
    - getdifficulty
    - gettxout (confirmed, spent in the mempool, mempool outputs)
    - waitfornewblock, waitforblock, waitforblockheight
    - getchaintxstats (including two blocks with the same time)
    - calculatescrypthash, calculateblockhash
    - verifychain

Tests correspond to code in rpc/blockchain.cpp.
"""

from decimal import Decimal
import json
import threading

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    assert_is_hex_string,
    assert_is_hash_string,
    get_rpc_proxy,
    raw_rpc,
    rpc_url,
    wait_until,
)
from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.messages import CBlock, CBlockHeader, FromHex, hash256, uint256_from_compact


class BlockchainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False

    def run_test(self):
        self.mine_chain()

        self.log.info("Running blockchain tests")
        self._test_gettimechaininfo()
        self._test_getchaintxstats()
        self._test_getblockheader()
        assert self.nodes[0].verifychain(4, 0)
        self._test_getblock()
        self._test_money_supply()
        self._test_getblockheader_hex()
        self._test_getblockhash()
        self._test_getdifficulty()
        self._test_getblockbynumber()
        self._test_calculatescrypthash()
        self._test_calculateblockhash()
        self._test_getbestblockhashsha256()
        # These add blocks.
        self._test_gettxout()
        self._test_waitfor()
        self._test_getchaintxstats_same_time()
        # Last: the invalidation can't be undone.
        self._test_getchaintxstats_not_in_main_chain()

    def mine_chain(self):
        self.log.info('Create some old blocks')
        address = self.nodes[0].get_deterministic_priv_key().address
        for t in range(TIME_GENESIS_BLOCK, TIME_GENESIS_BLOCK + 40 * 60, 60):
            # 1-minute steps from genesis block time. Through set_mocktime,
            # so that a restarted node keeps the clock.
            self.set_mocktime(t)
            self.nodes[0].generatetoaddress(1, address)
        assert_equal(self.nodes[0].gettimechaininfo()['blocks'], 40)

    def _test_gettimechaininfo(self):
        self.log.info("Test gettimechaininfo")

        keys = [
            'Latest block time',
            'bestblockhash',
            'blocks',
            'bnChainTrust',
            'chain',
            'difficulty',
            'headers',
            'txcount',
            'verificationprogress'
        ]
        res = self.nodes[0].gettimechaininfo()
        # should have exact keys
        assert_equal(sorted(res.keys()), keys)
        
        assert_equal(res['blocks'], 40)
        assert_equal(res['headers'], 40)
        assert_equal(res['txcount'], 41)

    def _test_getchaintxstats(self):
        self.log.info("Test getchaintxstats")

        # Test `getchaintxstats` invalid extra parameters
        assert_raises_rpc_error(-1, 'getchaintxstats', self.nodes[0].getchaintxstats, 0, '', 0)

        # Test `getchaintxstats` invalid `nblocks`
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", self.nodes[0].getchaintxstats, '')
        assert_raises_rpc_error(-8, "Invalid block count: should be between 1 and the block's height", self.nodes[0].getchaintxstats, -1)

        # Test `getchaintxstats` invalid `blockhash`
        assert_raises_rpc_error(-1, "JSON value is not a string as expected", self.nodes[0].getchaintxstats, blockhash=0)
        assert_raises_rpc_error(-5, "Block not found", self.nodes[0].getchaintxstats, blockhash='0000000000000000000000000000000000000000000000000000000000000000')

        chaintxstats = self.nodes[0].getchaintxstats(nblocks=1)
        # 40 txs plus genesis tx
        assert_equal(chaintxstats['txcount'], 41)
        # tx rate should be 1 per minute, or 1/60
        # we have to round because of binary math
        assert_equal(round(chaintxstats['txrate'] * 60, 10), Decimal(1))

        b1_hash = self.nodes[0].getblockhash(1)
        b1 = self.nodes[0].getblock(b1_hash)
        b40_hash = self.nodes[0].getblockhash(40)
        b40 = self.nodes[0].getblock(b40_hash)
        time_diff = b40['time'] - b1['time']

        chaintxstats = self.nodes[0].getchaintxstats(39)
        assert_equal(chaintxstats['time'], b40['time'])
        assert_equal(chaintxstats['txcount'], 41)
        assert_equal(round(chaintxstats['txrate'] * time_diff, 10), Decimal(39))

    def _test_getblockheader(self):
        node = self.nodes[0]

        assert_raises_rpc_error(-5, "Block not found", node.getblockheader, "nonsense")

        besthash = node.getbestblockhash()
        secondbesthash = node.getblockhash(39)
        header = node.getblockheader(blockhash=besthash)

        assert_equal(header['hash'], besthash)
        assert_equal(header['height'], 40)
        assert_equal(header['confirmations'], 1)
        assert_equal(header['previousblockhash'], secondbesthash)
        assert_is_hex_string(header['chaintrust'])
        assert_is_hash_string(header['hash'])
        assert_is_hash_string(header['previousblockhash'])
        assert_is_hash_string(header['merkleroot'])
        assert_is_hash_string(header['bits'], length=None)
        assert isinstance(header['time'], int)
        assert isinstance(header['nonce'], int)
        assert isinstance(header['version'], int)
        assert isinstance(int(header['versionHex'], 16), int)
        assert isinstance(header['difficulty'], Decimal)

    def _test_getblock(self):
        self.log.info("Test getblock")
        node = self.nodes[0]
        h20 = node.getblockhash(20)
        block = node.getblock(h20)
        assert_equal(sorted(block), ['bits', 'blocktrust', 'chaintrust', 'confirmations', 'difficulty', 'entropybit',
                                     'flags', 'hash', 'height', 'merkleroot', 'mint', 'modifier', 'modifierchecksum',
                                     'money supply', 'nextblockhash', 'nonce', 'previousblockhash', 'proofhash',
                                     'size', 'time', 'tx', 'version', 'versionHex'])
        assert_equal(block['flags'], 'proof-of-work')
        assert_equal(block['proofhash'], h20)
        assert 'nextblockhash' not in node.getblock(node.getbestblockhash())

        raw = node.getblock(h20, 0)
        decoded = FromHex(CBlock(), raw)
        decoded.rehash()
        assert_equal(decoded.hash, h20)
        assert_equal(node.getblock(h20, False), raw)
        assert_equal(node.getblock(h20, True), block)
        assert_equal(node.getblock(h20, 1), block)
        decoded.vtx[0].rehash()
        assert_equal(block['tx'], [decoded.vtx[0].hash])
        detailed = node.getblock(h20, 2)
        assert_equal(sorted(detailed['tx'][0]), ['hex', 'locktime', 'size', 'time', 'txid', 'version', 'vin', 'vout'])
        assert_equal(detailed['tx'][0]['txid'], block['tx'][0])
        # Above 2 is like 2, below 0 like 0.
        assert_equal(node.getblock(h20, 3), detailed)
        assert_equal(node.getblock(h20, -1), raw)
        assert_raises_rpc_error(-5, "Block not found", node.getblock, '00' * 32)

    def _test_money_supply(self):
        self.log.info("Test the money supply and mint of every block")
        node = self.nodes[0]
        genesis = node.getblock(node.getblockhash(0))
        assert_equal((genesis['money supply'], genesis['mint']), (Decimal('100000000'), 0))
        previous = genesis
        for height in range(1, 41):
            block = node.getblock(node.getblockhash(height))
            coinbase = node.getrawtransaction(block['tx'][0], 1)
            # No fees in these blocks: the mint is the coinbase.
            assert_equal(block['mint'], sum(out['value'] for out in coinbase['vout']))
            assert_equal(block['money supply'], previous['money supply'] + block['mint'])
            previous = block
        assert_equal(node.getinfo()['moneysupply'], previous['money supply'])

    def _test_getblockheader_hex(self):
        self.log.info("Test getblockheader verbose=False")
        node = self.nodes[0]
        h20 = node.getblockhash(20)
        header = node.getblockheader(h20, False)
        # Version 7 headers have a 64-bit time: 84 bytes; genesis has 80.
        assert_equal(len(header), 168)
        assert_equal(node.calculatescrypthash(header)['hash_BE'], h20)
        assert_equal(len(node.getblockheader(node.getblockhash(0), False)), 160)
        verbose = node.getblockheader(h20)
        assert_equal(verbose['nextblockhash'], node.getblockhash(21))
        assert isinstance(verbose['mediantime'], int)
        assert 'nextblockhash' not in node.getblockheader(node.getbestblockhash())

    def _test_getblockhash(self):
        self.log.info("Test getblockhash out of range")
        for height in [-1, 41]:
            assert_raises_rpc_error(-8, "Block height out of range", self.nodes[0].getblockhash, height)

    def _test_getdifficulty(self):
        self.log.info("Test getdifficulty")
        node = self.nodes[0]
        difficulty = node.getdifficulty()
        assert_equal(difficulty['proof-of-work'], node.getmininginfo()['difficulty'])
        bits = int(node.getblockheader(node.getbestblockhash())['bits'], 16)
        assert_equal(difficulty['target'], ('%064x' % uint256_from_compact(bits))[:16])

    def _test_getblockbynumber(self):
        self.log.info("Test getblockbynumber")
        node = self.nodes[0]
        for height in [0, 20, 40]:
            assert_equal(node.getblockbynumber(height), node.getblock(node.getblockhash(height)))
        assert isinstance(node.getblockbynumber(20, True)['tx'][0], dict)
        for height in [-1, 41]:
            assert_raises_rpc_error(-1, "Block number out of range.", node.getblockbynumber, height)

    def _test_calculatescrypthash(self):
        self.log.info("Test calculatescrypthash")
        node = self.nodes[0]
        tip = node.getbestblockhash()
        header_hex = node.getblockheader(tip, False)
        verbose = node.getblockheader(tip)
        result = node.calculatescrypthash(header_hex)
        assert_equal(result, {
            'hash_BE': tip,
            'hash_LE': bytes.fromhex(tip)[::-1].hex(),
            'input_size': 84,
            'version': 7,
            'prev_block': verbose['previousblockhash'],
            'merkle_root': verbose['merkleroot'],
            'timestamp': verbose['time'],
            'bits': int(verbose['bits'], 16),
            'nonce': verbose['nonce'],
        })
        assert_raises_rpc_error(-8, "Invalid parameter: data must be exactly 80 or 84 bytes", node.calculatescrypthash, header_hex[:166])
        assert_raises_rpc_error(-8, "Invalid parameter: data must be exactly 80 or 84 bytes", node.calculatescrypthash, 'zz' * 84)
        # 80 bytes of a version 7 header: its time is 8 bytes.
        assert_raises_rpc_error(-22, "Block header decode failed", node.calculatescrypthash, header_hex[:160])

        header = CBlockHeader(FromHex(CBlock(), node.getblock(tip, 0)))
        header.nNonce = 0x80000001
        self.known_failure("uxP8YzbJ item 6 (nonce)",
                           lambda: assert_equal(node.calculatescrypthash(header.serialize().hex())['nonce'], 0x80000001),
                           expected="not(-2147483647 == 2147483649)")
        self.known_failure("uxP8YzbJ item 6 (extra parameter)",
                           lambda: assert_raises_rpc_error(-1, "calculatescrypthash", node.calculatescrypthash, header_hex, 1),
                           expected="No exception raised")

    def _test_calculateblockhash(self):
        self.log.info("Test calculateblockhash")
        node = self.nodes[0]
        for height in [0, 20]:
            block_hash = node.getblockhash(height)
            assert_equal(node.calculateblockhash(node.getblock(block_hash, 0)), block_hash)
        self.known_failure("16Ik4F0L item 1",
                           lambda: assert_raises_rpc_error(-22, "Block decode failed", node.calculateblockhash, "00"),
                           expected="No exception raised")

    def _test_getbestblockhashsha256(self):
        self.log.info("Test getbestblockhashsha256")
        node = self.nodes[0]
        header = bytes.fromhex(node.getblockheader(node.getbestblockhash(), False))
        assert_equal(node.getbestblockhashsha256(), hash256(header)[::-1].hex())

    def _test_gettxout(self):
        self.log.info("Test gettxout")
        node = self.nodes[0]
        tip = node.getbestblockhash()
        coinbase = node.getblock(node.getblockhash(5))['tx'][0]
        out = node.gettxout(coinbase, 0)
        assert_equal(out['bestblock'], tip)
        assert_equal(out['confirmations'], 40 - 5 + 1)
        assert_equal(out['coinbase'], True)
        assert_equal(out['scriptPubKey']['type'], 'pubkeyhash')
        assert_equal(out['value'], node.getrawtransaction(coinbase, 1)['vout'][0]['value'])
        assert_equal(node.gettxout(coinbase, 5), None)

        txid = node.sendtoaddress(address=node.getnewaddress(), amount=1)
        spent = node.getrawtransaction(txid, 1)['vin'][0]
        # Spent in the mempool: gone, unless the mempool is left out.
        assert_equal(node.gettxout(spent['txid'], spent['vout']), None)
        assert_equal(node.gettxout(spent['txid'], spent['vout'], False)['coinbase'], True)
        mempool_out = node.gettxout(txid, 0)
        assert_equal((mempool_out['confirmations'], mempool_out['coinbase']), (0, False))
        assert_equal(node.gettxout(txid, 0, False), None)
        self.mine_with_mocktime(node, 1)
        assert_equal(node.gettxout(spent['txid'], spent['vout']), None)
        assert_equal(node.gettxout(spent['txid'], spent['vout'], False), None)
        assert_equal(node.gettxout(txid, 0, False)['confirmations'], 1)

    def _test_waitfor(self):
        self.log.info("Test waitfornewblock, waitforblock, waitforblockheight")
        node = self.nodes[0]
        tip = {'hash': node.getbestblockhash(), 'height': node.getblockcount()}
        # After the timeout: the current tip.
        assert_equal(node.waitfornewblock(100), tip)
        assert_equal(node.waitforblockheight(tip['height'] + 1, 100), tip)
        # Already there: at once.
        assert_equal(node.waitforblockheight(tip['height']), tip)
        assert_equal(node.waitforblock(tip['hash'], 100), tip)
        assert_equal(node.waitforblock(tip['hash']), tip)

        result = {}

        def wait():
            proxy = get_rpc_proxy(rpc_url(node.datadir, 0, node.chain, None), 0, timeout=90)
            result['tip'] = proxy.waitfornewblock(60000)
        thread = threading.Thread(target=wait)
        thread.start()
        wait_until(lambda: 'waitfornewblock' in [c['method'] for c in node.getrpcinfo()['active_commands']])
        new_hash = self.mine_with_mocktime(node, 1)[0]
        thread.join()
        assert_equal(result['tip'], {'hash': new_hash, 'height': tip['height'] + 1})

        self.restart_node(0)
        assert_equal(node.waitfornewblock(100), {'hash': new_hash, 'height': tip['height'] + 1})

    def _test_getchaintxstats_same_time(self):
        self.log.info("Test getchaintxstats for a block with its parent's time")
        node = self.nodes[0]
        # With the clock standing still, blocks get the median time past
        # plus one, so some have the same time as their parent.
        self.set_mocktime(self.mocktime + 1)
        hashes = node.generate(15)
        times = [node.getblockheader(h)['time'] for h in hashes]
        same = [hashes[i] for i in range(1, len(hashes)) if times[i] == times[i - 1]]
        assert same, times

        def check():
            status, _, body = raw_rpc(node, {"method": "getchaintxstats", "params": [1, same[0]], "id": 1})
            assert_equal(status, 200)
            try:
                result = json.loads(body.decode('utf-8'))['result']
            except ValueError:
                raise AssertionError("invalid JSON: %r" % body)
            assert result.get('txrate', 0) == 0, result
        self.known_failure("uxP8YzbJ item 2", check, expected='"txrate":}')

    def _test_getchaintxstats_not_in_main_chain(self):
        self.log.info("Test getchaintxstats with a block not in the main chain")
        node = self.nodes[0]
        tip = node.getbestblockhash()
        node.invalidateblock(tip)
        assert_equal(node.getblockheader(tip)['confirmations'], -1)
        assert_raises_rpc_error(-8, "Block is not in main chain", node.getchaintxstats, blockhash=tip)


if __name__ == '__main__':
    BlockchainTest().main()
