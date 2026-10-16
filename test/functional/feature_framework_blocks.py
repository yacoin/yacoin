#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Self-checks of the block and P2P parts of the test framework.

Tests that build blocks and talk P2P rely on these, so check them against a
real node:
- CBlock reads and writes the node's block serialization (vchBlockSig
  included), and msg_headers its headers message.
- reject messages are parsed and wait_for_reject matches each one once.
- CBlockHeader.hash is the node's block hash (scrypt-jane in Python), for
  version 7 and for older headers across their N-factor steps.
"""

from test_framework.messages import (
    CBlock,
    CBlockHeader,
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    REJECT_DUPLICATE,
    REJECT_INVALID,
    msg_getheaders,
    msg_headers,
    msg_tx,
    msg_version,
)
from test_framework.blocktools import block_hash_rpc
from test_framework.scrypt_jane import keccak512, scrypt_jane
from test_framework.mininode import P2PInterface, mininode_lock
from test_framework.script import CScript, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import NFACTOR_AT_HARDFORK, assert_equal, wait_until


class FrameworkBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Node 1 is a donor that only connects when a check needs it.
        self.setup_nodes()

    def generate_to(self, node, n, address=TestNode.PRIV_KEYS[0].address, spacing=60):
        """Mine n blocks paying address, moving the mocktime forward."""
        hashes = []
        for _ in range(n):
            self.set_mocktime(self.mocktime + spacing)
            hashes += node.generatetoaddress(1, address)
        return hashes

    def run_test(self):
        self.set_mocktime(1600000000)
        self.generate_to(self.nodes[0], 12)
        self.test_block_serialization()
        self.test_headers_message()
        self.test_reject()
        self.test_block_hash()

    def test_block_serialization(self):
        node = self.nodes[0]
        self.log.info("CBlock re-serializes the node's blocks byte for byte, vchBlockSig included")
        for height in range(node.getblockcount() + 1):
            raw = node.getblock(node.getblockhash(height), False)
            block = FromHex(CBlock(), raw)
            assert_equal(block.serialize().hex(), raw)
            assert_equal(block.vchBlockSig, b"")
            assert_equal(raw[-2:], "00")
        assert_equal(block.nVersion, 7)
        assert_equal(FromHex(CBlock(), node.getblock(node.getblockhash(0), False)).nVersion, 1)

    def test_headers_message(self):
        node = self.nodes[0]
        self.log.info("msg_headers parses the node's headers message")
        peer = node.add_p2p_connection(P2PInterface())
        getheaders = msg_getheaders()
        getheaders.locator.vHave = [int(node.getblockhash(5), 16)]
        peer.send_and_ping(getheaders)
        with mininode_lock:
            headers = peer.last_message['headers'].headers
        assert_equal(len(headers), node.getblockcount() - 5)
        for height, header in enumerate(headers, start=6):
            expected = node.getblockheader(node.getblockhash(height))
            assert_equal(header.hashPrevBlock, int(expected['previousblockhash'], 16))
            assert_equal(header.hashMerkleRoot, int(expected['merkleroot'], 16))
            assert_equal((header.nTime, header.nNonce, '%08x' % header.nBits),
                         (expected['time'], expected['nonce'], expected['bits']))
        # Each entry is the 84-byte header plus two zero bytes.
        assert_equal(len(msg_headers(headers).serialize()), 1 + len(headers) * 86)
        node.disconnect_p2ps()

    def test_reject(self):
        node = self.nodes[0]
        self.log.info("wait_for_reject: a second version message")
        peer = node.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_version())
        rej = peer.wait_for_reject(message=b"version", code=REJECT_DUPLICATE, reason=b"Duplicate version message")
        assert_equal(rej.data, 0)
        assert_equal(peer.rejects, [])

        self.log.info("wait_for_reject: a transaction reject carries the txid")
        coinbase = node.getblock(node.getblockhash(1))['tx'][0]
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(coinbase, 16), 0))]
        tx.vout = [CTxOut(1000 * COIN, CScript([OP_DUP, OP_HASH160, bytes(20), OP_EQUALVERIFY, OP_CHECKSIG]))]
        tx.rehash()
        # The amount check comes before the script check, so no signature is
        # needed; the node disconnects the peer after this reject.
        peer.send_message(msg_tx(tx))
        peer.wait_for_reject(message=b"tx", code=REJECT_INVALID, reason=b"bad-txns-in-belowout", data=tx.sha256)
        peer.wait_for_disconnect()
        assert_equal(peer.rejects, [])
        node.disconnect_p2ps()
        wait_until(lambda: node.getconnectioncount() == 0)

    def test_block_hash(self):
        node = self.nodes[0]
        self.log.info("scrypt-jane's own self-test vectors (Keccak-512, ChaCha20/8)")
        # scrypt-jane-hash.h scrypt_test_hash and scrypt-jane-test-vectors.h
        msg = bytes(range(256)) + b"\x00"
        chained = b"".join(keccak512(msg[:i]) for i in range(len(msg) + 1))
        assert_equal(keccak512(chained)[:8].hex(), "17c78ca0d9081dba")
        assert_equal(scrypt_jane(b"", b"", 3, 64)[:16].hex(), "77cb70bfaed44c5bbcd3ec8a82438db3")

        self.log.info("CBlockHeader.hash is the node's block hash, for genesis (version 1) and version 7 blocks")
        assert_equal(node.getmininginfo()['Nfactor'], NFACTOR_AT_HARDFORK)
        for height in range(node.getblockcount() + 1):
            block_hash = node.getblockhash(height)
            block = FromHex(CBlock(), node.getblock(block_hash, False))
            block.calc_sha256()
            assert_equal(block.hash, block_hash)
            assert_equal(block_hash_rpc(node, block), block_hash)
        assert_equal(block.sha256d, int(node.getbestblockhashsha256(), 16))

        self.log.info("Copying a header doesn't hash it")
        unhashed = FromHex(CBlock(), node.getblock(block_hash, False))
        assert_equal(CBlockHeader(unhashed).sha256, None)
        assert_equal(CBlockHeader(block).hash, block_hash)

        self.log.info("Older headers use the time-based N-factor; check both sides of its first steps")
        header = CBlockHeader(block)
        header.nVersion = 6
        for step in (1368515488, 1368777632, 1369039776, 1369826208):
            for ntime in (step - 1, step):
                header.nTime = ntime
                header.rehash()
                assert_equal(header.hash, block_hash_rpc(node, header))
        self.log.info("A version 7 header with a time beyond 32 bits")
        header.nVersion = 7
        header.nTime = 2**32 + 5
        header.rehash()
        assert_equal(header.hash, block_hash_rpc(node, header))


if __name__ == '__main__':
    FrameworkBlocksTest().main()
