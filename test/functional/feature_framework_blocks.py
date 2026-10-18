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
- create_block_yac / solve_block build blocks the node accepts, through
  submitblock and P2P, on the tip (also at a retarget height) and on
  another parent; assert_block_accepted / assert_block_rejected.
- blocks_from_node takes blocks from an unconnected donor node; the two
  merkle mutations keep the header and are rejected with their reasons.
- yac_tx signs P2PKH, P2SH CLTV and P2SH CSV spends the node accepts, builds
  the wallet's timelock redeem scripts and the node's token scripts, and
  makes version 1 copies; address.py encodes YACoin addresses.
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
from test_framework.address import key_to_p2pkh, script_to_p2sh
from test_framework.blocktools import (
    assert_block_accepted,
    assert_block_rejected,
    block_hash_rpc,
    blocks_from_node,
    create_block_yac,
    get_template,
    mutate_duplicate_last_tx,
    mutate_merkle_mismatch,
    solve_block,
)
from test_framework.scrypt_jane import keccak512, scrypt_jane
from test_framework.mininode import P2PDataStore, P2PInterface, mininode_lock
from test_framework.script import CScript, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160, OP_NOP4
from test_framework.yac_tx import (
    cltv_p2sh_redeem_script,
    csv_p2sh_redeem_script,
    key_from_wif,
    p2pkh_script,
    p2sh_script,
    sign_p2pkh_input,
    sign_p2sh_input,
    to_v1,
    token_issue_script,
    token_owner_script,
    token_reissue_script,
    token_transfer_script,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    NFACTOR_AT_HARDFORK,
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    peers,
    wait_until,
)


class FrameworkBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Tokens for the token script checks.
        self.extra_args = [["-tokenSupportBlockNumber=5"], []]

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
        self.test_build_blocks()
        self.test_donor_blocks()
        self.test_signing()
        self.test_token_scripts()

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

    def test_build_blocks(self):
        node = self.nodes[0]
        self.log.info("getblocktemplate needs a peer; get_template says so")
        assert_raises_rpc_error(-9, "Yacoin is not connected!", node.getblocktemplate)
        try:
            get_template(node)
        except AssertionError as e:
            assert "needs a connected peer" in str(e), str(e)
        else:
            raise AssertionError("get_template did not fail without a peer")
        self.store = node.add_p2p_connection(P2PDataStore())

        self.log.info("A template block, solved through the node, is accepted by submitblock")
        block = solve_block(node, create_block_yac(node))
        assert_block_accepted(node, block)
        assert_equal(node.submitblock(block.serialize().hex()), "duplicate")

        self.log.info("The coinbase has the node's shape: version 2, block time, height first")
        own = FromHex(CTransaction(), node.getrawtransaction(node.getblock(node.getblockhash(12))['tx'][0]))
        assert_equal((own.nVersion, own.nTime), (2, node.getblockheader(node.getblockhash(12))['time']))
        # The height check compares this prefix (CScript() << nHeight).
        assert own.vin[0].scriptSig.startswith(bytes(CScript([12])))
        assert block.vtx[0].vin[0].scriptSig.startswith(bytes(CScript([13])))
        assert_equal((block.vtx[0].nVersion, block.vtx[0].nTime), (2, block.nTime))

        self.log.info("Two default blocks on the same parent differ")
        tmpl = get_template(node)
        first, second = create_block_yac(node, tmpl=tmpl), create_block_yac(node, tmpl=tmpl)
        assert first.calc_merkle_root() != second.calc_merkle_root()
        try:
            create_block_yac(node, height=5)
        except ValueError as e:
            assert "pass coinbase=" in str(e), str(e)
        else:
            raise AssertionError("create_block_yac ignored height= on the tip")

        self.log.info("assert_block_rejected: coinbase above the template's value")
        assert_block_rejected(node, solve_block(node, create_block_yac(node, coinbase_value=tmpl['coinbasevalue'] + 1)), "bad-cb-amount")

        self.log.info("A block through P2P: headers, getdata by block hash, block")
        block = solve_block(node, create_block_yac(node))
        self.store.send_blocks_and_test([block], node)

        self.log.info("At a retarget height the template's nBits differ from the tip's")
        interval = node.getmininginfo()['Difficulty Interval']
        while (node.getblockcount() + 1) % interval:
            # Faster than the 60 s spacing, so the target changes.
            self.generate_to(node, 1, spacing=20)
        self.set_mocktime(self.mocktime + 20)
        tmpl = get_template(node)
        tip = node.getbestblockhash()
        assert int(tmpl['bits'], 16) != int(node.getblockheader(tip)['bits'], 16)
        try:
            create_block_yac(node, prev=tip)
        except ValueError as e:
            assert "pass nbits" in str(e), str(e)
        else:
            raise AssertionError("create_block_yac took the parent's nBits at a retarget height")
        assert_block_accepted(node, solve_block(node, create_block_yac(node, tmpl=tmpl)))

        self.log.info("Blocks on another parent: a side block, then a longer branch")
        parent = node.getbestblockhash()
        assert_block_accepted(node, solve_block(node, create_block_yac(node)))
        side = solve_block(node, create_block_yac(node, prev=parent))
        assert_equal(node.submitblock(side.serialize().hex()), "inconclusive")
        assert node.getbestblockhash() != side.hash
        child = solve_block(node, create_block_yac(node, prev=side, height=node.getblockcount() + 1))
        assert_block_accepted(node, child)

        self.log.info("solve_block(invalid=True): proof-of-work failures have no reason string (C-S12)")
        assert_block_rejected(node, solve_block(node, create_block_yac(node), invalid=True), "rejected")

    def test_donor_blocks(self):
        node, donor = self.nodes
        self.log.info("A donor node shares the chain, then mines blocks with transactions on its own")
        connect_nodes(donor, 0)
        self.sync_blocks()
        disconnect_nodes(donor, 0)
        # Node 0 keeps only the P2PDataStore connection.
        wait_until(lambda: peers(donor) == [] and len(peers(node)) == 1)
        # The donor's wallet spends the coinbases of PRIV_KEYS[0].
        donor.importprivkey(TestNode.PRIV_KEYS[0].key)
        hashes = []
        for _ in range(2):
            self.set_mocktime(self.mocktime + 60)
            donor.sendtoaddress(address=donor.getnewaddress(), amount=1)
            donor.sendtoaddress(address=donor.getnewaddress(), amount=2)
            hashes += donor.generate(1)
        blocks = blocks_from_node(donor, hashes)
        assert_equal([b.hash for b in blocks], hashes)
        assert_equal([len(b.vtx) for b in blocks], [3, 3])

        self.log.info("A copy with the last transaction duplicated keeps the hash and is rejected; the block is accepted")
        duplicated = mutate_duplicate_last_tx(blocks[0])
        duplicated.rehash()
        assert_equal(duplicated.hash, hashes[0])
        assert_block_rejected(node, duplicated, "bad-txns-duplicate")
        assert_block_accepted(node, blocks[0])

        self.log.info("A copy whose transactions don't match the merkle root is rejected; the block is accepted")
        mismatch = mutate_merkle_mismatch(blocks[1])
        assert_equal(mismatch.hashMerkleRoot, blocks[1].hashMerkleRoot)
        assert_block_rejected(node, mismatch, "bad-txnmrklroot")
        assert_block_accepted(node, blocks[1])

        self.log.info("Further donor blocks reach the node through P2PDataStore")
        hashes = self.mine_with_mocktime(donor, 3, sync=False)
        self.store.send_blocks_and_test(blocks_from_node(donor, hashes), node)
        assert_equal(node.getbestblockhash(), hashes[-1])

    def unspent_coinbases(self, count):
        """(txid, value) of mature, unspent coinbases paying PRIV_KEYS[0]."""
        node = self.nodes[0]
        script = p2pkh_script(self.key.get_pubkey().get_bytes()).hex()
        found = []
        for height in range(1, node.getblockcount() - 6):
            txid = node.getblock(node.getblockhash(height))['tx'][0]
            out = node.gettxout(txid, 0)
            if out is not None and out['scriptPubKey']['hex'] == script:
                found.append((txid, int(out['value'] * COIN)))
        assert len(found) >= count
        return found[:count]

    def test_signing(self):
        node = self.nodes[0]
        self.log.info("key_from_wif and key_to_p2pkh give TestNode.PRIV_KEYS[0] and its address")
        self.key = key_from_wif(TestNode.PRIV_KEYS[0].key)
        pubkey = self.key.get_pubkey().get_bytes()
        assert_equal(key_to_p2pkh(pubkey), TestNode.PRIV_KEYS[0].address)
        assert_equal(node.validateaddress(TestNode.PRIV_KEYS[0].address)['scriptPubKey'], p2pkh_script(pubkey).hex())

        self.log.info("A P2PKH spend signed in Python (legacy sighash with nTime) is accepted")
        (spend_txid, spend_value), (fund_txid, fund_value) = self.unspent_coinbases(2)
        tx = CTransaction()
        tx.nTime = self.mocktime
        tx.vin = [CTxIn(COutPoint(int(spend_txid, 16), 0))]
        tx.vout = [CTxOut(spend_value - COIN // 100, p2pkh_script(pubkey))]
        sign_p2pkh_input(tx, 0, self.key)
        assert_equal(node.sendrawtransaction(tx.serialize().hex()), tx.hash)

        self.log.info("to_v1: a version 1 copy with a 32-bit nTime, signed after converting")
        v1 = to_v1(tx)
        assert_equal(len(v1.serialize()), len(tx.serialize()) - 4)
        sign_p2pkh_input(v1, 0, self.key)
        decoded = node.decoderawtransaction(v1.serialize().hex())
        assert_equal((decoded['version'], decoded['txid']), (1, v1.hash))

        self.log.info("The timelock redeem scripts and P2SH addresses match the wallet's")
        for locktime in (5, 100, 1700000000):
            created = node.createcltvaddress(locktime)
            redeem = bytes.fromhex(created['redeemScript'])
            assert_equal(cltv_p2sh_redeem_script(locktime, list(CScript(redeem))[3]), redeem)
            assert_equal(script_to_p2sh(redeem), created['cltv address'])
        created = node.createcsvaddress(5, True)
        redeem = bytes.fromhex(created['redeemScript'])
        assert_equal(csv_p2sh_redeem_script(5, list(CScript(redeem))[3]), redeem)
        assert_equal(script_to_p2sh(redeem), created['csv address'])

        self.log.info("P2SH CLTV and CSV outputs, spent with Python signatures")
        height = node.getblockcount()
        cltv = cltv_p2sh_redeem_script(height, pubkey)
        csv = csv_p2sh_redeem_script(2, pubkey)
        fund = CTransaction()
        fund.nTime = self.mocktime
        fund.vin = [CTxIn(COutPoint(int(fund_txid, 16), 0))]
        half = (fund_value - COIN // 100) // 2
        fund.vout = [CTxOut(half, p2sh_script(cltv)), CTxOut(half, p2sh_script(csv))]
        sign_p2pkh_input(fund, 0, self.key)
        assert_equal(node.sendrawtransaction(fund.serialize().hex()), fund.hash)
        self.generate_to(node, 1)

        cltv_spend = CTransaction()
        cltv_spend.nTime = self.mocktime
        cltv_spend.nLockTime = height
        cltv_spend.vin = [CTxIn(COutPoint(fund.sha256, 0), nSequence=0xfffffffe)]
        cltv_spend.vout = [CTxOut(half - COIN // 100, p2pkh_script(pubkey))]
        sign_p2sh_input(cltv_spend, 0, cltv, [self.key])
        assert_equal(node.sendrawtransaction(cltv_spend.serialize().hex()), cltv_spend.hash)

        csv_spend = CTransaction()
        csv_spend.nTime = self.mocktime
        csv_spend.vin = [CTxIn(COutPoint(fund.sha256, 1), nSequence=2)]
        csv_spend.vout = [CTxOut(half - COIN // 100, p2pkh_script(pubkey))]
        sign_p2sh_input(csv_spend, 0, csv, [self.key])
        assert_raises_rpc_error(-26, "64: non-BIP68-final", node.sendrawtransaction, csv_spend.serialize().hex())
        self.generate_to(node, 1)
        assert_equal(node.sendrawtransaction(csv_spend.serialize().hex()), csv_spend.hash)
        self.generate_to(node, 1)
        assert_equal(node.getrawmempool(), [])

    def token_outputs(self, txid):
        tx = FromHex(CTransaction(), self.nodes[0].getrawtransaction(txid))
        # Match the OP_YAC_TOKEN opcode, not the byte: a key hash can contain 0xb3
        return [bytes(out.scriptPubKey) for out in tx.vout if OP_NOP4 in list(out.scriptPubKey)]

    def test_token_scripts(self):
        node = self.nodes[0]
        self.log.info("Token issue, owner, reissue and owner transfer scripts match the node's")
        node.importprivkey(TestNode.PRIV_KEYS[0].key)
        address = node.getnewaddress()
        prefix = bytes.fromhex(node.validateaddress(address)['scriptPubKey'])
        issue_txid = node.issue("PYTOKEN", 1000, 2, True, False, "", address, "")
        self.generate_to(node, 1)
        assert_equal(sorted(self.token_outputs(issue_txid)),
                     sorted([bytes(token_issue_script(prefix, "PYTOKEN", 1000 * COIN, 2, True)),
                             bytes(token_owner_script(prefix, "PYTOKEN"))]))
        reissue_txid = node.reissue("PYTOKEN", 5, True, address)
        outputs = self.token_outputs(reissue_txid)
        assert bytes(token_reissue_script(prefix, "PYTOKEN", 5 * COIN)) in outputs
        # The owner token goes back to a change address of the wallet.
        owner_back = [o for o in outputs if b"yact" in o]
        assert_equal(len(owner_back), 1)
        assert_equal(owner_back[0], bytes(token_transfer_script(owner_back[0][:25], "PYTOKEN!", COIN)))


if __name__ == '__main__':
    FrameworkBlocksTest().main()
