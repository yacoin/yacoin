#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Utilities for building, solving and submitting YACoin blocks.

Building a block on the node's tip:

    node.add_p2p_connection(P2PInterface())  # getblocktemplate needs a peer
    block = create_block_yac(node, txs)
    solve_block(node, block)
    assert_block_accepted(node, block)

The template supplies nBits (which changes at retarget heights), the block
time and the coinbase value (which follows the money supply). These helpers
build post-fork blocks (version 7) only.
"""
import itertools
from io import BytesIO

from .authproxy import JSONRPCException
from .messages import (
    BLOCK_VERSION,
    CBlock,
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    FromHex,
    TX_VERSION,
    hex_str_to_bytes,
    uint256_from_compact,
)
from .script import (
    CScript,
    CScriptNum,
    CScriptOp,
    OP_1,
    OP_TRUE,
)
from .util import assert_equal

# The node's limit is GetMaxSize(MAX_BLOCK_SIGOPS), which follows the money
# supply (getblocktemplate's sigoplimit); 20000 on the suite's young chains.
MAX_BLOCK_SIGOPS = 20000

# Genesis block time (nChainStartTime)
TIME_GENESIS_BLOCK = 1367991200

# Makes every default coinbase unique, so two blocks built on the same parent
# with the same transactions differ.
_coinbase_counter = itertools.count(1)


def block_hash_rpc(node, header):
    """The node's block hash (hex) of a CBlockHeader or CBlock, computed by
    the node through calculatescrypthash. That RPC checks the length and the
    decoding of its input; calculateblockhash doesn't."""
    return node.calculatescrypthash(CBlockHeader.serialize(header).hex())['hash_BE']


def script_BIP34_coinbase_height(height):
    if height <= 16:
        res = CScriptOp.encode_op_n(height)
        # Append dummy to increase scriptSig size above 2 (see bad-cb-length consensus rule)
        return CScript([res, OP_1])
    return CScript([CScriptNum(height)])


def create_coinbase_yac(height, ntime, value, script_pubkey=CScript([OP_TRUE]), extra_script=None):
    """A coinbase as the node's miner makes it: version 2, nTime equal to
    the block time, scriptSig starting with the height (bad-cb-height), one
    output.

    extra_script is appended to the scriptSig; by default a counter that
    makes every coinbase unique. An OP_TRUE output is non-standard to spend
    in the mempool: spend it only in hand-built blocks, or pay to a key."""
    if extra_script is None:
        extra_script = CScript([CScriptNum(next(_coinbase_counter))])
    coinbase = CTransaction()
    coinbase.nVersion = TX_VERSION
    coinbase.nTime = ntime
    # bytes concatenation: CScript + CScript would push the right side as data
    script_sig = CScript(bytes(script_BIP34_coinbase_height(height)) + bytes(extra_script))
    coinbase.vin = [CTxIn(COutPoint(0, 0xffffffff), script_sig, 0xffffffff)]
    coinbase.vout = [CTxOut(value, script_pubkey)]
    coinbase.rehash()
    return coinbase


def get_template(node):
    """getblocktemplate, with a clear error when the node has no peer.

    The node caches the template until the tip changes, or until the mempool
    changed and more than 5 seconds passed (mocktime seconds if the test set
    mocktime). Move the mocktime more than 5 s after adding transactions."""
    try:
        return node.getblocktemplate()
    except JSONRPCException as e:
        if e.error['code'] == -9:
            raise AssertionError("getblocktemplate needs a connected peer, "
                                 "e.g. node.add_p2p_connection(P2PInterface())")
        raise


def txs_from_template(tmpl):
    """The template's transactions as CTransaction objects."""
    return [FromHex(CTransaction(), t['data']) for t in tmpl['transactions']]


def create_block_yac(node, txs=(), *, tmpl=None, prev=None, height=None, ntime=None, nbits=None,
                     coinbase_value=None, script_pubkey=None, coinbase=None):
    """Build an unsolved version 7 block (solve it with solve_block).

    On the tip (prev=None): height, nBits, block time and coinbase value come
    from getblocktemplate (tmpl, or a fresh one).

    On another parent (prev = a block hash the node knows, or a CBlock built
    earlier together with height=): nBits defaults to the parent's, the time
    to the parent's time + 1 and the coinbase value to 0 (paying less than
    the reward is valid). nbits must be given where the target changes: at
    heights 1 and 2, after a pre-fork parent, and at retarget heights
    (multiples of getmininginfo's "Difficulty Interval").

    ntime, nbits and coinbase_value override the defaults; script_pubkey is
    the coinbase output (OP_TRUE by default). coinbase replaces the whole
    coinbase transaction, e.g. one with a wrong height built with
    create_coinbase_yac. txs follow the coinbase in the given order; their
    nTime must not be later than the block time.

    Arguments that would be ignored are refused: height except with a CBlock
    parent, tmpl with prev, coinbase_value or script_pubkey with coinbase."""
    if height is not None and not isinstance(prev, CBlock):
        raise ValueError("height is only for a CBlock parent; for a wrong coinbase height pass coinbase=")
    if tmpl is not None and prev is not None:
        raise ValueError("tmpl is only for blocks on the tip (prev=None)")
    if coinbase is not None and (coinbase_value is not None or script_pubkey is not None):
        raise ValueError("coinbase replaces coinbase_value and script_pubkey")
    if script_pubkey is None:
        script_pubkey = CScript([OP_TRUE])
    if prev is None:
        if tmpl is None:
            tmpl = get_template(node)
        if tmpl['version'] < BLOCK_VERSION:
            raise ValueError("create_block_yac builds post-fork (version 7) blocks only")
        prev_hash = int(tmpl['previousblockhash'], 16)
        height = tmpl['height']
        default_nbits = int(tmpl['bits'], 16)
        default_ntime = tmpl['curtime']
        default_value = tmpl['coinbasevalue']
    else:
        if isinstance(prev, CBlock):
            assert height is not None, "pass height= with a CBlock parent"
            prev.calc_sha256()
            prev_hash = prev.sha256
            parent_version, parent_time, parent_bits = prev.nVersion, prev.nTime, prev.nBits
        else:
            parent = node.getblockheader(prev)
            prev_hash = int(prev, 16)
            height = parent['height'] + 1
            parent_version, parent_time, parent_bits = parent['version'], parent['time'], int(parent['bits'], 16)
        if nbits is None:
            interval = node.getmininginfo()['Difficulty Interval']
            if height <= 2 or parent_version < BLOCK_VERSION or height % interval == 0:
                raise ValueError("the target changes at height %d: pass nbits" % height)
        default_nbits = parent_bits
        default_ntime = parent_time + 1
        default_value = 0
    block = CBlock()
    block.nVersion = BLOCK_VERSION
    block.hashPrevBlock = prev_hash
    block.nTime = default_ntime if ntime is None else ntime
    block.nBits = default_nbits if nbits is None else nbits
    if coinbase is None:
        coinbase = create_coinbase_yac(height, block.nTime,
                                       default_value if coinbase_value is None else coinbase_value,
                                       script_pubkey)
    block.vtx = [coinbase] + list(txs)
    block.hashMerkleRoot = block.calc_merkle_root()
    return block


def solve_block(node, block, *, max_tries=1 << 16, invalid=False):
    """Set block.nNonce so that the block hash meets its target (or, with
    invalid=True, doesn't), counting up from the current nonce.

    The hashes come from the node (calculatescrypthash, batched): Python
    takes about 10 ms per hash, and the suite's targets need a few hundred
    tries. Every call writes a few lines to the node's debug.log. The found
    hash is checked against the Python one. Returns the block."""
    target = uint256_from_compact(block.nBits)
    expected_tries = (1 << 256) // (target + 1)
    batch = 16 if invalid else max(16, min(512, 2 * expected_tries))
    header = CBlockHeader(block)
    nonce = block.nNonce
    while nonce - block.nNonce < max_tries:
        requests = []
        for n in range(nonce, nonce + batch):
            header.nNonce = n
            requests.append(node.calculatescrypthash.get_request(CBlockHeader.serialize(header).hex()))
        for n, response in zip(range(nonce, nonce + batch), node.batch(requests)):
            assert response['error'] is None, response['error']
            block_hash = response['result']['hash_BE']
            if (int(block_hash, 16) > target) == invalid:
                block.nNonce = n
                block.rehash()
                assert_equal(block.hash, block_hash)
                return block
        nonce += batch
    raise AssertionError("no nonce found in %d tries (nBits %08x)" % (max_tries, block.nBits))


def assert_block_accepted(node, block, *, tip=True):
    """submitblock accepts the block (returns None), and with tip=True it
    becomes the node's tip.

    A valid block that doesn't become the tip (a side block) returns
    "inconclusive", not None: assert that directly. tip=False is for a block
    that gets connected while another block ends up as the tip."""
    block.calc_sha256()
    assert_equal(node.submitblock(block.serialize().hex()), None)
    if tip:
        assert_equal(node.getbestblockhash(), block.hash)


def assert_block_rejected(node, block, reason):
    """submitblock returns exactly reason and the tip doesn't move.

    What the node returns:
    - "rejected" for failures without a reason string (proof of work,
      missing inputs);
    - "block-validation-failed" for script failures, unless the node runs
      with -par=1, which gives the mandatory-script-verify-flag-failed reason;
    - "inconclusive" for a block that doesn't become the tip and passes the
      checks before connecting (failures found when connecting it, such as
      bad-cb-amount, scripts or inputs, show only for a block on the tip;
      merkle, proof-of-work, nBits and time failures show on any block);
    - "duplicate" / "duplicate-invalid" for a block the node already has."""
    tip = node.getbestblockhash()
    assert_equal(node.submitblock(block.serialize().hex()), reason)
    assert_equal(node.getbestblockhash(), tip)


def create_tx_with_script(prevtx, n, script_sig=b"", *, amount, script_pub_key=CScript(), ntime=None):
    """Return one-input, one-output transaction object
       spending the prevtx's n-th output with the given amount.

       Can optionally pass scriptPubKey and scriptSig, default is anyone-can-spend output.
       ntime defaults to prevtx.nTime: a spend may not be older than its
       input (bad-txns-spent-too-early), nor newer than its block.
    """
    tx = CTransaction()
    tx.nTime = prevtx.nTime if ntime is None else ntime
    assert n < len(prevtx.vout)
    prevtx.calc_sha256()
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), script_sig, 0xffffffff))
    tx.vout.append(CTxOut(amount, script_pub_key))
    tx.calc_sha256()
    return tx


def create_transaction(node, txid, to_address, *, amount):
    """ Return signed transaction spending the first output of the
        input txid. Note that the node must be able to sign for the
        output that is being spent, and the node must not be running
        multiple wallets.
    """
    raw_tx = create_raw_transaction(node, txid, to_address, amount=amount)
    tx = CTransaction()
    tx.deserialize(BytesIO(hex_str_to_bytes(raw_tx)))
    return tx


def create_raw_transaction(node, txid, to_address, *, amount):
    """ Return raw signed transaction spending the first output of the
        input txid. Note that the node must be able to sign for the
        output that is being spent, and the node must not be running
        multiple wallets.
    """
    rawtx = node.createrawtransaction(inputs=[{"txid": txid, "vout": 0}], outputs={to_address: amount})
    signresult = node.signrawtransaction(rawtx)
    assert_equal(signresult["complete"], True)
    return signresult['hex']


def get_legacy_sigopcount_block(block, accurate=True):
    count = 0
    for tx in block.vtx:
        count += get_legacy_sigopcount_tx(tx, accurate)
    return count


def get_legacy_sigopcount_tx(tx, accurate=True):
    count = 0
    for i in tx.vout:
        count += i.scriptPubKey.GetSigOpCount(accurate)
    for j in tx.vin:
        # scriptSig might be of type bytes, so convert to CScript for the moment
        count += CScript(j.scriptSig).GetSigOpCount(accurate)
    return count
