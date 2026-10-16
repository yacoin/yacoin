#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test token state across reorgs, restarts and reindexes.

- Three nodes split into {0, 1} and {2}. Node 0 issues, reissues and
  transfers tokens on a 30-block branch; node 2 issues other tokens and
  transfers on a 31-block branch. After the join every node must show node
  2's token state: the losing branch's issues, sub and unique tokens,
  reissues and transfers (including transferfromaddress) are undone, its
  transactions are gone from the mempool, and the winning branch's tokens are
  present (token DB, token address index, address index, wallets).
- The state survives a restart, -reindex and -reindex-fast.
- A reissue that was flushed to the token DB and then reorged away is undone
  from the DB, including its token address entry.

Node 0 mines nothing on the common chain, so its side-branch transactions
depend on side-branch coinbases and can't return to the mempool after the
reorg.
"""

from decimal import Decimal

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    disconnect_nodes,
)

IPFS1 = "QmcvyefkqQX3PpjpY5L8B2yMd47XrVwAipr6cxUt2zvYU8"
IPFS1_V1 = "bafybeigyz3d6i6dpwfgdsvrwdoxxh7vuy7zl35c2ceoab2jipnmzzkvrhe"
IPFS2 = "QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"
IPFS2_V1 = "bafybeifwk6tdgqf3ee2wfsqgsbqegd43r44b2e7bpo67txg4awfhgvkonq"

NAMES = ["REORG", "REORG!", "REORG/SUB", "REORG/SUB!", "REORG#U1",
         "OTHER", "OTHER!", "BSIDE", "BSIDE!", "FLUSHME", "FLUSHME!"]

ZERO_ENTRIES = "zero-balance entries after a reorg (rX9HGVUZ item 8)"
ZERO_BLOCKHASH = "zero block hash after a reissue is undone (rX9HGVUZ item 2)"
RESTORED_HEIGHT = "address index height of restored UTXOs (KXUa7eJZ)"


def without(d, keys):
    return {k: v for k, v in d.items() if k not in keys}


class TokenReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        # -reindex with the fork at block 0 doesn't work (card XpHqZPNh).
        self.block_fork_1_0 = 1
        self.extra_args = [["-tokenindex=1", "-addressindex=1", "-tokenSupportBlockNumber=10"]] * 3

    def state(self, node):
        """Token state as the RPCs show it.

        The listing RPCs flush the token cache to the token DB
        (FlushStateToDisk in CTokensDB::TokenDir/AddressDir/TokenAddressDir),
        so they run before gettokendata."""
        return {
            "listtokens": node.listtokens("*", True),
            "byname": {name: node.listaddressesbytoken(name) for name in NAMES},
            "byaddress": {a: node.listtokenbalancesbyaddress(a) for a in self.addrs},
            "tokendata": {name: node.gettokendata(name) for name in NAMES},
            "utxos": node.getaddressutxos({"addresses": self.addrs, "tokenName": "*"}),
            "moneysupply": node.getinfo()["moneysupply"],
            "tip": node.getbestblockhash(),
            "mempool": node.getrawmempool(),
        }

    def run_test(self):
        self.set_mocktime(TIME_GENESIS_BLOCK)
        self.common_chain()
        self.side_a()
        self.side_b()
        self.join()
        self.persistence()
        self.reissue_undo_after_flush()

    def common_chain(self):
        self.log.info("Mine the common chain on node 2 and issue FLUSHME")
        n0, n1, n2 = self.nodes
        self.mine_with_mocktime(n2, 45)
        self.a0, self.a0r, self.aS, self.aU = [n0.getnewaddress() for _ in range(4)]
        self.a1, self.a1b = n1.getnewaddress(), n1.getnewaddress()
        self.a2, self.a2f, self.a2F, self.a2x = [n2.getnewaddress() for _ in range(4)]
        self.addrs = [self.a0, self.a0r, self.aS, self.aU, self.a1, self.a1b,
                      self.a2, self.a2f, self.a2F, self.a2x]
        n2.issue(token_name="FLUSHME", qty=100, units=2, reissuable=True, has_ipfs=True,
                 ipfs_hash=IPFS1, to_address=self.a2f)
        self.mine_with_mocktime(n2, 1)
        self.h_flush = n2.getblockcount()
        assert_equal(n0.listunspent(), [])

    def side_a(self):
        self.log.info("Side A: node 0 issues, reissues and transfers tokens")
        n0, n1, n2 = self.nodes
        disconnect_nodes(n1, 2)
        disconnect_nodes(n2, 1)
        # Enough mature side-A coinbases for five issues and reissues.
        self.mine_with_mocktime(n0, 26, sync=[n0, n1])
        n0.issue(token_name="REORG", qty=1000, units=4, reissuable=True, has_ipfs=True,
                 ipfs_hash=IPFS1, to_address=self.a0)
        self.mine_with_mocktime(n0, 1, sync=[n0, n1])
        n0.issue(token_name="REORG/SUB", qty=100, units=2, reissuable=True, has_ipfs=False, to_address=self.aS)
        n0.issue(token_name="REORG#U1", qty=1, units=0, reissuable=False, has_ipfs=False, to_address=self.aU)
        self.mine_with_mocktime(n0, 1, sync=[n0, n1])
        n0.reissue(token_name="REORG", qty=500, reissuable=False, to_address=self.a0r, change_address="",
                   new_units=6, new_ipfs=IPFS2)
        n0.reissue(token_name="REORG/SUB", qty=10, reissuable=True, to_address=self.aS, change_address="",
                   new_units=3, new_ipfs=IPFS2)
        self.mine_with_mocktime(n0, 1, sync=[n0, n1])
        n0.transferfromaddress("REORG", self.a0r, 50, self.a1b)
        n0.transfer("REORG", 200, self.a1)
        self.mine_with_mocktime(n0, 1, sync=[n0, n1])

        # The listings write side A into both token DBs, as the hourly flush
        # or any listing call would on a real node.
        sa0, sa1 = self.state(n0), self.state(n1)
        assert_equal(sa0["byname"], sa1["byname"])
        assert_equal(sa0["tokendata"], sa1["tokendata"])
        assert_equal(sa0["tokendata"]["REORG"], {
            "name": "REORG", "token_type": "YA-token", "amount": "1500.000000", "units": 6,
            "reissuable": 0, "has_ipfs": 1, "ipfs_hash_cidv0": IPFS2, "ipfs_hash_cidv1": IPFS2_V1})
        assert_equal(sa0["tokendata"]["REORG/SUB"], {
            "name": "REORG/SUB", "token_type": "Sub-token", "amount": "110.000", "units": 3,
            "reissuable": 1, "has_ipfs": 1, "ipfs_hash_cidv0": IPFS2, "ipfs_hash_cidv1": IPFS2_V1})
        holders = sa0["byname"]["REORG"]
        assert_equal(sum(Decimal(v) for v in holders.values()), Decimal("1500"))
        assert_equal((holders[self.a1], holders[self.a1b]), ("200.000000", "50.000000"))
        assert self.a0 not in holders and self.a0r not in holders
        assert_equal(n1.listmytokens(), {"REORG": "250.000000"})

    def side_b(self):
        self.log.info("Side B: node 2 issues other tokens on a longer branch")
        n2 = self.nodes[2]
        n2.issue(token_name="OTHER", qty=1, units=0, reissuable=True, has_ipfs=False, to_address=self.a2)
        n2.issue(token_name="BSIDE", qty=50, units=1, reissuable=True, has_ipfs=True,
                 ipfs_hash=IPFS2, to_address=self.a2)
        n2.transfer("FLUSHME", 10, self.a2x)
        self.mine_with_mocktime(n2, 31, sync=[n2])
        self.sb = sb = self.state(n2)
        self.sb_mine = n2.listmytokens()
        for name in ["REORG", "REORG!", "REORG/SUB", "REORG/SUB!", "REORG#U1"]:
            assert_equal(sb["tokendata"][name], None)
            assert_equal(sb["byname"][name], {})
        assert_equal(sb["tokendata"]["OTHER"], {
            "name": "OTHER", "token_type": "YA-token", "amount": "1", "units": 0,
            "reissuable": 1, "has_ipfs": 0})
        assert_equal(sb["tokendata"]["BSIDE"], {
            "name": "BSIDE", "token_type": "YA-token", "amount": "50.0", "units": 1,
            "reissuable": 1, "has_ipfs": 1, "ipfs_hash_cidv0": IPFS2, "ipfs_hash_cidv1": IPFS2_V1})
        assert_equal(sb["byname"]["FLUSHME"][self.a2x], "10.00")
        assert_equal(sorted(sb["byname"]["FLUSHME"].values()), ["10.00", "90.00"])
        assert_equal(self.sb_mine, {"BSIDE": "50.0", "BSIDE!": "1", "FLUSHME": "100.00", "FLUSHME!": "1",
                                    "OTHER": "1", "OTHER!": "1"})

    def join(self):
        self.log.info("Join: nodes 0 and 1 reorg to side B")
        n0, n1, n2 = self.nodes
        sb = self.sb
        connect_nodes(n1, 2)
        self.sync_blocks()
        zero_names = ["REORG", "REORG!", "REORG/SUB!"]
        zero_addrs = [self.a0, self.a0r, self.aS]
        for node in self.nodes:
            st = self.state(node)
            for key in ["listtokens", "tokendata", "utxos", "moneysupply", "tip", "mempool"]:
                assert_equal(st[key], sb[key])
            # Nodes that saw side A after it was flushed keep its token
            # address entries with a zero balance.
            reorged = node is not n2
            for name in NAMES:
                got = st["byname"][name]
                if reorged and name in zero_names:
                    assert all(Decimal(v) == 0 for v in got.values()), got
                    self.known_failure(ZERO_ENTRIES, lambda: assert_equal(got, sb["byname"][name]), " == {})")
                else:
                    assert_equal(got, sb["byname"][name])
            for a in self.addrs:
                got = st["byaddress"][a]
                if reorged and a in zero_addrs:
                    assert all(Decimal(v) == 0 for v in got.values()), got
                    self.known_failure(ZERO_ENTRIES, lambda: assert_equal(got, sb["byaddress"][a]), " == {})")
                else:
                    assert_equal(got, sb["byaddress"][a])
        assert_equal(n0.listmytokens(), {})
        assert_equal(n1.listmytokens(), {})
        assert_equal(n2.listmytokens(), self.sb_mine)

    def persistence(self):
        self.log.info("Restart node 0, -reindex node 1, -reindex-fast node 2")
        n0, n1, n2 = self.nodes
        pre0, pre2 = self.state(n0), self.state(n2)
        self.restart_node(0)
        self.restart_node(1, self.extra_args[1] + ["-reindex"])
        self.restart_node(2, self.extra_args[2] + ["-reindex-fast"])
        connect_nodes(n1, 0)
        connect_nodes(n2, 1)
        self.sync_blocks()
        assert_equal(self.state(n0), pre0)
        assert_equal(self.state(n2), pre2)
        # The reindex connects side A first and then reorgs to side B, in
        # block file order, without a flush in between.
        assert_equal(self.state(n1), pre2)

    def reissue_undo_after_flush(self):
        """Last step: the reissue goes back to the mempool, nothing is mined after it."""
        self.log.info("Undo a reissue that was flushed to the token DB")
        n0, n1, n2 = self.nodes
        disconnect_nodes(n1, 0)
        disconnect_nodes(n0, 1)
        # A fresh address, so undoing the reissue takes its balance to 0.
        n2.reissue(token_name="FLUSHME", qty=10, reissuable=False, to_address=self.a2F, change_address="",
                   new_units=4, new_ipfs=IPFS2)
        self.mine_with_mocktime(n2, 1, sync=[n1, n2])
        h_reissue = n2.getblockcount()
        holders = n2.listaddressesbytoken("FLUSHME")
        assert_equal(holders[self.a2F], "10.0000")
        assert_equal(sum(Decimal(v) for v in holders.values()), Decimal("110"))
        assert_equal(n2.gettokendata("FLUSHME"), {
            "name": "FLUSHME", "token_type": "YA-token", "amount": "110.0000", "units": 4,
            "reissuable": 0, "has_ipfs": 1, "ipfs_hash_cidv0": IPFS2, "ipfs_hash_cidv1": IPFS2_V1})
        # The restart empties node 2's token caches, so the undo reads the
        # balances from the DB. Node 1 gets no listing call before the reorg,
        # so it connects and undoes the reissue without a flush in between.
        self.restart_node(2)
        connect_nodes(n2, 1)
        self.mine_with_mocktime(n0, 2, sync=[n0])
        ref_holders = n0.listaddressesbytoken("FLUSHME")
        ref_owner = n0.listaddressesbytoken("FLUSHME!")
        ref_listing = n0.listtokens("FLUSHME", True)["FLUSHME"]
        utxo_addrs = sorted(set(ref_holders) | {self.a2f, self.a2F})
        ref_utxos = {t: n0.getaddressutxos({"addresses": utxo_addrs, "tokenName": t})
                     for t in ["FLUSHME", "FLUSHME!"]}
        assert_equal((ref_listing["block_height"], ref_listing["blockhash"]),
                     (self.h_flush, n0.getblockhash(self.h_flush)))
        assert self.a2F not in ref_holders
        connect_nodes(n1, 0)
        self.sync_blocks()

        orig = {"name": "FLUSHME", "token_type": "YA-token", "amount": "100.00", "units": 2,
                "reissuable": 1, "has_ipfs": 1, "ipfs_hash_cidv0": IPFS1, "ipfs_hash_cidv1": IPFS1_V1}
        for node in self.nodes:
            assert_equal(node.listaddressesbytoken("FLUSHME"), ref_holders)
            assert_equal(node.listaddressesbytoken("FLUSHME!"), ref_owner)
            assert_equal(node.listtokenbalancesbyaddress(self.a2F), {})
            assert_equal(node.gettokendata("FLUSHME"), orig)
            assert_equal(node.getaddressutxos({"addresses": utxo_addrs, "tokenName": "FLUSHME"}),
                         ref_utxos["FLUSHME"])
            owner_utxos = node.getaddressutxos({"addresses": utxo_addrs, "tokenName": "FLUSHME!"})
            assert_equal([without(u, ["height"]) for u in owner_utxos],
                         [without(u, ["height"]) for u in ref_utxos["FLUSHME!"]])
            if node is n0:
                continue
            # The restored UTXO gets the disconnected block's height minus 1.
            self.known_failure(RESTORED_HEIGHT, lambda: assert_equal(owner_utxos, ref_utxos["FLUSHME!"]),
                               "'height': %d" % (h_reissue - 1))
            listing = node.listtokens("FLUSHME", True)["FLUSHME"]
            if node is n1:
                assert_equal(without(listing, ["block_height", "blockhash"]),
                             without(ref_listing, ["block_height", "blockhash"]))
                # The height comes from an uninitialized int, so only the
                # zero hash identifies the bug.
                self.known_failure(ZERO_BLOCKHASH, lambda: assert_equal(listing, ref_listing),
                                   "'blockhash': '%s'" % ("0" * 64))
            else:
                assert_equal(listing, ref_listing)

        self.restart_node(2)
        assert_equal(n2.listaddressesbytoken("FLUSHME"), ref_holders)
        assert_equal(n2.gettokendata("FLUSHME"), orig)


if __name__ == "__main__":
    TokenReorgTest().main()
