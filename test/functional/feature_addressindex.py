#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the address index RPCs end to end.

getaddressbalance, getaddressdeltas, getaddressutxos and getaddresstxids on
P2PKH, P2SH (multisig), timelock and coinbase outputs: values, ranges,
chainInfo and errors; a spend; a reorg that undoes a spend and payments; a
restart, -reindex and -reindex-fast; switching -addressindex on and off;
-txindex=0; token queries and -tokenindex changes.
"""
from decimal import Decimal

from test_framework.messages import COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    disconnect_nodes,
    JSONRPCException,
    raw_rpc,
    wait_until,
)

TOKEN_HEIGHT = 40
COMMON = ["-tokenSupportBlockNumber=%d" % TOKEN_HEIGHT]
ARGS = [["-addressindex=1"] + COMMON, ["-addressindex=1", "-tokenindex=1"] + COMMON, list(COMMON)]
ADDRESS_RPCS = ['getaddressbalance', 'getaddressdeltas', 'getaddressutxos', 'getaddresstxids']
REBUILD = "You need to rebuild the database using -reindex-fast or -reindex to change %s"
NOT_FUNCTIONAL = "returned: _This rpc call is not functional unless %s is enabled "


def q(*addresses, **kw):
    d = {'addresses': list(addresses)}
    d.update(kw)
    return d


class AddressIndexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        # -reindex needs the fork above the genesis block.
        self.block_fork_1_0 = 1
        self.extra_args = [list(a) for a in ARGS]

    # helpers
    def out_index(self, node, txid, address):
        return [o['n'] for o in node.getrawtransaction(txid, 1)['vout']
                if o['scriptPubKey'].get('addresses') == [address]][0]

    def delta(self, node, txid, address, satoshis, index, token='YAC'):
        tx = node.getrawtransaction(txid, 1)
        block = node.getblock(tx['blockhash'])
        return {'tokenName': token, 'satoshis': satoshis, 'txid': txid, 'index': index,
                'blockindex': block['tx'].index(txid), 'height': block['height'], 'address': address}

    def utxo(self, node, txid, address, satoshis):
        tx = node.getrawtransaction(txid, 1)
        n = self.out_index(node, txid, address)
        return {'address': address, 'tokenName': 'YAC', 'txid': txid, 'outputIndex': n,
                'script': tx['vout'][n]['scriptPubKey']['hex'], 'satoshis': satoshis,
                'height': node.getblock(tx['blockhash'])['height']}

    def snapshot(self, node, addresses):
        snap = {}
        for name, a in sorted(addresses.items()):
            snap[name] = [node.getaddressbalance(q(a)), node.getaddressdeltas(q(a)),
                          node.getaddressutxos(q(a)), node.getaddresstxids(q(a))]
        allq = q(*sorted(addresses.values()))
        snap['*'] = [node.getaddressbalance(allq), node.getaddressdeltas(allq),
                     node.getaddressutxos(allq), node.getaddresstxids(allq)]
        return snap

    def rpc_error(self, f, code, message, *args):
        """Pass if f(*args) fails with code (None: any) and message; else raise
        an AssertionError that names the returned value, so that a known_failure
        can expect today's exact answer."""
        try:
            r = f(*args)
        except JSONRPCException as e:
            assert code is None or e.error['code'] == code, e.error
            assert message in e.error['message'], e.error
            return
        # %s, not %r: the R-8 string contains "haven't", which would change repr's quotes.
        raise AssertionError("returned: %s" % r)

    def assert_empty(self, node, address):
        assert_equal(node.getaddressbalance(q(address)), {'balance': 0, 'received': 0})
        assert_equal(node.getaddressdeltas(q(address)), [])
        assert_equal(node.getaddressutxos(q(address)), [])
        assert_equal(node.getaddresstxids(q(address)), [])

    def run_test(self):
        self.mine_with_mocktime(self.nodes[0], 15)
        self.test_without_index()
        self.test_payments()
        self.test_errors()
        self.test_spend_and_reorg()
        self.test_restart_and_reindex()
        self.test_index_switch()
        self.test_txindex_off()
        self.test_tokens()

    def test_without_index(self):
        self.log.info("Without -addressindex the RPCs answer with a string and help doesn't know them")
        n2 = self.nodes[2]
        a = self.nodes[0].getnewaddress()
        for rpc in ADDRESS_RPCS:
            self.known_failure("R-8 (gmPtMy1i 2)", lambda: self.rpc_error(getattr(n2, rpc), None, "-addressindex", q(a)),
                               expected=NOT_FUNCTIONAL % "-addressindex")
            self.known_failure("R-8 (gmPtMy1i 2)", lambda: assert_equal(n2.help(rpc).split('\n')[0], rpc),
                               expected="help: unknown command: %s" % rpc)
        cats = [l for l in self.nodes[0].help().split('\n') if l.startswith('== ')]
        assert '== Addressindex ==' in cats
        cats2 = [l for l in n2.help().split('\n') if l.startswith('== ')]
        without = [c for c in cats if c != '== Addressindex ==']
        self.known_failure("R-8 (gmPtMy1i 2)", lambda: assert_equal(cats2, cats),
                           expected="not(%s == %s)" % (without, cats))

    # Addresses: X P2PKH payee, P 2-of-2 P2SH, G generatetoaddress payee (all
    # node1); later W and Y new P2PKH, Q 1-of-1 P2SH, T timelocked P2PKH (node0),
    # K token holder (node1).
    def test_payments(self):
        self.log.info("Payments to P2PKH, P2SH and coinbase outputs")
        n0, n1 = self.nodes[0], self.nodes[1]
        self.X = X = n1.getnewaddress()
        self.G = G = n1.getnewaddress()
        k1, k2 = n1.getnewaddress(), n1.getnewaddress()
        self.P = P = n1.addmultisigaddress(2, [n1.validateaddress(k1)['pubkey'], n1.validateaddress(k2)['pubkey']])
        self.set_mocktime(self.mocktime + 60)
        cb_hash = n1.generatetoaddress(1, G)[0]
        self.sync_all()
        cb = n1.getblock(cb_hash)['tx'][0]
        self.cb_value = int(n1.getrawtransaction(cb, 1)['vout'][0]['value'] * COIN)
        self.t1 = n0.sendtoaddress(X, 1)
        self.tp = n0.sendtoaddress(P, 4)
        self.mine_with_mocktime(n0, 1)
        self.h1 = n0.getblockcount()
        self.t2 = n0.sendtoaddress(X, 2)
        self.mine_with_mocktime(n0, 1)
        self.t3 = n0.sendtoaddress(X, 3)
        self.mine_with_mocktime(n0, 1)
        h1, h3 = self.h1, n0.getblockcount()
        h2 = h1 + 1
        t1, t2, t3, tp = self.t1, self.t2, self.t3, self.tp

        for node in (n0, n1):
            assert_equal(node.getaddresstxids(q(X)), [t1, t2, t3])
            assert_equal(node.getaddresstxids(q(X, start=h2, end=h3)), [t2, t3])
            assert_equal(node.getaddresstxids(q(X, P)), [t for _, t in sorted([(h1, t1), (h1, tp), (h2, t2), (h3, t3)])])
            dx = [self.delta(node, t, X, v * COIN, self.out_index(node, t, X)) for t, v in ((t1, 1), (t2, 2), (t3, 3))]
            assert_equal(node.getaddressdeltas(q(X)), dx)
            dp = [self.delta(node, tp, P, 4 * COIN, self.out_index(node, tp, P))]
            assert_equal(node.getaddressdeltas(q(P)), dp)
            assert_equal(node.getaddressdeltas(q(P, X)), dp + dx)
            assert_equal(node.getaddressdeltas(q(X, start=h2, end=h3)), dx[1:])
            assert_equal(node.getaddressdeltas(q(G)), [self.delta(node, cb, G, self.cb_value, 0)])
            assert_equal(node.getaddressbalance(q(X)), {'balance': 6 * COIN, 'received': 6 * COIN})
            assert_equal(node.getaddressbalance(q(X, P)), {'balance': 10 * COIN, 'received': 10 * COIN})
            ux = [self.utxo(node, t, X, v * COIN) for t, v in ((t1, 1), (t2, 2), (t3, 3))]
            assert_equal(node.getaddressutxos(q(X)), ux)
            up = node.getaddressutxos(q(P))
            assert_equal(up, [self.utxo(node, tp, P, 4 * COIN)])
            assert_equal(up[0]['script'], n1.validateaddress(P)['scriptPubKey'])
            both = node.getaddressutxos(q(X, P))
            assert_equal(sorted(both, key=lambda u: (u['txid'], u['outputIndex'])),
                         sorted(ux + up, key=lambda u: (u['txid'], u['outputIndex'])))
            assert_equal([u['height'] for u in both], sorted(u['height'] for u in both))
        self.ux_before, self.up_before = ux, up
        self.dx_before, self.dp_before = dx, dp

        self.log.info("Ranges with chainInfo")
        tip = n0.getblockcount()
        r = n0.getaddressdeltas(q(X, start=h2, end=h3, chainInfo=True))
        assert_equal(r, {'deltas': dx[1:], 'start': {'hash': n0.getblockhash(h2), 'height': h2},
                         'end': {'hash': n0.getblockhash(h3), 'height': h3}})
        # chainInfo without a range is ignored.
        assert_equal(n0.getaddressdeltas(q(X, chainInfo=True)), dx)
        # Without chainInfo an end above the tip is accepted.
        assert_equal(n0.getaddressdeltas(q(X, start=h2, end=tip + 5)), dx[1:])
        assert_raises_rpc_error(-5, "Start or end is outside chain range", n0.getaddressdeltas, q(X, start=h2, end=tip + 1, chainInfo=True))
        assert_raises_rpc_error(-5, "Start and end is expected to be greater than zero", n0.getaddressdeltas, q(X, start=0, end=h3))
        assert_raises_rpc_error(-5, "End value is expected to be greater than start", n0.getaddressdeltas, q(X, start=h3, end=h2))
        r = n0.getaddressutxos(q(X, chainInfo=True))
        assert_equal(r, {'utxos': ux, 'hash': n0.getbestblockhash(), 'height': tip})
        status, _, body = raw_rpc(n0, {'method': 'getaddressutxos', 'params': [q(X, chainInfo=True)], 'id': 1})
        assert_equal(status, 200)
        self.known_failure("R-9 (gmPtMy1i 3)", lambda: assert_equal(body.count(b'"utxos"'), 1), expected="not(2 == 1)")

    def test_errors(self):
        self.log.info("Parameter errors")
        n0, X = self.nodes[0], self.X
        for rpc in ADDRESS_RPCS:
            f = getattr(n0, rpc)
            assert_raises_rpc_error(-5, "Invalid address", f, q('notanaddress'))
            assert_raises_rpc_error(-5, "Addresses is expected to be an array", f, {'addresses': X})
            assert_raises_rpc_error(-5, "Addresses is expected to be an array", f, {})
            assert_raises_rpc_error(-1, "JSON value is not a string as expected", f, q(1))
            # Only the object form is accepted; a plain string gets the help text.
            assert_raises_rpc_error(-1, rpc + "\n", f, X)
        assert_equal(n0.getaddressbalance(q()), {'balance': 0, 'received': 0})
        self.assert_empty(n0, n0.getnewaddress())
        assert_raises_rpc_error(-1, "getaddressdeltas\n", n0.getaddressdeltas, q(X), True)
        assert_raises_rpc_error(-1, "getaddressutxos\n", n0.getaddressutxos, q(X), True)
        assert_raises_rpc_error(-1, "getaddressbalance\n", n0.getaddressbalance, q(X), True, 1)
        assert_raises_rpc_error(-1, "getaddresstxids\n", n0.getaddresstxids, q(X), True, 1)
        assert n0.getblockcount() < TOKEN_HEIGHT
        assert_raises_rpc_error(-8, "Tokens aren't active.  tokenName can't be specified.", n0.getaddressdeltas, q(X, tokenName='ATOK'))
        assert_raises_rpc_error(-8, "Tokens aren't active.  tokenName can't be specified.", n0.getaddressutxos, q(X, tokenName='*'))
        assert_raises_rpc_error(-8, "Tokens aren't active.  includeTokens can't be true.", n0.getaddressbalance, q(X), True)
        assert_raises_rpc_error(-8, "Tokens aren't active.  includeTokens can't be true.", n0.getaddresstxids, q(X), True)
        assert_raises_rpc_error(-32601, "Method not found", n0.getaddressmempool, q(X))
        # Unlike getaddressdeltas, getaddresstxids doesn't check its range.
        tip = n0.getblockcount()
        # Today start=0 returns everything and end < start returns nothing.
        self.known_failure("txids range check (gmPtMy1i 6)", lambda: self.rpc_error(
            n0.getaddresstxids, -5, "Start and end is expected to be greater than zero", q(X, start=0, end=tip)),
            expected="returned: %s" % [self.t1, self.t2, self.t3])
        self.known_failure("txids range check (gmPtMy1i 6)", lambda: self.rpc_error(
            n0.getaddresstxids, -5, "End value is expected to be greater than start", q(X, start=tip, end=tip - 1)),
            expected="returned: []")

    def test_spend_and_reorg(self):
        self.log.info("Spend from P2PKH and P2SH, pay new P2PKH and P2SH addresses and lock coins")
        n0, n1, n2 = self.nodes
        X, P = self.X, self.P
        disconnect_nodes(n1, 2)
        disconnect_nodes(n2, 1)
        vx = self.out_index(n1, self.t1, X)
        vp = self.out_index(n1, self.tp, P)
        self.W, self.Y, self.T = W, Y, T = n0.getnewaddress(), n0.getnewaddress(), n0.getnewaddress()
        raw = n1.createrawtransaction([{'txid': self.t1, 'vout': vx}, {'txid': self.tp, 'vout': vp}], {W: Decimal('4.99')})
        signed = n1.signrawtransaction(raw)
        assert signed['complete']
        # Submitted to node0 so that all of them are in its next block without waiting for relay.
        S = n0.sendrawtransaction(signed['hex'])
        tY = n0.sendtoaddress(Y, 1)
        self.Q = Q = n0.addmultisigaddress(1, [n0.validateaddress(n0.getnewaddress())['pubkey']])
        tQ = n0.sendtoaddress(Q, 1)
        lock = n0.timelockcoins(1, 10, True, True, T)
        assert_equal(lock['address_containing_timelocked_coins'], T)
        tl = lock['txid']
        self.mine_with_mocktime(n0, 1, sync=[n0, n1])
        h4 = n0.getblockcount()
        for node in (n0, n1):
            assert_equal(node.getaddressdeltas(q(X)), self.dx_before + [self.delta(node, S, X, -COIN, 0)])
            assert_equal(node.getaddressdeltas(q(P)), self.dp_before + [self.delta(node, S, P, -4 * COIN, 1)])
            assert_equal(node.getaddressbalance(q(X)), {'balance': 5 * COIN, 'received': 6 * COIN})
            assert_equal(node.getaddressbalance(q(P)), {'balance': 0, 'received': 4 * COIN})
            assert_equal(node.getaddressutxos(q(X)), self.ux_before[1:])
            assert_equal(node.getaddressutxos(q(P)), [])
            assert_equal(node.getaddresstxids(q(X)), [self.t1, self.t2, self.t3, S])
            assert_equal(node.getaddresstxids(q(P)), [self.tp, S])
            # S touches both addresses but is listed once.
            assert_equal(node.getaddresstxids(q(X, P)), [t for _, t in sorted(
                [(self.h1, self.t1), (self.h1, self.tp), (self.h1 + 1, self.t2), (self.h1 + 2, self.t3), (h4, S)])])
            assert_equal(node.getaddressutxos(q(W)), [self.utxo(node, S, W, 4990000)])
            assert_equal(node.getaddressutxos(q(Y)), [self.utxo(node, tY, Y, COIN)])
            assert_equal(node.getaddressutxos(q(Q)), [self.utxo(node, tQ, Q, COIN)])
            ut = node.getaddressutxos(q(T))
            assert_equal(ut, [self.utxo(node, tl, T, COIN)])
            # <10> OP_CHECKSEQUENCEVERIFY OP_DROP, then T's P2PKH script.
            assert_equal(ut[0]['script'], '010ab275' + n0.validateaddress(T)['scriptPubKey'])
            assert_equal(node.getaddressdeltas(q(T)), [self.delta(node, tl, T, COIN, ut[0]['outputIndex'])])

        self.log.info("Reorg: a longer branch without block %d" % h4)
        self.mine_with_mocktime(n2, 2, sync=False)
        connect_nodes(n2, 1)
        self.sync_blocks()
        assert_equal(n0.getbestblockhash(), n2.getbestblockhash())
        for node in (n0, n1):
            wait_until(lambda: set(node.getrawmempool()) == {S, tY, tl, tQ}, timeout=10)
            assert_equal(node.getaddressdeltas(q(X)), self.dx_before)
            assert_equal(node.getaddressdeltas(q(P)), self.dp_before)
            assert_equal(node.getaddressbalance(q(X)), {'balance': 6 * COIN, 'received': 6 * COIN})
            assert_equal(node.getaddressbalance(q(P)), {'balance': 4 * COIN, 'received': 4 * COIN})
            assert_equal(node.getaddresstxids(q(X)), [self.t1, self.t2, self.t3])
            # The index has no mempool entries (validation.cpp:693 is commented out).
            for a in (W, Y, T, Q):
                self.assert_empty(node, a)
            restored = {(u['txid'], u['outputIndex']): u for u in node.getaddressutxos(q(X, P))}
            before = {(u['txid'], u['outputIndex']): u for u in self.ux_before + self.up_before}
            assert_equal(sorted(restored), sorted(before))
            for k in before:
                for field in ('address', 'script', 'satoshis'):
                    assert_equal(restored[k][field], before[k][field])
            spent = [(self.t1, vx), (self.tp, vp)]
            self.known_failure("C-S8 (KXUa7eJZ)", lambda: assert_equal([restored[k]['height'] for k in spent], [self.h1, self.h1]),
                               expected="not([%d, %d] == [%d, %d])" % (h4 - 1, h4 - 1, self.h1, self.h1))

        self.log.info("Mine the transactions again")
        self.mine_with_mocktime(n0, 1)
        h5 = n0.getblockcount()
        assert_equal(n0.getrawmempool(), [])
        for node in (n0, n1):
            assert_equal(node.getaddressdeltas(q(X))[-1], self.delta(node, S, X, -COIN, 0))
            assert_equal(node.getaddressdeltas(q(X))[-1]['height'], h5)
            assert_equal(node.getaddressutxos(q(X)), self.ux_before[1:])
            assert_equal(node.getaddressutxos(q(P)), [])
            assert_equal(node.getaddressutxos(q(Q)), [self.utxo(node, tQ, Q, COIN)])

    def test_restart_and_reindex(self):
        self.log.info("Restart, -reindex and -reindex-fast keep the answers")
        self.addresses = {'X': self.X, 'P': self.P, 'G': self.G, 'W': self.W, 'Y': self.Y, 'T': self.T, 'Q': self.Q}
        self.snap = self.snapshot(self.nodes[0], self.addresses)
        assert_equal(self.snapshot(self.nodes[1], self.addresses), self.snap)
        self.count = self.nodes[0].getblockcount()
        for extra in ([], ["-reindex"], ["-reindex-fast"]):
            self.restart_node(0, ARGS[0] + extra)
            wait_until(lambda: self.nodes[0].getblockcount() == self.count)
            assert_equal(self.snapshot(self.nodes[0], self.addresses), self.snap)
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(COMMON + ["-addressindex=0"], REBUILD % "-addressindex", match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(0, ARGS[0])
        connect_nodes(self.nodes[1], 0)

    def test_index_switch(self):
        self.log.info("Switching -addressindex on and off needs a reindex")
        self.stop_node(2)
        n2 = self.nodes[2]
        n2.assert_start_raises_init_error(COMMON + ["-addressindex=1"], REBUILD % "-addressindex", match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(2, COMMON + ["-addressindex=1", "-reindex"])
        wait_until(lambda: n2.getblockcount() == self.count)
        assert_equal(self.snapshot(n2, self.addresses), self.snap)
        self.stop_node(2)
        n2.assert_start_raises_init_error(COMMON, REBUILD % "-addressindex", match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(2, COMMON + ["-reindex-fast"])
        wait_until(lambda: n2.getblockcount() == self.count)
        self.known_failure("R-8 (gmPtMy1i 2)", lambda: self.rpc_error(n2.getaddressbalance, None, "-addressindex", q(self.X)),
                           expected=NOT_FUNCTIONAL % "-addressindex")

    def test_txindex_off(self):
        self.log.info("-txindex=0 can't be used, not even with -reindex")
        self.stop_node(2)
        n2 = self.nodes[2]
        # C-S5 (gmPtMy1i 4): today both fail with the rebuild message. Plain
        # assertions because the fixed behaviour (reject with a clear message
        # or ignore with a warning) isn't decided yet; any fix makes them fail.
        n2.assert_start_raises_init_error(COMMON + ["-txindex=0"], REBUILD % "-txindex", match=ErrorMatch.PARTIAL_REGEX)
        n2.assert_start_raises_init_error(COMMON + ["-txindex=0", "-reindex"], "Error: " + REBUILD % "-txindex", match=ErrorMatch.PARTIAL_REGEX)
        # C-S5 (gmPtMy1i 4): the failed -reindex has already wiped the block index.
        n2.assert_start_raises_init_error(COMMON, "Error initializing block database", match=ErrorMatch.PARTIAL_REGEX)
        self.start_node(2, COMMON + ["-reindex"])
        wait_until(lambda: n2.getblockcount() == self.count)
        assert_equal(n2.getbestblockhash(), self.nodes[0].getbestblockhash())
        self.stop_node(2)

    def test_tokens(self):
        self.log.info("Token entries")
        n0, n1 = self.nodes[0], self.nodes[1]
        self.mine_with_mocktime(n0, TOKEN_HEIGHT - n0.getblockcount())
        n0.sendtoaddress(n1.getnewaddress(), 50)
        self.mine_with_mocktime(n0, 1)
        K = n1.getnewaddress()
        issue = n1.issue(token_name="ATOK", qty=1000, units=0, reissuable=True, has_ipfs=False, to_address=K)
        self.mine_with_mocktime(n1, 1)
        hT = n0.getblockcount()
        self.mine_with_mocktime(n0, 2)
        tK = n0.sendtoaddress(K, 1)
        self.mine_with_mocktime(n0, 1)
        hK = n0.getblockcount()
        itx = n0.getrawtransaction(issue, 1)
        vtok = [o['n'] for o in itx['vout'] if o['scriptPubKey'].get('addresses') == [K]]
        assert_equal(len(vtok), 2)
        for node in (n0, n1):
            assert_equal(node.getaddressbalance(q(K), True), [
                {'tokenName': 'ATOK', 'balance': 1000 * COIN, 'received': 1000 * COIN},
                {'tokenName': 'ATOK!', 'balance': COIN, 'received': COIN},
                {'tokenName': 'YAC', 'balance': COIN, 'received': COIN}])
            assert_equal(node.getaddressbalance(q(K)), {'balance': COIN, 'received': COIN})
            d = node.getaddressdeltas(q(K, tokenName='ATOK'))
            assert_equal(len(d), 1)
            assert_equal(d, [self.delta(node, issue, K, 1000 * COIN, d[0]['index'], token='ATOK')])
            assert d[0]['index'] in vtok
            assert_equal(node.getaddressdeltas(q(K, tokenName='atok')), d)
            assert_equal(node.getaddressdeltas(q(K, tokenName='ATOK', start=hT, end=hT, chainInfo=True)),
                         {'deltas': d, 'start': {'hash': node.getblockhash(hT), 'height': hT}, 'end': {'hash': node.getblockhash(hT), 'height': hT}})
            assert_equal(node.getaddressdeltas(q(K, tokenName='NOPE')), [])
            u = node.getaddressutxos(q(K, tokenName='ATOK'))
            assert_equal([(x['tokenName'], x['txid'], x['satoshis'], x['height']) for x in u], [('ATOK', issue, 1000 * COIN, hT)])
            star = node.getaddressutxos(q(K, tokenName='*'))
            # '*' lists the token outputs only, not YAC.
            assert_equal(sorted((x['tokenName'], x['satoshis']) for x in star), [('ATOK', 1000 * COIN), ('ATOK!', COIN)])
            assert_equal(node.getaddressutxos(q(K, tokenName='YAC')), [self.utxo(node, tK, K, COIN)])
            # One address: index order, grouped by token with YAC first (length-prefixed
            # names), not by height; several addresses would be sorted by height.
            assert_equal(node.getaddresstxids(q(K), True), [tK, issue])
            assert_equal(node.getaddresstxids(q(K)), [tK])
            self.known_failure("R-new (gmPtMy1i 1)", lambda: assert_equal(node.getaddresstxids(q(K, start=hT, end=hT), True), [issue]),
                               expected="not([] == ['%s'])" % issue)
            self.known_failure("R-new (gmPtMy1i 1)", lambda: assert_equal(node.getaddresstxids(q(K, start=hK, end=hK), True), [tK]),
                               expected="not(['%s', '%s'] == ['%s'])" % (tK, issue, tK))
        assert_equal(n1.listaddressesbytoken("ATOK"), {K: '1000'})
        assert_equal(n1.listtokenbalancesbyaddress(K), {'ATOK': '1000', 'ATOK!': '1'})
        self.known_failure("R-8 (gmPtMy1i 2)", lambda: self.rpc_error(n0.listaddressesbytoken, None, "-tokenindex", "ATOK"),
                           expected=NOT_FUNCTIONAL % "-tokenindex")
        self.known_failure("R-8 (gmPtMy1i 2)", lambda: assert_equal(n0.help("listaddressesbytoken").split('\n')[0],
                                                             n1.help("listaddressesbytoken").split('\n')[0]),
                           expected="help: unknown command: listaddressesbytoken")
        self.known_failure("R-8 (gmPtMy1i 2)", lambda: self.rpc_error(n0.listtokenbalancesbyaddress, None, "-tokenindex", K),
                           expected=NOT_FUNCTIONAL % "-tokenindex")
        self.known_failure("R-8 (gmPtMy1i 2)", lambda: assert_equal(n0.help("listtokenbalancesbyaddress").split('\n')[0],
                                                                     n1.help("listtokenbalancesbyaddress").split('\n')[0]),
                           expected="help: unknown command: listtokenbalancesbyaddress")

        self.log.info("-tokenindex changes need a reindex")
        tok_snap = [n1.getaddressbalance(q(K), True), n1.getaddressutxos(q(K, tokenName='*'))]
        self.stop_node(0)
        self.known_failure("C-S6 (gmPtMy1i 5)", lambda: self.nodes[0].assert_start_raises_init_error(
            ARGS[0] + ["-tokenindex=1"], REBUILD % "-tokenindex", match=ErrorMatch.PARTIAL_REGEX),
            expected="should have exited with expected error")
        self.start_node(0, ARGS[0] + ["-tokenindex=1", "-reindex"])
        n0 = self.nodes[0]
        wait_until(lambda: n0.getblockcount() == hK)
        assert_equal(n0.listaddressesbytoken("ATOK"), {K: '1000'})
        assert_equal([n0.getaddressbalance(q(K), True), n0.getaddressutxos(q(K, tokenName='*'))], tok_snap)
        self.stop_node(1)
        self.known_failure("C-S6 (gmPtMy1i 5)", lambda: self.nodes[1].assert_start_raises_init_error(
            ["-addressindex=1", "-tokenindex=0"] + COMMON, REBUILD % "-tokenindex", match=ErrorMatch.PARTIAL_REGEX),
            expected="should have exited with expected error")
        # That start left node1's token index intact.
        self.start_node(1, ARGS[1])
        assert_equal(self.nodes[1].listaddressesbytoken("ATOK"), {K: '1000'})


if __name__ == '__main__':
    AddressIndexTest().main()
