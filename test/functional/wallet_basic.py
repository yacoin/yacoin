#!/usr/bin/env python3
# Copyright (c) 2014-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the basic wallet functions (adapted from Bitcoin Core's wallet.py).

- coinbase maturity: immature_balance, balance and the transaction category
  around depth 6;
- listunspent fields, arguments and query options (known failure W-B5:
  minimumAmount and maximumAmount are ignored), unconfirmed and unsafe
  outputs;
- lockunspent / listlockunspent, including errors and that locks don't
  survive a restart;
- sendtoaddress and sendmany: fees, comments, errors;
- getrawchangeaddress;
- -walletbroadcast=0 and resendwallettransactions;
- getreceivedbyaddress, getunconfirmedbalance, gettransaction (also for
  transactions that aren't in the wallet);
- -spendzeroconfchange=0;
- balance and history after restarts with -rescan, -reindex and
  -zapwallettxes=1/2.

Porting notes (see wallet_util.py): named arguments for sendtoaddress /
sendmany; mined coins belong to the 'coinbase' account (generate pays the
node's deterministic key), so sendmany uses fromaccount='coinbase'; the fee
is at least 0.01 per transaction. block_fork_1_0 = 1 because -reindex
rejects the genesis block when the fork height is 0 (as in
feature_reindex.py).
"""
from decimal import Decimal

from test_framework.messages import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
    wait_until,
)
from test_framework.wallet_util import assert_yac_fee, coinbase_value

INSUFFICIENT_FUNDS_FEE = "Error: This transaction requires a transaction fee of at least 0.01"


class WalletTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.block_fork_1_0 = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)
        connect_nodes(self.nodes[1], 2)
        connect_nodes(self.nodes[0], 2)
        self.sync_all()

    def reconnect(self, i):
        for j in range(self.num_nodes):
            if j != i:
                connect_nodes(self.nodes[i], j)

    def mine(self, node=None, relay=True):
        """Mine one block (on node 0 by default) and sync. relay=False when
        the miner created the new transactions itself."""
        if relay:
            self.sync_mempools()
        (node or self.nodes[0]).generate(1)
        self.sync_blocks()

    def decoded(self, node, txid):
        return node.decoderawtransaction(node.gettransaction(txid)['hex'])

    def run_test(self):
        self.test_maturity()
        self.test_listunspent()
        self.test_lockunspent()
        self.test_sendtoaddress()
        self.test_sendmany()
        self.test_rawchangeaddress()
        self.test_walletbroadcast()
        self.test_unconfirmed()
        self.test_gettransaction()
        self.test_spendzeroconfchange()
        self.test_maintenance()

    def test_maturity(self):
        self.log.info("Coinbase maturity")
        node0 = self.nodes[0]
        hashes = node0.generate(1)
        cb1 = node0.getblock(hashes[0])['tx'][0]
        r1 = coinbase_value(node0, hashes[0])
        info = node0.getwalletinfo()
        assert_equal((info['balance'], info['immature_balance']), (0, r1))
        assert_equal(node0.gettransaction(cb1)['details'][0]['category'], 'immature')

        hashes += node0.generate(COINBASE_MATURITY - 2)
        info = node0.getwalletinfo()
        assert_equal(info['balance'], 0)
        assert_equal(info['immature_balance'], sum(coinbase_value(node0, h) for h in hashes))
        assert_equal(node0.gettransaction(cb1)['details'][0]['category'], 'immature')

        # Mature at depth COINBASE_MATURITY: spendable in the next block
        hashes += node0.generate(1)
        info = node0.getwalletinfo()
        assert_equal(info['balance'], r1)
        assert_equal(info['immature_balance'], sum(coinbase_value(node0, h) for h in hashes[1:]))
        assert_equal(node0.gettransaction(cb1)['details'][0]['category'], 'generate')

        node0.generate(20)
        self.sync_blocks()

    def test_listunspent(self):
        self.log.info("listunspent")
        node0 = self.nodes[0]
        utxos = node0.listunspent()
        assert len(utxos) > 1
        for u in utxos:
            assert_equal((u['account'], u['spendable'], u['solvable'], u['safe']), ('coinbase', True, True, True))
            assert u['confirmations'] >= COINBASE_MATURITY
        address = utxos[0]['address']

        assert_raises_rpc_error(-3, "Expected type number, got string", node0.listunspent, 'a')
        assert_raises_rpc_error(-5, "Invalid Yacoin address: bad", node0.listunspent, 1, 9999999, ['bad'])
        assert_raises_rpc_error(-8, "Invalid parameter, duplicated address: " + address,
                                node0.listunspent, 1, 9999999, [address, address])
        assert_raises_rpc_error(-3, "Expected type bool, got string", node0.listunspent, 1, 9999999, [], 'x')

        assert_equal(len(node0.listunspent(1, 9999999, [], True, {'maximumCount': 1})), 1)
        assert_equal(len(node0.listunspent(1, 9999999, [], True, {'minimumSumAmount': Decimal('0.000001')})), 1)
        total = sum(u['amount'] for u in utxos)
        assert_equal(len(node0.listunspent(1, 9999999, [], True, {'minimumSumAmount': total + 1})), len(utxos))

        amounts = [u['amount'] for u in utxos]
        largest, smallest = max(amounts), min(amounts)

        def check_amount_filters():
            above = node0.listunspent(1, 9999999, [], True, {'minimumAmount': largest + Decimal('0.000001')})
            assert not above, "minimumAmount ignored: %d entries" % len(above)
            below = node0.listunspent(1, 9999999, [], True, {'maximumAmount': smallest - Decimal('0.000001')})
            assert not below, "maximumAmount ignored: %d entries" % len(below)
            at_largest = node0.listunspent(1, 9999999, [], True, {'minimumAmount': largest})
            assert_equal(len(at_largest), amounts.count(largest))
        # The query options minimumAmount / maximumAmount are never read
        self.known_failure("W-B5 (XbGM5oTW)", check_amount_filters, expected="minimumAmount ignored")

    def test_lockunspent(self):
        self.log.info("lockunspent / listlockunspent")
        node0, node1, node2 = self.nodes
        for _ in range(3):
            node0.sendtoaddress(node2.getnewaddress(), 10)
        node0.sendtoaddress(node1.getnewaddress(), 20)
        self.mine(relay=False)

        utxos = node2.listunspent()
        assert_equal([u['amount'] for u in utxos], [10, 10, 10])
        locked = [{'txid': u['txid'], 'vout': u['vout']} for u in utxos[:2]]
        free = (utxos[2]['txid'], utxos[2]['vout'])
        assert_equal(node2.lockunspent(False, locked), True)
        assert_equal(sorted((o['txid'], o['vout']) for o in node2.listlockunspent()),
                     sorted((o['txid'], o['vout']) for o in locked))
        # Coins locked with lockunspent still count in the balance
        assert_equal(node2.getbalance(), 30)
        assert_raises_rpc_error(-4, "Insufficient funds", node2.sendtoaddress, node0.getnewaddress(), 15)
        txid = node2.sendtoaddress(node0.getnewaddress(), 9)
        vin = self.decoded(node2, txid)['vin']
        assert_equal([(i['txid'], i['vout']) for i in vin], [free])
        self.mine()

        assert_raises_rpc_error(-3, "Expected type bool, got string", node2.lockunspent, 'x')
        assert_raises_rpc_error(-8, "Invalid parameter, expected object", node2.lockunspent, False, ['x'])
        assert_raises_rpc_error(-8, "Invalid parameter, expected hex txid", node2.lockunspent, False, [{'txid': 'zz', 'vout': 0}])
        assert_raises_rpc_error(-8, "Invalid parameter, vout must be positive", node2.lockunspent, False, [{'txid': '00' * 32, 'vout': -1}])
        # Unknown outpoints are accepted; a short txid is zero-padded
        assert_equal(node2.lockunspent(False, [{'txid': '11' * 32, 'vout': 0}, {'txid': 'ab', 'vout': 0}]), True)
        listed = [(o['txid'], o['vout']) for o in node2.listlockunspent()]
        assert ('11' * 32, 0) in listed
        assert ('00' * 31 + 'ab', 0) in listed

        assert_equal(node2.lockunspent(True), True)
        assert_equal(node2.listlockunspent(), [])

        self.log.info("Coin locks don't survive a restart")
        node2.lockunspent(False, locked)
        self.restart_node(2)
        self.reconnect(2)
        assert_equal(self.nodes[2].listlockunspent(), [])

    def test_sendtoaddress(self):
        self.log.info("sendtoaddress")
        node0, node1 = self.nodes[0], self.nodes[1]
        balance1 = node1.getbalance()
        txid = node0.sendtoaddress(node1.getnewaddress(), 10)
        assert_yac_fee(node0, txid)
        self.mine(relay=False)
        assert_equal(node1.getbalance(), balance1 + 10)

        self.log.info("sendtoaddress with comments")
        self.address_a = node1.getnewaddress()
        self.t_c1 = node0.sendtoaddress(address=self.address_a, amount=1, comment='c1', comment_to='t1')
        tx = node0.gettransaction(self.t_c1)
        assert_equal((tx['comment'], tx['to']), ('c1', 't1'))
        entries = [e for e in node0.listtransactions('*', 100) if e['txid'] == self.t_c1 and e['category'] == 'send']
        assert_equal(len(entries), 1)
        e = entries[0]
        assert_equal((e['comment'], e['to'], e['amount'], e['fee'], e['abandoned']),
                     ('c1', 't1', Decimal('-1'), Decimal('-0.01'), False))
        self.mine(relay=False)

        self.log.info("sendtoaddress errors")
        address = node1.getnewaddress()
        assert_raises_rpc_error(-5, "Invalid Yacoin address", node0.sendtoaddress, 'bad', 1)
        assert_raises_rpc_error(-3, "Send amount too small", node0.sendtoaddress, address, Decimal('0.00009'))
        assert_raises_rpc_error(-3, "Invalid amount", node0.sendtoaddress, address, Decimal('0.0000001'))
        assert_raises_rpc_error(-3, "Amount out of range", node0.sendtoaddress, address, -1)
        balance = node0.getbalance()
        assert_raises_rpc_error(-6, "Insufficient funds", node0.sendtoaddress, address, balance + 1)
        assert_raises_rpc_error(-4, INSUFFICIENT_FUNDS_FEE, node0.sendtoaddress, address, balance)

    def test_sendmany(self):
        self.log.info("sendmany")
        node0, node1 = self.nodes[0], self.nodes[1]
        balance1 = node1.getbalance()
        a1, a2 = node1.getnewaddress(), node1.getnewaddress()
        txid = node0.sendmany(fromaccount='coinbase', amounts={a1: 1, a2: 2})
        outputs = self.decoded(node0, txid)['vout']
        assert_equal(len(outputs), 3)
        assert_yac_fee(node0, txid)
        self.mine(relay=False)
        assert_equal(node1.getbalance(), balance1 + 3)

        self.log.info("sendmany errors")
        address = node1.getnewaddress()
        assert_raises_rpc_error(-6, "Transaction must have at least one recipient", node0.sendmany, 'coinbase', {})
        assert_raises_rpc_error(-5, "Invalid Yacoin address: bad", node0.sendmany, 'coinbase', {'bad': 1})
        assert_raises_rpc_error(-3, "Send amount too small", node0.sendmany, 'coinbase', {address: Decimal('0.00001')})
        assert_raises_rpc_error(-6, "Account has insufficient funds", node0.sendmany, 'coinbase', {address: 100000})
        assert_raises_rpc_error(-11, "Invalid account name", node0.sendmany, '*', {address: 1})
        # The mined coins belong to the 'coinbase' account, not to ''
        assert_raises_rpc_error(-6, "Account has insufficient funds", node0.sendmany, '', {address: 1})

    def test_rawchangeaddress(self):
        self.log.info("getrawchangeaddress")
        node0, node1 = self.nodes[0], self.nodes[1]
        change = node1.getrawchangeaddress()
        info = node1.validateaddress(change)
        assert info['ismine']
        assert info['hdkeypath'].startswith("m/0'/1'/")
        assert_equal(node1.getaccount(change), '')
        # A payment from another wallet to it is a normal receive
        txid = node0.sendtoaddress(change, 1)
        self.mine(relay=False)
        entries = [e for e in node1.listtransactions('*', 100) if e['txid'] == txid]
        assert_equal([(e['category'], e['amount']) for e in entries], [('receive', Decimal('1'))])
        assert_equal(node1.getreceivedbyaddress(change), 1)

    def test_walletbroadcast(self):
        self.log.info("-walletbroadcast=0")
        self.restart_node(0, ['-walletbroadcast=0'])
        self.reconnect(0)
        node0, node1, node2 = self.nodes
        balance2 = node2.getbalance()
        txid = node0.sendtoaddress(node2.getnewaddress(), 2)
        assert txid not in node0.getrawmempool()
        assert_raises_rpc_error(-4, "Error: Wallet transaction broadcasting is disabled with -walletbroadcast",
                                node0.resendwallettransactions)
        self.mine(node1, relay=False)
        assert_equal(node2.getbalance(), balance2)

        # Broadcast it by hand
        node1.sendrawtransaction(node0.gettransaction(txid)['hex'])
        self.mine(node1, relay=False)
        assert_equal(node2.getbalance(), balance2 + 2)
        assert_equal(node0.gettransaction(txid)['confirmations'], 1)

        self.log.info("An unbroadcast transaction is relayed after a normal restart")
        txid2 = node0.sendtoaddress(node2.getnewaddress(), 2)
        self.restart_node(0)
        self.reconnect(0)
        assert txid2 in node0.getrawmempool()
        assert_equal(node0.resendwallettransactions(), [txid2])
        self.mine(relay=False)
        assert_equal(node0.gettransaction(txid2)['confirmations'], 1)
        assert_equal(node2.getbalance(), balance2 + 4)

    def test_unconfirmed(self):
        self.log.info("Unconfirmed receipts: balances, getreceivedbyaddress, listunspent")
        node0, node1 = self.nodes[0], self.nodes[1]
        a = self.address_a
        balance = node1.getbalance()
        received = node1.getreceivedbyaddress(a)
        txid = node0.sendtoaddress(a, 1)
        # Own change from an unconfirmed send is listed with minconf 0
        assert txid in [u['txid'] for u in node0.listunspent(0)]
        self.sync_mempools()
        assert_equal(node1.getunconfirmedbalance(), 1)
        assert_equal(node1.getwalletinfo()['unconfirmed_balance'], 1)
        assert_equal(node1.getbalance(), balance)
        assert_equal(node1.getbalance('*', 0), balance + 1)
        assert_equal(node1.getreceivedbyaddress(a), received)
        assert_equal(node1.getreceivedbyaddress(a, 0), received + 1)
        # A receipt from another wallet is unconfirmed and unsafe
        assert txid in [u['txid'] for u in node1.listunspent(0)]
        assert txid not in [u['txid'] for u in node1.listunspent(0, 9999999, [], False)]

        assert_equal(node1.getreceivedbyaddress(node0.getnewaddress()), 0)
        assert_raises_rpc_error(-5, "Invalid Yacoin address", node1.getreceivedbyaddress, 'bad')
        self.mine(relay=False)
        assert_equal(node1.getunconfirmedbalance(), 0)
        assert_equal(node1.getreceivedbyaddress(a), received + 1)

    def test_gettransaction(self):
        self.log.info("gettransaction")
        node0, node1, node2 = self.nodes
        tx = node0.gettransaction(self.t_c1)
        for key in ['Credit', 'Debit', 'amount', 'fee', 'details', 'token_details', 'hex',
                    'confirmations', 'blockhash', 'txid', 'vin', 'vout']:
            assert key in tx, key

        # A transaction that isn't in node 0's wallet comes from the txindex
        txid = node1.sendtoaddress(node2.getnewaddress(), 2)
        self.mine()
        tx = node0.gettransaction(txid)
        assert 'details' not in tx
        assert_equal((tx['hex'], tx['confirmations'], tx['blockhash']),
                     (node1.gettransaction(txid)['hex'], 1, node0.getbestblockhash()))
        assert_raises_rpc_error(-5, "No information available about transaction", node0.gettransaction, '00' * 32)
        assert_raises_rpc_error(-5, "No information available about transaction", node0.gettransaction, 'zz')

    def test_spendzeroconfchange(self):
        self.log.info("-spendzeroconfchange=0")
        self.restart_node(2, ['-spendzeroconfchange=0'])
        self.reconnect(2)
        node0, node2 = self.nodes[0], self.nodes[2]
        node2.sendtoaddress(address=node0.getnewaddress(), amount=node2.getbalance(), subtractfeefromamount=True)
        self.mine()
        self.single_utxo_wallet(node0, node2, 10)
        node2.sendtoaddress(node0.getnewaddress(), 1)
        # The unconfirmed change is not trusted
        assert_equal(node2.getbalance(), 0)
        assert_raises_rpc_error(-6, "Insufficient funds", node2.sendtoaddress, node0.getnewaddress(), 1)
        self.mine()
        node2.sendtoaddress(node0.getnewaddress(), 1)
        self.mine()

    def test_maintenance(self):
        self.log.info("Balance and history after maintenance restarts")
        node1 = self.nodes[1]
        # Everything is confirmed: -zapwallettxes would drop unconfirmed
        # transactions (it turns off the mempool persistence).
        assert_equal(self.nodes[0].getrawmempool(), [])
        balance = self.nodes[0].getbalance()
        txids = set(e['txid'] for e in self.nodes[0].listtransactions('*', 1000))
        for option in ['-rescan', '-reindex', '-zapwallettxes=1', '-zapwallettxes=2']:
            self.log.info("Restart with " + option)
            self.restart_node(0, [option])
            node0 = self.nodes[0]
            wait_until(lambda: node0.getblockcount() == node1.getblockcount(), timeout=60)
            self.reconnect(0)
            assert_equal(node0.getbalance(), balance)
            assert_equal(set(e['txid'] for e in node0.listtransactions('*', 1000)), txids)
            tx = node0.gettransaction(self.t_c1)
            if option == '-zapwallettxes=2':
                assert 'comment' not in tx and 'to' not in tx
            else:
                assert_equal((tx['comment'], tx['to']), ('c1', 't1'))


if __name__ == '__main__':
    WalletTest().main()
