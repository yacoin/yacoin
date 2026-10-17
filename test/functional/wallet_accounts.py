#!/usr/bin/env python3
# Copyright (c) 2016-2017 The Bitcoin Core developers
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the (deprecated) accounts API (adapted from Bitcoin Core's wallet-accounts.py).

- listaccounts and listaddressgroupings of a fresh wallet with mined coins;
- a new address in a new account has received nothing (moved here from
  wallet_fee.py, originally feature_set_min_fee.py);
- getaccountaddress: stable until the address appears in a wallet
  transaction, then a new one; getreceivedbyaccount, getaddressesbyaccount;
- setaccount, including the rotation of an account's current address, and
  getaccount; their errors;
- move: listaccounts, getbalance(account) and the 'move' entries of
  listtransactions; negative accounts; errors;
- sendfrom: account balances, comments, errors; amounts at the minimum
  (known failure: sendfrom rejects 0.0001, the others accept it);
- '*' is rejected as an account name wherever an account is created or
  selected;
- addmultisigaddress with an account;
- known failures: named arguments that leave out a middle optional
  argument; move entries are lost from listaccounts and listtransactions
  after a restart, while getbalance(account) keeps them.

Porting notes (see wallet_util.py): generate pays the node's deterministic
key, which has the account 'coinbase', so mined coins belong to 'coinbase'
and sendtoaddress debits ''. Amounts are read from the wallet, not
hard-coded (epoch reward).
"""
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

# A valid address that no test node owns
FOREIGN = TestNode.PRIV_KEYS[11].address


class WalletAccountsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def moves(self, account='*'):
        return [e for e in self.nodes[0].listtransactions(account, 1000) if e['category'] == 'move']

    def run_test(self):
        self.nodes[0].generate(30)
        self.test_fresh_wallet()
        self.test_new_account()
        self.test_account_address()
        self.test_setaccount()
        self.test_move()
        self.test_sendfrom()
        self.test_invalid_account_name()
        self.test_multisig()
        self.test_named_arguments()
        self.test_restart()

    def test_fresh_wallet(self):
        self.log.info("Accounts and address groupings of a wallet with mined coins")
        node = self.nodes[0]
        balance = node.getbalance()
        coinbase = node.get_deterministic_priv_key().address
        assert_equal(node.listaccounts(), {'': 0, 'coinbase': balance})
        assert_equal(node.listaddressgroupings(), [[[coinbase, balance, 'coinbase']]])

    def test_new_account(self):
        self.log.info("A new address in a new account has received nothing")
        node = self.nodes[0]
        address = node.getnewaddress('test-node2')
        assert_equal(node.getaccount(address), 'test-node2')
        assert_equal(node.getreceivedbyaddress(address), 0)
        assert_equal(node.getreceivedbyaccount('test-node2'), 0)
        assert_equal(node.listaccounts()['test-node2'], 0)

    def test_account_address(self):
        self.log.info("getaccountaddress changes once the address is used")
        node = self.nodes[0]
        first = node.getaccountaddress('acc1')
        assert_equal(node.getaccountaddress('acc1'), first)
        txid = node.sendtoaddress(first, 1)
        # Already while the payment is unconfirmed
        second = node.getaccountaddress('acc1')
        assert second != first
        node.generate(1)
        assert_equal(node.getreceivedbyaccount('acc1'), 1)
        assert_equal(sorted(node.getaddressesbyaccount('acc1')), sorted([first, second]))

        # The change of the payment joins the coinbase address's group
        coinbase = node.get_deterministic_priv_key().address
        outputs = node.decoderawtransaction(node.gettransaction(txid)['hex'])['vout']
        change = [o['scriptPubKey']['addresses'][0] for o in outputs if o['value'] != 1]
        assert_equal(len(change), 1)
        groups = node.listaddressgroupings()
        assert_equal(sorted(sorted(entry[0] for entry in group) for group in groups),
                     sorted([sorted([coinbase, change[0]]), [first]]))
        entries = {entry[0]: entry for group in groups for entry in group}
        assert_equal(entries[first], [first, Decimal('1'), 'acc1'])
        assert_equal(len(entries[change[0]]), 2)  # no address book entry
        assert_equal(sum(entry[1] for entry in entries.values()), node.getbalance())

    def test_setaccount(self):
        self.log.info("setaccount and getaccount")
        node = self.nodes[0]
        current = node.getaccountaddress('rot')
        assert_equal(node.setaccount(current, 'other'), None)
        assert_equal(node.getaccount(current), 'other')
        # 'rot' lost its current address, so it gets a new one
        assert node.getaccountaddress('rot') != current

        address = node.getnewaddress('x')
        node.setaccount(address)
        assert_equal(node.getaccount(address), '')

        assert_raises_rpc_error(-1, "setaccount can only be used with own address", node.setaccount, FOREIGN, 'x')
        assert_raises_rpc_error(-5, "Invalid Yacoin address", node.setaccount, 'bad', 'x')
        assert_raises_rpc_error(-5, "Invalid Yacoin address", node.getaccount, 'bad')
        assert_equal(node.getaccount(FOREIGN), '')

    def test_move(self):
        self.log.info("move between accounts")
        node = self.nodes[0]
        self.address_a = node.getnewaddress('a')
        before = node.listaccounts()
        assert_equal(node.move('coinbase', 'a', 2, 0, 'm1'), True)
        assert_equal(node.move('a', '', Decimal('0.5')), True)
        # An account without addresses, which goes negative
        assert_equal(node.move('z', '', 1), True)
        expected = dict(before)
        expected['coinbase'] -= 2
        expected['a'] = Decimal('1.5')
        expected[''] += Decimal('1.5')
        expected['z'] = Decimal('-1')
        assert_equal(node.listaccounts(), expected)
        assert_equal(node.getbalance('a'), Decimal('1.5'))
        assert_equal(node.getbalance('z'), -1)
        assert_equal(node.getbalance('*'), node.getbalance())

        entries = self.moves('a')
        assert_equal(len(entries), 2)
        for e in entries:
            assert abs(e['time'] - time.time()) < 300, e
        assert_equal(entries, [
            {'account': 'a', 'category': 'move', 'time': entries[0]['time'], 'amount': Decimal('2'),
             'otheraccount': 'coinbase', 'comment': 'm1'},
            {'account': 'a', 'category': 'move', 'time': entries[1]['time'], 'amount': Decimal('-0.5'),
             'otheraccount': '', 'comment': ''},
        ])

        assert_raises_rpc_error(-3, "Send amount too small", node.move, '', 'a', Decimal('0.00009'))
        assert_equal(node.move('', 'a', Decimal('0.0001')), True)
        assert_raises_rpc_error(-3, "Amount out of range", node.move, '', 'a', -1)
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", node.move, '', 'a', 1, 'x')
        assert_raises_rpc_error(-1, "JSON value is not a string as expected", node.move, '', 'a', 1, 0, 5)

    def test_sendfrom(self):
        self.log.info("sendfrom")
        node = self.nodes[0]
        address = self.address_a
        coinbase = node.getbalance('coinbase')
        balance_a = node.getbalance('a')
        txid = node.sendfrom('coinbase', address, 1)
        fee = node.gettransaction(txid)['fee']
        assert_equal(node.getbalance('coinbase'), coinbase - 1 + fee)
        # The receipt counts once it is confirmed
        assert_equal(node.getbalance('a'), balance_a)
        assert_equal(node.getbalance('a', 0), balance_a + 1)
        node.generate(1)
        assert_equal(node.getbalance('a'), balance_a + 1)

        node.sendfrom('coinbase', address, 1, True, 0)
        txid = node.sendfrom('coinbase', address, 1, True, 1, 'cmt', 'to')
        tx = node.gettransaction(txid)
        assert_equal((tx['comment'], tx['to']), ('cmt', 'to'))
        node.sendfrom(fromaccount='coinbase', toaddress=address, amount=1, minconf=1)

        assert_raises_rpc_error(-6, "Account has insufficient funds", node.sendfrom, 'a', FOREIGN, 100)
        assert_raises_rpc_error(-5, "Invalid Yacoin address", node.sendfrom, 'coinbase', 'bad', 1)
        node.sendfrom('coinbase', FOREIGN, Decimal('0.000101'))
        # The other send RPCs accept the minimum amount
        node.sendtoaddress(FOREIGN, Decimal('0.0001'))
        node.sendmany('coinbase', {FOREIGN: Decimal('0.0001')})

        def check_sendfrom_minimum():
            node.sendfrom('coinbase', FOREIGN, Decimal('0.0001'))
        # sendfrom compares with <= where the others use <
        self.known_failure("sendfrom minimum (DCjqQX73 item 5)", check_sendfrom_minimum,
                           expected="Send amount too small")
        node.generate(1)

        self.log.info("Balances by account")
        assert_equal(node.getbalance('', 0), node.listaccounts(0)[''])
        assert_equal(node.getbalance('*'), node.getbalance())
        assert_equal(node.getbalance('*', 1, True), node.getbalance())
        received = node.listreceivedbyaccount()
        assert {'account': 'acc1', 'amount': Decimal('1'), 'confirmations': 3} in received, received
        assert {'account': 'coinbase', 'amount': 0, 'confirmations': 0} in node.listreceivedbyaccount(1, True)

    def test_invalid_account_name(self):
        self.log.info("'*' is not an account name")
        node = self.nodes[0]
        address = self.address_a
        for method, args in [
            (node.getnewaddress, ['*']),
            (node.getaccountaddress, ['*']),
            (node.setaccount, [address, '*']),
            (node.move, ['*', '', 1]),
            (node.move, ['', '*', 1]),
            (node.sendfrom, ['*', address, 1]),
            (node.getreceivedbyaccount, ['*']),
            (node.getaddressesbyaccount, ['*']),
            (node.addmultisigaddress, [1, [address], '*']),
            (node.createcltvaddress, [100, '*']),
            (node.createcsvaddress, [10, True, '*']),
            (node.addredeemscript, ['51', '*']),
            (node.sendmany, ['*', {address: 1}]),
        ]:
            assert_raises_rpc_error(-11, "Invalid account name", method, *args)
        # '*' selects all accounts here
        node.getbalance('*')
        node.listtransactions('*')

    def test_multisig(self):
        self.log.info("addmultisigaddress with an account")
        node = self.nodes[0]
        multisig = node.addmultisigaddress(nrequired=1, keys=[self.address_a], account='ms')
        assert_equal(node.getaddressesbyaccount('ms'), [multisig])
        assert_equal(node.listaccounts()['ms'], 0)

    def test_named_arguments(self):
        self.log.info("Named arguments that leave out a middle optional argument")
        node = self.nodes[0]
        address = self.address_a

        def check_move():
            assert_equal(node.move(fromaccount='coinbase', toaccount='a', amount=1, comment='named'), True)

        def check_sendfrom():
            txid = node.sendfrom(fromaccount='coinbase', toaddress=address, amount=1, comment='c')
            assert_equal(node.gettransaction(txid)['comment'], 'c')

        def check_listaccounts():
            assert_equal(node.listaccounts(include_watchonly=True), node.listaccounts(1, True))

        def check_getbalance():
            assert_equal(node.getbalance(minconf=0), node.getbalance('*', 0))

        # The optional arguments are read without checking isNull()
        for check, expected in [
            (check_move, "JSON value is not an integer as expected"),
            (check_sendfrom, "JSON value is not an integer as expected"),
            (check_listaccounts, "JSON value is not an integer as expected"),
            (check_getbalance, "JSON value is not a string as expected"),
        ]:
            self.known_failure("named arguments (VKLzdLmd item 4)", check, expected=expected)

    def test_restart(self):
        self.log.info("Account moves after a restart")
        node = self.nodes[0]
        node.generate(1)
        accounts = node.listaccounts()
        balance_a = node.getbalance('a')
        moves = self.moves()
        assert len(moves) >= 6, moves

        self.restart_node(0)
        node = self.nodes[0]
        # getbalance(account) reads the moves from the wallet file
        assert_equal(node.getbalance('a'), balance_a)
        assert_equal(node.getbalance('*'), node.getbalance())
        assert_equal(node.move('', 'a', 1), True)
        assert_equal(node.getbalance('a'), balance_a + 1)

        def check_moves_kept():
            now = self.moves()
            assert now[:len(moves)] == moves, "move entries lost: %d of %d left" % (len(now) - 2, len(moves))
            expected = dict(accounts)
            expected['a'] += 1
            expected[''] -= 1
            assert_equal(node.listaccounts(), expected)
            assert_equal(len(now), len(moves) + 2)
        # The accounting entries aren't loaded at startup (walletdb.cpp,
        # commented out after ReorderTransactions)
        self.known_failure("move lost after restart (VKLzdLmd item 1)", check_moves_kept,
                           expected="move entries lost")


if __name__ == '__main__':
    WalletAccountsTest().main()
