#!/usr/bin/env python3
# Copyright (c) 2026 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the life cycle of CLTV/CSV timelock addresses in the wallet.

- createcltvaddress / createcsvaddress (block-height locks) return the
  documented warning texts.
- The redeem scripts survive a restart: the wallet still recognises the
  addresses, their accounts and the coins received on them.
- A height lock can't be spent one block before it expires, and can be spent
  from the first block on which it has expired: a CLTV lock L when the tip is
  at least L, a CSV lock of n blocks funded at height F when the tip is at
  least F + n - 1. The spends set nLockTime / nSequence accordingly.
- A wallet restored from a backupwallet copy into an empty datadir still
  knows its timelock addresses and can spend from them after expiry.
- Moving a CLTV address to another wallet: dumpprivkey, then
  addredeemscript and importprivkey with a rescan; the other wallet spends
  it after expiry.
- Arguments, warnings and errors of createcltvaddress, createcsvaddress,
  timelockcoins, spendcltv and spendcsv; comments of the spends;
  sendtoaddress with useexpiredtimelockutxo=false leaves an expired
  timelock output alone.
- Known failures: errors with code -1 or a boost::bad_get message, named
  arguments, the "enough coins" check counting spent outputs, spendcsv
  sending from an address that isn't a CSV script.
"""
from decimal import Decimal
import os
import shutil

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    connect_nodes,
)
from test_framework.wallet_util import wipe_chain

NOT_SPENDABLE_YET = "Error: Transaction creation failed: Insufficient funds"
NOT_ENOUGH = "Not enough coin in the wallet to spend"
CODE_MINUS_1 = "Unexpected JSONRPC error code -1"


class WalletTimelockRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes[0], 1)

    def mine_to(self, height):
        """Mine on node 0 until the tip is at height, and sync."""
        node0 = self.nodes[0]
        node0.generate(height - node0.getblockcount())
        self.sync_blocks()

    def funding_outpoint(self, txid, address):
        tx = self.nodes[0].getrawtransaction(txid, 1)
        vout = [o['n'] for o in tx['vout'] if o['scriptPubKey'].get('addresses') == [address]]
        assert_equal(len(vout), 1)
        return txid, vout[0]

    def decode(self, node, txid):
        return node.decoderawtransaction(node.gettransaction(txid)['hex'])

    def run_test(self):
        node0, node1 = self.nodes
        node0.generate(10)
        self.sync_blocks()
        h = node0.getblockcount()

        self.log.info("Create CLTV and CSV addresses with block-height locks")
        cl = node1.createcltvaddress(h + 5, 'c')
        assert_equal(cl['Warning'], "Any coins sent to this cltv address will be locked until block height %d" % (h + 5))
        cs = node1.createcsvaddress(3, True, 's')
        assert_equal(cs['Warning'], "Any coins sent to this csv address will be locked within 3 blocks")
        cl2 = node1.createcltvaddress(h + 8, 'c2')
        cl_addr, cs_addr, cl2_addr = cl['cltv address'], cs['csv address'], cl2['cltv address']

        fund = {}
        for addr in (cl_addr, cs_addr, cl2_addr):
            fund[addr] = self.funding_outpoint(node0.sendtoaddress(addr, 5), addr)
        self.mine_to(h + 1)
        funding_height = h + 1

        self.log.info("Restart node 1: the redeem scripts are loaded from the wallet file")
        self.restart_node(1)
        node1 = self.nodes[1]
        connect_nodes(node1, 0)
        expected = [
            (cl_addr, 'CLTV_P2SH_timelock', cl['redeemScript'], 'c'),
            (cs_addr, 'CSV_P2SH_timelock', cs['redeemScript'], 's'),
            (cl2_addr, 'CLTV_P2SH_timelock', cl2['redeemScript'], 'c2'),
        ]
        for addr, script_type, redeem_script, account in expected:
            info = node1.validateaddress(addr)
            assert_equal((info['ismine'], info['script'], info['hex'], info['account']),
                         (True, script_type, redeem_script, account))
            assert_equal(node1.getreceivedbyaddress(addr), 5)
        described = node1.describeredeemscript(cl['redeemScript'])
        assert_equal((described['LockType'], described['CltvAddress']), ('Block-based lock', cl_addr))

        dest = node0.getnewaddress()

        self.log.info("CSV: can't spend before the lock expires, can spend from the expiry block on")
        csv_expiry = funding_height + 3 - 1
        self.mine_to(csv_expiry - 1)
        assert_raises_rpc_error(-4, NOT_SPENDABLE_YET, node1.spendcsv, cs_addr, dest, 4)
        self.mine_to(csv_expiry)
        tx_csv = node1.spendcsv(cs_addr, dest, 4)
        vin = self.decode(node1, tx_csv)['vin']
        assert_equal(len(vin), 1)
        assert_equal((vin[0]['txid'], vin[0]['vout'], vin[0]['sequence']), fund[cs_addr] + (3,))
        self.relay()

        self.log.info("CLTV: can't spend before the lock expires, can spend from the expiry block on")
        self.mine_to(h + 4)
        assert_raises_rpc_error(-4, NOT_SPENDABLE_YET, node1.spendcltv, cl_addr, dest, 4)
        self.mine_to(h + 5)
        tx_cltv = node1.spendcltv(cl_addr, dest, 4)
        decoded = self.decode(node1, tx_cltv)
        assert_equal(decoded['locktime'], h + 5)
        assert_equal(len(decoded['vin']), 1)
        assert_equal((decoded['vin'][0]['txid'], decoded['vin'][0]['vout'], decoded['vin'][0]['sequence']),
                     fund[cl_addr] + (0,))

        self.relay()
        self.mine_to(h + 6)
        assert_equal(node0.getreceivedbyaddress(dest), 8)
        assert_equal(node1.gettransaction(tx_cltv)['confirmations'], 1)
        assert_equal(node1.gettransaction(tx_csv)['confirmations'], 3)

        self.log.info("Restore node 1's wallet from a backup into an empty datadir")
        backup = os.path.join(self.options.tmpdir, 'node1.bak')
        node1.backupwallet(backup)
        self.stop_node(1)
        wipe_chain(node1, wallet=True)
        assert not os.path.exists(os.path.join(node1.datadir, 'blocks'))
        shutil.copyfile(backup, os.path.join(node1.datadir, 'wallet.dat'))
        self.start_node(1)
        node1 = self.nodes[1]
        connect_nodes(node1, 0)
        self.sync_blocks()
        for addr, script_type, redeem_script, account in expected:
            info = node1.validateaddress(addr)
            assert_equal((info['ismine'], info['hex'], info['account']), (True, redeem_script, account))

        self.log.info("Spend from the restored wallet's CLTV address after expiry")
        self.mine_to(h + 7)
        assert_raises_rpc_error(-4, NOT_SPENDABLE_YET, node1.spendcltv, cl2_addr, dest, 4)
        self.mine_to(h + 8)
        tx_cltv2 = node1.spendcltv(cl2_addr, dest, 4)
        assert_equal(self.decode(node1, tx_cltv2)['vin'][0]['txid'], fund[cl2_addr][0])
        self.relay()
        self.mine_to(h + 9)
        assert_equal(node0.getreceivedbyaddress(dest), 12)

        self.test_address_arguments()
        self.test_timelockcoins_arguments()
        self.test_spends()
        self.test_useexpiredtimelockutxo()

    def relay(self):
        """Give node 0 node 1's mempool directly, parents first (no relay delay)."""
        node0, node1 = self.nodes
        pending = [t for t in node1.getrawmempool() if t not in node0.getrawmempool()]
        while pending:
            left = []
            for txid in pending:
                try:
                    node0.sendrawtransaction(node1.getrawtransaction(txid))
                except JSONRPCException:
                    if txid not in node0.getrawmempool():
                        left.append(txid)
            assert len(left) < len(pending), left
            pending = left

    def test_address_arguments(self):
        self.log.info("createcltvaddress / createcsvaddress arguments and warnings")
        node1 = self.nodes[1]
        assert_raises_rpc_error(-1, "createcltvaddress <lock_time> [account]\nCreate a P2SH address which lock coins until lock_time\n",
                                node1.createcltvaddress)
        assert_raises_rpc_error(-1, "JSON value is not an integer as expected", node1.createcltvaddress, 'x')
        assert_raises_rpc_error(-1, "createcsvaddress <lock_time> [isBlockHeightLock] [account]", node1.createcsvaddress)
        assert_raises_rpc_error(-1, "JSON value is not a boolean as expected", node1.createcsvaddress, 10, 'x')

        def check_csv_range_code():
            for lock_time in (0, 1073741824):
                assert_raises_rpc_error(-8, "<lock_time> must be between 1 and 1073741823", node1.createcsvaddress, lock_time)
        self.known_failure("more -1 errors (DCjqQX73 item 4)", check_csv_range_code, expected=CODE_MINUS_1)

        assert_equal(node1.createcltvaddress(1000)['Warning'],
                     "Any coins sent to this cltv address will be locked until block height 1000")
        assert_equal(node1.createcltvaddress(500000000)['Warning'],
                     "Any coins sent to this cltv address will be locked until 1985-11-05 00:53:20 UTC")
        csv = node1.createcsvaddress(600)
        assert_equal(csv['Warning'], "Any coins sent to this csv address will be locked for a period of 600 seconds")
        described = node1.describeredeemscript(csv['redeemScript'])
        assert_equal((described['LockType'], described['CsvAddress']), ('Time-based lock', csv['csv address']))
        assert "locked for a period of 600 seconds" in described['Description']

        assert_raises_rpc_error(-8, "redeemScript must be hexadecimal string (not 'zz')", node1.addredeemscript, 'zz')

        def check_named_csv():
            address = node1.createcsvaddress(locktime=10, account='q')['csv address']
            assert_equal(node1.getaccount(address), 'q')
        # isblockheightlock is read without checking isNull()
        self.known_failure("named arguments (VKLzdLmd item 4)", check_named_csv,
                           expected="JSON value is not a boolean as expected")

    def test_timelockcoins_arguments(self):
        self.log.info("timelockcoins arguments")
        node0, node1 = self.nodes
        relative = "For relative timelock, <lock_time> must be in range of 1->1073741823"
        assert_raises_rpc_error(-3, "Lock amount too small", node1.timelockcoins, Decimal('0.00001'), 10)
        assert_raises_rpc_error(-32602, relative, node1.timelockcoins, 1, 0)
        assert_raises_rpc_error(-32602, relative, node1.timelockcoins, 1, 1073741824)
        assert_raises_rpc_error(-32602, "For absolute timelock, <lock_time> must be in range of 1->", node1.timelockcoins, 1, 0, False)
        assert_raises_rpc_error(-5, "Invalid Yacoin address: bad", node1.timelockcoins, 1, 10, True, True, 'bad')
        assert_raises_rpc_error(-1, "JSON value is not a boolean as expected", node1.timelockcoins, 1, 10, 'x')
        assert_raises_rpc_error(-1, "timelockcoins <amount> <lock_time>", node1.timelockcoins, 1)
        # Pinned until DCjqQX73 item 2 (misleading message) is decided
        assert_raises_rpc_error(-4, "Error: This transaction requires a transaction fee of at least 0.01 because of its amount, complexity, or use of recently received funds",
                                node1.timelockcoins, 10**6, 10)

        p2sh = node0.createcltvaddress(100)['cltv address']

        def check_p2sh_destination():
            assert_raises_rpc_error(-5, None, node1.timelockcoins, 1, 10, True, True, p2sh)
        # boost::get<CKeyID> on a script destination
        self.known_failure("bad_get (DCjqQX73 item 1)", check_p2sh_destination, expected=CODE_MINUS_1)

        def check_named_relative():
            assert 'txid' in node1.timelockcoins(amount=1, locktime=10, isrelativetimelock=True)

        def check_named_blockheight():
            assert 'txid' in node1.timelockcoins(amount=1, locktime=10, isblockheightlock=True)
        # The parameter is registered as "isrealtivetimelock", and the bools
        # are read without checking isNull()
        self.known_failure("named arguments (VKLzdLmd item 4)", check_named_relative,
                           expected="Unknown named parameter isrelativetimelock")
        self.known_failure("named arguments (VKLzdLmd item 4)", check_named_blockheight,
                           expected="JSON value is not a boolean as expected")

    def test_spends(self):
        self.log.info("spendcltv / spendcsv errors and comments, moving an address to another wallet")
        node0, node1 = self.nodes
        h = node0.getblockcount()
        dest = node0.getnewaddress()
        cl3 = node1.createcltvaddress(h + 3, 'c3')['cltv address']
        cs3 = node1.createcsvaddress(2, True, 's3')['csv address']
        cl4 = node1.createcltvaddress(h + 3, 'c4')['cltv address']
        own = node1.getnewaddress()
        spare = node1.getnewaddress()
        foreign = node0.createcltvaddress(h + 3)['cltv address']
        for address, amount in ((cl3, 5), (cs3, 5), (own, 10), (spare, 3)):
            node0.sendtoaddress(address, amount)
        self.mine_to(h + 1)

        def check_spendcsv_address_type():
            assert_raises_rpc_error(-5, None, node1.spendcsv, spare, dest, 1)
        # spendcsv sends from any own address
        self.known_failure("spendcsv on P2PKH (VKLzdLmd item 7)", check_spendcsv_address_type,
                           expected="No exception raised")

        def check_spendcltv_address_type():
            assert_raises_rpc_error(-5, None, node1.spendcltv, spare, dest, 1)
        # boost::get<CScriptID> on a key destination
        self.known_failure("bad_get (DCjqQX73 item 1)", check_spendcltv_address_type, expected=CODE_MINUS_1)

        assert_raises_rpc_error(-5, "Invalid cltv address", node1.spendcltv, 'bad', dest, 1)
        assert_raises_rpc_error(-5, "Wallet doesn't manage coins in this address", node1.spendcltv, foreign, dest, 1)
        assert_raises_rpc_error(-5, "Invalid destination address", node1.spendcltv, cl3, 'bad', 1)
        assert_raises_rpc_error(-5, NOT_ENOUGH, node1.spendcltv, cl3, dest, 6)
        assert_raises_rpc_error(-4, "Invalid amount", node1.spendcltv, cl3, dest, 0)
        assert_raises_rpc_error(-4, NOT_SPENDABLE_YET, node1.spendcltv, cl3, dest, 1)
        assert_raises_rpc_error(-5, NOT_ENOUGH, node1.spendcsv, cs3, dest, 6)
        assert_raises_rpc_error(-4, "Invalid amount", node1.spendcsv, cs3, dest, 0)

        def check_spendcsv_codes():
            assert_raises_rpc_error(-5, "Invalid csv address", node1.spendcsv, 'bad', dest, 1)
            assert_raises_rpc_error(-5, "Wallet doesn't manage coins in this address", node1.spendcsv, foreign, dest, 1)
            assert_raises_rpc_error(-5, "Invalid destination address", node1.spendcsv, cs3, 'bad', 1)
        # spendcsv throws runtime_error where spendcltv uses -5
        self.known_failure("more -1 errors (DCjqQX73 item 4)", check_spendcsv_codes, expected=CODE_MINUS_1)

        self.log.info("Move a CLTV address to node 0")
        funding = node1.sendtoaddress(cl4, 5)
        self.relay()
        self.mine_to(h + 2)
        key = node1.dumpprivkey(cl4)
        redeem_script = node1.validateaddress(cl4)['hex']
        assert_equal(key, {'address_type': 'P2SH address', 'private_key': key['private_key'], 'redeem_script': redeem_script})
        # Funded by node 1, so only a rescan with the script lets node 0 find it
        assert 'details' not in node0.gettransaction(funding)
        assert_equal(node0.addredeemscript(redeem_script, 'r'), cl4)
        node0.importprivkey(key['private_key'], '', True)
        info = node0.validateaddress(cl4)
        assert_equal((info['ismine'], info['script'], info['account']), (True, 'CLTV_P2SH_timelock', 'r'))
        assert_equal(node0.dumpprivkey(cl4), key)
        details = node0.gettransaction(funding)['details']
        assert_equal([(d['category'], d['address'], d['amount']) for d in details], [('receive', cl4, Decimal('5'))])
        assert_equal(node0.getreceivedbyaddress(cl4), 5)

        self.log.info("Spends after expiry, with comments")
        self.mine_to(h + 3)
        assert_raises_rpc_error(-4, NOT_SPENDABLE_YET, node1.spendcltv, cl3, dest, 5)
        txid = node1.spendcltv(cl3, dest, 1, 'c', 't')
        tx = node1.gettransaction(txid)
        assert_equal((tx['comment'], tx['to']), ('c', 't'))
        decoded = self.decode(node1, txid)
        assert_equal((decoded['locktime'], len(decoded['vin']), decoded['vin'][0]['sequence'], len(decoded['vout'])),
                     (h + 3, 1, 0, 2))
        self.relay()
        txid = node1.spendcsv(cs3, dest, 1, 'c2', 't2')
        tx = node1.gettransaction(txid)
        assert_equal((tx['comment'], tx['to']), ('c2', 't2'))
        assert_equal(self.decode(node1, txid)['vin'][0]['sequence'], 2)
        self.relay()
        receiver = node1.getnewaddress()
        txid = node0.spendcltv(cl4, receiver, 4)
        self.mine_to(h + 4)
        assert_equal(node0.gettransaction(txid)['confirmations'], 1)
        assert_equal(node1.getreceivedbyaddress(receiver), 4)

        # cl3 and cs3 have no coins left (the change went to new addresses)
        assert_equal(node1.listunspent(0, 9999999, [cl3, cs3]), [])

        def check_emptied_cltv():
            assert_raises_rpc_error(-5, NOT_ENOUGH, node1.spendcltv, cl3, dest, 1)

        def check_emptied_csv():
            assert_raises_rpc_error(-5, NOT_ENOUGH, node1.spendcsv, cs3, dest, 1)
        # The check sums every output ever paid to the address
        self.known_failure("emptied address -4 vs -5 (DCjqQX73 item 3)", check_emptied_cltv,
                           expected="Unexpected JSONRPC error code -4")
        self.known_failure("emptied address -4 vs -5 (DCjqQX73 item 3)", check_emptied_csv,
                           expected="Unexpected JSONRPC error code -4")

    def test_useexpiredtimelockutxo(self):
        self.log.info("sendtoaddress with useexpiredtimelockutxo=false")
        node0, node1 = self.nodes
        result = node1.timelockcoins(1, 2)
        assert_equal(result['message'], "1.000000 YAC are now locked. These coins will be locked within 2 blocks")
        outputs = self.decode(node1, result['txid'])['vout']
        lock = [o['n'] for o in outputs if o['scriptPubKey']['type'] == 'CSV_P2PKH_timelock']
        assert_equal(len(lock), 1)
        lock = (result['txid'], lock[0])
        self.relay()
        self.mine_to(node0.getblockcount() + 3)
        txid = node1.sendtoaddress(address=node0.getnewaddress(), amount=Decimal('0.5'), useexpiredtimelockutxo=False)
        assert lock not in [(i['txid'], i['vout']) for i in self.decode(node1, txid)['vin']]
        assert lock in [(u['txid'], u['vout']) for u in node1.listunspent(0)]


if __name__ == '__main__':
    WalletTimelockRPCTest().main()
