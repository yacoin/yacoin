#!/usr/bin/env python3
# Copyright (c) 2023 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Testing token use cases"""

from datetime import datetime
from decimal import Decimal

from test_framework.blocktools import TIME_GENESIS_BLOCK

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_is_hash_string,
    assert_does_not_contain_key,
    assert_raises_rpc_error,
    assert_equal,
    assert_greater_than_or_equal,
    JSONRPCException,
    Decimal,
    wait_until,
)


class TokenTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.mocktime = TIME_GENESIS_BLOCK
        self.extra_args = [["-addressindex=1"], ["-addressindex=1"]]

    def setmocktimeforallnodes(self, mocktime):
        self.mocktime = mocktime
        for node in self.nodes:
            node.setmocktime(mocktime)

    def mine_blocks_init(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        self.setmocktimeforallnodes(self.mocktime)
        self.mocktime = (
            self.mocktime + timeBetweenBlocks + timeBetweenBlocks * numberOfBlocks
        )
        self.nodes[nodeId].generate(numberOfBlocks)
        self.sync_all()

    def mine_blocks(self, nodeId, numberOfBlocks):
        timeBetweenBlocks = 60
        for i in range(numberOfBlocks):
            self.setmocktimeforallnodes(self.mocktime)
            self.mocktime = self.mocktime + timeBetweenBlocks
            self.nodes[nodeId].generate(1)
        self.sync_all()

    def verify_result(self, address_0, address_1, amount_timelock_coins):
        n0, n1 = self.nodes[0], self.nodes[1]
        balance_0 = int(n0.getbalance())
        availablebalance_0 = int(n0.getavailablebalance())
        balance_1 = int(n1.getbalance())
        availablebalance_1 = int(n1.getavailablebalance())
        assert balance_0 - amount_timelock_coins == availablebalance_0
        assert balance_1 - amount_timelock_coins == availablebalance_1
        received_address_0 = int(n0.getreceivedbyaddress(address_0))
        received_address_1 = int(n1.getreceivedbyaddress(address_1))
        assert_equal(received_address_0, amount_timelock_coins)
        assert_equal(received_address_1, amount_timelock_coins)

        getaddressbalance_0 = n0.getaddressbalance({"addresses": ["%s" % address_0]})
        getaddressbalance_1 = n1.getaddressbalance({"addresses": ["%s" % address_1]})
        sum_balance_address_0 = getaddressbalance_0["balance"]
        sum_balance_address_1 = getaddressbalance_1["balance"]
        sum_received_address_0 = getaddressbalance_0["received"]
        sum_received_address_1 = getaddressbalance_1["received"]
        assert_equal(sum_received_address_0 / 1e6, received_address_0)
        assert_equal(sum_received_address_1 / 1e6, received_address_1)

        getaddressutxos_0 = n0.getaddressutxos({"addresses": ["%s" % address_0]})
        getaddressutxos_1 = n1.getaddressutxos({"addresses": ["%s" % address_1]})
        assert_equal(
            sum([element["satoshis"] for element in getaddressutxos_0]),
            sum_balance_address_0,
        )
        assert_equal(
            sum([element["satoshis"] for element in getaddressutxos_1]),
            sum_balance_address_1,
        )
        return balance_0

    def init_supply(self):
        self.log.info("Generating YAC for node[0]")
        self.mine_blocks(0, 10)

    def test_csv_p2pkh_timelock(self):
        self.log.info("Running test_csv_p2pkh_timelock!")
        LOCK_TIME = 600  # 600 seconds

        # The coinbase is already sent to first key in key pool, so remove it from key pool
        n0, n1 = self.nodes[0], self.nodes[1]
        n0.getnewaddress()

        # Get the address
        address_0 = n0.getnewaddress()
        address_1 = n1.getnewaddress()

        # Before timelocking coins
        balance_0 = self.verify_result(address_0, address_1, 0)
        amount_timelock_coins = int(balance_0 / 2)

        # Timelocking coins
        timelock_result_0 = n0.timelockcoins(
            amount_timelock_coins, LOCK_TIME, True, False, address_0
        )
        timelock_result_1 = n0.timelockcoins(
            amount_timelock_coins, LOCK_TIME, True, False, address_1
        )
        self.mine_blocks(0, 1)
        expected_message = (
            "%d.000000 YAC are now locked. These coins will be locked for a period of %d seconds"
            % (amount_timelock_coins, LOCK_TIME)
        )
        assert_equal(timelock_result_0["message"], expected_message)
        assert_equal(timelock_result_1["message"], expected_message)
        assert_equal(
            timelock_result_0["address_containing_timelocked_coins"], address_0
        )
        assert_equal(
            timelock_result_1["address_containing_timelocked_coins"], address_1
        )
        self.verify_result(address_0, address_1, amount_timelock_coins)
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n0.sendtoaddress,
            address_1,
            float(amount_timelock_coins) - 0.1,
        )
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n1.sendtoaddress,
            address_0,
            float(amount_timelock_coins) - 0.1,
        )

        # Timelock expired
        self.log.info("Waiting for timelock expired...")
        self.setmocktimeforallnodes(self.mocktime + LOCK_TIME - 60)
        self.mine_blocks(0, 1)
        # Get the address
        address_new_0 = n0.getnewaddress()
        txid_0 = n0.sendtoaddress(address_new_0, float(amount_timelock_coins) - 0.1)
        txid_1 = n1.sendtoaddress(address_new_0, float(amount_timelock_coins) - 0.1)
        wait_until(lambda: txid_1 in self.nodes[0].getrawmempool())
        self.mine_blocks(0, 1)
        getaddressutxos_0 = n1.getaddressutxos({"addresses": ["%s" % address_new_0]})
        count = 0
        for utxo in getaddressutxos_0:
            if utxo["txid"] == txid_0 or utxo["txid"] == txid_1:
                count += 1
        assert_equal(count, 2)

    def test_csv_p2pkh_blocklock(self):
        self.log.info("Running test_csv_p2pkh_blocklock!")
        LOCK_TIME = 10  # 10 blocks

        # The coinbase is already sent to first key in key pool, so remove it from key pool
        n0, n1 = self.nodes[0], self.nodes[1]
        n0.getnewaddress()

        # Get the address
        address_0 = n0.getnewaddress()
        address_1 = n1.getnewaddress()

        # Before timelocking coins
        balance_0 = self.verify_result(address_0, address_1, 0)
        amount_timelock_coins = int(balance_0 / 2)

        # Timelocking coins
        timelock_result_0 = n0.timelockcoins(
            amount_timelock_coins, LOCK_TIME, True, True, address_0
        )
        timelock_result_1 = n0.timelockcoins(
            amount_timelock_coins, LOCK_TIME, True, True, address_1
        )
        self.mine_blocks(0, 1)
        expected_message = (
            "%d.000000 YAC are now locked. These coins will be locked within %d blocks"
            % (amount_timelock_coins, LOCK_TIME)
        )
        assert_equal(timelock_result_0["message"], expected_message)
        assert_equal(timelock_result_1["message"], expected_message)
        assert_equal(
            timelock_result_0["address_containing_timelocked_coins"], address_0
        )
        assert_equal(
            timelock_result_1["address_containing_timelocked_coins"], address_1
        )
        self.verify_result(address_0, address_1, amount_timelock_coins)
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n0.sendtoaddress,
            address_1,
            float(amount_timelock_coins) - 0.1,
        )
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n1.sendtoaddress,
            address_0,
            float(amount_timelock_coins) - 0.1,
        )

        # Timelock expired
        self.log.info("Waiting for timelock expired...")
        self.mine_blocks(0, LOCK_TIME)
        # Get the address
        address_new_0 = n0.getnewaddress()
        txid_0 = n0.sendtoaddress(address_new_0, float(amount_timelock_coins) - 0.1)
        txid_1 = n1.sendtoaddress(address_new_0, float(amount_timelock_coins) - 0.1)
        wait_until(lambda: txid_1 in self.nodes[0].getrawmempool())
        self.mine_blocks(0, 1)
        getaddressutxos_0 = n1.getaddressutxos({"addresses": ["%s" % address_new_0]})
        count = 0
        for utxo in getaddressutxos_0:
            if utxo["txid"] == txid_0 or utxo["txid"] == txid_1:
                count += 1
        assert_equal(count, 2)

    def test_cltv_p2pkh_timelock(self):
        self.log.info("Running test_cltv_p2pkh_timelock!")
        LOCK_TIME = self.mocktime + 600  # set specific timestamp

        # The coinbase is already sent to first key in key pool, so remove it from key pool
        n0, n1 = self.nodes[0], self.nodes[1]
        n0.getnewaddress()

        # Get the address
        address_0 = n0.getnewaddress()
        address_1 = n1.getnewaddress()

        # Before timelocking coins
        balance_0 = self.verify_result(address_0, address_1, 0)
        amount_timelock_coins = int(balance_0 / 2)

        # Timelocking coins
        timelock_result_0 = n0.timelockcoins(
            amount_timelock_coins, LOCK_TIME, False, False, address_0
        )
        timelock_result_1 = n0.timelockcoins(
            amount_timelock_coins, LOCK_TIME, False, False, address_1
        )
        self.mine_blocks(0, 1)
        date_time = datetime.utcfromtimestamp(LOCK_TIME)
        timestamp_str = date_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        expected_message = (
            "%d.000000 YAC are now locked. These coins will be locked until %s"
            % (amount_timelock_coins, timestamp_str)
        )
        assert_equal(timelock_result_0["message"], expected_message)
        assert_equal(timelock_result_1["message"], expected_message)
        assert_equal(
            timelock_result_0["address_containing_timelocked_coins"], address_0
        )
        assert_equal(
            timelock_result_1["address_containing_timelocked_coins"], address_1
        )
        self.verify_result(address_0, address_1, amount_timelock_coins)
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n0.sendtoaddress,
            address_1,
            float(amount_timelock_coins) - 0.1,
        )
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n1.sendtoaddress,
            address_0,
            float(amount_timelock_coins) - 0.1,
        )

        # Timelock expired
        self.log.info("Waiting for timelock expired...")
        self.setmocktimeforallnodes(LOCK_TIME + 1)
        self.mine_blocks(0, 1)
        # Get the address
        address_new_0 = n0.getnewaddress()
        txid_0 = n0.sendtoaddress(address_new_0, float(amount_timelock_coins) - 0.1)
        txid_1 = n1.sendtoaddress(address_new_0, float(amount_timelock_coins) - 0.1)
        wait_until(lambda: txid_1 in self.nodes[0].getrawmempool())
        self.mine_blocks(0, 1)
        getaddressutxos_0 = n1.getaddressutxos({"addresses": ["%s" % address_new_0]})
        count = 0
        for utxo in getaddressutxos_0:
            if utxo["txid"] == txid_0 or utxo["txid"] == txid_1:
                count += 1
        assert_equal(count, 2)

    def test_cltv_p2pkh_blocklock(self):
        self.log.info("Running test_cltv_p2pkh_blocklock!")
        LOCK_TIME = 40  # block height = 30

        # The coinbase is already sent to first key in key pool, so remove it from key pool
        n0, n1 = self.nodes[0], self.nodes[1]
        n0.getnewaddress()

        # Get the address
        address_0 = n0.getnewaddress()
        address_1 = n1.getnewaddress()

        # Before timelocking coins
        balance_0 = self.verify_result(address_0, address_1, 0)
        amount_timelock_coins = int(balance_0 / 2)

        # Timelocking coins
        timelock_result_0 = n0.timelockcoins(
            amount_timelock_coins, LOCK_TIME, False, True, address_0
        )
        timelock_result_1 = n0.timelockcoins(
            amount_timelock_coins, LOCK_TIME, False, True, address_1
        )
        self.mine_blocks(0, 1)
        expected_message = (
            "%d.000000 YAC are now locked. These coins will be locked until block height %d"
            % (amount_timelock_coins, LOCK_TIME)
        )
        assert_equal(timelock_result_0["message"], expected_message)
        assert_equal(timelock_result_1["message"], expected_message)
        assert_equal(
            timelock_result_0["address_containing_timelocked_coins"], address_0
        )
        assert_equal(
            timelock_result_1["address_containing_timelocked_coins"], address_1
        )
        self.verify_result(address_0, address_1, amount_timelock_coins)
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n0.sendtoaddress,
            address_1,
            float(amount_timelock_coins) - 0.1,
        )
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n1.sendtoaddress,
            address_0,
            float(amount_timelock_coins) - 0.1,
        )

        # Timelock expired
        self.log.info("Waiting for timelock expired...")
        current_block_height = n0.getblockcount()
        self.mine_blocks(0, LOCK_TIME - current_block_height)
        # Get the address
        address_new_0 = n0.getnewaddress()
        txid_0 = n0.sendtoaddress(address_new_0, float(amount_timelock_coins) - 0.1)
        txid_1 = n1.sendtoaddress(address_new_0, float(amount_timelock_coins) - 0.1)
        wait_until(lambda: txid_1 in self.nodes[0].getrawmempool())
        self.mine_blocks(0, 1)
        getaddressutxos_0 = n1.getaddressutxos({"addresses": ["%s" % address_new_0]})
        count = 0
        for utxo in getaddressutxos_0:
            if utxo["txid"] == txid_0 or utxo["txid"] == txid_1:
                count += 1
        assert_equal(count, 2)

    def run_test(self):
        self.init_supply()
        self.test_csv_p2pkh_timelock()
        self.test_csv_p2pkh_blocklock()
        self.test_cltv_p2pkh_timelock()
        self.test_cltv_p2pkh_blocklock()


if __name__ == "__main__":
    TokenTest().main()
