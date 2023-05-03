#!/usr/bin/env python3
# Copyright (c) 2023 The Yacoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Testing token use cases"""

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
        self.extra_args = [
            ["-tokenindex=1", "-tokenSupportBlockNumber=10"],
            ["-tokenindex=1", "-tokenSupportBlockNumber=10"],
        ]

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

    def activate_tokens(self):
        self.log.info("Generating YAC for node[0] and activating tokens at block 10")
        n0 = self.nodes[0]

        self.mine_blocks(0, 10)
        assert_equal({}, n0.listtokens("*", True))
        self.mine_blocks(0, 20)

    def big_test(self):
        self.log.info("Running big test!")
        n0, n1 = self.nodes[0], self.nodes[1]
        address0 = n0.getnewaddress()
        address1 = n1.getnewaddress()

        # TEST ISSUE YA-TOKEN
        self.log.info("Calling issue()...")
        ipfs_hash = "QmcvyefkqQX3PpjpY5L8B2yMd47XrVwAipr6cxUt2zvYU8"
        n0.issue("TEST_YATOKEN", 1000, 4, True, True, ipfs_hash, address0, "")

        self.log.info("Waiting for 1 confirmation after issue...")
        self.mine_blocks(0, 1)
        self.log.info("Checking that 10 YAC is locked...")
        balance_0 = int(n0.getbalance())
        available_balance_0 = int(n0.getavailablebalance())
        assert balance_0 - 10 == available_balance_0
        self.log.info("Try sending all balance...")
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n0.sendtoaddress,
            address1,
            balance_0,
        )

        self.log.info("Waiting for 10 confirmations after issue...")
        self.mine_blocks(0, 9)
        self.log.info("Checking that no YAC is locked...")
        balance_0 = int(n0.getbalance())
        available_balance_0 = int(n0.getavailablebalance())
        assert balance_0 == available_balance_0
        self.log.info("Try sending all balance of node 0...")
        transaction_id = n0.sendtoaddress(address1, balance_0)
        assert_equal(int(n0.gettransaction(transaction_id)["version"]), 2)
        self.mine_blocks(0, 1)
        balance_1 = int(n1.getbalance())
        assert_equal(balance_0, balance_1)
        self.log.info("Try sending all balance of node 1...")
        transaction_id = n1.sendtoaddress(address0, float(balance_1) - 0.1)
        assert_equal(int(n1.gettransaction(transaction_id)["version"]), 2)
        wait_until(lambda: transaction_id in self.nodes[0].getrawmempool())
        self.mine_blocks(0, 1)
        balance_0_after = int(n0.getbalance())
        assert_greater_than_or_equal(balance_0_after, balance_0)

        self.log.info("Checkout listtoken()...")
        tokendata = n0.listtokens("TEST_YATOKEN", True)["TEST_YATOKEN"]
        assert_equal(tokendata["name"], "TEST_YATOKEN")
        assert_equal(tokendata["token_type"], "YA-token")
        assert_equal(tokendata["amount"], "1000.0000")
        assert_equal(tokendata["units"], 4)
        assert_equal(tokendata["reissuable"], 1)
        assert_equal(tokendata["has_ipfs"], 1)
        assert_equal(tokendata["ipfs_hash_cidv0"], ipfs_hash)

        self.log.info("Checking listmytokens()...")
        mytokens = n0.listmytokens("TEST_YATOKEN*", True)
        assert_equal(len(mytokens), 2)
        token_names = list(mytokens.keys())
        assert_equal(token_names.count("TEST_YATOKEN"), 1)
        assert_equal(token_names.count("TEST_YATOKEN!"), 1)
        assert_equal(mytokens["TEST_YATOKEN"]["balance"], "1000.0000")
        assert_equal(mytokens["TEST_YATOKEN!"]["balance"], "1")
        assert_equal(len(mytokens["TEST_YATOKEN"]["outpoints"]), 1)
        assert_equal(len(mytokens["TEST_YATOKEN!"]["outpoints"]), 1)
        assert_is_hash_string(mytokens["TEST_YATOKEN"]["outpoints"][0]["txid"])
        assert_equal(
            mytokens["TEST_YATOKEN"]["outpoints"][0]["txid"],
            mytokens["TEST_YATOKEN!"]["outpoints"][0]["txid"],
        )
        assert int(mytokens["TEST_YATOKEN"]["outpoints"][0]["vout"]) >= 0
        assert int(mytokens["TEST_YATOKEN!"]["outpoints"][0]["vout"]) >= 0
        assert_equal(mytokens["TEST_YATOKEN"]["outpoints"][0]["amount"], "1000.0000")
        assert_equal(mytokens["TEST_YATOKEN!"]["outpoints"][0]["amount"], "1")

        self.log.info("Checking listtokenbalancesbyaddress()...")
        assert_equal(
            n0.listtokenbalancesbyaddress(address0)["TEST_YATOKEN"], "1000.0000"
        )
        assert_equal(n0.listtokenbalancesbyaddress(address0)["TEST_YATOKEN!"], "1")

        self.log.info("Checking listtokenbalancesbyaddress()...")
        assert_equal(
            n0.listaddressesbytoken("TEST_YATOKEN"),
            n1.listaddressesbytoken("TEST_YATOKEN"),
        )

        # TEST TRANSFER YA-TOKEN
        self.log.info("Calling transfer()...")
        n0.transfer("TEST_YATOKEN", 200, address1)

        self.log.info("Waiting for ten confirmations after transfer...")
        self.mine_blocks(0, 10)

        self.log.info("Checking listmytokens()...")
        mytokens = n1.listmytokens("TEST_YATOKEN*", True)
        assert_equal(len(mytokens), 1)
        token_names = list(mytokens.keys())
        assert_equal(token_names.count("TEST_YATOKEN"), 1)
        assert_equal(token_names.count("TEST_YATOKEN!"), 0)
        assert_equal(mytokens["TEST_YATOKEN"]["balance"], "200.0000")
        assert_equal(len(mytokens["TEST_YATOKEN"]["outpoints"]), 1)
        assert_is_hash_string(mytokens["TEST_YATOKEN"]["outpoints"][0]["txid"])
        assert int(mytokens["TEST_YATOKEN"]["outpoints"][0]["vout"]) >= 0
        assert_equal(n0.listmytokens("TEST_YATOKEN")["TEST_YATOKEN"], "800.0000")

        self.log.info("Checking listtokenbalancesbyaddress()...")
        assert_equal(
            n1.listtokenbalancesbyaddress(address1)["TEST_YATOKEN"], "200.0000"
        )
        changeaddress = None
        assert_equal(
            n0.listaddressesbytoken("TEST_YATOKEN"),
            n1.listaddressesbytoken("TEST_YATOKEN"),
        )
        assert_equal(
            sum([eval(i) for i in n0.listaddressesbytoken("TEST_YATOKEN").values()]),
            1000,
        )
        assert_equal(
            sum([eval(i) for i in n0.listaddressesbytoken("TEST_YATOKEN").values()]),
            1000,
        )
        for assaddr in n0.listaddressesbytoken("TEST_YATOKEN").keys():
            if n0.validateaddress(assaddr)["ismine"]:
                changeaddress = assaddr
                assert_equal(
                    n0.listtokenbalancesbyaddress(changeaddress)["TEST_YATOKEN"],
                    "800.0000",
                )
        assert changeaddress is not None
        assert_equal(n0.listtokenbalancesbyaddress(address0)["TEST_YATOKEN!"], "1")

        self.log.info("Burning all units to test reissue on zero units...")
        n0.transfer("TEST_YATOKEN", 800, "YJTF2npk3ESUVEqBA8CcM8rP3CqMTNMsTs")
        self.mine_blocks(0, 1)
        assert_does_not_contain_key(
            "TEST_YATOKEN", n0.listmytokens("TEST_YATOKEN", True)
        )

        # TEST REISSUE YA-TOKEN
        self.log.info("Calling reissue()...")
        address0_2 = n0.getnewaddress()
        ipfs_hash2 = "QmcvyefkqQX3PpjpY5L8B2yMd47XrVwAipr6cxUt2zvYU8"
        n0.reissue("TEST_YATOKEN", 2000, False, address0, address0_2, -1, ipfs_hash2)

        self.log.info("Waiting for 1 confirmation after reissue...")
        self.mine_blocks(0, 1)
        self.log.info("Checking that 10 YAC is locked...")
        balance_0 = int(n0.getbalance())
        available_balance_0 = int(n0.getavailablebalance())
        assert balance_0 - 10 == available_balance_0
        self.log.info("Try sending all balance...")
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n0.sendtoaddress,
            address1,
            balance_0,
        )

        self.log.info("Waiting for 10 confirmations after reissue...")
        self.mine_blocks(0, 9)
        self.log.info("Checking that no YAC is locked...")
        balance_0 = int(n0.getbalance())
        available_balance_0 = int(n0.getavailablebalance())
        assert balance_0 == available_balance_0
        self.log.info("Try sending all balance of node 0...")
        transaction_id = n0.sendtoaddress(address1, balance_0)
        assert_equal(int(n0.gettransaction(transaction_id)["version"]), 2)
        self.mine_blocks(0, 1)
        balance_1 = int(n1.getbalance())
        assert_equal(balance_0, balance_1)
        self.log.info("Try sending all balance of node 1...")
        transaction_id = n1.sendtoaddress(address0, float(balance_1) - 0.1)
        assert_equal(int(n1.gettransaction(transaction_id)["version"]), 2)
        wait_until(lambda: transaction_id in self.nodes[0].getrawmempool())
        self.mine_blocks(0, 1)
        balance_0_after = int(n0.getbalance())
        assert_greater_than_or_equal(balance_0_after, balance_0)

        self.log.info("Checkout listtoken()...")
        tokendata = n0.listtokens("TEST_YATOKEN", True)["TEST_YATOKEN"]
        assert_equal(tokendata["name"], "TEST_YATOKEN")
        assert_equal(tokendata["token_type"], "YA-token")
        assert_equal(tokendata["amount"], "3000.0000")
        assert_equal(tokendata["units"], 4)
        assert_equal(tokendata["reissuable"], 0)
        assert_equal(tokendata["has_ipfs"], 1)
        assert_equal(tokendata["ipfs_hash_cidv0"], ipfs_hash2)

        self.log.info("Checking listtokenbalancesbyaddress()...")
        assert_equal(
            n0.listtokenbalancesbyaddress(address0)["TEST_YATOKEN"], "2000.0000"
        )

        # TEST ISSUE SUB-TOKEN
        self.log.info("Creating some sub-tokens...")
        n0.issue(
            "TEST_YATOKEN/SUB1", 1000, 4, True, True, ipfs_hash, address0, address0
        )

        self.log.info("Waiting for 1 confirmation after issue Sub-token...")
        self.mine_blocks(0, 1)
        self.log.info("Checking that 10 YAC is locked...")
        balance_0 = int(n0.getbalance())
        available_balance_0 = int(n0.getavailablebalance())
        assert balance_0 - 10 == available_balance_0
        self.log.info("Try sending all balance...")
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n0.sendtoaddress,
            address1,
            balance_0,
        )

        self.log.info("Waiting for 10 confirmations after issue Sub-token...")
        self.mine_blocks(0, 9)
        self.log.info("Checking that no YAC is locked...")
        balance_0 = int(n0.getbalance())
        available_balance_0 = int(n0.getavailablebalance())
        assert balance_0 == available_balance_0
        self.log.info("Try sending all balance of node 0...")
        transaction_id = n0.sendtoaddress(address1, balance_0)
        assert_equal(int(n0.gettransaction(transaction_id)["version"]), 2)
        self.mine_blocks(0, 1)
        balance_1 = int(n1.getbalance())
        assert_equal(balance_0, balance_1)
        self.log.info("Try sending all balance of node 1...")
        transaction_id = n1.sendtoaddress(address0, float(balance_1) - 0.1)
        assert_equal(int(n1.gettransaction(transaction_id)["version"]), 2)
        wait_until(lambda: transaction_id in self.nodes[0].getrawmempool())
        self.mine_blocks(0, 1)
        balance_0_after = int(n0.getbalance())
        assert_greater_than_or_equal(balance_0_after, balance_0)

        self.log.info("Checkout listtoken()...")
        tokendata = n0.listtokens("TEST_YATOKEN/SUB1", True)["TEST_YATOKEN/SUB1"]
        assert_equal(tokendata["name"], "TEST_YATOKEN/SUB1")
        assert_equal(tokendata["token_type"], "Sub-token")
        assert_equal(tokendata["amount"], "1000.0000")
        assert_equal(tokendata["units"], 4)
        assert_equal(tokendata["reissuable"], 1)
        assert_equal(tokendata["has_ipfs"], 1)
        assert_equal(tokendata["ipfs_hash_cidv0"], ipfs_hash)

        # TEST ISSUE UNIQUE-TOKEN
        self.log.info("Creating some Unique-tokens...")
        n0.issue("test_YaToKEN#uniQUE_TOKen")
        n0.issue("test_YaTOKEN#UniQUE_TOKEn")

        self.log.info("Waiting for 1 confirmation after issue Unique-token...")
        self.mine_blocks(0, 1)
        self.log.info("Checking that 20 YAC is locked...")
        balance_0 = int(n0.getbalance())
        available_balance_0 = int(n0.getavailablebalance())
        assert balance_0 - 20 == available_balance_0
        self.log.info("Try sending all balance...")
        assert_raises_rpc_error(
            -4,
            "Error: Transaction creation failed",
            n0.sendtoaddress,
            address1,
            balance_0,
        )

        self.log.info("Waiting for 10 confirmations after issue Unique-token...")
        self.mine_blocks(0, 9)
        self.log.info("Checking that no YAC is locked...")
        balance_0 = int(n0.getbalance())
        available_balance_0 = int(n0.getavailablebalance())
        assert balance_0 == available_balance_0
        self.log.info("Try sending all balance of node 0...")
        transaction_id = n0.sendtoaddress(address1, balance_0)
        assert_equal(int(n0.gettransaction(transaction_id)["version"]), 2)
        self.mine_blocks(0, 1)
        balance_1 = int(n1.getbalance())
        assert_equal(balance_0, balance_1)
        self.log.info("Try sending all balance of node 1...")
        transaction_id = n1.sendtoaddress(address0, float(balance_1) - 0.1)
        assert_equal(int(n1.gettransaction(transaction_id)["version"]), 2)
        wait_until(lambda: transaction_id in self.nodes[0].getrawmempool())
        self.mine_blocks(0, 1)
        balance_0_after = int(n0.getbalance())
        assert_greater_than_or_equal(balance_0_after, balance_0)

        self.log.info("Checkout listtoken()...")
        tokendata = n0.listtokens("test_YaToKEN#uniQUE_TOKen", True)[
            "TEST_YATOKEN#uniQUE_TOKen"
        ]
        assert_equal(tokendata["name"], "TEST_YATOKEN#uniQUE_TOKen")
        assert_equal(tokendata["token_type"], "Unique-token")
        assert_equal(tokendata["amount"], "1")
        assert_equal(tokendata["units"], 0)
        assert_equal(tokendata["reissuable"], 0)
        assert_equal(tokendata["has_ipfs"], 0)

        tokendata = n0.listtokens("test_YaToKEN#UniQUE_TOKEn", True)[
            "TEST_YATOKEN#UniQUE_TOKEn"
        ]
        assert_equal(tokendata["name"], "TEST_YATOKEN#UniQUE_TOKEn")
        assert_equal(tokendata["token_type"], "Unique-token")
        assert_equal(tokendata["amount"], "1")
        assert_equal(tokendata["units"], 0)
        assert_equal(tokendata["reissuable"], 0)
        assert_equal(tokendata["has_ipfs"], 0)
        self.log.info("Checking listaddressesbytoken()...")
        assert n0.listaddressesbytoken(
            "TEST_YATOKEN#uniQUE_TOKen"
        ) != n1.listaddressesbytoken("TEST_YATOKEN#UniQUE_TOKEn")

        # Checking issue many YAC tokens
        self.log.info("Checking listtokens()...")
        n0.issue("YAC1", 1000)
        n0.issue("YAC2", 1000)
        n0.issue("YAC3", 1000)
        self.mine_blocks(0, 1)
        yac_tokens = n0.listtokens("YAC*", False, 2, 1)
        assert_equal(len(yac_tokens), 2)
        assert_equal(yac_tokens[0], "YAC2")
        assert_equal(yac_tokens[1], "YAC3")

    def issue_param_checks(self):
        self.log.info("Checking bad parameter handling!")
        n0 = self.nodes[0]

        # just plain bad token name
        assert_raises_rpc_error(
            -8,
            "Invalid token name: BAD-TOKEN-NAME\nError: Name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can't be the first or last characters)",
            n0.issue,
            "bad-token-name",
        )

        # trying to issue things that can't be issued
        assert_raises_rpc_error(
            -8, "Unsupported token type: Owner-token", n0.issue, "AN_OWNER!"
        )

        # check bad unique params
        assert_raises_rpc_error(
            -8,
            "Invalid parameters for issuing a unique token.",
            n0.issue,
            "A_UNIQUE#TOKEN",
            2,
        )
        assert_raises_rpc_error(
            -8,
            "Invalid parameters for issuing a unique token.",
            n0.issue,
            "A_UNIQUE#TOKEN",
            1,
            1,
        )
        assert_raises_rpc_error(
            -8,
            "Invalid parameters for issuing a unique token.",
            n0.issue,
            "A_UNIQUE#TOKEN",
            1,
            0,
            True,
        )

    def chain_tokens(self):
        self.log.info("Issuing chained tokens in depth issue()...")
        n0, n1 = self.nodes[0], self.nodes[1]
        self.mine_blocks(0, 10)

        chain_address = n0.getnewaddress()
        ipfs_hash = "QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"
        chain_string = "CHAIN1"
        n0.issue(chain_string, 1000, 4, True, True, ipfs_hash, chain_address, "")

        for i in range(0, 5):
            chain_string += "/" + str(i)
            n0.issue(chain_string, 1000, 4, True, True, ipfs_hash, chain_address, "")

        self.mine_blocks(0, 1)

        chain_tokens = n1.listtokens("CHAIN1*", False)
        assert_equal(len(chain_tokens), 6)

        self.log.info("Issuing chained tokens in width issue()...")
        chain_address = n0.getnewaddress()
        chain_string = "CHAIN2"
        n0.issue(chain_string, 1000, 4, True, True, ipfs_hash, chain_address, "")

        for i in range(0, 5):
            token_name = chain_string + "/" + str(i)
            n0.issue(token_name, 1000, 4, True, True, ipfs_hash, chain_address, "")

        self.mine_blocks(0, 1)

        chain_tokens = n1.listtokens("CHAIN2/*", False)
        assert_equal(len(chain_tokens), 5)

        self.log.info("Chaining reissue transactions...")
        address0 = n0.getnewaddress()
        n0.issue("CHAIN_REISSUE", 1000, 4, True, False, address0, "")

        self.mine_blocks(0, 1)

        n0.reissue("CHAIN_REISSUE", 1000, True, address0, "")
        assert_raises_rpc_error(
            -4, None, n0.reissue, "CHAIN_REISSUE", 1000, True, address0, ""
        )

        self.mine_blocks(0, 1)

        n0.reissue("CHAIN_REISSUE", 1000, True, address0, "")

        self.mine_blocks(0, 1)

        self.log.info("Checkout listtoken()...")
        tokendata = n0.listtokens("CHAIN_REISSUE", True)["CHAIN_REISSUE"]
        assert_equal(tokendata["name"], "CHAIN_REISSUE")
        assert_equal(tokendata["token_type"], "YA-token")
        assert_equal(tokendata["amount"], "3000.0000")
        assert_equal(tokendata["units"], 4)
        assert_equal(tokendata["reissuable"], 1)
        assert_equal(tokendata["has_ipfs"], 0)

    def ipfs_state(self):
        self.log.info("Checking ipfs hash state changes...")
        n0 = self.nodes[0]
        self.mine_blocks(0, 10)

        token_name1 = "TOKEN111"
        token_name2 = "TOKEN222"
        address1 = n0.getnewaddress()
        address2 = n0.getnewaddress()
        ipfs_hash = "QmcvyefkqQX3PpjpY5L8B2yMd47XrVwAipr6cxUt2zvYU8"
        bad_hash = "RncvyefkqQX3PpjpY5L8B2yMd47XrVwAipr6cxUt2zvYU8"

        ########################################
        # bad hash (isn't a valid multihash sha2-256)
        self.log.info("Testing issue token with invalid IPFS...")
        try:
            n0.issue(token_name1, 1000, 0, True, True, bad_hash, address1, address2)
        except JSONRPCException as e:
            if "Invalid IPFS hash" not in e.error["message"]:
                raise AssertionError(
                    "Expected substring not found:" + e.error["message"]
                )
        except Exception as e:
            raise AssertionError("Unexpected exception raised: " + type(e).__name__)
        else:
            raise AssertionError("No exception raised")

        ########################################
        # no hash
        self.log.info("Testing issue token with no IPFS...")
        n0.issue(token_name2, 1000, 0, True, False, address1, address2)
        self.mine_blocks(0, 1)
        ad = n0.listtokens(token_name2, True)[token_name2]
        assert_equal(0, ad["has_ipfs"])
        assert_does_not_contain_key("ipfs_hash_cidv0", ad)

        ########################################
        # reissue w/ bad hash
        self.log.info("Testing re-issue token with invalid IPFS...")
        try:
            n0.reissue(token_name2, 2000, True, address1, address2, -1, bad_hash)
        except JSONRPCException as e:
            if "Invalid IPFS hash" not in e.error["message"]:
                raise AssertionError(
                    "Expected substring not found:" + e.error["message"]
                )
        except Exception as e:
            raise AssertionError("Unexpected exception raised: " + type(e).__name__)
        else:
            raise AssertionError("No exception raised")

        ########################################
        # reissue w/ hash
        self.log.info("Testing re-issue token with valid IPFS...")
        n0.reissue(token_name2, 2000, True, address1, address2, -1, ipfs_hash)
        self.mine_blocks(0, 1)
        ad = n0.listtokens(token_name2, True)[token_name2]
        assert_equal(1, ad["has_ipfs"])
        assert_equal(ipfs_hash, ad["ipfs_hash_cidv0"])

    def reissue_prec_change(self):
        self.log.info("Testing precision change on reissue...")
        n0 = self.nodes[0]
        self.mine_blocks(0, 10)

        token_name = "PREC_CHANGES"
        address = n0.getnewaddress()

        n0.issue(token_name, 10, 0, True, False, "", "")
        self.mine_blocks(0, 1)
        assert_equal(0, n0.listtokens("*", True)[token_name]["units"])

        for i in range(0, 6):
            n0.reissue(token_name, 10.0 ** (-i), True, address, "", i + 1)
            self.mine_blocks(0, 1)
            assert_equal(i + 1, n0.listtokens("*", True)[token_name]["units"])
            assert_raises_rpc_error(
                -25,
                "Error: Unable to reissue token: unit must be larger than current unit selection",
                n0.reissue,
                token_name,
                10.0 ** (-i),
                True,
                address,
                "",
                i,
            )

        n0.reissue(token_name, 0.000001, True, address)
        self.mine_blocks(0, 1)
        assert_equal("11.111111", n0.listtokens("*", True)[token_name]["amount"])

    def run_test(self):
        self.activate_tokens()
        self.big_test()
        self.issue_param_checks()
        self.chain_tokens()
        self.ipfs_state()
        self.reissue_prec_change()


if __name__ == "__main__":
    TokenTest().main()
