#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test RPC authentication with rpcuser/rpcpassword and multiple -rpcauth users.

- node0 keeps rpcuser/rpcpassword and has several rpcauth lines in its
  config file (Core's two, a generated one, a malformed one, a user with
  two entries, a password with a colon) plus one -rpcauth on the command
  line. Every valid pair is accepted; wrong passwords, other users'
  passwords, case changes, unknown users and the malformed entry are not.
- A failed attempt is answered only after a delay (anti brute force).
- node1 has other rpcuser/rpcpassword values; node0's don't work there.
"""

import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    append_config,
    assert_equal,
    assert_greater_than_or_equal,
    raw_rpc,
    rpcauth_value,
)

# Core's rpc_users.py lines and their passwords.
RT_LINE = "rpcauth=rt:93648e835a54c573682c2eb19f882535$7681e9c5b74bdd85e78166031d2058e1069b3ed7ed967c93fc63abba06f31144"
RT_PASSWORD = "cA773lm788buwYe4g4WT+05pKyNruVKjQ25x3n0DQcM="
RT2_LINE = "rpcauth=rt2:f8607b1a88861fac29dfccf9b52ff9f$ff36a0c23c8c62b4846112e50fa888416e94c17bfd4c42f88fd8f55ec6a3137e"
RT2_PASSWORD = "8/F3uMDw4KSEbw96U3CA1C4X05dkHDN2BPFjTgZW4KI="

GEN_PASSWORD = "Gen-pw-1"
COLON_PASSWORD = "pass:with:colons"


class HTTPBasicsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [['-rpcauth=' + rpcauth_value('cmd', 'cmdpw')], []]

    def setup_chain(self):
        super().setup_chain()
        append_config(os.path.join(self.options.tmpdir, 'node0'), [
            RT_LINE,
            RT2_LINE,
            'rpcauth=' + rpcauth_value('gen', GEN_PASSWORD),
            # Two fields only: skipped.
            'rpcauth=bad:nosalt',
            'rpcauth=' + rpcauth_value('dup', 'pw1'),
            'rpcauth=' + rpcauth_value('dup', 'pw2'),
            'rpcauth=' + rpcauth_value('colon', COLON_PASSWORD),
        ])
        # node1 gets other credentials. Replace the lines: the node and the
        # framework both expect a single rpcuser/rpcpassword line.
        conf = os.path.join(self.options.tmpdir, 'node1', 'yacoin.conf')
        with open(conf, encoding='utf8') as f:
            lines = f.read().splitlines()
        lines = ['rpcuser=rpcuser2' if l.startswith('rpcuser=') else
                 'rpcpassword=pass:word' if l.startswith('rpcpassword=') else l for l in lines]
        with open(conf, 'w', encoding='utf8') as f:
            f.write('\n'.join(lines) + '\n')

    def status(self, node, user, password):
        return raw_rpc(node, '{"method": "getbestblockhash"}', auth=(user, password))[0]

    def run_test(self):
        node0, node1 = self.nodes
        # The node started despite the malformed line.
        assert_equal(node0.getblockcount(), 0)

        self.log.info("Accepted: rpcuser/rpcpassword and every rpcauth entry")
        for user, password in [
            ('yacoinuser', 'yacoinpwd'),
            ('rt', RT_PASSWORD),
            ('rt2', RT2_PASSWORD),
            ('gen', GEN_PASSWORD),
            ('cmd', 'cmdpw'),
            # Each entry of a user is tried.
            ('dup', 'pw1'),
            ('dup', 'pw2'),
            # The user name ends at the first colon.
            ('colon', COLON_PASSWORD),
        ]:
            assert_equal((user, self.status(node0, user, password)), (user, 200))

        self.log.info("Refused: wrong passwords, other users' passwords, case, unknown users")
        for user, password in [
            ('rt', RT2_PASSWORD),
            ('RT', RT_PASSWORD),
            ('bad', 'nosalt'),
            ('bad', ''),
            ('nobody', 'x'),
            ('gen', GEN_PASSWORD + 'x'),
            ('yacoinuser', RT_PASSWORD),
            ('colon', 'pass'),
        ]:
            assert_equal((user, password, self.status(node0, user, password)), (user, password, 401))

        self.log.info("A failed attempt is answered after a delay")
        start = time.time()
        assert_equal(self.status(node0, 'yacoinuser', 'wrong'), 401)
        assert_greater_than_or_equal(time.time() - start, 0.2)

        self.log.info("node1 has its own rpcuser/rpcpassword")
        assert_equal(self.status(node1, 'rpcuser2', 'pass:word'), 200)
        assert_equal(self.status(node1, 'yacoinuser', 'yacoinpwd'), 401)
        assert_equal(self.status(node1, 'rpcuser2', 'pass'), 401)


if __name__ == '__main__':
    HTTPBasicsTest().main()
