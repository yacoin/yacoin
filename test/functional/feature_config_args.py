#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test command-line and config file arguments.

- Init errors: invalid config file lines, -testnet with -regtest, -bind
  with -listen=0, removed options (-socks, -tor, -rpcssl), an invalid
  -rpcallowip, -acceptnonstdtxn on main.
- Warnings for unknown -debug/-debugexclude categories and the removed
  -debugnet/-benchmark.
- -pid, -rpcbind without -rpcallowip, -rpcworkqueue/-rpcthreads below 1,
  -printtoconsole.
- -conf (relative and absolute), the command line winning over the
  file, the first of two values in a file winning, sections, and a
  negated option in the file and on the command line.
"""

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error

HTTP_START_ERROR = "Error: Unable to start HTTP server. See debug log for details."
BROADCAST_DISABLED = "Error: Wallet transaction broadcasting is disabled with -walletbroadcast"


class ConfArgsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False

    def write_conf(self, name, drop=(), extra=()):
        """Write a copy of the node's yacoin.conf to name in its datadir,
        without the lines starting with one of drop and with extra lines."""
        node = self.nodes[0]
        with open(os.path.join(node.datadir, 'yacoin.conf'), encoding='utf8') as f:
            lines = [l for l in f.read().splitlines() if not l.startswith(tuple(drop))]
        path = os.path.join(node.datadir, name)
        with open(path, 'w', encoding='utf8') as f:
            f.write('\n'.join(lines + list(extra)) + '\n')
        return path

    def run_test(self):
        self.stop_node(0)
        self.test_init_errors()
        self.test_warnings()
        self.test_options()
        self.test_config_files()

    def test_init_errors(self):
        node = self.nodes[0]
        self.log.info("Invalid config file lines")
        for line in ['foo', 'foo bar']:
            self.write_conf('bad.conf', extra=[line])
            node.assert_start_raises_init_error(['-conf=bad.conf'],
                "Error reading configuration file: the options configuration file contains an invalid line '%s'" % line)

        self.log.info("Invalid argument combinations and removed options")
        for args, message in [
            (['-testnet=1', '-regtest=1'], "Error: Invalid combination of -regtest and -testnet."),
            (['-bind=127.0.0.1', '-listen=0'], "Error: Cannot set -bind or -whitebind together with -listen=0"),
            (['-whitebind=127.0.0.1:1', '-listen=0'], "Error: Cannot set -bind or -whitebind together with -listen=0"),
            (['-socks=5'], "Error: Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."),
            (['-tor=1'], "Error: Unsupported argument -tor found, use -onion."),
            (['-rpcssl=1'], "Error: SSL mode for RPC (-rpcssl) is no longer supported.\n" + HTTP_START_ERROR),
            (['-rpcallowip=300.0.0.1'], "Error: Invalid -rpcallowip subnet specification: 300.0.0.1. Valid are a single IP (e.g. 1.2.3.4), "
                                        "a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24).\n" + HTTP_START_ERROR),
            (['-acceptnonstdtxn=1'], "Error: acceptnonstdtxn is not currently supported for main chain"),
        ]:
            node.assert_start_raises_init_error(args, message, match=ErrorMatch.FULL_TEXT)

    def test_warnings(self):
        self.log.info("Warnings for unknown debug categories and removed debug options")
        self.start_node(0, ['-debug=foo', '-debugexclude=foo', '-debugnet=1', '-benchmark=1'])
        self.stop_node(0, expected_stderr='\n'.join([
            "Warning: Unsupported logging category -debug=foo.",
            "Warning: Unsupported logging category -debugexclude=foo.",
            "Warning: Unsupported argument -debugnet ignored, use -debug=net.",
            "Warning: Unsupported argument -benchmark ignored, use -debug=bench.",
        ]))

    def test_options(self):
        node = self.nodes[0]
        datadir = node.datadir
        custom_pid = os.path.join(datadir, 'custom.pid')
        default_pid = os.path.join(datadir, 'yacoind.pid')

        self.log.info("-pid, -rpcbind without -rpcallowip, -rpcworkqueue/-rpcthreads 0")
        with node.assert_debug_log([
            "WARNING: option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect",
            "HTTP: creating work queue of depth 1",
            "HTTP: starting 1 worker threads",
        ]):
            self.start_node(0, ['-pid=custom.pid', '-rpcbind=127.0.0.1', '-rpcworkqueue=0', '-rpcthreads=0'])
        with open(custom_pid, encoding='utf8') as f:
            assert_equal(f.read(), "%d\n" % node.process.pid)
        assert not os.path.exists(default_pid)
        self.stop_node(0)
        assert not os.path.exists(custom_pid)

        self.log.info("The default pid file")
        self.start_node(0)
        with open(default_pid, encoding='utf8') as f:
            assert_equal(f.read(), "%d\n" % node.process.pid)
        # The default config, for comparison with the files below.
        assert_equal(node.getmininginfo()['Epoch Interval'], 10)
        assert_equal(node.resendwallettransactions(), [])
        self.stop_node(0)
        assert not os.path.exists(default_pid)

        self.log.info("-printtoconsole")
        self.start_node(0, ['-printtoconsole=1'])
        with open(node.stdout.name, encoding='utf8') as f:
            assert 'Using data directory' in f.read()
        self.stop_node(0)

    def test_config_files(self):
        node = self.nodes[0]
        self.log.info("-conf, relative to the datadir and absolute")
        # Without the file's own epochinterval line: the first value wins.
        path = self.write_conf('alt.conf', drop=['epochinterval='], extra=['epochinterval=12', 'nowalletbroadcast=1'])
        self.start_node(0, ['-conf=alt.conf'])
        assert_equal(node.getmininginfo()['Epoch Interval'], 12)
        # A negated option in the file.
        assert_raises_rpc_error(-4, BROADCAST_DISABLED, node.resendwallettransactions)
        self.stop_node(0)
        self.log.info("The command line wins over the file")
        self.start_node(0, ['-conf=' + path, '-epochinterval=14'])
        assert_equal(node.getmininginfo()['Epoch Interval'], 14)
        assert_raises_rpc_error(-4, BROADCAST_DISABLED, node.resendwallettransactions)
        self.stop_node(0)

        self.log.info("Two values in a file: the first wins; options in a section are ignored")
        self.write_conf('dup.conf', drop=['epochinterval='],
                        extra=['epochinterval=15', 'epochinterval=16', '[test]', 'nowalletbroadcast=1'])
        self.start_node(0, ['-conf=dup.conf'])
        assert_equal(node.getmininginfo()['Epoch Interval'], 15)
        # In the section it is test.nowalletbroadcast: no effect (outside
        # a section, as in alt.conf, it disables broadcasting).
        assert_equal(node.resendwallettransactions(), [])
        self.stop_node(0)

        self.log.info("A negated option on the command line")
        self.start_node(0, ['-nowalletbroadcast'])
        assert_raises_rpc_error(-4, BROADCAST_DISABLED, node.resendwallettransactions)


if __name__ == '__main__':
    ConfArgsTest().main()
