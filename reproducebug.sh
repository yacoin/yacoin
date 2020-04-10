#!/bin/bash

./src/yacoind -datadir=/tmp/test_runner_20200409_080007/mining_basic_0/node0 -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getmininginfo
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getmininginfo
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getblockcount
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getwalletinfo
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getbestblockhash
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getrpcinfo
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd invalidmethod
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getblockhash 42
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getblockcount
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getwalletinfo
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getbestblockhash
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd getrpcinfo
./src/yacoind -datadir=/tmp/test_runner_20200409_080007/interface_rpc_0/node0/ -printtoconsole -rpcport=16000 -rpcuser=yacoinuser -rpcpassword=yacoinpwd stop
