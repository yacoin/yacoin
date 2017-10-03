#!/bin/bash

git clone https://github.com/ya4-old-c-coder/yacoin.git
cd yacoin/src
ln -s ../../miniupnpc-1.8 miniupnpc
ln -s makefile.ubuntu makefile
cd leveldb
make
cd ..
make