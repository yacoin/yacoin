// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

// Allow switching between LevelDB and BerkelyDB here in case we need to temporarily
// go back to BDB for any reason. Once we're confident enough with LevelDB to stick
// with it, this can be deleted.

#ifdef USE_LEVELDB
 #ifndef BITCOIN_LEVELDB_H
  #include "txdb-leveldb.h"
 #endif
#else
 // is Berkeley DB for the block chain
 #ifndef BITCOIN_DB_H
  #include "db.h"
 #endif

 #ifndef BITCOIN_TXDB_BDB_H
  #include "txdb-bdb.h"
 #endif
#endif

#endif  // BITCOIN_TXDB_H
