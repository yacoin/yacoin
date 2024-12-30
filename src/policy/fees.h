// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2024 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef YACOIN_POLICYFEE_H
#define YACOIN_POLICYFEE_H

#include "amount.h"

static const ::int64_t MIN_TX_FEE = CENT;
static const ::int64_t MIN_RELAY_TX_FEE = MIN_TX_FEE;

::int64_t GetMinFee(unsigned int nBytes);

#endif // YACOIN_POLICYFEE_H
