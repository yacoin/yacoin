// Copyright (c) 2017-2019 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokentypes.h"

int IntFromTokenType(TokenType type) {
    return (int)type;
}

TokenType TokenTypeFromInt(int nType) {
    return (TokenType)nType;
}
