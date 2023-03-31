// Copyright (c) 2017-2019 The Raven Core developers
// Copyright (c) 2023 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokentypes.h"

int IntFromETokenType(ETokenType type) {
    return (int)type;
}

ETokenType ETokenTypeFromInt(int nType) {
    return (ETokenType)nType;
}

std::string ETokenTypeToString(ETokenType& tokenType)
{
    switch (tokenType)
    {
        case ETokenType::YATOKEN:            return "YA-token";
        case ETokenType::SUB:                return "Sub-token";
        case ETokenType::UNIQUE:             return "Unique-token";
        case ETokenType::OWNER:              return "Owner-token";
        case ETokenType::VOTE:               return "Vote";
        case ETokenType::REISSUE:            return "Reissue";
        case ETokenType::INVALID:            return "Invalid";
        default:                            return "Unknown";
    }
}
