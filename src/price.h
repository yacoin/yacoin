// Copyright (c) 2024 The Yacoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef YACOIN_PRICE_H
#define YACOIN_PRICE_H

#include <string>

class CProvider
{
public:
    std::string sDomain, sPriceRatioKey, sApi;
    int nOffset;
    int nPort;
};

extern void initialize_price_vectors(int &nIndexBtcToYac, int &nIndexUsdToBtc);
extern bool GetMyExternalWebPage1(int &nIndex, std::string &strBuffer,
                                  double &dPrice);
extern bool GetMyExternalWebPage2(int &nIndex, std::string &strBuffer,
                                  double &dPrice);
extern void clearLocalSocketError(SOCKET hSocket);

#endif
