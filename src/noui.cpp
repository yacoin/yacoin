// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include <stdint.h>

    #include "msvc_warnings.push.h"
#endif

#include <string>

#ifndef BITCOIN_UI_INTERFACE_H
 #include "ui_interface.h"
#endif

static int noui_ThreadSafeMessageBox(const std::string& message, const std::string& caption, int style)
{
    LogPrintf("%s: %s\n", caption, message);
    fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    return 4;
}

static bool noui_ThreadSafeAskFee(::int64_t nFeeRequired, const std::string& strCaption)
{
    return true;
}

void noui_connect()
{
    // Connect yacoind signal handlers
    uiInterface.ThreadSafeMessageBox.connect(noui_ThreadSafeMessageBox);
    uiInterface.ThreadSafeAskFee.connect(noui_ThreadSafeAskFee);
}
#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
