
#ifndef BITCOIN_TIMESTAMPS_H
#define BITCOIN_TIMESTAMPS_H

#ifndef _MSC_VER
    #include <limits.h>
#endif
// saironiq : block height where "no consecutive PoS blocks" rule activates
// Yacoin, updated to time.
//static const int nConsecutiveStakeSwitchHeight = 420000;
static const unsigned int 
    CONSECUTIVE_STAKE_SWITCH_TIME = (unsigned int)1392241857;   // 02/12/2014 9:50pm (UTC)
// we should set the above value as given to match the no two consecutive 
// PoS rule which went into effect at block 420000 (2/12/14 9:50pm Z
// this will allow 0.4.5 to agree with 0.4.4 with respect to new blocks.


static const unsigned int 
    nJan_01_2017 = 1483228800U,
  //nNov_01_2016 = 1477958400U,
  //nOct_01_2016 = 1475280000U,
  //nSep_01_2016 = 1472688000U,
  //nJul_16_2016 = 1468654496U,
  //nApr_01_2016 = 1459468800U,
    nConstantly_changing_date = nJan_01_2017, 

    YACOIN_NEW_LOGIC_SWITCH_TIME = nConstantly_changing_date;
// we should set the above value as given to match the future time we expect 
// all nodes will have upgraded and "caught up".  
// I believe this will create various blocks, therefore branches, forks, that 
// 0.4.4 code will not accept

// YACOIN TODO
static const unsigned int 
    nSecondsOfFriNov12_2055 = 2709614280U,
    nSomeObscureFutureTime = nSecondsOfFriNov12_2055;

static const unsigned int STAKE_SWITCH_TIME         = nSomeObscureFutureTime;  // for gcc's benefit, not MSVC++!
static const unsigned int TARGETS_SWITCH_TIME       = nSomeObscureFutureTime;  // Fri, 12 Nov 2055 06:38:00 GMT
//static const unsigned int CHAINCHECKS_SWITCH_TIME = 2709614280;
static const unsigned int STAKECURVE_SWITCH_TIME    = nSomeObscureFutureTime; 

static const unsigned int VALIDATION_SWITCH_TIME    = nSomeObscureFutureTime; 
static const unsigned int SIG_SWITCH_TIME           = nSomeObscureFutureTime; 

// Protocol switch time for fixed kernel modifier interval
static const unsigned int nModifierSwitchTime       = nSomeObscureFutureTime;   
static const unsigned int nModifierTestSwitchTime   = nSomeObscureFutureTime; 

#endif
