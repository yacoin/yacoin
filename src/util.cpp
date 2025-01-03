// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifdef _MSC_VER
    #include "msvc_warnings.push.h"
#endif

#ifndef BITCOIN_UTIL_H
 #include "util.h"
#endif

#ifndef BITCOIN_SYNC_H
 #include "sync.h"
#endif

#ifndef BITCOIN_STRLCPY_H
 #include "strlcpy.h"
#endif

#ifndef BITCOIN_UI_INTERFACE_H
 #include "ui_interface.h"
#endif

#include <boost/algorithm/string/join.hpp>

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {
    namespace program_options {
        std::string to_internal(const std::string&);
    }
}

#include <boost/program_options/detail/config_file.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#ifdef WIN32
 #ifdef _MSC_VER
 #pragma warning(disable:4786)
 #pragma warning(disable:4804)
 #pragma warning(disable:4805)
 #pragma warning(disable:4717)
 #else
 //#include "stdio.h"
 //#include "string.h"
 #endif
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h> /* for _commit */
#include "shlobj.h"
#elif defined(__linux__)
# include <sys/prctl.h>
#endif

#if !defined(WIN32) && !defined(ANDROID)
#include <execinfo.h>
#endif

using std::map;
using std::string;
using std::vector;
using std::ofstream;
using std::set;

namespace bt = boost::posix_time;

map<string, string> mapArgs;
map<string, vector<string> > mapMultiArgs;
bool fDebug = false;
bool fDebugNet = false;
bool fTestNetNewLogic = false;
::int32_t nTestNetNewLogicBlockNumber;
::int32_t nMainnetNewLogicBlockNumber;
::int32_t nTokenSupportBlockNumber;
unsigned char MAXIMUM_YAC1DOT0_N_FACTOR;
::int32_t nYac20BlockNumberTime = 0;
::int64_t nYac10HardforkTime = 1619048730;
// Epoch interval is a difficulty period. Right now on testnet, it is 21,000 blocks
::uint32_t nEpochInterval = 21000;
::uint32_t nDifficultyInterval = nEpochInterval;
bool fPrintToConsole = false;
bool fPrintToDebugger = false;
bool fRequestShutdown = false;
bool fShutdown = false;
bool fDaemon = false;
bool fServer = false;
string strMiscWarning;
bool fTestNet = false;
bool fUseOld044Rules = true;
bool fNoListen = false;
bool fLogTimestamps = false;
CMedianFilter< int64_t> vTimeOffsets(200,0);
bool fReopenDebugLog = false;

static int64_t nMockTime = 0;  // For unit testing

// Extended DecodeDumpTime implementation, see this page for details:
// http://stackoverflow.com/questions/3786201/parsing-of-date-time-from-string-boost
const std::locale formats[] = {
    std::locale(std::locale::classic(),new bt::time_input_facet("%Y-%m-%dT%H:%M:%SZ")),
    std::locale(std::locale::classic(),new bt::time_input_facet("%Y-%m-%d %H:%M:%S")),
    std::locale(std::locale::classic(),new bt::time_input_facet("%Y/%m/%d %H:%M:%S")),
    std::locale(std::locale::classic(),new bt::time_input_facet("%d.%m.%Y %H:%M:%S")),
    std::locale(std::locale::classic(),new bt::time_input_facet("%Y-%m-%d"))
};

const size_t formats_n = sizeof(formats)/sizeof(formats[0]);

std::time_t pt_to_time_t(const bt::ptime& pt)
{
    bt::ptime timet_start(boost::gregorian::date(1970,1,1));
    bt::time_duration diff = pt - timet_start;
    return diff.ticks()/bt::time_duration::rep_type::ticks_per_second;
}

// Init OpenSSL library multithreading support
static CCriticalSection** ppmutexOpenSSL;
static void locking_callback(int mode, int i, const char* file, int line)
{
    if (mode & CRYPTO_LOCK) 
    {
        ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i])
    } 
    else 
    {
        LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i])
    }
}

LockedPageManager LockedPageManager::instance;

static void RandAddSeed()
{
    // Seed with CPU performance counter
    int64_t nCounter = GetPerformanceCounter();
    RAND_add(&nCounter, sizeof(nCounter), 1.5);
    memset(&nCounter, 0, sizeof(nCounter));
}


// Init
class CInit
{
private:
    int
        nUnknownWhy_Crypto_Number_of_Locks;
public:
    CInit() 
    {   // Init OpenSSL library multithreading support.  How?  Where?  Why?

        //CRYPTO_num_locks()/2                                              // that just crashes on startup!
        //nUnknownWhy_Crypto_Number_of_Locks = CRYPTO_num_locks() - 10;     // still crashes at startup!
        //nUnknownWhy_Crypto_Number_of_Locks = CRYPTO_num_locks() - 5;      // this works too!! But causes a rescan of the wallet?!???!!!
        //nUnknownWhy_Crypto_Number_of_Locks = CRYPTO_num_locks() - 1;      // this works!!
        //nUnknownWhy_Crypto_Number_of_Locks = CRYPTO_num_locks() - 3;        // this works too!!  So I stop here!
        nUnknownWhy_Crypto_Number_of_Locks = CRYPTO_num_locks();        // test old value
                                                                            // does -4 work? WTFK!  NFD!  As usual
                                                                            // BTW, in the latest bitcoin, litcoin, etc, this
                                                                            // CInit is completely different!  And that code doesn't
                                                                            // work with this OpenSSL!  More NFD!!!
        ppmutexOpenSSL = (CCriticalSection**)OPENSSL_malloc(nUnknownWhy_Crypto_Number_of_Locks * sizeof(CCriticalSection*));
        for (int i = 0; i < nUnknownWhy_Crypto_Number_of_Locks; ++i)
            ppmutexOpenSSL[i] = new CCriticalSection();
        CRYPTO_set_locking_callback(locking_callback);
#ifdef WIN32
        // Seed random number generator with screen scrape and other hardware sources
        RAND_screen();
#endif

        // Seed random number generator with performance counter
        RandAddSeed();
    }
    ~CInit()
    {
        // Shutdown OpenSSL library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < nUnknownWhy_Crypto_Number_of_Locks; ++i)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
}
instance_of_cinit;

void RandAddSeedPerfmon()
{
    RandAddSeed();

    // This can take up to 2 seconds, so only do it every 10 minutes
    static int64_t nLastPerfmon;
    if (GetTime() < nLastPerfmon + 10 * 60)
        return;
    nLastPerfmon = GetTime();

#ifdef WIN32
    // Don't need this on Linux, OpenSSL automatically uses /dev/urandom
    // Seed with the entire set of perfmon data
    unsigned char pdata[250000];
    memset(pdata, 0, sizeof(pdata));
    unsigned long nSize = sizeof(pdata);
    long ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", NULL, NULL, pdata, &nSize);
    RegCloseKey(HKEY_PERFORMANCE_DATA);
    if (ret == ERROR_SUCCESS)
    {
        RAND_add(pdata, nSize, nSize/100.0);
        memset(pdata, 0, nSize);
        printf("RandAddSeed() %lu bytes\n", nSize);
    }
#endif
}

uint64_t GetRand(uint64_t nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64_t nRange = (std::numeric_limits< uint64_t>::max() / nMax) * nMax;
    uint64_t nRand = 0;
    do
        RAND_bytes((unsigned char*)&nRand, sizeof(nRand));
    while (nRand >= nRange);
    return (nRand % nMax);
}

int GetRandInt(int nMax)
{
    return GetRand(nMax);
}

uint256 GetRandHash()
{
    uint256 hash;
    RAND_bytes((unsigned char*)&hash, sizeof(hash));
    return hash;
}


std::string GetDebugLogPathName(){
    return (GetDataDir() / "debug.log").string();
}

static FILE* fileout = NULL;

inline int OutputDebugStringF(const char* pszFormat, ...)
{
    int ret = 0;
    if (fPrintToConsole)
    {
        // print to console
        va_list arg_ptr;
        va_start(arg_ptr, pszFormat);
        ret = vprintf(pszFormat, arg_ptr);
        va_end(arg_ptr);
    }
    else if (!fPrintToDebugger)
    {
        // print to debug.log

        if (!fileout)
        {
            boost::filesystem::path pathDebug = GetDataDir() / "debug.log"; // not clear if fTestNet is set yet?
            fileout = fopen(pathDebug.string().c_str(), "a");
            if (fileout) 
                setbuf(fileout, NULL); // unbuffered
        }
        if (fileout)
        {
            static bool fStartedNewLine = true;

            // This routine may be called by global destructors during shutdown.
            // Since the order of destruction of static/global objects is undefined,
            // allocate mutexDebugLog on the heap the first time this routine
            // is called to avoid crashes during shutdown.
            static boost::mutex
                * mutexDebugLog = NULL;
            if (mutexDebugLog == NULL) 
                mutexDebugLog = new boost::mutex();
            boost::mutex::scoped_lock 
                scoped_lock(*mutexDebugLog);

            // reopen the log file, if requested
            if (fReopenDebugLog) 
            {
                fReopenDebugLog = false;
                boost::filesystem::path 
                    pathDebug = GetDataDir() / "debug.log";     // again, fTestNet
                if (freopen(pathDebug.string().c_str(),"a",fileout) != NULL)
                    setbuf(fileout, NULL); // unbuffered
            }

            // Debug print useful for profiling
            if (fLogTimestamps && fStartedNewLine)
            {
                if(nMockTime == 0)
                    fprintf(fileout, "%s ", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
                else
                    fprintf(fileout, "Mock %s Real %s ",DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str(), DateTimeStrFormat("%x %H:%M:%S", time(NULL)).c_str());
            }
            if (pszFormat[strlen(pszFormat) - 1] == '\n')
                fStartedNewLine = true;
            else
                fStartedNewLine = false;

            va_list arg_ptr;
            va_start(arg_ptr, pszFormat);
            ret = vfprintf(fileout, pszFormat, arg_ptr);
            va_end(arg_ptr);
        }
    }

#ifdef WIN32
    if (fPrintToDebugger)
    {
        static CCriticalSection cs_OutputDebugStringF;

        // accumulate and output a line at a time
        {
            LOCK(cs_OutputDebugStringF);
            static std::string buffer;

            va_list arg_ptr;
            va_start(arg_ptr, pszFormat);
            buffer += vstrprintf(pszFormat, arg_ptr);
            va_end(arg_ptr);

            int line_start = 0, line_end;
            while((line_end = buffer.find('\n', line_start)) != -1)
            {
                OutputDebugStringA(buffer.substr(line_start, line_end - line_start).c_str());
                line_start = line_end + 1;
            }
            buffer.erase(0, line_start);
        }
    }
#endif
    return ret;
}

string vstrprintf(const char *format, va_list ap)
{
    char buffer[50000];
    char* p = buffer;
    int limit = sizeof(buffer);
    int ret;
    while (true)
    {
/*************
#ifndef _MSC_VER
        va_list arg_ptr;
        va_copy(arg_ptr, ap);
#else
        va_list arg_ptr = ap;
#endif
// I think this old way is clearer, as it shows what MS is doing
*************/
        va_list arg_ptr;
#ifdef _MSC_VER
    #define va_copy(dest, src) (dest = src)
#endif   
        va_copy(arg_ptr, ap);

#ifdef WIN32
        ret = _vsnprintf(p, limit, format, arg_ptr);
#else
        ret = vsnprintf(p, limit, format, arg_ptr);
#endif
        va_end(arg_ptr);
        if (ret >= 0 && ret < limit)
            break;
        if (p != buffer)
            delete[] p;
        limit *= 2;
        p = new char[limit];
        if (p == NULL)
            throw std::bad_alloc();
    }
    string str(p, p+ret);
    if (p != buffer)
        delete[] p;
    return str;
}

string real_strprintf(const char *format, int dummy, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, dummy);
    string str = vstrprintf(format, arg_ptr);
    va_end(arg_ptr);
    return str;
}

string real_strprintf(const std::string &format, int dummy, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, dummy);
    string str = vstrprintf(format.c_str(), arg_ptr);
    va_end(arg_ptr);
    return str;
}

void ParseString(const string& str, char c, vector<string>& v)
{
    if (str.empty())
        return;
    string::size_type i1 = 0;
    string::size_type i2;
    while (true)
    {
        i2 = str.find(c, i1);
        if (i2 == str.npos)
        {
            v.push_back(str.substr(i1));
            return;
        }
        v.push_back(str.substr(i1, i2-i1));
        i1 = i2+1;
    }
}


string FormatMoney(int64_t n, bool fPlus)
{
    // Note: not using straight sprintf here because we do NOT want
    // localized number formatting.
    int64_t n_abs = (n > 0 ? n : -n);
    int64_t quotient = n_abs/COIN;
    int64_t remainder = n_abs%COIN;
    string str = strprintf("%" PRId64 ".%06" PRId64, quotient, remainder);
                    // because COIN is 10^6

    // Right-trim excess zeros before the decimal point:
    // doesn't this (instead!) remove trailing 0's after the last non zero digit!?
    int 
        nTrim = 0;

    for (int i = str.size()-1; (str[i] == '0' && isdigit(str[i-2])); --i)
        ++nTrim;
    if (nTrim)
        str.erase(str.size()-nTrim, nTrim);

    if (n < 0)
        str.insert((unsigned int)0, 1, '-');
    else if (fPlus && n > 0)
        str.insert((unsigned int)0, 1, '+');
    return str;
}


bool ParseMoney(const string& str, int64_t& nRet)
{
    return ParseMoney(str.c_str(), nRet);
}

bool ParseMoney(const char* pszIn, int64_t& nRet)
{
    string strWhole;
    int64_t nUnits = 0;
    const char* p = pszIn;
    while (isspace(*p))
        p++;
    for (; *p; p++)
    {
        if (*p == '.')
        {
            p++;
            int64_t nMult = CENT*10;
            while (isdigit(*p) && (nMult > 0))
            {
                nUnits += nMult * (*p++ - '0');
                nMult /= 10;
            }
            break;
        }
        if (isspace(*p))
            break;
        if (!isdigit(*p))
            return false;
        strWhole.insert(strWhole.end(), *p);
    }
    for (; *p; p++)
        if (!isspace(*p))
            return false;
    if (strWhole.size() > 10) // guard against 63 bit overflow
        return false;
    if (nUnits < 0 || nUnits > COIN)
        return false;
    int64_t nWhole = atoi64(strWhole);
    int64_t nValue = nWhole*COIN + nUnits;

    nRet = nValue;
    return true;
}


static const signed char phexdigit[256] =
{ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, };

bool IsHex(const string& str)
{
    BOOST_FOREACH(unsigned char c, str)
    {
        if (phexdigit[c] < 0)
            return false;
    }
    return (str.size() > 0) && (str.size()%2 == 0);
}

vector<unsigned char> ParseHex(const char* psz)
{
    // convert hex dump to vector
    vector<unsigned char> vch;
    while (true)
    {
        while (isspace(*psz))
            psz++;
        signed char c = phexdigit[(unsigned char)*psz++];
        if (c == (signed char)-1)
            break;
        unsigned char n = (c << 4);
        c = phexdigit[(unsigned char)*psz++];
        if (c == (signed char)-1)
            break;
        n |= c;
        vch.push_back(n);
    }
    return vch;
}

vector<unsigned char> ParseHex(const string& str)
{
    return ParseHex(str.c_str());
}

static void InterpretNegativeSetting(string name, map<string, string>& mapSettingsRet)
{
    // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
    if (name.find("-no") == 0)
    {
        std::string positive("-");
        positive.append(name.begin()+3, name.end());
        if (mapSettingsRet.count(positive) == 0)
        {
            bool value = !GetBoolArg(name);
            mapSettingsRet[positive] = (value ? "1" : "0");
        }
    }
}

void ParseParameters(int argc, const char* const argv[])
{
    mapArgs.clear();
    mapMultiArgs.clear();
    for (int i = 1; i < argc; i++)
    {
        char psz[10000];
        strlcpy(psz, argv[i], sizeof(psz));
        char* pszValue = (char*)"";
        if (strchr(psz, '='))
        {
            pszValue = strchr(psz, '=');
            *pszValue++ = '\0';
        }
#ifdef WIN32
        _strlwr(psz);
        if (psz[0] == '/')
            psz[0] = '-';
#endif
#ifdef _MSC_VER
        if ('-' != psz[0])  // how about this instead
            continue;
#else
        if (psz[0] != '-')  // why? This forces all -arg=xxx to be first
            break;
#endif
        mapArgs[psz] = pszValue;
        mapMultiArgs[psz].push_back(pszValue);
    }

    // New 0.6 features:
    BOOST_FOREACH(const PAIRTYPE(string,string)& entry, mapArgs)
    {
        string name = entry.first;

        //  interpret --foo as -foo (as long as both are not set)
        if (name.find("--") == 0)
        {
            std::string singleDash(name.begin()+1, name.end());
            if (mapArgs.count(singleDash) == 0)
                mapArgs[singleDash] = entry.second;
            name = singleDash;
        }

        // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
        InterpretNegativeSetting(name, mapArgs);
    }
}

std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool GetBoolArg(const std::string& strArg, bool fDefault)   // 2nd arg defaults to false
{
    if (mapArgs.count(strArg))                  // there is/are an argument(s)
    {                                           // i.e an = sign
        if (mapArgs[strArg].empty())            // if nothing
            return true;                        // say true
        // shouldn't we also test for true or false?!
        return (atoi(mapArgs[strArg]) != 0);    // if integer not 0 then true
    }
    return fDefault;
}

bool SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    if (mapArgs.count(strArg) || mapMultiArgs.count(strArg))
        return false;
    mapArgs[strArg] = strValue;
    mapMultiArgs[strArg].push_back(strValue);

    return true;
}

bool SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}


string EncodeBase64(const unsigned char* pch, size_t len)
{
    static const char *pbase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    string strRet="";
    strRet.reserve((len+2)/3*4);

    int mode=0, left=0;
    const unsigned char *pchEnd = pch+len;

    while (pch<pchEnd)
    {
        int enc = *(pch++);
        switch (mode)
        {
            case 0: // we have no bits
                strRet += pbase64[enc >> 2];
                left = (enc & 3) << 4;
                mode = 1;
                break;

            case 1: // we have two bits
                strRet += pbase64[left | (enc >> 4)];
                left = (enc & 15) << 2;
                mode = 2;
                break;

            case 2: // we have four bits
                strRet += pbase64[left | (enc >> 6)];
                strRet += pbase64[enc & 63];
                mode = 0;
                break;
        }
    }

    if (mode)
    {
        strRet += pbase64[left];
        strRet += '=';
        if (mode == 1)
            strRet += '=';
    }

    return strRet;
}

string EncodeBase64(const string& str)
{
    return EncodeBase64((const unsigned char*)str.c_str(), str.size());
}

vector<unsigned char> DecodeBase64(const char* p, bool* pfInvalid)
{
    static const int decode64_table[256] =
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
        -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    if (pfInvalid)
        *pfInvalid = false;

    vector<unsigned char> vchRet;
    vchRet.reserve(strlen(p)*3/4);

    int mode = 0;
    int left = 0;

    while (1)
    {
         int dec = decode64_table[(unsigned char)*p];
         if (dec == -1) break;
         p++;
         switch (mode)
         {
             case 0: // we have no bits and get 6
                 left = dec;
                 mode = 1;
                 break;

              case 1: // we have 6 bits and keep 4
                  vchRet.push_back((left<<2) | (dec>>4));
                  left = dec & 15;
                  mode = 2;
                  break;

             case 2: // we have 4 bits and get 6, we keep 2
                 vchRet.push_back((left<<4) | (dec>>2));
                 left = dec & 3;
                 mode = 3;
                 break;

             case 3: // we have 2 bits and get 6
                 vchRet.push_back((left<<6) | dec);
                 mode = 0;
                 break;
         }
    }

    if (pfInvalid)
        switch (mode)
        {
            case 0: // 4n base64 characters processed: ok
                break;

            case 1: // 4n+1 base64 character processed: impossible
                *pfInvalid = true;
                break;

            case 2: // 4n+2 base64 characters processed: require '=='
                if (left || p[0] != '=' || p[1] != '=' || decode64_table[(unsigned char)p[2]] != -1)
                    *pfInvalid = true;
                break;

            case 3: // 4n+3 base64 characters processed: require '='
                if (left || p[0] != '=' || decode64_table[(unsigned char)p[1]] != -1)
                    *pfInvalid = true;
                break;
        }

    return vchRet;
}

string DecodeBase64(const string& str)
{
    vector<unsigned char> vchRet = DecodeBase64(str.c_str());
#ifdef _MSC_VER
    if( vchRet.empty() )    // can one return the nul string?
        return string( "" );
#endif
    return string((const char*)&vchRet[0], vchRet.size());
}

string EncodeBase32(const unsigned char* pch, size_t len)
{
    static const char *pbase32 = "abcdefghijklmnopqrstuvwxyz234567";

    string strRet="";
    strRet.reserve((len+4)/5*8);

    int mode=0, left=0;
    const unsigned char *pchEnd = pch+len;

    while (pch<pchEnd)
    {
        int enc = *(pch++);
        switch (mode)
        {
            case 0: // we have no bits
                strRet += pbase32[enc >> 3];
                left = (enc & 7) << 2;
                mode = 1;
                break;

            case 1: // we have three bits
                strRet += pbase32[left | (enc >> 6)];
                strRet += pbase32[(enc >> 1) & 31];
                left = (enc & 1) << 4;
                mode = 2;
                break;

            case 2: // we have one bit
                strRet += pbase32[left | (enc >> 4)];
                left = (enc & 15) << 1;
                mode = 3;
                break;

            case 3: // we have four bits
                strRet += pbase32[left | (enc >> 7)];
                strRet += pbase32[(enc >> 2) & 31];
                left = (enc & 3) << 3;
                mode = 4;
                break;

            case 4: // we have two bits
                strRet += pbase32[left | (enc >> 5)];
                strRet += pbase32[enc & 31];
                mode = 0;
        }
    }

    static const int nPadding[5] = {0, 6, 4, 3, 1};
    if (mode)
    {
        strRet += pbase32[left];
        for (int n=0; n<nPadding[mode]; n++)
             strRet += '=';
    }

    return strRet;
}

string EncodeBase32(const string& str)
{
    return EncodeBase32((const unsigned char*)str.c_str(), str.size());
}

vector<unsigned char> DecodeBase32(const char* p, bool* pfInvalid)
{
    static const int decode32_table[256] =
    {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1,
        -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,  0,  1,  2,
         3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    if (pfInvalid)
        *pfInvalid = false;

    vector<unsigned char> vchRet;
    vchRet.reserve((strlen(p))*5/8);

    int mode = 0;
    int left = 0;

    while (1)
    {
         int dec = decode32_table[(unsigned char)*p];
         if (dec == -1) break;
         p++;
         switch (mode)
         {
             case 0: // we have no bits and get 5
                 left = dec;
                 mode = 1;
                 break;

              case 1: // we have 5 bits and keep 2
                  vchRet.push_back((left<<3) | (dec>>2));
                  left = dec & 3;
                  mode = 2;
                  break;

             case 2: // we have 2 bits and keep 7
                 left = left << 5 | dec;
                 mode = 3;
                 break;

             case 3: // we have 7 bits and keep 4
                 vchRet.push_back((left<<1) | (dec>>4));
                 left = dec & 15;
                 mode = 4;
                 break;

             case 4: // we have 4 bits, and keep 1
                 vchRet.push_back((left<<4) | (dec>>1));
                 left = dec & 1;
                 mode = 5;
                 break;

             case 5: // we have 1 bit, and keep 6
                 left = left << 5 | dec;
                 mode = 6;
                 break;

             case 6: // we have 6 bits, and keep 3
                 vchRet.push_back((left<<2) | (dec>>3));
                 left = dec & 7;
                 mode = 7;
                 break;

             case 7: // we have 3 bits, and keep 0
                 vchRet.push_back((left<<5) | dec);
                 mode = 0;
                 break;
         }
    }

    if (pfInvalid)
        switch (mode)
        {
            case 0: // 8n base32 characters processed: ok
                break;

            case 1: // 8n+1 base32 characters processed: impossible
            case 3: //   +3
            case 6: //   +6
                *pfInvalid = true;
                break;

            case 2: // 8n+2 base32 characters processed: require '======'
                if (left || p[0] != '=' || p[1] != '=' || p[2] != '=' || p[3] != '=' || p[4] != '=' || p[5] != '=' || decode32_table[(unsigned char)p[6]] != -1)
                    *pfInvalid = true;
                break;

            case 4: // 8n+4 base32 characters processed: require '===='
                if (left || p[0] != '=' || p[1] != '=' || p[2] != '=' || p[3] != '=' || decode32_table[(unsigned char)p[4]] != -1)
                    *pfInvalid = true;
                break;

            case 5: // 8n+5 base32 characters processed: require '==='
                if (left || p[0] != '=' || p[1] != '=' || p[2] != '=' || decode32_table[(unsigned char)p[3]] != -1)
                    *pfInvalid = true;
                break;

            case 7: // 8n+7 base32 characters processed: require '='
                if (left || p[0] != '=' || decode32_table[(unsigned char)p[1]] != -1)
                    *pfInvalid = true;
                break;
        }

    return vchRet;
}

string DecodeBase32(const string& str)
{
    vector<unsigned char> vchRet = DecodeBase32(str.c_str());
#ifdef _MSC_VER
    if( vchRet.empty() )
        return string( "" );
#endif
    return string((const char*)&vchRet[0], vchRet.size());
}


int64_t DecodeDumpTime(const std::string& s)
{
    bt::ptime pt;

    for(size_t i=0; i<formats_n; ++i)
    {
        std::istringstream is(s);
        is.imbue(formats[i]);
        is >> pt;
        if(pt != bt::ptime()) break;
    }

    return pt_to_time_t(pt);
}

std::string EncodeDumpTime(int64_t nTime) {
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

std::string EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    BOOST_FOREACH(unsigned char c, str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string DecodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) {
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) | 
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

bool WildcardMatch(const char* psz, const char* mask)
{
    while (true)
    {
        switch (*mask)
        {
        case '\0':
            return (*psz == '\0');
        case '*':
            return WildcardMatch(psz, mask+1) || (*psz && WildcardMatch(psz+1, mask));
        case '?':
            if (*psz == '\0')
                return false;
            break;
        default:
            if (*psz != *mask)
                return false;
            break;
        }
        psz++;
        mask++;
    }
}

bool WildcardMatch(const string& str, const string& mask)
{
    return WildcardMatch(str.c_str(), mask.c_str());
}








static std::string FormatException(std::exception* pex, const char* pszThread)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "yacoin";
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void LogException(std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    printf("\n%s", message.c_str());
}

void PrintException(std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    printf("\n\n************************\n%s\n", message.c_str());
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
    strMiscWarning = message;
    throw;
}

void LogStackTrace() {
    printf("\n\n******* exception encountered *******\n");
    if (fileout)
    {
#if !defined(WIN32) && !defined(ANDROID)
        void* pszBuffer[32];
        size_t size;
        size = backtrace(pszBuffer, 32);
        backtrace_symbols_fd(pszBuffer, size, fileno(fileout));
#endif
    }
}

void PrintExceptionContinue(std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    printf("\n\n************************\n%s\n", message.c_str());
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
    strMiscWarning = message;
}

boost::filesystem::path GetDefaultDataDir()
{
    namespace fs = boost::filesystem;
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Yacoin
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Yacoin
    // Mac: ~/Library/Application Support/Yacoin
    // Unix: ~/.yacoin
#ifdef WIN32
    // Windows
    return GetSpecialFolderPath(CSIDL_APPDATA) / "Yacoin";
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
  #ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    fs::create_directory(pathRet);
    return pathRet / "Yacoin";
  #else
    // Unix
    return pathRet / ".yacoin";
  #endif
#endif
}

const boost::filesystem::path &GetDataDir(bool fTest_or_Main_Net_is_decided)    // defaults to true
{
    namespace fs = boost::filesystem;

    static fs::path CachedPathsArray[2];
  //static bool IsCachedArray[2] = {false, false};
    static bool IsCachedArray[2];

    fs::path &path = CachedPathsArray[ static_cast<int>(fTest_or_Main_Net_is_decided) ];

    // This can be called during exceptions by printf, so we cache the
    // value so we don't have to do memory allocations after that.
    if (IsCachedArray[ static_cast<int>(fTest_or_Main_Net_is_decided) ] )
        return path;

    static CCriticalSection csPathCached;
    LOCK(csPathCached);

    if ( mapArgs.count( "-datadir" ) ) 
    {
        path = fs::system_complete(mapArgs["-datadir"]);
        if (!fs::is_directory( path )) 
        {
            path = "";
            return path;                // is this a correct exit?
        }
    }
    else 
    {
        path = GetDefaultDataDir();
    }
    if (
        fTest_or_Main_Net_is_decided &&
        GetBoolArg("-testnet", false)   // this is known after config file is read  
       )                                // or testnet was set on the command line
        path /= "testnet";

    fs::create_directory(path);

    IsCachedArray[ static_cast<int>(fTest_or_Main_Net_is_decided) ] = true;
    return path;
}

string randomStrGen(int length) {
    static string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    string result;
    result.resize(length);
    for (int32_t i = 0; i < length; ++i)
        result[i] = charset[rand() % charset.length()];

    return result;
}

boost::filesystem::path GetConfigFile()
{
    boost::filesystem::path 
        pathConfigFile(GetArg("-conf", "yacoin.conf"));

    if (!pathConfigFile.is_complete())
    {
        bool 
            fTest_or_Main_Net_is_decided = false;

        pathConfigFile = GetDataDir(fTest_or_Main_Net_is_decided) / pathConfigFile;
    }
    return pathConfigFile;
}

static void createConf()
{
    srand(time(NULL));

    ofstream pConf;
    pConf.open(GetConfigFile().generic_string().c_str());
    pConf << "rpcuser=user\nrpcpassword="
            + randomStrGen(15)
            + "\nrpcport=7687"
            + "\nport=7688"
            + "\n#(0=off, 1=on) daemon - run in the background as a daemon and accept commands"
            + "\ndaemon=0"
            + "\n#(0=off, 1=on) server - accept command line and JSON-RPC commands"
            + "\nserver=0"
            + "\nrpcallowip=127.0.0.1"
            + "\ntestnet=0";
    pConf.close();
}

void ReadConfigFile(map<string, string>& mapSettingsRet,
                    map<string, vector<string> >& mapMultiSettingsRet)
{
    boost::filesystem::ifstream streamConfig(GetConfigFile());
    if (!streamConfig.good())
    {
        createConf();
        new(&streamConfig) boost::filesystem::ifstream(GetConfigFile());
        if(!streamConfig.good())
            return;
    }

    set<string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; 
         it != end; 
         ++it)
    {
        // Don't overwrite existing settings so command line settings override bitcoin.conf
        string strKey = string("-") + it->string_key;
        if (mapSettingsRet.count(strKey) == 0)
        {
            mapSettingsRet[strKey] = it->value[0];
            // interpret nofoo=1 as foo=0 (and nofoo=0 as foo=1) as long as foo not set)
            InterpretNegativeSetting(strKey, mapSettingsRet);
        }
        mapMultiSettingsRet[strKey].push_back(it->value[0]);
    }
}

boost::filesystem::path GetPidFile()
{
    boost::filesystem::path pathPidFile(GetArg("-pid", "yacoind.pid"));
    if (!pathPidFile.is_complete())
    {
        bool
            fTest_or_Main_Net_is_decided = false;

        pathPidFile = GetDataDir( fTest_or_Main_Net_is_decided ) / pathPidFile;
    }
    return pathPidFile;
}

#ifndef WIN32
void CreatePidFile(const boost::filesystem::path &path, pid_t pid)
{
    FILE* file = fopen(path.string().c_str(), "w");
    if (file)
    {
        fprintf(file, "%d\n", pid);
        fclose(file);
    }
}
#endif

bool RenameOver(boost::filesystem::path src, boost::filesystem::path dest)
{
#ifdef WIN32
    return MoveFileExA(src.string().c_str(), dest.string().c_str(),
                      MOVEFILE_REPLACE_EXISTING);
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif /* WIN32 */
}

void FileCommit(FILE *fileout)
{
    fflush(fileout);                // harmless if redundantly called
#ifdef WIN32
    _commit(_fileno(fileout));
#else
    fsync(fileno(fileout));
#endif
}

int GetFilesize(FILE* file)
{
    int nSavePos = ftell(file);
    int nFilesize = -1;
    if (fseek(file, 0, SEEK_END) == 0)
        nFilesize = ftell(file);
    fseek(file, nSavePos, SEEK_SET);
    return nFilesize;
}

void ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    boost::filesystem::path pathLog = GetDataDir() / "debug.log";
    FILE* file = fopen(pathLog.string().c_str(), "r");
    if (file && GetFilesize(file) > 10 * 1000000)
    {
        // Restart the file with some of the end
        char pch[200000];
        fseek(file, -sizeof(pch), SEEK_END);
        int nBytes = fread(pch, 1, sizeof(pch), file);
        fclose(file);

        file = fopen(pathLog.string().c_str(), "w");
        if (file)
        {
            fwrite(pch, 1, nBytes, file);
            fclose(file);
        }
    }
}








//
// "Never go to sea with two chronometers; take one or three."
// Our three time sources are:
//  - System clock
//  - Median of other nodes clocks
//  - The user (asking the user to fix the system clock if the first two disagree)
//

int64_t GetTime()
{
    if (nMockTime) return nMockTime;

    return time(NULL);
}

void SetMockTime(int64_t nMockTimeIn)
{
    nMockTime = nMockTimeIn;
}

static int64_t nTimeOffset = 0;

int64_t GetTimeOffset()
{
    return nTimeOffset;
}

int64_t GetAdjustedTime()
{
    return GetTime() + GetTimeOffset();
}

void AddTimeData(const CNetAddr& ip, int64_t nTime)
{
    int64_t nOffsetSample = nTime - GetTime();

    // Ignore duplicates
    static set<CNetAddr> setKnown;
    if (!setKnown.insert(ip).second)
        return;

    // Add data
    vTimeOffsets.input(nOffsetSample);
    printf("Added time data, samples %d, offset %+" PRId64 " (%+" PRId64 " minutes)\n", vTimeOffsets.size(), nOffsetSample, nOffsetSample/60);
    if (vTimeOffsets.size() >= 5 && vTimeOffsets.size() % 2 == 1)
    {
        int64_t nMedian = vTimeOffsets.median();
        std::vector< int64_t> vSorted = vTimeOffsets.sorted();
        // Only let other nodes change our time by so much
        if (abs64(nMedian) < 70 * 60)
        {
            nTimeOffset = nMedian;
        }
        else
        {
            nTimeOffset = 0;

            static bool fDone;
            if (!fDone)
            {
                // If nobody has a time different than ours but within 5 minutes of ours, give a warning
                bool fMatch = false;
                BOOST_FOREACH(int64_t nOffset, vSorted)
                    if (nOffset != 0 && abs64(nOffset) < 5 * 60)
                        fMatch = true;

                if (!fMatch)
                {
                    fDone = true;
                    string strMessage = _("Warning: Please check that your computer's date and time are correct! If your clock is wrong Yacoin will not work properly.");
                    strMiscWarning = strMessage;
                    printf("*** %s\n", strMessage.c_str());
                    uiInterface.ThreadSafeMessageBox(strMessage+" ", string("Yacoin"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION);
                }
            }
        }
        if (fDebug) {
            BOOST_FOREACH(int64_t n, vSorted)
                printf("%+" PRId64 "  ", n);
            printf("|  ");
        }
        printf("nTimeOffset = %+" PRId64 "  (%+" PRId64 " minutes)\n", nTimeOffset, nTimeOffset/60);
    }
}








string FormatVersion(int nVersion)
{
    if (nVersion%100 == 0)
        return strprintf("%d.%d.%d", nVersion/1000000, (nVersion/10000)%100, (nVersion/100)%100);
    else
        return strprintf("%d.%d.%d.%d", nVersion/1000000, (nVersion/10000)%100, (nVersion/100)%100, nVersion%100);
}

string FormatFullVersion()
{
    return CLIENT_BUILD;
}

// Format the subversion field according to BIP 14 spec (https://en.bitcoin.it/wiki/BIP_0014)
std::string FormatSubVersion(const std::string& name, int nClientVersion, const std::vector<std::string>& comments)
{
    std::ostringstream ss;
    ss << "/";
    ss << name << ":" << FormatVersion(nClientVersion);
    if (!comments.empty())
        ss << "(" << boost::algorithm::join(comments, "; ") << ")";
    ss << "/";
    return ss.str();
}

#ifdef WIN32
boost::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    namespace fs = boost::filesystem;

    char pszPath[MAX_PATH] = "";

    if(SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate))
    {
        return fs::path(pszPath);
    }

    printf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

void runCommand(std::string strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr)
        printf("runCommand error: system(%s) returned %d\n", strCommand.c_str(), nErr);
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif 0 && (defined(__FreeBSD__) || defined(__OpenBSD__))
    // TODO: This is currently disabled because it needs to be verified to work
    //       on FreeBSD or OpenBSD first. When verified the '0 &&' part can be
    //       removed.
    pthread_set_name_np(pthread_self(), name);

// This is XCode 10.6-and-later; bring back if we drop 10.5 support:
// #elif defined(MAC_OSX)
//    pthread_setname_np(name);

#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}

bool NewThread(void(*pfn)(void*), void* parg)
{
    try
    {
        boost::thread(pfn, parg); // thread detaches when out of scope
    } catch(boost::thread_resource_error &e) {
        printf("Error creating thread: %s\n", e.what());
        return false;
    }
    return true;
}

unsigned long getThreadId(){
    std::string threadId = boost::lexical_cast<std::string>(boost::this_thread::get_id());
    unsigned long threadNumber = 0;
    sscanf(threadId.c_str(), "%lx", &threadNumber);
    return threadNumber;
}

void Timestamp::stamp()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    mValue = tv.tv_sec * 1000000 + tv.tv_usec;
}

uint64_t Timestamp::getValue() const
{
    return mValue;
}

MeasureTime::MeasureTime()
{
    mStart.stamp();
}

uint64_t MeasureTime::getExecutionTime() const
{
    return mEnd.getValue() - mStart.getValue();
}

#ifdef WIN32
//_____________________________________________________________________________
void
    DoProgress( int nCount, int nTotalToScan, int64_t n64MsStartTime )
{
    int64_t
        n64SecondsEstimatedTotalTime,
        n64MsEstimatedTotalTime,
        n64MsDeltaTime;
    #ifdef QT_GUI
    std::string
        sTextString;
    #endif
    if(
        (0 == (nCount % 6) )   // every 6th time
      )
    {
        if( 0 == nCount )       // first time
        {
            (void)printf(
                    "%6d "
                    ""
                    , nCount
                        );
    #ifdef QT_GUI
            uiInterface.InitMessage(
                                    strprintf(
                                               _( "%6d " ), 
                                               nCount
                                             ).c_str() 
                                   );
    #endif
        }
        else                    // all the next times
        {
            n64SecondsEstimatedTotalTime = 0;
    #ifndef QT_GUI
            if( 
              //(0 == (nCount % 100) )   // every 100th time (every 10th next time)
                (0 == (nCount % 12) )   // every 12th time (every 6th next time)
              )
    #endif
            {   // let's estimate the time remaining too!
                n64MsDeltaTime = GetTimeMillis() - n64MsStartTime;
                // we have done nCount / nTotalToScan th of them in n64MsDeltaTime
                // so total time in ms ~ n64MsDeltaTime * nTotalToScan / nCount
                n64MsEstimatedTotalTime = n64MsDeltaTime * nTotalToScan / nCount;
                // time (seconds) remaining is
                n64SecondsEstimatedTotalTime =
                    ( n64MsEstimatedTotalTime + n64MsStartTime - GetTimeMillis() ) / 1000;
            }
            if (fPrintToConsole)
                (void)printf(
                            "%6d "
                            "%2.2f%% "
                            ""
                            , nCount
                            , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                            );
    #ifdef QT_GUI
            uiInterface.InitMessage(
                                    strprintf(
                                              _("%6d "
                                                "%2.2f%% "
                                                ""
                                               )
                                                , nCount
                                                , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                                             ).c_str() 
                                   );
    #endif
            if( 0 != n64SecondsEstimatedTotalTime )
            {
                const int64_t
                    nSecondsPerMinute = 60,
                    nMinutesPerHour = 60;
                int64_t
                    nSeconds = 0,
                    nMinutes = 0,
                    nHours = 0;

                if( n64SecondsEstimatedTotalTime >= nSecondsPerMinute )
                {                   // there are minutes to go
                    nSeconds = n64SecondsEstimatedTotalTime % nSecondsPerMinute;
                    nMinutes = n64SecondsEstimatedTotalTime / nSecondsPerMinute;
                    if( nMinutes >= nMinutesPerHour ) // there are hours to go
                    {
                        nHours = nMinutes / nMinutesPerHour;
                        nMinutes %= nMinutesPerHour;
                        if (fPrintToConsole)
                            (void)printf(
                                        "~%d:%02d:%02d hrs:min:sec"
                                        ""
                                        ,
                                        (int)nHours,
                                        (int)nMinutes,
                                        (int)nSeconds
                                        );
    #ifdef QT_GUI
                        uiInterface.InitMessage( 
                                                strprintf(
                                                          _("%6d "
                                                            "%2.2f%% "
                                                            ""
                                                            "~%d:%02d:%02d hrs:min:sec"
                                                            ""
                                                           )
                                                            , nCount
                                                            , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                                                            ,
                                                            (int)nHours,
                                                            (int)nMinutes,
                                                            (int)nSeconds
                                                         ).c_str() 
                                               );
    #endif
                    }
                    else    // there are only minutes
                    {
                        if (fPrintToConsole)
                            (void)printf(
                                        "~%2d:%02d min:sec      "
                                        "\r"
                                        ""
                                        ,
                                        (int)nMinutes,
                                        (int)nSeconds
                                        );
    #ifdef QT_GUI
                        uiInterface.InitMessage( 
                                                strprintf(
                                                          _("%6d "
                                                            "%2.2f%% "
                                                            ""
                                                            "~%2d:%02d min:sec    "
                                                            ""
                                                           )
                                                           , nCount
                                                           , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                                                           ,
                                                         (int)nMinutes,
                                                         (int)nSeconds
                                                         ).c_str() 
                                               );
    #endif
                    }
                }
                else    // there are only seconds
                {
                    nSeconds = n64SecondsEstimatedTotalTime;
                    if (fPrintToConsole)
                        (void)printf(
                                    "~%2d sec       "
                                    ""
                                    ,
                                    (int)nSeconds
                                    );
    #ifdef QT_GUI
                    uiInterface.InitMessage(
                                            strprintf(
                                                      _("%6d "
                                                        "%2.2f%% "
                                                        ""
                                                        "~%2d sec         "
                                                        ""
                                                       )
                                                       , nCount
                                                       , floorf( float(nCount * 10000.0 / nTotalToScan) ) / 100
                                                       ,
                                                      (int)nSeconds
                                                     ).c_str() 
                                           );
    #endif
                }
            }
        }
        (void)printf( "\r" );
    }
}
//_____________________________________________________________________________
#endif


#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
//
unsigned long long getTotalSystemMemory( void )
{
#ifdef WIN32
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatusEx(&status);
    return status.ullTotalPhys;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    return pages * page_size;
#endif
}

#ifdef _MSC_VER
    #include "msvc_warnings.pop.h"
#endif
