// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include "crypto/common.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <stdint.h>

inline int Testuint256AdHoc(std::vector<std::string> vArg);

extern bool fNewerOpenSSL;  // for key.h => key.cpp's benefit

/** Base class without constructors for uint256 and uint160.
 * This makes the compiler let u use it in a union.
 */
template<unsigned int BITS>
class base_blob
{
protected:
    enum { WIDTH=BITS/32 };
    unsigned int pn[WIDTH];
public:

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (pn[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(pn, 0, sizeof(pn));
    }

    inline int Compare(const base_blob& other) const { return memcmp(pn, other.pn, sizeof(pn)); }

    bool operator!() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (pn[i] != 0)
                return false;
        return true;
    }

    const base_blob operator~() const
    {
        base_blob ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        return ret;
    }

    const base_blob operator-() const
    {
        base_blob ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        ret++;
        return ret;
    }

    double getdouble() const
    {
        double ret = 0.0;
        double fact = 1.0;
        for (int i = 0; i < WIDTH; i++) {
            ret += fact * pn[i];
            fact *= 4294967296.0;
        }
        return ret;
    }

    base_blob& operator=(::uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
        return *this;
    }

    base_blob& operator^=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] ^= b.pn[i];
        return *this;
    }

    base_blob& operator&=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] &= b.pn[i];
        return *this;
    }

    base_blob& operator|=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] |= b.pn[i];
        return *this;
    }

    base_blob& operator^=(::uint64_t b)
    {
        pn[0] ^= (unsigned int)b;
        pn[1] ^= (unsigned int)(b >> 32);
        return *this;
    }

    base_blob& operator|=(::uint64_t b)
    {
        pn[0] |= (unsigned int)b;
        pn[1] |= (unsigned int)(b >> 32);
        return *this;
    }

    base_blob& operator<<=(unsigned int shift)
    {
        base_blob a(*this);
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
        int k = shift / 32;
        shift = shift % 32;
        for (int i = 0; i < WIDTH; i++)
        {
            if (i+k+1 < WIDTH && shift != 0)
                pn[i+k+1] |= (a.pn[i] >> (32-shift));
            if (i+k < WIDTH)
                pn[i+k] |= (a.pn[i] << shift);
        }
        return *this;
    }

    base_blob& operator>>=(unsigned int shift)
    {
        base_blob a(*this);
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
        int k = shift / 32;
        shift = shift % 32;
        for (int i = 0; i < WIDTH; i++)
        {
            if (i-k-1 >= 0 && shift != 0)
                pn[i-k-1] |= (a.pn[i] << (32-shift));
            if (i-k >= 0)
                pn[i-k] |= (a.pn[i] >> shift);
        }
        return *this;
    }

    base_blob& operator+=(const base_blob& b)
    {
        ::uint64_t carry = 0;
        for (int i = 0; i < WIDTH; i++)
        {
            ::uint64_t n = carry + pn[i] + b.pn[i];
            pn[i] = n & 0xffffffff;
            carry = n >> 32;
        }
        return *this;
    }

    base_blob& operator-=(const base_blob& b)
    {
        *this += -b;
        return *this;
    }

    base_blob& operator+=(::uint64_t b64)
    {
        base_blob b;
        b = b64;
        *this += b;
        return *this;
    }

    base_blob& operator-=(::uint64_t b64)
    {
        base_blob b;
        b = b64;
        *this += -b;
        return *this;
    }


    base_blob& operator++()
    {
        // prefix operator
        int i = 0;
        while (++pn[i] == 0 && i < WIDTH-1)
            i++;
        return *this;
    }

    const base_blob operator++(int)
    {
        // postfix operator
        const base_blob ret = *this;
        ++(*this);
        return ret;
    }

    base_blob& operator--()
    {
        // prefix operator
        int i = 0;
        while (--pn[i] == -1 && i < WIDTH-1)
            i++;
        return *this;
    }

    const base_blob operator--(int)
    {
        // postfix operator
        const base_blob ret = *this;
        --(*this);
        return ret;
    }


    friend inline bool operator<(const base_blob& a, const base_blob& b)
    {
        for (int i = base_blob::WIDTH-1; i >= 0; i--)
        {
            if (a.pn[i] < b.pn[i])
                return true;
            else if (a.pn[i] > b.pn[i])
                return false;
        }
        return false;
    }

    friend inline bool operator<=(const base_blob& a, const base_blob& b)
    {
        for (int i = base_blob::WIDTH-1; i >= 0; i--)
        {
            if (a.pn[i] < b.pn[i])
                return true;
            else if (a.pn[i] > b.pn[i])
                return false;
        }
        return true;
    }

    friend inline bool operator>(const base_blob& a, const base_blob& b)
    {
        for (int i = base_blob::WIDTH-1; i >= 0; i--)
        {
            if (a.pn[i] > b.pn[i])
                return true;
            else if (a.pn[i] < b.pn[i])
                return false;
        }
        return false;
    }

    friend inline bool operator>=(const base_blob& a, const base_blob& b)
    {
        for (int i = base_blob::WIDTH-1; i >= 0; i--)
        {
            if (a.pn[i] > b.pn[i])
                return true;
            else if (a.pn[i] < b.pn[i])
                return false;
        }
        return true;
    }

    friend inline bool operator==(const base_blob& a, const base_blob& b)
    {
        for (int i = 0; i < base_blob::WIDTH; i++)
            if (a.pn[i] != b.pn[i])
                return false;
        return true;
    }

    friend inline bool operator==(const base_blob& a, ::uint64_t b)
    {
        if (a.pn[0] != (unsigned int)b)
            return false;
        if (a.pn[1] != (unsigned int)(b >> 32))
            return false;
        for (int i = 2; i < base_blob::WIDTH; i++)
            if (a.pn[i] != 0)
                return false;
        return true;
    }

    friend inline bool operator!=(const base_blob& a, const base_blob& b)
    {
        return (!(a == b));
    }

    friend inline bool operator!=(const base_blob& a, ::uint64_t b)
    {
        return (!(a == b));
    }



    std::string GetHex() const
    {
        char psz[sizeof(pn)*2 + 1];
        for (unsigned int i = 0; i < sizeof(pn); i++)
            sprintf(psz + i*2, "%02x", ((unsigned char*)pn)[sizeof(pn) - i - 1]);
        return std::string(psz, psz + sizeof(pn)*2);
    }

    void SetHex(const char* psz)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;

        // skip leading spaces
        while (isspace(*psz))
            psz++;

        // skip 0x
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;

        // hex string to uint
        static const unsigned char phexdigit[256] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0 };
        const char* pbegin = psz;
        while (phexdigit[(unsigned char)*psz] || *psz == '0')
            psz++;
        psz--;
        unsigned char* p1 = (unsigned char*)pn;
        unsigned char* pend = p1 + WIDTH * 4;
        while (psz >= pbegin && p1 < pend)
        {
            *p1 = phexdigit[(unsigned char)*psz--];
            if (psz >= pbegin)
            {
                *p1 |= (phexdigit[(unsigned char)*psz--] << 4);
                p1++;
            }
        }
    }

    void SetHex(const std::string& str)
    {
        SetHex(str.c_str());
    }

    std::string ToString() const
    {
        return (GetHex());
    }

    unsigned char* begin()
    {
        return (unsigned char*)&pn[0];
    }

    unsigned char* end()
    {
        return (unsigned char*)&pn[WIDTH];
    }

    const unsigned char* begin() const
    {
        return (unsigned char*)&pn[0];
    }

    const unsigned char* end() const
    {
        return (unsigned char*)&pn[WIDTH];
    }

    std::vector<unsigned char> getBytes()
    {
        return std::vector<unsigned char>(begin(), end());
    }

    unsigned int size() const
    {
        return sizeof(pn);
    }

    uint64_t GetUint64(int pos) const
    {
        return Get64(0);
    }

    ::uint64_t Get64(int n=0) const
    {
        return pn[2*n] | (::uint64_t)pn[2*n+1] << 32;
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write((char*)pn, sizeof(pn));
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read((char*)pn, sizeof(pn));
    }

    friend class uint160;
    friend class uint256;
    friend inline int Testuint256AdHoc(std::vector<std::string> vArg);
};

typedef base_blob<160> base_blob160;
typedef base_blob<256> base_blob256;

//
// uint160 and uint256 could be implemented as templates, but to keep
// compile errors and debugging cleaner, they're copy and pasted.
//



//////////////////////////////////////////////////////////////////////////////
//
// uint160
//

/** 160-bit unsigned integer */
class uint160 : public base_blob160
{
public:
    typedef base_blob160 basetype;

    uint160()
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
    }

    uint160(const basetype& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
    }

    uint160& operator=(const basetype& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
        return *this;
    }

    uint160(::uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
    }

    uint160& operator=(::uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
        return *this;
    }

    explicit uint160(const std::string& str)
    {
        SetHex(str);
    }

    explicit uint160(const std::vector<unsigned char>& vch)
    {
        if (vch.size() == sizeof(pn))
            memcpy(pn, &vch[0], sizeof(pn));
        else
            *this = 0;
    }
};

inline bool operator==(const uint160& a, ::uint64_t b)                           { return (base_blob160)a == b; }
inline bool operator!=(const uint160& a, ::uint64_t b)                           { return (base_blob160)a != b; }
inline const uint160 operator<<(const base_blob160& a, unsigned int shift)   { return uint160(a) <<= shift; }
inline const uint160 operator>>(const base_blob160& a, unsigned int shift)   { return uint160(a) >>= shift; }
inline const uint160 operator<<(const uint160& a, unsigned int shift)        { return uint160(a) <<= shift; }
inline const uint160 operator>>(const uint160& a, unsigned int shift)        { return uint160(a) >>= shift; }

inline const uint160 operator^(const base_blob160& a, const base_blob160& b) { return uint160(a) ^= b; }
inline const uint160 operator&(const base_blob160& a, const base_blob160& b) { return uint160(a) &= b; }
inline const uint160 operator|(const base_blob160& a, const base_blob160& b) { return uint160(a) |= b; }
inline const uint160 operator+(const base_blob160& a, const base_blob160& b) { return uint160(a) += b; }
inline const uint160 operator-(const base_blob160& a, const base_blob160& b) { return uint160(a) -= b; }

inline bool operator<(const base_blob160& a, const uint160& b)          { return (base_blob160)a <  (base_blob160)b; }
inline bool operator<=(const base_blob160& a, const uint160& b)         { return (base_blob160)a <= (base_blob160)b; }
inline bool operator>(const base_blob160& a, const uint160& b)          { return (base_blob160)a >  (base_blob160)b; }
inline bool operator>=(const base_blob160& a, const uint160& b)         { return (base_blob160)a >= (base_blob160)b; }
inline bool operator==(const base_blob160& a, const uint160& b)         { return (base_blob160)a == (base_blob160)b; }
inline bool operator!=(const base_blob160& a, const uint160& b)         { return (base_blob160)a != (base_blob160)b; }
inline const uint160 operator^(const base_blob160& a, const uint160& b) { return (base_blob160)a ^  (base_blob160)b; }
inline const uint160 operator&(const base_blob160& a, const uint160& b) { return (base_blob160)a &  (base_blob160)b; }
inline const uint160 operator|(const base_blob160& a, const uint160& b) { return (base_blob160)a |  (base_blob160)b; }
inline const uint160 operator+(const base_blob160& a, const uint160& b) { return (base_blob160)a +  (base_blob160)b; }
inline const uint160 operator-(const base_blob160& a, const uint160& b) { return (base_blob160)a -  (base_blob160)b; }

inline bool operator<(const uint160& a, const base_blob160& b)          { return (base_blob160)a <  (base_blob160)b; }
inline bool operator<=(const uint160& a, const base_blob160& b)         { return (base_blob160)a <= (base_blob160)b; }
inline bool operator>(const uint160& a, const base_blob160& b)          { return (base_blob160)a >  (base_blob160)b; }
inline bool operator>=(const uint160& a, const base_blob160& b)         { return (base_blob160)a >= (base_blob160)b; }
inline bool operator==(const uint160& a, const base_blob160& b)         { return (base_blob160)a == (base_blob160)b; }
inline bool operator!=(const uint160& a, const base_blob160& b)         { return (base_blob160)a != (base_blob160)b; }
inline const uint160 operator^(const uint160& a, const base_blob160& b) { return (base_blob160)a ^  (base_blob160)b; }
inline const uint160 operator&(const uint160& a, const base_blob160& b) { return (base_blob160)a &  (base_blob160)b; }
inline const uint160 operator|(const uint160& a, const base_blob160& b) { return (base_blob160)a |  (base_blob160)b; }
inline const uint160 operator+(const uint160& a, const base_blob160& b) { return (base_blob160)a +  (base_blob160)b; }
inline const uint160 operator-(const uint160& a, const base_blob160& b) { return (base_blob160)a -  (base_blob160)b; }

inline bool operator<(const uint160& a, const uint160& b)               { return (base_blob160)a <  (base_blob160)b; }
inline bool operator<=(const uint160& a, const uint160& b)              { return (base_blob160)a <= (base_blob160)b; }
inline bool operator>(const uint160& a, const uint160& b)               { return (base_blob160)a >  (base_blob160)b; }
inline bool operator>=(const uint160& a, const uint160& b)              { return (base_blob160)a >= (base_blob160)b; }
inline bool operator==(const uint160& a, const uint160& b)              { return (base_blob160)a == (base_blob160)b; }
inline bool operator!=(const uint160& a, const uint160& b)              { return (base_blob160)a != (base_blob160)b; }
inline const uint160 operator^(const uint160& a, const uint160& b)      { return (base_blob160)a ^  (base_blob160)b; }
inline const uint160 operator&(const uint160& a, const uint160& b)      { return (base_blob160)a &  (base_blob160)b; }
inline const uint160 operator|(const uint160& a, const uint160& b)      { return (base_blob160)a |  (base_blob160)b; }
inline const uint160 operator+(const uint160& a, const uint160& b)      { return (base_blob160)a +  (base_blob160)b; }
inline const uint160 operator-(const uint160& a, const uint160& b)      { return (base_blob160)a -  (base_blob160)b; }






//////////////////////////////////////////////////////////////////////////////
//
// uint256
//

/** 256-bit unsigned integer */
class uint256 : public base_blob256
{
public:
    typedef base_blob256 basetype;

    uint256()
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
    }

    uint256(const basetype& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
    }

    uint256& operator=(const basetype& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
        return *this;
    }

    uint256(::uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
    }

    uint256& operator=(::uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
        return *this;
    }

    explicit uint256(const std::string& str)
    {
        SetHex(str);
    }

    explicit uint256(const std::vector<unsigned char>& vch)
    {
        if (vch.size() == sizeof(pn))
            memcpy(pn, &vch[0], sizeof(pn));
        else
            *this = 0;
    }

    /** A cheap hash function that just returns 64 bits from the result, it can be
     * used when the contents are considered uniformly random. It is not appropriate
     * when the value can easily be influenced from outside as e.g. a network adversary could
     * provide values to trigger worst-case behavior.
     */
    uint64_t GetCheapHash() const
    {
        return ReadLE64((unsigned char*)&pn);
    }
};

inline bool operator==(const uint256& a, ::uint64_t b)                           { return (base_blob256)a == b; }
inline bool operator!=(const uint256& a, ::uint64_t b)                           { return (base_blob256)a != b; }
inline const uint256 operator<<(const base_blob256& a, unsigned int shift)   { return uint256(a) <<= shift; }
inline const uint256 operator>>(const base_blob256& a, unsigned int shift)   { return uint256(a) >>= shift; }
inline const uint256 operator<<(const uint256& a, unsigned int shift)        { return uint256(a) <<= shift; }
inline const uint256 operator>>(const uint256& a, unsigned int shift)        { return uint256(a) >>= shift; }

inline const uint256 operator^(const base_blob256& a, const base_blob256& b) { return uint256(a) ^= b; }
inline const uint256 operator&(const base_blob256& a, const base_blob256& b) { return uint256(a) &= b; }
inline const uint256 operator|(const base_blob256& a, const base_blob256& b) { return uint256(a) |= b; }
inline const uint256 operator+(const base_blob256& a, const base_blob256& b) { return uint256(a) += b; }
inline const uint256 operator-(const base_blob256& a, const base_blob256& b) { return uint256(a) -= b; }

inline bool operator<(const base_blob256& a, const uint256& b)          { return (base_blob256)a <  (base_blob256)b; }
inline bool operator<=(const base_blob256& a, const uint256& b)         { return (base_blob256)a <= (base_blob256)b; }
inline bool operator>(const base_blob256& a, const uint256& b)          { return (base_blob256)a >  (base_blob256)b; }
inline bool operator>=(const base_blob256& a, const uint256& b)         { return (base_blob256)a >= (base_blob256)b; }
inline bool operator==(const base_blob256& a, const uint256& b)         { return (base_blob256)a == (base_blob256)b; }
inline bool operator!=(const base_blob256& a, const uint256& b)         { return (base_blob256)a != (base_blob256)b; }
inline const uint256 operator^(const base_blob256& a, const uint256& b) { return (base_blob256)a ^  (base_blob256)b; }
inline const uint256 operator&(const base_blob256& a, const uint256& b) { return (base_blob256)a &  (base_blob256)b; }
inline const uint256 operator|(const base_blob256& a, const uint256& b) { return (base_blob256)a |  (base_blob256)b; }
inline const uint256 operator+(const base_blob256& a, const uint256& b) { return (base_blob256)a +  (base_blob256)b; }
inline const uint256 operator-(const base_blob256& a, const uint256& b) { return (base_blob256)a -  (base_blob256)b; }

inline bool operator<(const uint256& a, const base_blob256& b)          { return (base_blob256)a <  (base_blob256)b; }
inline bool operator<=(const uint256& a, const base_blob256& b)         { return (base_blob256)a <= (base_blob256)b; }
inline bool operator>(const uint256& a, const base_blob256& b)          { return (base_blob256)a >  (base_blob256)b; }
inline bool operator>=(const uint256& a, const base_blob256& b)         { return (base_blob256)a >= (base_blob256)b; }
inline bool operator==(const uint256& a, const base_blob256& b)         { return (base_blob256)a == (base_blob256)b; }
inline bool operator!=(const uint256& a, const base_blob256& b)         { return (base_blob256)a != (base_blob256)b; }
inline const uint256 operator^(const uint256& a, const base_blob256& b) { return (base_blob256)a ^  (base_blob256)b; }
inline const uint256 operator&(const uint256& a, const base_blob256& b) { return (base_blob256)a &  (base_blob256)b; }
inline const uint256 operator|(const uint256& a, const base_blob256& b) { return (base_blob256)a |  (base_blob256)b; }
inline const uint256 operator+(const uint256& a, const base_blob256& b) { return (base_blob256)a +  (base_blob256)b; }
inline const uint256 operator-(const uint256& a, const base_blob256& b) { return (base_blob256)a -  (base_blob256)b; }

inline bool operator<(const uint256& a, const uint256& b)               { return (base_blob256)a <  (base_blob256)b; }
inline bool operator<=(const uint256& a, const uint256& b)              { return (base_blob256)a <= (base_blob256)b; }
inline bool operator>(const uint256& a, const uint256& b)               { return (base_blob256)a >  (base_blob256)b; }
inline bool operator>=(const uint256& a, const uint256& b)              { return (base_blob256)a >= (base_blob256)b; }
inline bool operator==(const uint256& a, const uint256& b)              { return (base_blob256)a == (base_blob256)b; }
inline bool operator!=(const uint256& a, const uint256& b)              { return (base_blob256)a != (base_blob256)b; }
inline const uint256 operator^(const uint256& a, const uint256& b)      { return (base_blob256)a ^  (base_blob256)b; }
inline const uint256 operator&(const uint256& a, const uint256& b)      { return (base_blob256)a &  (base_blob256)b; }
inline const uint256 operator|(const uint256& a, const uint256& b)      { return (base_blob256)a |  (base_blob256)b; }
inline const uint256 operator+(const uint256& a, const uint256& b)      { return (base_blob256)a +  (base_blob256)b; }
inline const uint256 operator-(const uint256& a, const uint256& b)      { return (base_blob256)a -  (base_blob256)b; }

#endif
