// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <stdexcept>
#include <vector>
#include <openssl/bn.h>

#include "util.h"
#include "version.h"
#include "serialize.h"

/** Errors thrown by the bignum class */
class bignum_error : public std::runtime_error
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};


/** RAII encapsulated BN_CTX (OpenSSL bignum context) */
class CAutoBN_CTX
{
protected:
    BN_CTX* pctx;
    BN_CTX* operator=(BN_CTX* pnew) { return pctx = pnew; }

public:
    CAutoBN_CTX()
    {
        pctx = BN_CTX_new();
        if (pctx == NULL)
            throw bignum_error("CAutoBN_CTX : BN_CTX_new() returned NULL");
    }

    ~CAutoBN_CTX()
    {
        if (pctx != NULL)
            BN_CTX_free(pctx);
    }

    operator BN_CTX*() { return pctx; }
    BN_CTX& operator*() { return *pctx; }
    BN_CTX** operator&() { return &pctx; }
    bool operator!() { return (pctx == NULL); }
};


/** C++ wrapper for BIGNUM (OpenSSL bignum) */
class CBigNum : public BIGNUM
{
public:
    CBigNum()
    {
        BN_init(this);
    }

    CBigNum(const CBigNum& b)
    {
        BN_init(this);
        if (!BN_copy(this, &b))
        {
            BN_clear_free(this);
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_copy failed");
        }
    }

    CBigNum& operator=(const CBigNum& b)
    {
        if (!BN_copy(this, &b))
            throw bignum_error("CBigNum::operator= : BN_copy failed");
        return (*this);
    }

    ~CBigNum()
    {
        BN_clear_free(this);
    }

    CBigNum(::int8_t  n)  
    { 
        BN_init(this); 
        if (n >= 0) 
            setuint32(n); 
        else 
            setint64(n); 
    }

    CBigNum(::int16_t n)  
    { 
        BN_init(this); 
        if (n >= 0) 
            setuint32(n); 
        else 
            setint64(n); 
    }

    CBigNum(::int32_t n)  
    { 
        BN_init(this); 
        if (n >= 0) 
            setuint32(n); 
        else 
            setint64(n); 
    }

    CBigNum(::int64_t n)  
    { 
        BN_init(this); 
        if (n >= 0) 
            setuint64(n); 
        else 
            setint64(n); 
    }

    CBigNum(::uint8_t  n) 
    { 
        BN_init(this); 
        setuint32(n); 
    }

    CBigNum(::uint16_t n) 
    { 
        BN_init(this); 
        setuint32(n); 
    }

    CBigNum(::uint32_t n) 
    { 
        BN_init(this); 
        setuint32(n); 
    }

    CBigNum(::uint64_t n) 
    { 
        BN_init(this); 
        setuint64(n); 
    }

    explicit CBigNum(uint256 n) 
    { 
        BN_init(this); 
        setuint256(n); 
    }

    explicit CBigNum(const std::vector< ::uint8_t>& vch)
    {
        BN_init(this);
        setvch(vch);
    }

    /** Generates a cryptographically secure random number between zero and range exclusive
    * i.e. 0 < returned number < range
    * @param range The upper bound on the number.
    * @return
    */
    static CBigNum  randBignum(const CBigNum& range) {
        CBigNum ret;
        if(!BN_rand_range(&ret, &range)){
            throw bignum_error("CBigNum:rand element : BN_rand_range failed");
        }
        return ret;
    }

    /** Generates a cryptographically secure random k-bit number
    * @param k The bit length of the number.
    * @return
    */
    static CBigNum RandKBitBigum(const ::uint32_t k){
        CBigNum ret;
        if(!BN_rand(&ret, k, -1, 0)){
            throw bignum_error("CBigNum:rand element : BN_rand failed");
        }
        return ret;
    }

    /**Returns the size in bits of the underlying bignum.
     *
     * @return the size
     */
    int bitSize() const{
        return  BN_num_bits(this);
    }


    void setuint32(::uint32_t n)
    {
        if (!BN_set_word(this, n))
            throw bignum_error("CBigNum conversion from uint32_t : BN_set_word failed");
    }

    ::uint32_t getuint32() const
    {
        return BN_get_word(this);
    }

    ::int32_t getint32() const
    {
        ::uint64_t 
            n = BN_get_word(this);

        if (!BN_is_negative(this))
            return (n > (::uint64_t)std::numeric_limits< ::int32_t>::max() ? 
                         std::numeric_limits< ::int32_t>::max() : 
                         (::int32_t)n);
        else
            return (n > (::uint64_t)std::numeric_limits< ::int32_t>::max() ? 
                         std::numeric_limits< ::int32_t>::min() :
                         -(::int32_t)n);
    }

    void setint64(::int64_t sn)
    {
        ::uint8_t 
            pch[sizeof(sn) + 6];
        ::uint8_t
            *p = pch + 4;
        bool 
            fNegative;
        ::uint64_t 
            n;

        if (sn < (::int64_t)0)
        {
            // Since the minimum signed integer cannot be represented as positive so long as its type is signed, and it's not well-defined what happens if you make it unsigned before negating it, we instead increment the negative integer by 1, convert it, then increment the (now positive) unsigned integer by 1 to compensate
            n = -(sn + 1);
            ++n;
            fNegative = true;
        } else {
            n = sn;
            fNegative = false;
        }

        bool 
            fLeadingZeroes = true;

        for (int i = 0; i < 8; i++)
        {
            ::uint8_t 
                c = (n >> 56) & 0xff;

            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = (fNegative ? 0x80 : 0);
                else if (fNegative)
                    c |= 0x80;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        ::uint32_t 
            nSize = (::uint32_t) (p - (pch + 4));

        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, (int)(p - pch), this);
    }

    ::uint64_t getuint64()
    {
        size_t 
            nSize = BN_bn2mpi(this, NULL);

        if (nSize < 4)
            return 0;
        
        std::vector< ::uint8_t> vch(nSize);

        BN_bn2mpi(this, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;

        ::uint64_t 
            n = 0;

        for (size_t i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((::uint8_t*)&n)[i] = vch[j];
        return n;
    }

    void setuint64(::uint64_t n)
    {
        // Use BN_set_word if word size is sufficient for uint64_t
        if (sizeof(n) <= sizeof(BN_ULONG))
        {
            if (!BN_set_word(this, (BN_ULONG)n))
                throw bignum_error("CBigNum conversion from uint64_t : BN_set_word failed");
            return;
        }

        ::uint8_t pch[sizeof(n) + 6];
        ::uint8_t* p = pch + 4;
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            ::uint8_t c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        ::uint32_t nSize = (::uint32_t) (p - (pch + 4));
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, (int)(p - pch), this);
    }

    void setuint160(uint160 n)
    {
        ::uint8_t pch[sizeof(n) + 6];
        ::uint8_t* p = pch + 4;
        bool fLeadingZeroes = true;
        ::uint8_t* pbegin = (::uint8_t*)&n;
        ::uint8_t* psrc = pbegin + sizeof(n);
        while (psrc != pbegin)
        {
            ::uint8_t c = *(--psrc);
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        ::uint32_t nSize = (::uint32_t) (p - (pch + 4));
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize >> 0) & 0xff;
        BN_mpi2bn(pch, (int) (p - pch), this);
    }

    uint160 getuint160() const
    {
        unsigned int nSize = BN_bn2mpi(this, NULL);
        if (nSize < 4)
            return 0;
        std::vector< ::uint8_t> vch(nSize);
        BN_bn2mpi(this, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint160 n = 0;
        for (size_t i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((::uint8_t*)&n)[i] = vch[j];
        return n;
    }

    void setuint256(uint256 n)
    {
        ::uint8_t pch[sizeof(n) + 6];
        ::uint8_t* p = pch + 4;
        bool fLeadingZeroes = true;
        ::uint8_t* pbegin = (::uint8_t*)&n;
        ::uint8_t* psrc = pbegin + sizeof(n);
        while (psrc != pbegin)
        {
            ::uint8_t c = *(--psrc);
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        ::uint32_t nSize = (::uint32_t) (p - (pch + 4));
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize >> 0) & 0xff;
        BN_mpi2bn(pch, (int) (p - pch), this);
    }

    uint256 getuint256() const
    {
        unsigned int nSize = BN_bn2mpi(this, NULL);
        if (nSize < 4)
            return 0;
        std::vector< ::uint8_t> vch(nSize);
        BN_bn2mpi(this, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint256 n = 0;
        for (size_t i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((::uint8_t*)&n)[i] = vch[j];
        return n;
    }

    void setBytes(const std::vector< ::uint8_t>& vchBytes)
    {
        BN_bin2bn(&vchBytes[0], (int) vchBytes.size(), this);
    }

    std::vector< ::uint8_t> getBytes() const
    {
        int nBytes = BN_num_bytes(this);

        std::vector< ::uint8_t> vchBytes(nBytes);

        int n = BN_bn2bin(this, &vchBytes[0]);
        if (n != nBytes) {
            throw bignum_error("CBigNum::getBytes : BN_bn2bin failed");
        }

        return vchBytes;
    }

    void setvch(const std::vector< ::uint8_t>& vch)
    {
        std::vector< ::uint8_t> vch2(vch.size() + 4);
        ::uint32_t nSize = (::uint32_t) vch.size();
        // BIGNUM's byte stream format expects 4 bytes of
        // big endian size data info at the front
        vch2[0] = (nSize >> 24) & 0xff;
        vch2[1] = (nSize >> 16) & 0xff;
        vch2[2] = (nSize >> 8) & 0xff;
        vch2[3] = (nSize >> 0) & 0xff;
        // swap data to big endian
        reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);
        BN_mpi2bn(&vch2[0], (int) vch2.size(), this);
    }

    std::vector< ::uint8_t> getvch() const
    {
        unsigned int nSize = BN_bn2mpi(this, NULL);
        if (nSize <= 4)
            return std::vector< ::uint8_t>();
        std::vector< ::uint8_t> vch(nSize);
        BN_bn2mpi(this, &vch[0]);
        vch.erase(vch.begin(), vch.begin() + 4);
        reverse(vch.begin(), vch.end());
        return vch;
    }

    CBigNum& SetCompact(::uint32_t nCompact)
    {
        ::uint32_t nSize = nCompact >> 24;
        std::vector< ::uint8_t> vch(4 + nSize);
        vch[3] = nSize;
        if (nSize >= 1) vch[4] = (nCompact >> 16) & 0xff;
        if (nSize >= 2) vch[5] = (nCompact >> 8) & 0xff;
        if (nSize >= 3) vch[6] = (nCompact >> 0) & 0xff;
        BN_mpi2bn(&vch[0], (int) vch.size(), this);
        return *this;
    }

    ::uint32_t GetCompact() const
    {
        ::uint32_t nSize = BN_bn2mpi(this, NULL);
        std::vector< ::uint8_t> vch(nSize);
        nSize -= 4;
        BN_bn2mpi(this, &vch[0]);
        ::uint32_t nCompact = nSize << 24;
        if (nSize >= 1) nCompact |= (vch[4] << 16);
        if (nSize >= 2) nCompact |= (vch[5] << 8);
        if (nSize >= 3) nCompact |= (vch[6] << 0);
        return nCompact;
    }

    void SetHex(const std::string& str)
    {
        // skip 0x
        const char* psz = str.c_str();
        while (isspace(*psz))
            psz++;
        bool fNegative = false;
        if (*psz == '-')
        {
            fNegative = true;
            psz++;
        }
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;
        while (isspace(*psz))
            psz++;

        // hex string to bignum
        static const signed char phexdigit[256] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0 };
        *this = 0;
        while (isxdigit(*psz))
        {
            *this <<= 4;
            int n = phexdigit[(::uint8_t)*psz++];
            *this += n;
        }
        if (fNegative)
            *this = 0 - *this;
    }

    std::string ToString(int nBase=10) const
    {
        CAutoBN_CTX pctx;
        CBigNum bnBase = nBase;
        CBigNum bn0 = 0;
        std::string str;
        CBigNum bn = *this;
        BN_set_negative(&bn, false);
        CBigNum dv;
        CBigNum rem;
        if (BN_cmp(&bn, &bn0) == 0)
            return "0";
        while (BN_cmp(&bn, &bn0) > 0)
        {
            if (!BN_div(&dv, &rem, &bn, &bnBase, pctx))
                throw bignum_error("CBigNum::ToString() : BN_div failed");
            bn = dv;
            ::uint32_t c = rem.getuint32();
            str += "0123456789abcdef"[c];
        }
        if (BN_is_negative(this))
            str += "-";
        reverse(str.begin(), str.end());
        return str;
    }

    std::string GetHex() const
    {
        return ToString(16);
    }

    unsigned int GetSerializeSize(int nType=0, int nVersion=PROTOCOL_VERSION) const
    {
        return ::GetSerializeSize(getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, getvch());
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        std::vector< ::uint8_t> vch;
        ::Unserialize(s, vch);
        setvch(vch);
    }

    /**
    * exponentiation with an int. this^e
    * @param e the exponent as an int
    * @return
    */
    CBigNum pow(const int e) const {
        return this->pow(CBigNum(e));
    }

    /**
     * exponentiation this^e
     * @param e the exponent
     * @return
     */
    CBigNum pow(const CBigNum& e) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_exp(&ret, this, &e, pctx))
            throw bignum_error("CBigNum::pow : BN_exp failed");
        return ret;
    }

    /**
     * modular multiplication: (this * b) mod m
     * @param b operand
     * @param m modulus
     */
    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod_mul(&ret, this, &b, &m, pctx))
            throw bignum_error("CBigNum::mul_mod : BN_mod_mul failed");

        return ret;
    }

    /**
     * modular exponentiation: this^e mod n
     * @param e exponent
     * @param m modulus
     */
    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if( e < 0){
            // g^-x = (g^-1)^x
            CBigNum inv = this->inverse(m);
            CBigNum posE = e * -1;
            if (!BN_mod_exp(&ret, &inv, &posE, &m, pctx))
                throw bignum_error("CBigNum::pow_mod: BN_mod_exp failed on negative exponent");
        }else
            if (!BN_mod_exp(&ret, this, &e, &m, pctx))
                throw bignum_error("CBigNum::pow_mod : BN_mod_exp failed");

        return ret;
    }

    /**
    * Calculates the inverse of this element mod m.
    * i.e. i such this*i = 1 mod m
    * @param m the modu
    * @return the inverse
    */
    CBigNum inverse(const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod_inverse(&ret, this, &m, pctx))
            throw bignum_error("CBigNum::inverse*= :BN_mod_inverse");
        return ret;
    }

    /**
     * Generates a random (safe) prime of numBits bits
     * @param numBits the number of bits
     * @param safe true for a safe prime
     * @return the prime
     */
    static CBigNum generatePrime(const unsigned int numBits, bool safe = false) {
        CBigNum ret;
        if(!BN_generate_prime_ex(&ret, numBits, (safe == true), NULL, NULL, NULL))
            throw bignum_error("CBigNum::generatePrime*= :BN_generate_prime_ex");
        return ret;
    }

    /**
     * Calculates the greatest common divisor (GCD) of two numbers.
     * @param m the second element
     * @return the GCD
     */
    CBigNum gcd( const CBigNum& b) const{
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_gcd(&ret, this, &b, pctx))
            throw bignum_error("CBigNum::gcd*= :BN_gcd");
        return ret;
    }

    /**
    * Miller-Rabin primality test on this element
    * @param checks: optional, the number of Miller-Rabin tests to run
    * default causes error rate of 2^-80.
    * @return true if prime
    */
    bool isPrime(const int checks=BN_prime_checks) const {
        CAutoBN_CTX pctx;
        int ret = BN_is_prime(this, checks, NULL, pctx, NULL);
        if(ret < 0){
            throw bignum_error("CBigNum::isPrime :BN_is_prime");
        }
        return ret != 0;
    }

    bool isOne() const {
        return BN_is_one(this);
    }


    bool operator!() const
    {
        return BN_is_zero(this);
    }

    CBigNum& operator+=(const CBigNum& b)
    {
        if (!BN_add(this, this, &b))
            throw bignum_error("CBigNum::operator+= : BN_add failed");
        return *this;
    }

    CBigNum& operator-=(const CBigNum& b)
    {
        *this = *this - b;
        return *this;
    }

    CBigNum& operator*=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_mul(this, this, &b, pctx))
            throw bignum_error("CBigNum::operator*= : BN_mul failed");
        return *this;
    }

    CBigNum& operator/=(const CBigNum& b)
    {
        *this = *this / b;
        return *this;
    }

    CBigNum& operator%=(const CBigNum& b)
    {
        *this = *this % b;
        return *this;
    }

    CBigNum& operator<<=(unsigned int shift)
    {
        if (!BN_lshift(this, this, shift))
            throw bignum_error("CBigNum:operator<<= : BN_lshift failed");
        return *this;
    }

    CBigNum& operator>>=(unsigned int shift)
    {
        // Note: BN_rshift segfaults on 64-bit if 2^shift is greater than the number
        //   if built on ubuntu 9.04 or 9.10, probably depends on version of OpenSSL
        CBigNum a = 1;
        a <<= shift;
        if (BN_cmp(&a, this) > 0)
        {
            *this = 0;
            return *this;
        }

        if (!BN_rshift(this, this, shift))
            throw bignum_error("CBigNum:operator>>= : BN_rshift failed");
        return *this;
    }


    CBigNum& operator++()
    {
        // prefix operator
        if (!BN_add(this, this, BN_value_one()))
            throw bignum_error("CBigNum::operator++ : BN_add failed");
        return *this;
    }

    const CBigNum operator++(int)
    {
        // postfix operator
        const CBigNum ret = *this;
        ++(*this);
        return ret;
    }

    CBigNum& operator--()
    {
        // prefix operator
        CBigNum r;
        if (!BN_sub(&r, this, BN_value_one()))
            throw bignum_error("CBigNum::operator-- : BN_sub failed");
        *this = r;
        return *this;
    }

    const CBigNum operator--(int)
    {
        // postfix operator
        const CBigNum ret = *this;
        --(*this);
        return ret;
    }


    friend inline const CBigNum operator-(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator/(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator%(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator*(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<(const CBigNum& a, const CBigNum& b);
};



inline const CBigNum operator+(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_add(&r, &a, &b))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_sub(&r, &a, &b))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a)
{
    CBigNum r(a);
    BN_set_negative(&r, !BN_is_negative(&r));
    return r;
}

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mul(&r, &a, &b, pctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    return r;
}

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_div(&r, NULL, &a, &b, pctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    return r;
}

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_nnmod(&r, &a, &b, pctx))
        throw bignum_error("CBigNum::operator% : BN_div failed");
    return r;
}

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r;
    if (!BN_lshift(&r, &a, shift))
        throw bignum_error("CBigNum:operator<< : BN_lshift failed");
    return r;
}

inline const CBigNum operator>>(const CBigNum& a, unsigned int shift)
{
    CBigNum r = a;
    r >>= shift;
    return r;
}

inline bool operator==(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) == 0); }
inline bool operator!=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) != 0); }
inline bool operator<=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) <= 0); }
inline bool operator>=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(&a, &b) >= 0); }
inline bool operator<(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(&a, &b) < 0); }
inline bool operator>(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(&a, &b) > 0); }

inline std::ostream& operator<<(std::ostream &strm, const CBigNum &b) { return strm << b.ToString(10); }

typedef  CBigNum Bignum;

#endif
