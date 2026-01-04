#pragma once
#include <stdint.h>

// Check for compiler-specific intrinsics
#if defined(__GNUC__) || defined(__clang__)
#define __CRYPTOGRAPHY_PORTABLE_BSWAP32__(x) __builtin_bswap32(x)
#define __CRYPTOGRAPHY_PORTABLE_BSWAP64__(x) __builtin_bswap64(x)
#define __(x) __builtin_bswap16(x)
#elif defined(_MSC_VER)
#include <stdlib.h>
#define __CRYPTOGRAPHY_PORTABLE_BSWAP32__(x) _byteswap_ulong(x)
#define __CRYPTOGRAPHY_PORTABLE_BSWAP64__(x) _byteswap_uint64(x)
#define __CRYPTOGRAPHY_PORTABLE_BSWAP16__(x) _byteswap_ushort(x)
#else
    // Portable implementations
static inline uint16_t __portableBitSwap16(uint16_t x) {
    return (x << 8) | (x >> 8);
}

static inline uint32_t __portableBitSwap32(uint32_t x) {
    return ((x & 0xFF000000u) >> 24) |
        ((x & 0x00FF0000u) >> 8) |
        ((x & 0x0000FF00u) << 8) |
        ((x & 0x000000FFu) << 24);
}

static inline uint64_t __portableBitSwap64(uint64_t x) {
    return ((x & 0xFF00000000000000ULL) >> 56) |
        ((x & 0x00FF000000000000ULL) >> 40) |
        ((x & 0x0000FF0000000000ULL) >> 24) |
        ((x & 0x000000FF00000000ULL) >> 8) |
        ((x & 0x00000000FF000000ULL) << 8) |
        ((x & 0x0000000000FF0000ULL) << 24) |
        ((x & 0x000000000000FF00ULL) << 40) |
        ((x & 0x00000000000000FFULL) << 56);
}

#define __CRYPTOGRAPHY_PORTABLE_BSWAP16__(x) __portableBitSwap16(x)
#define __CRYPTOGRAPHY_PORTABLE_BSWAP32__(x) __portableBitSwap32(x)
#define __CRYPTOGRAPHY_PORTABLE_BSWAP64__(x) __portableBitSwap64(x)
#endif

// 128 bit arithmetic
#if defined(__GNUC__) || defined(__clang__)
class uint128_t {
private:
    union {
        __uint128_t full;
        struct { uint64_t m_low, m_high; } parts;
    } num;

public:
    uint128_t() : num(0) {}

    uint128_t& operator=(const uint64_t& other) {
        num.full = other;
        return *this;
    }

    uint128_t& operator=(const uint128_t& other) {
        num.full = other.num.full;
        return *this;
    }

    uint128_t& operator+=(const uint64_t& other) {
        num.full += other;
        return *this;
    }

    uint128_t& operator+=(const uint128_t& other) {
        num.full += other.num.full;
        return *this;
    }

    uint64_t low() const { return num.parts.m_low; }
    uint64_t high() const { return num.parts.m_high; }
};

#elif defined(_MSC_VER)
class uint128_t {
private:
    uint64_t m_low;
    uint64_t m_high;

public:
    uint128_t() : m_low(0), m_high(0) {}

    uint128_t& operator=(const uint64_t& other) {
        m_low = other;
        m_high = 0;
        return *this;
    }

    uint128_t& operator=(const uint128_t& other) {
        m_low = other.m_low;
        m_high = other.m_high;
        return *this;
    }

    uint128_t& operator+=(const uint64_t& other) {
        unsigned char _carry = _addcarry_u64(0, m_low, other, &m_low);
        _addcarry_u64(_carry, m_high, 0, &m_high);
        return *this;
    }

    uint128_t& operator+=(const uint128_t& other) {
        unsigned char _carry = _addcarry_u64(0, m_low, other.m_low, &m_low);
        _addcarry_u64(_carry, m_high, other.m_high, &m_high);
        return *this;
    }

    uint64_t low() const { return m_low; }
    uint64_t high() const { return m_high; }
};

#else
class uint128_t {
private:
    uint64_t m_low;
    uint64_t m_high;

public:
    uint128_t() : m_low(0), m_high(0) {}

    uint128_t& operator=(const uint64_t& other) {
        m_low = other;
        m_high = 0;
        return *this;
    }

    uint128_t& operator=(const uint128_t& other) {
        m_low = other.m_low;
        m_high = other.m_high;
        return *this;
    }

    uint128_t& operator+=(const uint64_t& other) {
        uint64_t old_lo = lo;
        lo += value;
        if (lo < old_lo) { // Carry occurred
            hi++;
        }
        return *this;
    }

    uint128_t& operator+=(const uint128_t& other) {
        uint64_t old_lo = lo;
        lo += other.lo;
        hi += other.hi;
        if (lo < old_lo) { // Carry from m_low to m_high
            hi++;
        }
        return *this;
    }

    uint64_t low() const { return m_low; }
    uint64_t high() const { return m_high; }
};

#endif

// SIMD macros
#include <cstddef>
#include <array>
#include <stdexcept>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
#include <immintrin.h>
#define __HAS_SSE2__
#if defined(__AVX2__) || (defined(_MSC_VER) && defined(__AVX2__))
#define __HAS_AVX2__
#endif
#endif

#ifdef _MSC_VER
#include <intrin.h>
#define __CTZ32__(x) _tzcnt_u32(x)
#define __CTZ16__(x) _tzcnt_u16(x)
#elif defined(__GNUC__) || defined(__clang__)
#define __CTZ32__(x) __builtin_ctz(x)
#define __CTZ16__(x) __builtin_ctz(x)
#else
namespace
{
    inline int CTZ16_FUNC(uint16_t x) {
        int count = 0;
        while ((x & 1) == 0 && x != 0) { x >>= 1; count++; }
        return count;
    }
    inline int CTZ32_FUNC(uint32_t x) {
        int count = 0;
        while ((x & 1) == 0 && x != 0) { x >>= 1; count++; }
        return count;
    }
}
#define __CTZ32__(x) CTZ32_FUNC(x)
#define __CTZ16__(x) CTZ16_FUNC(x)
#endif
