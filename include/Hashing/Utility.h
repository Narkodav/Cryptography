#pragma once
#include <cstdint>

namespace Cryptography::Detail {
        template<typename T>
        static constexpr T rotateRight(T x, uint8_t n) {
            return (x >> n) | (x << (sizeof(T) * 8 - n));
        }

        template<typename T>
        static constexpr T rotateLeft(T x, uint8_t n) {
            return (x << n) | (x >> (sizeof(T) * 8 - n));
        }

        template<typename T>
        static constexpr T choice(T x, T y, T z) {
            return (x & y) ^ (~x & z);
        }

        template<typename T>
        static constexpr T majority(T x, T y, T z) {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        template<typename T>
        static constexpr T majorityOr(T x, T y, T z) {
            return (x & y) | (x & z) | (y & z);
        }

        template<typename T>
        static constexpr T conditionalMajority(T x, T y, T z) {
            return (x & z) | (y & ~z);
        }

        template<typename T>
        static constexpr T choiceOr(T x, T y, T z) {
            return (x & y) | (~x & z);
        }

        template<typename T>
        static constexpr T parity(T x, T y, T z) {
            return x ^ y ^ z;
        }

        template<typename T>
        static constexpr T mixed(T x, T y, T z) {
            return y ^ (x | ~z);
        }

        template<typename T>
        static constexpr T sigma0(T x) {
            static_assert(false, "Not implemented for this type");
        }

        template<>
        static constexpr uint32_t sigma0<uint32_t>(uint32_t x) {
            return rotateRight<uint32_t>(x, 2)
                ^ rotateRight<uint32_t>(x, 13)
                ^ rotateRight<uint32_t>(x, 22);
        }

        template<>
        static constexpr uint64_t sigma0<uint64_t>(uint64_t x) {
            return rotateRight<uint64_t>(x, 28)
                ^ rotateRight<uint64_t>(x, 34)
                ^ rotateRight<uint64_t>(x, 39);
        }

        template<typename T>
        static constexpr T sigma1(T x) {
            static_assert(false, "Not implemented for this type");
        }

        template<>
        static constexpr uint32_t sigma1<uint32_t>(uint32_t x) {
            return rotateRight<uint32_t>(x, 6)
                ^ rotateRight<uint32_t>(x, 11)
                ^ rotateRight<uint32_t>(x, 25);
        }

        template<>
        static constexpr uint64_t sigma1<uint64_t>(uint64_t x) {
            return rotateRight<uint64_t>(x, 14)
                ^ rotateRight<uint64_t>(x, 18)
                ^ rotateRight<uint64_t>(x, 41);
        }

        template<typename T>
        static constexpr T gamma0(T x) {
            static_assert(false, "Not implemented for this type");
        }

        template<>
        static constexpr uint32_t gamma0<uint32_t>(uint32_t x) {
            return rotateRight<uint32_t>(x, 7)
                ^ rotateRight<uint32_t>(x, 18)
                ^ (x >> 3);
        }

        template<>
        static constexpr uint64_t gamma0<uint64_t>(uint64_t x) {
            return rotateRight<uint64_t>(x, 1)
                ^ rotateRight<uint64_t>(x, 8)
                ^ (x >> 7);
        }

        template<typename T>
        static constexpr T gamma1(T x) {
            static_assert(false, "Not implemented for this type");
        }

        template<>
        static constexpr uint32_t gamma1<uint32_t>(uint32_t x) {
            return rotateRight<uint32_t>(x, 17)
                ^ rotateRight<uint32_t>(x, 19)
                ^ (x >> 10);
        }

        template<>
        static constexpr uint64_t gamma1<uint64_t>(uint64_t x) {
            return rotateRight<uint64_t>(x, 19)
                ^ rotateRight<uint64_t>(x, 61)
                ^ (x >> 6);
        }

        template<typename Word, size_t ByteIndex, size_t TotalBytes = sizeof(Word)>
        inline constexpr Word extractByteAndShiftBigEndian(const uint8_t* chunk) {
            if constexpr (ByteIndex < TotalBytes) {
                constexpr size_t shiftAmount = 8 * (TotalBytes - ByteIndex - 1);
                return (static_cast<Word>(chunk[ByteIndex]) << shiftAmount) |
                    extractByteAndShiftBigEndian<Word, ByteIndex + 1, TotalBytes>(chunk);
            }
            return 0;
        }

        template<typename Word, size_t ByteIndex, size_t TotalBytes = sizeof(Word)>
        inline constexpr Word extractByteAndShiftLittleEndian(const uint8_t* chunk) {
            if constexpr (ByteIndex < TotalBytes) {
                constexpr size_t shiftAmount = 8 * ByteIndex;
                return (static_cast<Word>(chunk[ByteIndex]) << shiftAmount) |
                    extractByteAndShiftLittleEndian<Word, ByteIndex + 1, TotalBytes>(chunk);
            }
            return 0;
        }
}