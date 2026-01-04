#pragma once
#include "Base.h"

namespace Cryptography::Hash {
    // WARNING: MD5 is cryptographically broken and should only be used for
    // legacy compatibility, NOT for security purposes.
    class MD5 : public MerkleDamgardBase<MD5, uint32_t, uint64_t, 64, 4>
    {
    protected:

        static inline const std::array<uint32_t, 64> s_const = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        // Rotation amounts for each round
        static inline const std::array<uint8_t, 64> s_rot = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        static inline const std::array<uint32_t, 4> s_initialState = {
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        };

        // Process a single 512-bit block
        void processChunk(std::span<const uint8_t, 64> chunk) {
            uint32_t a = m_state[0];
            uint32_t b = m_state[1];
            uint32_t c = m_state[2];
            uint32_t d = m_state[3];

            // Copy block to X (16 x 32-bit words, little-endian)
            std::array<uint32_t, 16> X;
            for (int i = 0; i < 16; ++i) {
                X[i] = Detail::extractByteAndShiftLittleEndian< uint32_t, 0>(chunk.data() + i * 4);
            }

            // Round 1
            for (int i = 0; i < 16; ++i) {
                uint32_t f = Detail::choiceOr(b, c, d);
                uint32_t g = i;

                uint32_t temp = d;
                d = c;
                c = b;
                b = b + Detail::rotateLeft((a + f + s_const[i] + X[g]), s_rot[i]);
                a = temp;
            }

            // Round 2
            for (int i = 16; i < 32; ++i) {
                uint32_t f = Detail::conditionalMajority(b, c, d);
                uint32_t g = (5 * i + 1) % 16;

                uint32_t temp = d;
                d = c;
                c = b;
                b = b + Detail::rotateLeft((a + f + s_const[i] + X[g]), s_rot[i]);
                a = temp;
            }

            // Round 3
            for (int i = 32; i < 48; ++i) {
                uint32_t f = Detail::parity(b, c, d);
                uint32_t g = (3 * i + 5) % 16;

                uint32_t temp = d;
                d = c;
                c = b;
                b = b + Detail::rotateLeft((a + f + s_const[i] + X[g]), s_rot[i]);
                a = temp;
            }

            // Round 4
            for (int i = 48; i < 64; ++i) {
                uint32_t f = Detail::mixed(b, c, d);
                uint32_t g = (7 * i) % 16;

                uint32_t temp = d;
                d = c;
                c = b;
                b = b + Detail::rotateLeft((a + f + s_const[i] + X[g]), s_rot[i]);
                a = temp;
            }

            // Update state
            m_state[0] += a;
            m_state[1] += b;
            m_state[2] += c;
            m_state[3] += d;
        }

        static inline const std::array<uint32_t, 4> getInitialState() {
            return s_initialState;
        }

        inline std::array<uint32_t, 4> formatResult() {
            std::array<uint32_t, 4> result;
            for (size_t i = 0; i < 4; ++i) {
                result[i] = (m_state[i] & 0xFF) << 24
                    | (m_state[i] & 0xFF00) << 8
                    | (m_state[i] & 0xFF0000) >> 8
                    | (m_state[i] & 0xFF000000) >> 24;
            }
            return result;
        }

        inline void appendLength() {
            for (int i = 0; i < 8; ++i) {
                m_buffer[m_bufferLen++] = (m_bitCount >> (i * 8)) & 0xFF;
            }
        }

        static inline uint8_t getPaddingByte() {
            return 0x80; // Default Merkle-Damgård padding
        }

    public:
        using B = MerkleDamgardBase<MD5, uint32_t, uint64_t, 64, 4>;
        using B::B;
        friend class B;
        friend class Base<MD5, uint32_t, uint64_t, 64, 4>;
    };
}