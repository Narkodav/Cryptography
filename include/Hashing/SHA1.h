#pragma once
#include "Base.h"

namespace Cryptography::Hash {
    class SHA1 : public MerkleDamgardBase<SHA1, uint32_t, uint64_t, 64, 5>
    {
    protected:

        static inline const std::array<uint32_t, 4> s_k = {
            0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
        };

        static inline const std::array<uint32_t, 5> s_initialState = {
            0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
        };

        void processChunk(std::span<const uint8_t, 64> chunk) {
            std::array<uint32_t, 80> w;
            
            // Copy chunk to w (big-endian)
            for (int i = 0; i < 16; ++i) {
                w[i] = Detail::extractByteAndShiftBigEndian<uint32_t, 0>(chunk.data() + i * 4);
            }
            
            // Extend w
            for (int i = 16; i < 80; ++i) {
                w[i] = Detail::rotateLeft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
            }
            
            uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3], e = m_state[4];
            
            uint32_t f, k;
            size_t i = 0;
            for (; i < 20; ++i)
            {
                f = Detail::choiceOr(b, c, d);
                k = s_k[0];
                uint32_t temp = Detail::rotateLeft(a, 5) + f + e + k + w[i];
                e = d; d = c; c = Detail::rotateLeft(b, 30); b = a; a = temp;
            }
            for (; i < 40; ++i)
            {
                f = Detail::parity(b, c, d);
                k = s_k[1];
                uint32_t temp = Detail::rotateLeft(a, 5) + f + e + k + w[i];
                e = d; d = c; c = Detail::rotateLeft(b, 30); b = a; a = temp;
            }
            for (; i < 60; ++i)
            {
                f = Detail::majorityOr(b, c, d);
                k = s_k[2];
                uint32_t temp = Detail::rotateLeft(a, 5) + f + e + k + w[i];
                e = d; d = c; c = Detail::rotateLeft(b, 30); b = a; a = temp;
            }
            for (; i < 80; ++i)
            {
                f = Detail::parity(b, c, d);
                k = s_k[3];
                uint32_t temp = Detail::rotateLeft(a, 5) + f + e + k + w[i];
                e = d; d = c; c = Detail::rotateLeft(b, 30); b = a; a = temp;
            }            
            m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d; m_state[4] += e;
        }

        static inline const std::array<uint32_t, 5> getInitialState() {
            return s_initialState;
        }

        inline std::array<uint32_t, 5> formatResult() {
            return m_state;
        }

        inline void appendLength() {
            for (int i = 7; i >= 0; --i) {
                m_buffer[m_bufferLen++] = (m_bitCount >> (i * 8)) & 0xFF;
            }
        }

    public:
        using B = MerkleDamgardBase<SHA1, uint32_t, uint64_t, 64, 5>;
        using B::B;
        friend class B;
        friend class Base<SHA1, uint32_t, uint64_t, 64, 5>;
    };
}