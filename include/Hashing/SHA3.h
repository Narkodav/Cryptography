#pragma once
#include "Base.h"

namespace Cryptography::Hash {

    template<typename Derived, size_t s_chunkByteCount>
    class SHA3Base : public Base<Derived, uint64_t, uint64_t, s_chunkByteCount, 25> {
    protected:
        static inline const std::array<uint64_t, 24> s_RC = {
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
            0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        };

        static inline const std::array<uint64_t, 24> s_rhoOffsets = {
                1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27,
                41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
        };

        static inline const std::array<uint64_t, 24> s_phiIndices = {
                10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15,
                23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
        };

        static inline const size_t s_laneCount = s_chunkByteCount / 8;

        void processChunk(std::span<const uint8_t, s_chunkByteCount> chunk) {
            // Absorb phase: XOR input into state
            for (size_t i = 0; i < s_laneCount; ++i) {
                uint64_t lane = 0;
                for (int j = 0; j < 8; ++j) {
                    lane |= static_cast<uint64_t>(chunk[i * 8 + j]) << (j * 8);
                }
                this->m_state[i] ^= lane;
            }

            // Keccak-f[1600] permutation
            keccakF1600();
        }

        void finalize() {
            // SHA-3 padding: append 0x06, pad with zeros, then 0x80 at end
            this->m_buffer[this->m_bufferLen++] = 0x06;

            // Pad with zeros until last byte
            for (; this->m_bufferLen < s_chunkByteCount - 1; ++this->m_bufferLen)
                this->m_buffer[this->m_bufferLen] = 0;

            // Set final bit
            this->m_buffer[this->m_bufferLen++] = 0x80;

            // Process final block
            processChunk(this->m_buffer);
        }

        void keccakF1600() {

            for (int round = 0; round < 24; ++round) {
                // θ (Theta)
                uint64_t C[5], D[5];
                for (size_t x = 0; x < 5; ++x) {
                    C[x] = this->m_state[x] ^ this->m_state[x + 5] ^ this->m_state[x + 10]
                        ^ this->m_state[x + 15] ^ this->m_state[x + 20];
                }
                for (size_t x = 0; x < 5; ++x) {
                    D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63));
                }
                for (size_t x = 0; x < 5; ++x) {
                    for (size_t y = 0; y < 5; ++y) {
                        this->m_state[y * 5 + x] ^= D[x];
                    }
                }

                // ρ (Rho) and π (Pi)
                uint64_t current = this->m_state[1];
                for (size_t t = 0; t < 24; ++t) {
                    size_t index = s_phiIndices[t];
                    uint64_t temp = this->m_state[index];
                    size_t offset = s_rhoOffsets[t];
                    this->m_state[index] = (current << offset) | (current >> (64 - offset));
                    current = temp;
                }

                // χ (Chi)
                for (size_t y = 0; y < 5; ++y) {
                    uint64_t temp[5];
                    for (size_t x = 0; x < 5; ++x) {
                        temp[x] = this->m_state[y * 5 + x];
                    }
                    for (size_t x = 0; x < 5; ++x) {
                        this->m_state[y * 5 + x] = temp[x] ^ ((~temp[(x + 1) % 5])
                            & temp[(x + 2) % 5]);
                    }
                }

                // ι (Iota)
                this->m_state[0] ^= s_RC[round];
            }
        }

        static inline const std::array<uint64_t, 25> getInitialState() {
            std::array<uint64_t, 25> state;
            state.fill(0);
            return state;
        }
    public:
        using B = Base<Derived, uint64_t, uint64_t, s_chunkByteCount, 25>;
        using B::B;
        friend class B;
    };

    class SHA3_256 : public SHA3Base<SHA3_256, 136>
    {
    protected:
        inline std::array<uint64_t, 4> formatResult() {
            std::array<uint64_t, 4> result;
            // Convert to big-endian byte order for proper SHA3-256 output
            for (int i = 0; i < 4; ++i) {
                result[i] =
                    ((m_state[i] & 0x00000000000000FF) << 56) |
                    ((m_state[i] & 0x000000000000FF00) << 40) |
                    ((m_state[i] & 0x0000000000FF0000) << 24) |
                    ((m_state[i] & 0x00000000FF000000) << 8) |
                    ((m_state[i] & 0x000000FF00000000) >> 8) |
                    ((m_state[i] & 0x0000FF0000000000) >> 24) |
                    ((m_state[i] & 0x00FF000000000000) >> 40) |
                    ((m_state[i] & 0xFF00000000000000) >> 56);
            }
            return result;
        }

    public:
        using B = SHA3Base<SHA3_256, 136>;
        using B::B;
        friend class B;
        friend class Base<SHA3_256, uint64_t, uint64_t, 136, 25>;
    };

    class SHA3_224 : public SHA3Base<SHA3_224, 144>
    {
    protected:
        inline std::array<uint32_t, 7> formatResult() {
            std::array<uint32_t, 7> result;
            for (int i = 0; i < 3; ++i) {
                uint64_t word = m_state[i];
                result[i * 2] = static_cast<uint32_t>(
                    ((word & 0x00000000000000FF) << 24) |
                    ((word & 0x000000000000FF00) << 8) |
                    ((word & 0x0000000000FF0000) >> 8) |
                    ((word & 0x00000000FF000000) >> 24));
                result[i * 2 + 1] = static_cast<uint32_t>(
                    ((word & 0x000000FF00000000) >> 8) |
                    ((word & 0x0000FF0000000000) >> 24) |
                    ((word & 0x00FF000000000000) >> 40) |
                    ((word & 0xFF00000000000000) >> 56));
            }
            uint64_t word = m_state[3];
            result[6] = static_cast<uint32_t>(
                ((word & 0x00000000000000FF) << 24) |
                ((word & 0x000000000000FF00) << 8) |
                ((word & 0x0000000000FF0000) >> 8) |
                ((word & 0x00000000FF000000) >> 24));
            return result;
        }

    public:
        using B = SHA3Base<SHA3_224, 144>;
        using B::B;
        friend class B;
        friend class Base<SHA3_224, uint64_t, uint64_t, 144, 25>;
    };

    class SHA3_512 : public SHA3Base<SHA3_512, 72>
    {
    protected:
        inline std::array<uint64_t, 8> formatResult() {
            std::array<uint64_t, 8> result;
            for (int i = 0; i < 8; ++i) {
                result[i] =
                    ((m_state[i] & 0x00000000000000FF) << 56) |
                    ((m_state[i] & 0x000000000000FF00) << 40) |
                    ((m_state[i] & 0x0000000000FF0000) << 24) |
                    ((m_state[i] & 0x00000000FF000000) << 8) |
                    ((m_state[i] & 0x000000FF00000000) >> 8) |
                    ((m_state[i] & 0x0000FF0000000000) >> 24) |
                    ((m_state[i] & 0x00FF000000000000) >> 40) |
                    ((m_state[i] & 0xFF00000000000000) >> 56);
            }
            return result;
        }

    public:
        using B = SHA3Base<SHA3_512, 72>;
        using B::B;
        friend class B;
        friend class Base<SHA3_512, uint64_t, uint64_t, 72, 25>;
    };

    class SHA3_384 : public SHA3Base<SHA3_384, 104>
    {
    protected:
        inline std::array<uint64_t, 6> formatResult() {
            std::array<uint64_t, 6> result;
            for (int i = 0; i < 6; ++i) {
                result[i] =
                    ((m_state[i] & 0x00000000000000FF) << 56) |
                    ((m_state[i] & 0x000000000000FF00) << 40) |
                    ((m_state[i] & 0x0000000000FF0000) << 24) |
                    ((m_state[i] & 0x00000000FF000000) << 8) |
                    ((m_state[i] & 0x000000FF00000000) >> 8) |
                    ((m_state[i] & 0x0000FF0000000000) >> 24) |
                    ((m_state[i] & 0x00FF000000000000) >> 40) |
                    ((m_state[i] & 0xFF00000000000000) >> 56);
            }
            return result;
        }

    public:
        using B = SHA3Base<SHA3_384, 104>;
        using B::B;
        friend class B;
        friend class Base<SHA3_384, uint64_t, uint64_t, 104, 25>;
    };
}