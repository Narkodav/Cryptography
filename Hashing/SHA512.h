#pragma once
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <array>
#include <span>

#include "../CrossCompilerMacros.h"
#include "../Concepts.h"
#include "SHA2Base.h"

namespace Cryptography {

    class SHA512
    {
    private:
        // Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
        static inline const std::array<uint64_t, 8> s_h0 = {
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
        };

        // Round constants (first 64 bits of fractional parts of cube roots of first 80 primes)
        static inline const std::array<uint64_t, 80> s_k = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        std::array<uint64_t, 8> m_state;
        std::array<uint8_t, 128> m_buffer;
        uint128_t m_bitCount;
        size_t m_bufferLen;

    public:

        // Constructor
        SHA512() {
            reset();
        }

        // Reset to initial state
        void reset() {
            // Initial hash values
            m_state = s_h0;
            m_buffer.fill(0);
            m_bitCount = 0;
            m_bufferLen = 0;
        }

        void update(std::span<const uint8_t> bytes) {

            // Add to bit count
            m_bitCount += bytes.size() * 8;

            // Process any leftover bytes in buffer
            size_t i = 0;
            if (m_bufferLen > 0) {
                size_t toCopy = std::min(128 - m_bufferLen, bytes.size());
                std::memcpy(m_buffer.data() + m_bufferLen, bytes.data(), toCopy);
                m_bufferLen += toCopy;
                i += toCopy;

                if (m_bufferLen == 128) {
                    processChunk(m_buffer);
                    m_bufferLen = 0;
                }
            }

            // Process full blocks directly from input
            for (; i + 128 <= bytes.size(); i += 128) {
                processChunk(std::span<const uint8_t, 128>(bytes.data() + i, 128));
            }

            // Store remaining bytes in buffer
            if (i < bytes.size()) {
                std::memcpy(m_buffer.data(), bytes.data() + i, bytes.size() - i);
                m_bufferLen = bytes.size() - i;
            }
        }

        void update(std::string_view str) {
            update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()), str.size()));
        }

        template <Container C>
        void update(const C& container) {
            update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(container.data()), container.size() *
                sizeof(decltype(*container.begin()))));
        }

        // Get final hash
        std::array<uint64_t, 8> digest() {
            // Save state for finalization
            auto savedState = m_state;
            auto savedBuffer = m_buffer;
            auto savedBitCount = m_bitCount;
            auto savedBufferLen = m_bufferLen;

            // Finalize
            finalize();
            auto result = m_state;

            // Restore state (allows continued use)
            m_state = savedState;
            m_buffer = savedBuffer;
            m_bitCount = savedBitCount;
            m_bufferLen = savedBufferLen;

            return result;
        }

        // Get hash as hex string
        std::string hexdigest() {
            auto digestVal = digest();
            std::stringstream ss;
            for (auto word : digestVal) {
                ss << std::hex << std::setfill('0') << std::setw(16) << word;
            }
            return ss.str();
        }

        // Initial update (reset and process)
        void initialUpdate(std::span<const uint8_t> bytes) {
            reset();
            // Add to bit count
            m_bitCount += bytes.size() * 8;

            // Process full blocks directly from input
            size_t i = 0;
            for (; i + 128 <= bytes.size(); i += 128) {
                processChunk(std::span<const uint8_t, 128>(bytes.data() + i, 128));
            }

            // Store remaining bytes in buffer
            if (i < bytes.size()) {
                std::memcpy(m_buffer.data(), bytes.data() + i, bytes.size() - i);
                m_bufferLen = bytes.size() - i;
            }
        }

        static std::string hash(const std::string& input) {
            SHA512 sha;
            sha.initialUpdate(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(input.data()), input.size()));
            return sha.hexdigest();
        }

    private:

        void processChunk(std::span<const uint8_t, 128> chunk) {
            // Prepare message schedule W[0..63]
            std::array<uint64_t, 80> W;

            // First 16 words from the chunk (big-endian)
            for (int i = 0; i < 16; ++i) {
                W[i] =
                    (static_cast<uint64_t>(chunk[i * 8]) << 56) |
                    (static_cast<uint64_t>(chunk[i * 8 + 1]) << 48) |
                    (static_cast<uint64_t>(chunk[i * 8 + 2]) << 40) |
                    (static_cast<uint64_t>(chunk[i * 8 + 3]) << 32) |
                    (static_cast<uint64_t>(chunk[i * 8 + 4]) << 24) |
                    (static_cast<uint64_t>(chunk[i * 8 + 5]) << 16) |
                    (static_cast<uint64_t>(chunk[i * 8 + 6]) << 8) |
                    (static_cast<uint64_t>(chunk[i * 8 + 7]));
            }

            // Remaining 48 words
            for (int i = 16; i < 80; ++i) {
                W[i] = Detail::gamma1(W[i - 2]) + W[i - 7]
                    + Detail::gamma0(W[i - 15]) + W[i - 16];
            }

            // Initialize working variables
            uint64_t a = m_state[0];
            uint64_t b = m_state[1];
            uint64_t c = m_state[2];
            uint64_t d = m_state[3];
            uint64_t e = m_state[4];
            uint64_t f = m_state[5];
            uint64_t g = m_state[6];
            uint64_t h = m_state[7];

            // Compression function main loop (80 rounds)
            for (int i = 0; i < 80; ++i) {
                uint64_t temp1 = h + Detail::sigma1(e) + Detail::choice(e, f, g) + s_k[i] + W[i];
                uint64_t temp2 = Detail::sigma0(a) + Detail::majority(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            // Update hash values
            m_state[0] += a;
            m_state[1] += b;
            m_state[2] += c;
            m_state[3] += d;
            m_state[4] += e;
            m_state[5] += f;
            m_state[6] += g;
            m_state[7] += h;
        }

        void finalize() {
            // Append '1' bit
            m_buffer[m_bufferLen++] = 0x80;

            // If no room for length (128 bits = 16 bytes), process this block
            if (m_bufferLen > 112) {
                for (; m_bufferLen < 128; ++m_bufferLen)
                    m_buffer[m_bufferLen] = 0;
                processChunk(m_buffer);
                m_bufferLen = 0;
            }

            // Pad with zeros
            for (; m_bufferLen < 112; ++m_bufferLen)
                m_buffer[m_bufferLen] = 0;

            // Append length (big-endian, 128-bit)
            for (int i = 0; i < 8; ++i) {
                m_buffer[m_bufferLen++] = (m_bitCount.high() >> (56 - i * 8)) & 0xFF;
            }

            // Store low 64 bits of length
            for (int i = 0; i < 8; ++i) {
                m_buffer[m_bufferLen++] = (m_bitCount.low() >> (56 - i * 8)) & 0xFF;
            }

            // Process final block
            processChunk(m_buffer);
        }
    };

}