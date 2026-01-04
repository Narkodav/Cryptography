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

#include "../Concepts.h"
#include "SHA2Base.h"

namespace Cryptography {

    class SHA256
    {
    private:
        // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
        static inline const std::array<uint32_t, 8> s_h0 = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        // Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
        static inline const std::array<uint32_t, 64> s_k = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        std::array<uint32_t, 8> m_state;
        std::array<uint8_t, 64> m_buffer;
        uint64_t m_bitCount;
        size_t m_bufferLen;
    public:

        // Constructor
        SHA256() {
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
                size_t toCopy = std::min(64 - m_bufferLen, bytes.size());
                std::memcpy(m_buffer.data() + m_bufferLen, bytes.data(), toCopy);
                m_bufferLen += toCopy;
                i += toCopy;

                if (m_bufferLen == 64) {
                    processChunk(m_buffer);
                    m_bufferLen = 0;
                }
            }

            // Process full blocks directly from input
            for (; i + 64 <= bytes.size(); i += 64) {
                processChunk(std::span<const uint8_t, 64>(bytes.data() + i, 64));
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
        std::array<uint32_t, 8> digest() {
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
                ss << std::hex << std::setfill('0') << std::setw(8) << word;
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
            for (; i + 64 <= bytes.size(); i += 64) {
                processChunk(std::span<const uint8_t, 64>(bytes.data() + i, 64));
            }

            // Store remaining bytes in buffer
            if (i < bytes.size()) {
                std::memcpy(m_buffer.data(), bytes.data() + i, bytes.size() - i);
                m_bufferLen = bytes.size() - i;
            }
		}

        static std::string hash(const std::string& input) {
            SHA256 sha;
            sha.initialUpdate(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(input.data()), input.size()));
            return sha.hexdigest();
		}

    private:

        void processChunk(std::span<const uint8_t, 64> chunk) {
            // Prepare message schedule W[0..63]
            std::array<uint32_t, 64> W;

            // First 16 words from the chunk (big-endian)
            for (int i = 0; i < 16; ++i) {
                W[i] = (static_cast<uint32_t>(chunk[i * 4]) << 24) |
                    (static_cast<uint32_t>(chunk[i * 4 + 1]) << 16) |
                    (static_cast<uint32_t>(chunk[i * 4 + 2]) << 8) |
                    static_cast<uint32_t>(chunk[i * 4 + 3]);
            }

            // Remaining 48 words
            for (int i = 16; i < 64; ++i) {
                W[i] = Detail::gamma1(W[i - 2]) + W[i - 7] + Detail::gamma0(W[i - 15]) + W[i - 16];
            }

            // Initialize working variables
            uint32_t a = m_state[0];
            uint32_t b = m_state[1];
            uint32_t c = m_state[2];
            uint32_t d = m_state[3];
            uint32_t e = m_state[4];
            uint32_t f = m_state[5];
            uint32_t g = m_state[6];
            uint32_t h = m_state[7];

            // Compression function main loop (64 rounds)
            for (int i = 0; i < 64; ++i) {
                uint32_t temp1 = h + Detail::sigma1(e) + Detail::choice(e, f, g) + s_k[i] + W[i];
                uint32_t temp2 = Detail::sigma0(a) + Detail::majority(a, b, c);

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

            // If no room for length (64 bits = 8 bytes), process this block
            if (m_bufferLen > 56) {
                for (; m_bufferLen < 64; ++m_bufferLen)
                    m_buffer[m_bufferLen] = 0;
                processChunk(m_buffer);
                m_bufferLen = 0;
            }

            // Pad with zeros
            for (; m_bufferLen < 56; ++m_bufferLen)
                m_buffer[m_bufferLen] = 0;

            // Append length (big-endian, 64-bit)
            for (int i = 7; i >= 0; --i) {
                m_buffer[m_bufferLen++] = (m_bitCount >> (i * 8)) & 0xFF;
            }

            // Process final block
            processChunk(m_buffer);
        }
    };

}