#pragma once
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <array>
#include <span>

#include "../CrossCompilerMacros.h"
#include "../Concepts.h"

namespace Cryptography {

    namespace Detail {
        template<typename T>
        static T rotateRight(T x, T n) {
            return (x >> n) | (x << (sizeof(T) * 8 - n));
        }

        template<typename T>
        static T choice(T x, T y, T z) {
            return (x & y) ^ (~x & z);
        }

        template<typename T>
        static T majority(T x, T y, T z) {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        template<typename T>
        static T sigma0(T x) {
            static_assert(false, "Not implemented for this type");
        }

        template<>
        static uint32_t sigma0<uint32_t>(uint32_t x) {
            return rotateRight<uint32_t>(x, 2) 
            ^ rotateRight<uint32_t>(x, 13)
            ^ rotateRight<uint32_t>(x, 22);
        }

        template<>
        static uint64_t sigma0<uint64_t>(uint64_t x) {
            return rotateRight<uint64_t>(x, 28)
                ^ rotateRight<uint64_t>(x, 34)
                ^ rotateRight<uint64_t>(x, 39);
        }

        template<typename T>
        static T sigma1(T x) {
            static_assert(false, "Not implemented for this type");
        }

        template<>
        static uint32_t sigma1<uint32_t>(uint32_t x) {
            return rotateRight<uint32_t>(x, 6)
                ^ rotateRight<uint32_t>(x, 11)
                ^ rotateRight<uint32_t>(x, 25);
        }

        template<>
        static uint64_t sigma1<uint64_t>(uint64_t x) {
            return rotateRight<uint64_t>(x, 14)
                ^ rotateRight<uint64_t>(x, 18)
                ^ rotateRight<uint64_t>(x, 41);
        }

        template<typename T>
        static T gamma0(T x) {
            static_assert(false, "Not implemented for this type");
        }

        template<>
        static uint32_t gamma0<uint32_t>(uint32_t x) {
            return rotateRight<uint32_t>(x, 7)
            ^ rotateRight<uint32_t>(x, 18)
            ^ (x >> 3);
        }

        template<>
        static uint64_t gamma0<uint64_t>(uint64_t x) {
            return rotateRight<uint64_t>(x, 1)
                ^ rotateRight<uint64_t>(x, 8)
                ^ (x >> 7);
        }

        template<typename T>
        static T gamma1(T x) {
            static_assert(false, "Not implemented for this type");
        }

        template<>
        static uint32_t gamma1<uint32_t>(uint32_t x) {
            return rotateRight<uint32_t>(x, 17)
                ^ rotateRight<uint32_t>(x, 19)
                ^ (x >> 10);
        }

        template<>
        static uint64_t gamma1<uint64_t>(uint64_t x) {
            return rotateRight<uint64_t>(x, 19)
                ^ rotateRight<uint64_t>(x, 61)
                ^ (x >> 6);
        }
    }

    template<typename Derived, typename Word, typename BitCounter, 
    size_t s_roundCount, size_t s_chunkByteCount>
    class SHA2Base
    {
    protected:
       std::array<Word, 8> m_state;
       std::array<uint8_t, s_chunkByteCount> m_buffer;
       BitCounter m_bitCount;
       size_t m_bufferLen;
    public:

       // Constructor
       SHA2Base() {
           reset();
       }

       // Reset to initial state
       void reset() {
           // Initial hash values
           m_state = static_cast<Derived*>(this)->getInitialState();
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
               size_t toCopy = std::min(m_buffer.size() - m_bufferLen, bytes.size());
               std::memcpy(m_buffer.data() + m_bufferLen, bytes.data(), toCopy);
               m_bufferLen += toCopy;
               i += toCopy;

               if (m_bufferLen == m_buffer.size()) {
                   processChunk(m_buffer);
                   m_bufferLen = 0;
               }
           }

           // Process full blocks directly from input
           for (; i + m_buffer.size() <= bytes.size(); i += m_buffer.size()) {
               processChunk(std::span<const uint8_t, m_buffer.size()>(bytes.data() + i, m_buffer.size()));
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
          
          auto result = static_cast<Derived*>(this)->formatResult();

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
               ss << std::hex << std::setfill('0') << word;
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
           for (; i + m_buffer.size() <= bytes.size(); i += m_buffer.size()) {
               processChunk(std::span<const uint8_t, m_buffer.size()>(bytes.data() + i, m_buffer.size()));
           }

           // Store remaining bytes in buffer
           if (i < bytes.size()) {
               std::memcpy(m_buffer.data(), bytes.data() + i, bytes.size() - i);
               m_bufferLen = bytes.size() - i;
           }
       }

       static std::string hash(const std::string& input) {
           Derived sha;
           sha.initialUpdate(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(input.data()), input.size()));
           return sha.hexdigest();
       }

    protected:

        template<size_t ByteIndex, size_t TotalBytes = sizeof(Word)>
        inline constexpr Word extractByteAndShift(const uint8_t* chunk) {
            if constexpr (ByteIndex < TotalBytes) {
                constexpr size_t shiftAmount = 8 * (TotalBytes - ByteIndex - 1);
                return (static_cast<Word>(chunk[ByteIndex]) << shiftAmount) |
                    extractByteAndShift<ByteIndex + 1, TotalBytes>(chunk);
            }
            return 0;
        }

        inline constexpr Word extractWord(const uint8_t* chunk) {
            return extractByteAndShift<0>(chunk);
        }

        void processChunk(std::span<const uint8_t, s_chunkByteCount> chunk) {
            // Prepare message schedule W[0..63]
            std::array<uint64_t, s_roundCount> W;

            // First 16 words from the chunk (big-endian)
            for (int i = 0; i < 16; ++i) {
                W[i] = extractWord(chunk.data() + i * 8);
            }

            // Remaining words
            for (int i = 16; i < s_roundCount; ++i) {
                W[i] = Detail::gamma1(W[i - 2]) + W[i - 7]
                    + Detail::gamma0(W[i - 15]) + W[i - 16];
            }

            // Initialize working variables
            Word a = m_state[0];
            Word b = m_state[1];
            Word c = m_state[2];
            Word d = m_state[3];
            Word e = m_state[4];
            Word f = m_state[5];
            Word g = m_state[6];
            Word h = m_state[7];

            auto K = static_cast<Derived*>(this)->getRoundConstants();

            // Compression function main loop
            for (int i = 0; i < s_roundCount; ++i) {
                Word temp1 = h + Detail::sigma1(e) + Detail::choice(e, f, g) + K[i] + W[i];
                Word temp2 = Detail::sigma0(a) + Detail::majority(a, b, c);

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

           // If no room for length, process this block
           if (m_bufferLen > s_chunkByteCount - sizeof(BitCounter)) {
               for (; m_bufferLen < s_chunkByteCount; ++m_bufferLen)
                   m_buffer[m_bufferLen] = 0;
               processChunk(m_buffer);
               m_bufferLen = 0;
           }

           // Pad with zeros
           for (; m_bufferLen < s_chunkByteCount - sizeof(BitCounter); ++m_bufferLen)
               m_buffer[m_bufferLen] = 0;

           static_cast<Derived*>(this)->appendLength();

           // Process final block
           processChunk(m_buffer);
        }
    };

    class SHA512 : public SHA2Base<SHA512, uint64_t, uint128_t, 80, 128> 
    {
    protected:
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

        static inline const std::array<uint64_t, 8> getInitialState() {
            return s_h0;
        }
        static inline const std::array<uint64_t, 80> getRoundConstants() {
            return s_k;
        }
        inline std::array<uint64_t, 8> formatResult() {
            return m_state;
        }

        inline void appendLength() {
            // Append length (big-endian, 128-bit)
            for (int i = 0; i < 8; ++i) {
               m_buffer[m_bufferLen++] = (m_bitCount.high() >> (56 - i * 8)) & 0xFF;
            }

            // Store low 64 bits of length
            for (int i = 0; i < 8; ++i) {
               m_buffer[m_bufferLen++] = (m_bitCount.low() >> (56 - i * 8)) & 0xFF;
            }
        }
    public:
        using Base = SHA2Base<SHA512, uint64_t, uint128_t, 80, 128>;
        using Base::Base;
        friend class Base;
    };

    class SHA384 : public SHA2Base<SHA384, uint64_t, uint128_t, 80, 128>
    {
    protected:
        // Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
        static inline const std::array<uint64_t, 8> s_h0 = {
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
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

        static inline const std::array<uint64_t, 8> getInitialState() {
            return s_h0;
        }
        static inline const std::array<uint64_t, 80> getRoundConstants() {
            return s_k;
        }
        inline std::array<uint64_t, 6> formatResult() {
            std::array<uint64_t, 6> result;
            result[0] = m_state[0];
            result[1] = m_state[1];
            result[2] = m_state[2];
            result[3] = m_state[3];
            result[4] = m_state[4];
            result[5] = m_state[5];
            return result;
        }

        inline void appendLength() {
            // Append length (big-endian, 128-bit)
            for (int i = 0; i < 8; ++i) {
                m_buffer[m_bufferLen++] = (m_bitCount.high() >> (56 - i * 8)) & 0xFF;
            }

            // Store low 64 bits of length
            for (int i = 0; i < 8; ++i) {
                m_buffer[m_bufferLen++] = (m_bitCount.low() >> (56 - i * 8)) & 0xFF;
            }
        }
    public:
        using Base = SHA2Base<SHA384, uint64_t, uint128_t, 80, 128>;
        using Base::Base;
        friend class Base;
    };

    class SHA256 : public SHA2Base<SHA256, uint32_t, uint64_t, 64, 64>
    {
    protected:
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

        static inline const std::array<uint32_t, 8> getInitialState() {
            return s_h0;
        }

        static inline const std::array<uint32_t, 64> getRoundConstants() {
            return s_k;
        }

        inline std::array<uint32_t, 8> formatResult() {
            return m_state;
        }

        inline void appendLength() {
            for (int i = 0; i < 8; ++i) {
                m_buffer[m_bufferLen++] = (m_bitCount >> (56 - i * 8)) & 0xFF;
            }
        }
    public:
        using Base = SHA2Base<SHA256, uint32_t, uint64_t, 64, 64>;
        using Base::Base;
        friend class Base;
    };

    class SHA224 : public SHA2Base<SHA224, uint32_t, uint64_t, 64, 64>
    {
    protected:
        // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
        static inline const std::array<uint32_t, 8> s_h0 = {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
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

        static inline const std::array<uint32_t, 8> getInitialState() {
            return s_h0;
        }

        static inline const std::array<uint32_t, 64> getRoundConstants() {
            return s_k;
        }

        inline std::array<uint32_t, 7> formatResult() {
            std::array<uint32_t, 7> result;
            result[0] = m_state[0];
            result[1] = m_state[1];
            result[2] = m_state[2];
            result[3] = m_state[3];
            result[4] = m_state[4];
            result[5] = m_state[5];
            result[6] = m_state[6];
            return result;
        }

        inline void appendLength() {
            for (int i = 0; i < 8; ++i) {
                m_buffer[m_bufferLen++] = (m_bitCount >> (56 - i * 8)) & 0xFF;
            }
        }
    public:
        using Base = SHA2Base<SHA224, uint32_t, uint64_t, 64, 64>;
        using Base::Base;
        friend class Base;
    };

}