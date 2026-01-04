#pragma once
#include <span>
#include <array>
#include <sstream>
#include <iomanip>
#include <fstream>

#include "../CrossCompilerMacros.h"
#include "../Concepts.h"
#include "Utility.h"

namespace Cryptography::Hash {

    template<typename Derived, typename Word, typename BitCounter,
        size_t s_chunkByteCount, size_t s_stateSize>
    class Base
    {
    protected:
        std::array<Word, s_stateSize> m_state;
        std::array<uint8_t, s_chunkByteCount> m_buffer;
        BitCounter m_bitCount;
        size_t m_bufferLen;
    public:

        // Constructor
        Base() {
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
                    static_cast<Derived*>(this)->processChunk(m_buffer);
                    m_bufferLen = 0;
                }
            }

            // Process full blocks directly from input
            for (; i + m_buffer.size() <= bytes.size(); i += m_buffer.size()) {
                static_cast<Derived*>(this)->processChunk(std::span<const uint8_t, m_buffer.size()>(bytes.data() + i, m_buffer.size()));
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
        auto digest() {
            // Save state for finalization
            auto savedState = m_state;
            auto savedBuffer = m_buffer;
            auto savedBitCount = m_bitCount;
            auto savedBufferLen = m_bufferLen;

            // Finalize
            static_cast<Derived*>(this)->finalize();

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
            ss << std::hex << std::setfill('0');
            for (auto word : digestVal) {
                ss << std::setw(sizeof(decltype(word)) * 2) << word;
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
                static_cast<Derived*>(this)->processChunk(
                    std::span<const uint8_t, m_buffer.size()>(bytes.data() + i, m_buffer.size()));
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
    };

    template<typename Derived, typename Word, typename BitCounter,
        size_t s_chunkByteCount, size_t s_stateSize>
    class MerkleDamgardBase : public Base<Derived, Word, BitCounter, s_chunkByteCount, s_stateSize>
    {
    public:
        using Base<Derived, Word, BitCounter, s_chunkByteCount, s_stateSize>::Base;
        friend class Base<Derived, Word, BitCounter, s_chunkByteCount, s_stateSize>;

    protected:

        void finalize() {
            // Append '1' bit
            this->m_buffer[this->m_bufferLen++] = 0x80;

            // If no room for length, process this block
            if (this->m_bufferLen > s_chunkByteCount - sizeof(BitCounter)) {
                for (; this->m_bufferLen < s_chunkByteCount; ++this->m_bufferLen)
                    this->m_buffer[this->m_bufferLen] = 0;
                static_cast<Derived*>(this)->processChunk(this->m_buffer);
                this->m_bufferLen = 0;
            }

            // Pad with zeros
            for (; this->m_bufferLen < s_chunkByteCount - sizeof(BitCounter); ++this->m_bufferLen)
                this->m_buffer[this->m_bufferLen] = 0;

            static_cast<Derived*>(this)->appendLength();

            // Process final block
            static_cast<Derived*>(this)->processChunk(this->m_buffer);
        }
    };
}