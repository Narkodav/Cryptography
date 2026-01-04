#pragma once

namespace Cryptography::Hash {

	template<typename Hash>
	class StreamHash
	{
	private:
		Hash m_hash;
	public:

		StreamHash() : m_hash() {}
		~StreamHash() {}

		StreamHash& operator<<(std::string_view str) {
			m_hash.update(str);
			return *this;
		}

		template <Container C>
		StreamHash& operator<<(const C& container) {
			m_hash.update(container);
			return *this;
		}

		auto digest() {
			return m_hash.digest();
		}

		auto hexdigest() {
			return m_hash.hexdigest();
		}

		void reset() {
			m_hash.reset();
		}
	};
}

