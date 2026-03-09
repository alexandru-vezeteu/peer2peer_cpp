#pragma once
#include <array>
#include <cstdint>
#include <span>

class SHA512 
{
	public:
		static constexpr std::size_t digest_size = 64;

		SHA512();
		void update(std::span<const uint8_t> data);
		std::array<uint8_t, digest_size> finalize();
		static std::array<uint8_t, digest_size> hash(std::span<const uint8_t> data);

	private:
		void transform(const uint8_t *block);
		uint64_t state[8];
		uint8_t buffer[128];
		size_t buffer_len;
		uint64_t bit_len_low;
		uint64_t bit_len_high;
};
