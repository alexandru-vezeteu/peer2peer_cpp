#pragma once

#include <array>
#include <span>

#include "impl/crypto/util/choice.hpp"

using std::array;
using std::span;

// aritmetica modulo L = 2^252 + 27742317777372353535851937790883648493
// L = 0x1000000000000000_00000000000000000_14def9dea2f79cd6_5812631a5cf5d3ed
// limbs[0] = bits   0.. 51 (LSB)
// limbs[1] = bits  52..103
// limbs[2] = bits 104..155
// limbs[3] = bits 156..207
// limbs[4] = bits 208..252 (MSB, 45 bits)
class field_q
{
	array<uint64_t, 5> limbs;
	constexpr field_q(array<uint64_t, 5> aux) : limbs(aux) {}

public:

	static constexpr size_t characteristic_bits = 253;
	static constexpr size_t byte_size = 32;
	static constexpr size_t wide_byte_size = 64;

	static consteval field_q p() {
		return field_q{{0x2631a5cf5d3ed,
							0xdea2f79cd6581,
							0x14def9,
							0x0ULL,
							0x100000000000}};
	}

	field_q() = default;
	~field_q() = default;

	field_q(const field_q &other) = default;
	field_q &operator=(const field_q &other) = default;

	field_q(field_q &&other) noexcept = default;
	field_q &operator=(field_q &&other) noexcept = default;

	field_q operator+(const field_q other) const;
	field_q operator-(const field_q other) const;
	field_q operator*(const field_q other) const;
	field_q operator-() const;

	constexpr field_q reduce() const
	{
		field_q r = *this;
		r.reduce_inplace();
		return r;
	}

	constexpr void reduce_inplace()
	{
		constexpr array<uint64_t, 5> limb_bases = {
			static_cast<uint64_t>(1) << 52,
			static_cast<uint64_t>(1) << 52,
			static_cast<uint64_t>(1) << 52,
			static_cast<uint64_t>(1) << 52,
			static_cast<uint64_t>(1) << 45,
		};

		constexpr array<uint64_t, 5> limb_masks = {
			limb_bases[0] - 1,
			limb_bases[1] - 1,
			limb_bases[2] - 1,
			limb_bases[3] - 1,
			limb_bases[4] - 1,
		};
		auto pv = p();

		auto normalize_low = [&]() 
		{
			for (size_t i = 0; i < 4; ++i) 
			{
				limbs[i + 1] += limbs[i] >> 52;
				limbs[i] &= limb_masks[i];
			}
		};

		normalize_low();

		for (int iter = 0; iter < 16; ++iter) 
		{
			normalize_low();

			array<uint64_t, 5> sub{};
			uint64_t borrow = 0;
			for (size_t i = 0; i < 5; ++i) 
			{
				__int128_t d = (__int128_t)limbs[i] - pv.limbs[i] - borrow;
				uint64_t next_borrow = static_cast<uint64_t>(d < 0);
				uint64_t borrow_mask = static_cast<uint64_t>(0) - next_borrow;
				sub[i] = static_cast<uint64_t>(d) + (limb_bases[i] & borrow_mask);
				borrow = next_borrow;
			}

			uint64_t mask = (!choice::from_nonzero(borrow)).mask();
			for (size_t i = 0; i < 5; ++i) 
			{
				limbs[i] = (sub[i] & mask) | (limbs[i] & ~mask);
			}
		}

		normalize_low();

		for (size_t i = 0; i < 5; ++i) 
		{
			limbs[i] &= limb_masks[i];
		}
	}


	choice operator==(const field_q other) const;

	static constexpr field_q one()  { return field_q{{1, 0, 0, 0, 0}}; }
	static constexpr field_q zero() { return field_q{{0, 0, 0, 0, 0}}; }



	// load raw little-endian bytes without reduction (for clamped scalars)
	static field_q from_bytes(array<uint8_t, 32> b);
	// load little-endian bytes and reduce mod L
	static field_q from_bytes_mod_l(array<uint8_t, 32> b);
	array<uint8_t, 32> to_bytes() const;

	

	friend field_q ct_select(field_q a, field_q b, choice c);
	friend void ct_swap(field_q &a, field_q &b, choice c);


	void clamp();
	choice get_bit_i(uint8_t bit) const;
	static field_q reduce_512(span<const uint8_t, 64> val);

};
