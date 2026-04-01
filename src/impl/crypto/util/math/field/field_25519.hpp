#pragma once

#include <array>


using std::size_t;
using std::array;


#include "impl/crypto/util/choice.hpp"
#include "impl/crypto/util/ct_optional.hpp"

// aritmetica modulo 2^255 - 19
// proprietati utile:
//  0.invert() trb sa fie 0
//  a^(p-1) ~  1 (mod p)
//  a^(-1)  ~ a^(p-2) (mod p)
//  2^255 ~ 19
//  2^256 ~ 38

class field_25519 
{
	array<uint64_t, 5> limbs;
	constexpr field_25519(array<uint64_t, 5> aux) : limbs(aux) {}

public:
	static constexpr size_t characteristic_bits = 255;
	static constexpr size_t byte_size = 32;
	static constexpr size_t wide_byte_size = 64;

	static consteval field_25519 p() {
		return field_25519{{(static_cast<uint64_t>(1) << 51) - 1 - 18,
												(static_cast<uint64_t>(1) << 51) - 1,
												(static_cast<uint64_t>(1) << 51) - 1,
												(static_cast<uint64_t>(1) << 51) - 1,
												(static_cast<uint64_t>(1) << 51) - 1}};
	};

	choice is_zero() const;

	field_25519() = default;
	~field_25519() = default;

	field_25519(const field_25519 &other) = default;
	field_25519 &operator=(const field_25519 &other) = default;

	field_25519(field_25519 &&other) noexcept = default;
	field_25519 &operator=(field_25519 &&other) noexcept = default;

	field_25519 operator+(const field_25519 other) const;
	field_25519 operator-(const field_25519 other) const;
	field_25519 operator*(const field_25519 other) const;
	field_25519 operator-() const;

	constexpr field_25519 reduce() const 
	{
		field_25519 ret = *this;
		ret.reduce_inplace();
		return ret;
	}

	constexpr void reduce_inplace() 
	{
		constexpr uint64_t mask = (static_cast<uint64_t>(1) << 51) - 1;

		for (size_t i = 0; i < 4; ++i) 
		{
			limbs[i + 1] += limbs[i] >> 51;
			limbs[i] &= mask;
		}

		limbs[0] += (limbs[4] >> 51) * 19;
		limbs[4] &= mask;

		for (size_t i = 0; i < 4; ++i) 
		{
			limbs[i + 1] += limbs[i] >> 51;
			limbs[i] &= mask;
		}

		auto eq_raw = [](const field_25519 &a, const field_25519 &b) 
		{
			return choice::from_equal(a.limbs[0], b.limbs[0]) &&
						 choice::from_equal(a.limbs[1], b.limbs[1]) &&
						 choice::from_equal(a.limbs[2], b.limbs[2]) &&
						 choice::from_equal(a.limbs[3], b.limbs[3]) &&
						 choice::from_equal(a.limbs[4], b.limbs[4]);
		};

		choice any_hit = choice::false_choice();
		field_25519 canonical{};
		for (uint64_t i = 0; i <= 18; ++i) 
		{
			choice hit = eq_raw(*this, p() + i);
			canonical = ct_select(field_25519::zero() + i, canonical, hit);
			any_hit = any_hit || hit;
		}
		*this = ct_select(canonical, *this, any_hit);
	}

	field_25519 square() const;
	field_25519 invert() const;

	choice operator==(const field_25519 other) const;

	static constexpr field_25519 one()  { return field_25519{{1, 0, 0, 0, 0}}; }
	static constexpr field_25519 zero() { return field_25519{{0, 0, 0, 0, 0}}; }

	

	field_25519 operator+(const uint64_t other) const;
	field_25519 operator-(const uint64_t other) const;

	// https://www.rfc-editor.org/rfc/rfc7748#section-5
	// MUST accept non-canonical values and reduce modulo p
	static field_25519 from_bytes(array<uint8_t, 32> b);
	array<uint8_t, 32> to_bytes() const;




	friend field_25519 ct_select(field_25519 a, field_25519 b, choice c);
	friend void ct_swap(field_25519 &a, field_25519 &b, choice c);

	template <typename T> friend ct_optional<T> sqrt(field_25519 a);
	static constexpr field_25519 i() 
	{
		auto sq_n = [](field_25519 x, int n) 
		{
			for (int i = 0; i < n; ++i)
				x = x.square();
			return x;
		};
		field_25519 z = field_25519::one() + field_25519::one();
		field_25519 z2 = z.square();
		field_25519 z9 = sq_n(z2, 2) * z;
		field_25519 z11 = z9 * z2;
		field_25519 z2_5 = z11.square() * z9;
		field_25519 z2_10 = sq_n(z2_5, 5) * z2_5;
		field_25519 z2_20 = sq_n(z2_10, 10) * z2_10;
		field_25519 z2_40 = sq_n(z2_20, 20) * z2_20;
		field_25519 z2_50 = sq_n(z2_40, 10) * z2_10;
		field_25519 z2_100 = sq_n(z2_50, 50) * z2_50;
		field_25519 z2_200 = sq_n(z2_100, 100) * z2_100;
		field_25519 z2_250 = sq_n(z2_200, 50) * z2_50;
		return sq_n(z2_250, 3) * z * z2;
	}
};


inline ct_optional<field_25519> sqrt(field_25519 to_take) {
	auto sq_n = [](field_25519 x, int n) {
		for (int i = 0; i < n; ++i)
			x = x.square();
		return x;
	};

	static const field_25519 i = field_25519::i();
	field_25519 z = to_take;
	field_25519 z2 = z.square();
	field_25519 z9 = sq_n(z2, 2) * z;
	field_25519 z11 = z9 * z2;
	field_25519 z2_5 = z11.square() * z9;
	field_25519 z2_10 = sq_n(z2_5, 5) * z2_5;
	field_25519 z2_20 = sq_n(z2_10, 10) * z2_10;
	field_25519 z2_40 = sq_n(z2_20, 20) * z2_20;
	field_25519 z2_50 = sq_n(z2_40, 10) * z2_10;
	field_25519 z2_100 = sq_n(z2_50, 50) * z2_50;
	field_25519 z2_200 = sq_n(z2_100, 100) * z2_100;
	field_25519 z2_250 = sq_n(z2_200, 50) * z2_50;

	field_25519 a = sq_n(z2_250, 2) * z2;
	field_25519 a_2 = a.square();

	choice are_equal     = a_2 == z;
	choice are_equal_neg = a_2 == -z;

	field_25519 a_rotated = a * i;
	field_25519 result    = ct_select(a, a_rotated, are_equal);
	choice is_root        = are_equal || are_equal_neg;

	return ct_optional<field_25519>::from_choice(result, is_root);
}

