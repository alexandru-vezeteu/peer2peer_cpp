#pragma once


#include "impl/crypto/util/math/field/field_25519.hpp"
//https://datatracker.ietf.org/doc/html/rfc8032
class scalar_25519
{
	// 64*4 = 256 bits
	std::array<uint64_t, 4> limbs;

public:
	
	explicit constexpr scalar_25519(std::array<uint64_t, 4> limbs) : limbs(limbs)
	{
		//trb niste clamping, cu 8 ca sa nu am small group attack??? urmeaza sa ma lamuresc mai mult
		this->limbs[0] &= static_cast<uint64_t>(-1)<<3;
		this->limbs[3] &= static_cast<uint64_t>(-1)>>1;
		this->limbs[3] |= static_cast<uint64_t>(1)<<62;

	};

	static scalar_25519 from_bytes(const std::array<uint8_t, 32> &b)
	{
		std::array<uint64_t, 4> limbs{};
		for (size_t i = 0; i < 4; ++i)
			for (size_t j = 0; j < 8; ++j)
				limbs[i] |= static_cast<uint64_t>(b[i * 8 + j]) << (j * 8);
		return scalar_25519(limbs);
	}

	choice get_bit_i(uint8_t bit) const;
};

//https://datatracker.ietf.org/doc/html/rfc8032
class montgomery_point
{

  private:
	field_25519 x;
    field_25519 y;
	field_25519 z;

  public:
	static constexpr montgomery_point from_affine(field_25519 x_coord)
	{
		montgomery_point ret;
		ret.x = x_coord;
		ret.z = field_25519::one();
		return ret;
	}
	field_25519 to_affine() const { return x * z.invert(); }
	

	static constexpr montgomery_point base_point()
	{
		return from_affine(field_25519::one()+8);
	}
	montgomery_point operator*(const scalar_25519 &other) const;
	choice operator==(const montgomery_point &other) const;
	choice operator!=(const montgomery_point &other) const;
	choice is_zero() const;
	friend montgomery_point ct_select(montgomery_point a, montgomery_point b,
									  choice c);
	friend void ct_swap(montgomery_point &a, montgomery_point &b, choice c);
	friend void ct_swap(montgomery_point &a, montgomery_point &b);
};

static_assert(constant_time<montgomery_point, choice>);
