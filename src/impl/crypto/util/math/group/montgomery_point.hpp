#pragma once


#include "impl/crypto/util/math/field/field_25519.hpp"
#include "impl/crypto/util/math/field/field_q.hpp"

class montgomery_point
{

  private:
	field_25519 x;
	field_25519 z;

  public:
	static constexpr montgomery_point from_affine(field_25519 x_coord)
	{
		montgomery_point ret;
		ret.x = x_coord;
		ret.z = field_25519::one();
		return ret;
	}

	field_25519 to_affine() const;
	

	static constexpr montgomery_point base_point()
	{
		return from_affine(field_25519::one()+8);
	}

	montgomery_point operator*(const field_q &other) const;

	friend void ct_swap(montgomery_point &a, montgomery_point &b, choice c);
};

