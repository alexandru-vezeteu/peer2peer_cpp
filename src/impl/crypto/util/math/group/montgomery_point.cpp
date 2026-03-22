#include "montgomery_point.hpp"

montgomery_point montgomery_point::operator*(const scalar_25519 &other) const
{
	montgomery_point x0;
	x0.x = field_25519::one();
	x0.z = field_25519::zero();
	montgomery_point x1 = *this;
	choice previous_bit = choice::false_choice();

	auto step = [this](montgomery_point &x0, montgomery_point &x1)
	{
		field_25519 A = x0.x + x0.z;
		field_25519 AA = A.square();
		field_25519 B = x0.x - x0.z;
		field_25519 BB = B.square();

		field_25519 E = AA - BB;
		field_25519 C = x1.x + x1.z;
		field_25519 D = x1.x - x1.z;
		field_25519 DA = D * A;
		field_25519 CB = C * B;
		x1.x = (DA + CB).square();
		x1.z = this->x * (DA - CB).square();
		x0.x = AA * BB;
		field_25519 a24_E = (field_25519::zero() + 121665) * E;
		x0.z = E * (AA + a24_E);
	};
	for (int i = 255; i >= 0; --i)
	{
		choice current_bit = other.get_bit_i(i);
		choice bit_xor = current_bit ^ previous_bit;
		ct_swap(x0, x1, bit_xor);
		
		step(x0, x1);

		previous_bit = current_bit;
	}
	ct_swap(x0, x1, previous_bit);
	return x0;
}

choice montgomery_point::operator==(const montgomery_point &other) const
{
	field_25519 x1_z2 = this->x * other.z;
	field_25519 x2_z1 = other.x * this->z;
	return x1_z2 == x2_z1;
}

choice montgomery_point::operator!=(const montgomery_point &other) const
{
	return !(*this == other);
}

choice montgomery_point::is_zero() const { return z.is_zero(); }

montgomery_point ct_select(montgomery_point a, montgomery_point b, choice c)
{
	montgomery_point ret;
	ret.x = ct_select(a.x, b.x, c);
	ret.z = ct_select(a.z, b.z, c);
	return ret;
}

void ct_swap(montgomery_point &a, montgomery_point &b, choice c)
{
	ct_swap(a.x, b.x, c);
	ct_swap(a.z, b.z, c);
}

void ct_swap(montgomery_point &a, montgomery_point &b)
{
	ct_swap(a.x, b.x);
	ct_swap(a.z, b.z);
}


// 0b00000000
// limbs[0]:0...63     0b00_xxxxxx
// limbs[1]:64...127   0b01_xxxxxx
// limbs[2]:128...191  0b10_xxxxxx
// limbs[3]:192...255  0b11_xxxxxx
choice scalar_25519::get_bit_i(uint8_t bit) const
{
	uint64_t mask = static_cast<uint64_t>(1) << (bit % 64);

	uint8_t limb_idx = bit >> 6;

	choice l0 = choice::from_nonzero(limbs[0] & mask);
	choice l1 = choice::from_nonzero(limbs[1] & mask);
	choice l2 = choice::from_nonzero(limbs[2] & mask);
	choice l3 = choice::from_nonzero(limbs[3] & mask);


	choice ret = choice::false_choice();
	ret = ret || (choice::from_equal(limb_idx, 3) && l3);
	ret = ret || (choice::from_equal(limb_idx, 2) && l2);
	ret = ret || (choice::from_equal(limb_idx, 1) && l1);
	ret = ret || (choice::from_equal(limb_idx, 0) && l0);
	return ret;
}

