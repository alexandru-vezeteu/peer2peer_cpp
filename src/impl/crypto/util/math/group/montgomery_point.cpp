#include "montgomery_point.hpp"

montgomery_point montgomery_point::operator*(const field_q &other) const
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

void ct_swap(montgomery_point &a, montgomery_point &b, choice c)
{
	ct_swap(a.x, b.x, c);
	ct_swap(a.z, b.z, c);
}

field_25519 montgomery_point::to_affine() const 
{
	return x * z.invert();
}

