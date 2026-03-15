#include "field_25519.hpp"


choice field_25519::is_one() const
{
	auto reduced = this->reduce();
	uint64_t diff = reduced.limbs[0] ^ 0x1; 
	// 1->0
	// fac asta pt ca daca al doilea limb are 1 pe primul bit in al doilea limb OR ul e orb..
	for(size_t i=1;i<reduced.limbs.size();++i)
	{
		diff |= reduced.limbs[i];
	}
	return choice::choice_from_equal(diff, 0);
}

choice field_25519::is_zero() const
{
	auto reduced = this->reduce();
	uint64_t diff = 0;
	for(size_t i=0;i<reduced.limbs.size();++i)
	{
		diff |= reduced.limbs[i];
	}
	return choice::choice_from_equal(diff, 0);
}
	


field_25519 field_25519::operator+(const field_25519 other) const
{
	field_25519 ret = other;
	for(size_t i=0;i<this->limbs.size();++i)
	{
		ret.limbs[i] += this->limbs[i];
	}
	return ret;
}
//(a-b) mod p = (p+a-b) mod p = a+p-b mod p
field_25519 field_25519::operator-(const field_25519 other) const
{
	field_25519 r = field_25519::p();
	for(size_t i =0;i<r.limbs.size();++i)
	{
		r.limbs[i] -= other.limbs[i];
	}
	r = r + *this;
	return r;
}

//2^255 = 19 (mod p)
// H1 L1 x 
// H2 L2
//----
// L2*L1
// L2*H1<<bits(L2)
// H2*L1<<bits(2*L2)
// H2*H1<<bits(3*l2) doar ca pt 5 limbs..

//A4 A3 A2 A1 A0
//B4 B3 B2 B1 B0
//--------------
//B0*A0...
//B1*A0... <<51
//B2*A0... <<2 * 51
//B3*A0... <<3*51

field_25519 field_25519::operator*(const field_25519 other) const
{
	
	return {};
}

//-a =0-a=p-a
field_25519 field_25519::operator-() const
{
	return field_25519::p()-*this;
}

//ar trb facut mai optim..
field_25519 field_25519::square() const
{
	return {};
}

//a^p-1 = 1 => a^p-2 = a^-1 => 
field_25519 field_25519::invert() const
{
	return {};
}

choice field_25519::operator==(const field_25519 other) const
{
	auto a = other.reduce();
	auto b = this->reduce();
	
	choice r = choice::true_choice();
	for(size_t i=0;i<a.limbs.size(); ++i)
	{
		r = r&&choice::from_equal(a.limbs[i], b.limbs[i]);
	}
	return r;
}
choice field_25519::operator!=(const field_25519 other) const
{
	return !(*this==other);
}


field_25519 field_25519::operator+(const uint64_t other) const
{
	auto r = *this;
	r.limbs[0] += other;
	return r;
}
//naiv..
field_25519 field_25519::operator-(const uint64_t other) const
{
	auto r = field_25519::p();
	r.limbs[0]-=other;
	auto r2 = *this;
	return r+r2;
}





const std::array<uint8_t, field_25519::byte_size> field_25519::to_bytes() const
{
	return {};
}