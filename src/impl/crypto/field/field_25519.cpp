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
	return choice::from_equal(diff, 0);
}

choice field_25519::is_zero() const
{
	auto reduced = this->reduce();
	uint64_t diff = 0;
	for(size_t i=0;i<reduced.limbs.size();++i)
	{
		diff |= reduced.limbs[i];
	}
	return choice::from_equal(diff, 0);
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



//A4 A3 A2 A1 A0
//B4 B3 B2 B1 B0
//--------------
//xx xx xx xx xx xx xx xx B0*A4 B0*A3 B0*A2 B0*A1 B0*A0
//xx xx xx xx xx xx B1*A4 B1*A3 B1*A2 B1*A1 B1*A0
//xx xx xx xx B2*A4 B2*A3 B2*A2 B2*A1 B2*A0
//xx xx B3*A4 B3*A3 B3*A2 B3*A1 B3*A0
//B4*A4 B4*A3 B4*A2 B4*A1 B4*A0
// suma indicilor pe coloana e constanta..?!

field_25519 field_25519::operator*(const field_25519 other) const
{
	auto a = *this;
	auto b = other;
	auto s = a.limbs.size();
	auto reduce_digits = [](std::array<__uint128_t, 9> digits)
	{
		constexpr uint64_t mask = (static_cast<uint64_t>(1) << 51) - 1;

		for (size_t i = 0; i < 8; ++i)
		{
			digits[i+1] += digits[i] >> 51;
			digits[i] &= mask;
		}

		std::array<__uint128_t, 5> out{};
		out[0] = digits[0] + digits[5] * static_cast<__uint128_t>(19);
		out[1] = digits[1] + digits[6] * static_cast<__uint128_t>(19);
		out[2] = digits[2] + digits[7] * static_cast<__uint128_t>(19);
		out[3] = digits[3] + digits[8] * static_cast<__uint128_t>(19);
		out[4] = digits[4];

		for (size_t i = 0; i < 4; ++i)
		{
			out[i+1] += out[i] >> 51;
			out[i] &= mask;
		}

		out[0] += (out[4] >> 51) * static_cast<__uint128_t>(19);
		out[4] &= mask;

		for (size_t i = 0; i < 4; ++i)
		{
			out[i+1] += out[i] >> 51;
			out[i] &= mask;
		}

		field_25519 ret;
		for (size_t i = 0; i < 5; ++i)
			ret.limbs[i] = static_cast<uint64_t>(out[i]);
		return ret;
	};
	
	std::array<__uint128_t, 9> digits{};
	for(size_t i=0;i<s;++i)
	{
		for(size_t j=0;j<s;++j)
		{
			//inmultirea nu va da overflow
			digits[i+j] += static_cast<__uint128_t>(a.limbs[i])*static_cast<__uint128_t>(b.limbs[j]);
		}
	}
	
	return reduce_digits(digits);
}

//-a =0-a=p-a
field_25519 field_25519::operator-() const
{
	return field_25519::p()-*this;
}


field_25519 field_25519::square() const
{
	const auto& a = this->limbs;
	constexpr size_t s = 5;
	auto reduce_digits = [](std::array<__uint128_t, 9> digits)
	{
		constexpr uint64_t mask = (static_cast<uint64_t>(1) << 51) - 1;

		for (size_t i = 0; i < 8; ++i)
		{
			digits[i+1] += digits[i] >> 51;
			digits[i] &= mask;
		}

		std::array<__uint128_t, 5> out{};
		out[0] = digits[0] + digits[5] * static_cast<__uint128_t>(19);
		out[1] = digits[1] + digits[6] * static_cast<__uint128_t>(19);
		out[2] = digits[2] + digits[7] * static_cast<__uint128_t>(19);
		out[3] = digits[3] + digits[8] * static_cast<__uint128_t>(19);
		out[4] = digits[4];

		for (size_t i = 0; i < 4; ++i)
		{
			out[i+1] += out[i] >> 51;
			out[i] &= mask;
		}

		out[0] += (out[4] >> 51) * static_cast<__uint128_t>(19);
		out[4] &= mask;

		for (size_t i = 0; i < 4; ++i)
		{
			out[i+1] += out[i] >> 51;
			out[i] &= mask;
		}

		field_25519 ret;
		for (size_t i = 0; i < 5; ++i)
			ret.limbs[i] = static_cast<uint64_t>(out[i]);
		return ret;
	};

	std::array<__uint128_t, 9> digits{};

	for (size_t i = 0; i < s; ++i)
		digits[2*i] += static_cast<__uint128_t>(a[i]) * a[i];

	for (size_t i = 0; i < s; ++i)
	{
		__uint128_t ai2 = static_cast<__uint128_t>(a[i]) * 2;
		for (size_t j = i+1; j < s; ++j)
			digits[i+j] += ai2 * a[j];
	}
	return reduce_digits(digits);
}





//a^p-1 = 1 => a^p-2 = a^-1 =>
//a^(2^255 -19-2) = a^(2^255 - 21)
field_25519 field_25519::invert() const
{
	auto sq_n = [](field_25519 x, int n) {
		for (int i = 0; i < n; ++i) x = x.square();
		return x;
	};

	//z^0
	field_25519 z        = *this;
	
	//z^2
	field_25519 z2       = z.square();

	//(z^2)^2^2 *z=z^8 *z = z^9
	field_25519 z9       = sq_n(z2, 2) * z;

	//z^11
	field_25519 z11      = z9 * z2;

	//z^22*z^9=z^31 = (z^(2^5 -1) )
	field_25519 z2_5   = z11.square() * z9;

	//z^31^2... *z31 = z^(31*2^5+31) = z^1023 = z^(2^10-1)
	field_25519 z2_10  = sq_n(z2_5,   5) * z2_5;

	
	field_25519 z2_20  = sq_n(z2_10, 10) * z2_10;
	field_25519 z2_40  = sq_n(z2_20, 20) * z2_20;
	field_25519 z2_50  = sq_n(z2_40, 10) * z2_10;
	field_25519 z2_100 = sq_n(z2_50,  50) * z2_50;
	field_25519 z2_200 = sq_n(z2_100, 100) * z2_100;
	field_25519 z2_250 = sq_n(z2_200, 50) * z2_50;

	//x^[(2^250-1)*(2^5)+11]
	//x^(2^255-32+11)
	//x^(255-21)
	return sq_n(z2_250, 5) * z11;
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
//naiv.. dar oricum ii pt.. teste
field_25519 field_25519::operator-(const uint64_t other) const
{
	auto r = field_25519::p();
	r.limbs[0]-=other;
	auto r2 = *this;
	return r+r2;
}





const std::array<uint8_t, field_25519::byte_size> field_25519::to_bytes() const
{
	auto f = this->reduce();
	const auto& l = f.limbs;



	std::array<uint8_t, 32> ret{};

	// l[0]: bits 0..50 => bytes 0..6
	ret[0] =  l[0]        & 0xFF;
	ret[1] = (l[0] >>  8) & 0xFF;
	ret[2] = (l[0] >> 16) & 0xFF;
	ret[3] = (l[0] >> 24) & 0xFF;
	ret[4] = (l[0] >> 32) & 0xFF;
	ret[5] = (l[0] >> 40) & 0xFF;
	ret[6] = (l[0] >> 48) & 0x07; 
	// bits 48..50 => low 3 bits of byte 6

	// l[1]: bits 51..101 => starts at bit 3 of byte 6
	// bits 0..4 of l[1] => bits 3..7 of byte 6
	// bits 45..50 of l[1] => low 6 bits of byte 12
	ret[6] |= (l[1] <<  3) & 0xFF;        
	ret[7] 	= (l[1] >>  5) & 0xFF;
	ret[8] 	= (l[1] >> 13) & 0xFF;
	ret[9] 	= (l[1] >> 21) & 0xFF;
	ret[10] = (l[1] >> 29) & 0xFF;
	ret[11] = (l[1] >> 37) & 0xFF;
	ret[12] = (l[1] >> 45) & 0x3F;

	// l[2]: bits 102..152 => starts at bit 6 of byte 12
	// bits 0..1 of l[2] => bits 6..7 of byte 12
	// bit 50 of l[2] => bit 0 of byte 19
	ret[12]|= (l[2] <<  6) & 0xFF;
	ret[13] = (l[2] >>  2) & 0xFF;
	ret[14] = (l[2] >> 10) & 0xFF;
	ret[15] = (l[2] >> 18) & 0xFF;
	ret[16] = (l[2] >> 26) & 0xFF;
	ret[17] = (l[2] >> 34) & 0xFF;
	ret[18] = (l[2] >> 42) & 0xFF;
	ret[19] = (l[2] >> 50) & 0x01;         

	// l[3]: bits 153..203 => starts at bit 1 of byte 19
	// bits 0..6 of l[3] => bits 1..7 of byte 19
 	// bits 47..50 of l[3] => low 4 bits of byte 25
	ret[19]|= (l[3] <<  1) & 0xFF;         
	ret[20] = (l[3] >>  7) & 0xFF;
	ret[21] = (l[3] >> 15) & 0xFF;
	ret[22] = (l[3] >> 23) & 0xFF;
	ret[23] = (l[3] >> 31) & 0xFF;
	ret[24] = (l[3] >> 39) & 0xFF;
	ret[25] = (l[3] >> 47) & 0x0F;        

	// l[4]: bits 204..254 => starts at bit 4 of byte 25
	// bits 0..3 of l[4] => bits 4..7 of byte 25
	// bits 44..50 of l[4] => bits 0..6 of byte 31
	// top bit of byte 31 is always 0 (value < 2^255)
	ret[25]|= (l[4] <<  4) & 0xFF;
	ret[26] = (l[4] >>  4) & 0xFF;
	ret[27] = (l[4] >> 12) & 0xFF;
	ret[28] = (l[4] >> 20) & 0xFF;
	ret[29] = (l[4] >> 28) & 0xFF;
	ret[30] = (l[4] >> 36) & 0xFF;
	ret[31] = (l[4] >> 44) & 0x7F;          
	return ret;
}

//c? a : b
field_25519 ct_select(field_25519 a, field_25519 b, choice c)
{
	field_25519 ret{};
	uint64_t mask = c.mask();
	for(size_t i = 0; i < 5; ++i)
	{
		ret.limbs[i] = (a.limbs[i] & mask) | (b.limbs[i] & ~mask);
	}
	return ret;
}


//if c swap(a,b)
void ct_swap(field_25519& a, field_25519& b, choice c)
{
	
	uint64_t mask = c.mask();
	for(size_t i = 0; i < 5; ++i)
	{
		uint64_t aux1 = a.limbs[i];
		uint64_t aux2 = b.limbs[i];
		a.limbs[i] = (aux1 & ~mask) | (aux2 & mask);
		b.limbs[i] = (aux1 & mask) | (aux2 & ~mask);
	}

}
void ct_swap(field_25519& a, field_25519& b)
{
	for(size_t i = 0; i < 5; ++i)
	{
		a.limbs[i] = a.limbs[i] ^ b.limbs[i];
		b.limbs[i] = a.limbs[i] ^ b.limbs[i];
		a.limbs[i] = a.limbs[i] ^ b.limbs[i];
	}

}


    //trick ca sa pacalesti compilatorul.. ca altfel nu merge ca vede field25519 in mijlocul parsarii 25519
    
    