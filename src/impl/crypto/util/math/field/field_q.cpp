#include "field_q.hpp"



namespace {
uint64_t load_bits_le(const array<uint8_t, 32> &bytes, size_t start_bit, size_t bit_count) {
    uint64_t out = 0;
    for (size_t i = 0; i < bit_count; ++i) {
        uint8_t bit = (bytes[(start_bit + i) / 8] >> ((start_bit + i) % 8)) & 1;
        out |= static_cast<uint64_t>(bit) << i;
    }
    return out;
}

void store_bits_le(array<uint8_t, 32> &bytes, uint64_t value, size_t start_bit, size_t bit_count) {
    for (size_t i = 0; i < bit_count; ++i) {
        uint8_t bit = static_cast<uint8_t>((value >> i) & 1ULL);
        size_t byte_index = (start_bit + i) / 8;
        size_t bit_index = (start_bit + i) % 8;
        bytes[byte_index] = static_cast<uint8_t>((bytes[byte_index] & ~(1U << bit_index)) | (bit << bit_index));
    }
}
} // namespace

field_q field_q::operator+(const field_q other) const 
{
    field_q ret = other;
    for (size_t i = 0; i < this->limbs.size(); ++i) 
    {
        ret.limbs[i] += this->limbs[i];
    }
    ret.reduce_inplace();
    return ret;
}

// a - b = (p - b) + a
field_q field_q::operator-(const field_q other) const 
{
	constexpr array<uint64_t, 5> limb_bases = {
		static_cast<uint64_t>(1) << 52,
		static_cast<uint64_t>(1) << 52,
		static_cast<uint64_t>(1) << 52,
		static_cast<uint64_t>(1) << 52,
		static_cast<uint64_t>(1) << 45,
	};

    field_q r = p();
    auto x = other;
    x.reduce_inplace();
    uint64_t borrow = 0;
    for (size_t i = 0; i < r.limbs.size(); ++i) {
        __int128_t d = (__int128_t)r.limbs[i] - x.limbs[i] - borrow;
        uint64_t next_borrow = static_cast<uint64_t>(d < 0);
        uint64_t borrow_mask = static_cast<uint64_t>(0) - next_borrow;
        r.limbs[i] = static_cast<uint64_t>(d) + (limb_bases[i] & borrow_mask);
        borrow = next_borrow;
    }
    field_q out = *this + r;
    out.reduce_inplace();
    return out;
}

field_q field_q::operator-() const 
{
    return p() - *this;
}

// double-and-add from MSB
field_q field_q::operator*(const field_q other) const 
{
    field_q result = zero();
    for (int i = static_cast<int>(characteristic_bits) - 1; i >= 0; --i) {
        result = result + result;
        choice bit = other.get_bit_i(static_cast<uint8_t>(i));
        field_q sum = result + *this;
        result = ct_select(sum, result, bit);
    }
    return result;
}





void field_q::clamp()
{
    limbs[0] &= ~7ULL;           // clear bits 0-2
    limbs[4] &= ~(1ULL << 47);   // clear bit 255
    limbs[4] |=  (1ULL << 46);   // set bit 254
}

// raw little-endian load, no reduction
field_q field_q::from_bytes(array<uint8_t, 32> b) 
{
    field_q s;
    s.limbs[0] = load_bits_le(b, 0, 52);
    s.limbs[1] = load_bits_le(b, 52, 52);
    s.limbs[2] = load_bits_le(b, 104, 52);
    s.limbs[3] = load_bits_le(b, 156, 52);
    s.limbs[4] = load_bits_le(b, 208, 48);
    return s;
}

field_q field_q::from_bytes_mod_l(array<uint8_t, 32> b) 
{
    array<uint8_t, 64> padded{};
    for (size_t i = 0; i < 32; ++i) padded[i] = b[i];
    return reduce_512(padded);
}

// feed bits MSB-first and reduce modulo L after each bit
field_q field_q::reduce_512(span<const uint8_t, 64> val) 
{
    field_q A = zero();
    for (int i = 511; i >= 0; --i) {
        A = A + A;
        choice bit = choice::from_nonzero((val[i / 8] >> (i % 8)) & 1);
        field_q with_bit = A + one();
        A = ct_select(with_bit, A, bit);
        A.reduce_inplace();
    }
    return A;
}

array<uint8_t, 32> field_q::to_bytes() const 
{
    auto f = reduce();
    array<uint8_t, 32> ret{};
    store_bits_le(ret, f.limbs[0], 0, 52);
    store_bits_le(ret, f.limbs[1], 52, 52);
    store_bits_le(ret, f.limbs[2], 104, 52);
    store_bits_le(ret, f.limbs[3], 156, 52);
    store_bits_le(ret, f.limbs[4], 208, 45);
    return ret;
}

choice field_q::get_bit_i(uint8_t bit) const 
{
    uint8_t limb_idx = 0;
    uint8_t bit_in_limb = 0;

    if (bit < 52) {
        limb_idx = 0;
        bit_in_limb = bit;
    } else if (bit < 104) {
        limb_idx = 1;
        bit_in_limb = static_cast<uint8_t>(bit - 52);
    } else if (bit < 156) {
        limb_idx = 2;
        bit_in_limb = static_cast<uint8_t>(bit - 104);
    } else if (bit < 208) {
        limb_idx = 3;
        bit_in_limb = static_cast<uint8_t>(bit - 156);
    } else {
        limb_idx = 4;
        bit_in_limb = static_cast<uint8_t>(bit - 208);
    }

    uint64_t mask = 1ULL << bit_in_limb;
    choice c = choice::false_choice();
    for (uint8_t i = 0; i < 5; ++i)
        c = c || (choice::from_equal(limb_idx, i) && choice::from_nonzero(limbs[i] & mask));
    return c;
}

choice field_q::operator==(const field_q other) const 
{
    auto a = reduce();
    auto b = other.reduce();
    choice eq = choice::true_choice();
    for (size_t i = 0; i < a.limbs.size(); ++i)
        eq = eq && choice::from_equal(a.limbs[i], b.limbs[i]);
    return eq;
}

field_q ct_select(field_q a, field_q b, choice c) 
{
    field_q ret;
    uint64_t mask = c.mask();
    for (size_t i = 0; i < 5; ++i)
        ret.limbs[i] = (a.limbs[i] & mask) | (b.limbs[i] & ~mask);
    return ret;
}

void ct_swap(field_q &a, field_q &b, choice c) 
{
    uint64_t mask = c.mask();
    for (size_t i = 0; i < 5; ++i) {
        uint64_t x = a.limbs[i], y = b.limbs[i];
        a.limbs[i] = (x & ~mask) | (y &  mask);
        b.limbs[i] = (x &  mask) | (y & ~mask);
    }
}
