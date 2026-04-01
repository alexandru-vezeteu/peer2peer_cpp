#include "field_1305.hpp"

#include <cstddef>

static constexpr uint64_t MASK26 = (1ULL << 26) - 1;

field_1305 field_1305::operator+(field_1305 other) const
{
    field_1305 ret = other;
    for (size_t i = 0; i < 5; ++i)
        ret.limbs[i] += this->limbs[i];
    return ret;
}

field_1305 field_1305::operator*(field_1305 other) const
{
    const auto& a = this->limbs;
    const auto& b = other.limbs;

    // Each limb < 2^26, so a[i]*b[j] < 2^52.
    // At most 5 products sum into one digit, so each digit < 5*2^52 < 2^55 — fits in uint64_t.
    uint64_t digits[9]{};
    for (size_t i = 0; i < 5; ++i)
        for (size_t j = 0; j < 5; ++j)
            digits[i + j] += a[i] * b[j];

    // Propagate carries so each digit is < 2^26 before folding.
    for (size_t i = 0; i < 8; ++i) {
        digits[i + 1] += digits[i] >> 26;
        digits[i] &= MASK26;
    }

    // Fold: 2^(5*26) = 2^1305 ≡ 5 (mod p), so digits[k] for k>=5 contribute *5.
    uint64_t out[5]{};
    out[0] = digits[0] + digits[5] * 5;
    out[1] = digits[1] + digits[6] * 5;
    out[2] = digits[2] + digits[7] * 5;
    out[3] = digits[3] + digits[8] * 5;
    out[4] = digits[4];

    for (size_t i = 0; i < 4; ++i) {
        out[i + 1] += out[i] >> 26;
        out[i] &= MASK26;
    }

    out[0] += (out[4] >> 26) * 5;
    out[4] &= MASK26;

    for (size_t i = 0; i < 4; ++i) {
        out[i + 1] += out[i] >> 26;
        out[i] &= MASK26;
    }

    field_1305 ret;
    for (size_t i = 0; i < 5; ++i)
        ret.limbs[i] = out[i];
    return ret;
}

void field_1305::reduce_inplace()
{
    // Pass 1: propagate carries so each limb fits in 26 bits.
    for (size_t i = 0; i < 4; ++i) {
        limbs[i + 1] += limbs[i] >> 26;
        limbs[i] &= MASK26;
    }
    limbs[0] += (limbs[4] >> 26) * 5;
    limbs[4] &= MASK26;

    // Pass 2: re-normalise after the fold into limb[0].
    for (size_t i = 0; i < 4; ++i) {
        limbs[i + 1] += limbs[i] >> 26;
        limbs[i] &= MASK26;
    }

    // Canonical reduction: subtract p if value >= p.
    // Trick: tentatively add 5; if carry escapes limb[4] then value >= 2^13055-5 = p.
    uint64_t c[5];
    uint64_t carry = 5;
    for (size_t i = 0; i < 5; ++i) {
        c[i]  = limbs[i] + carry;
        carry = c[i] >> 26;
        c[i] &= MASK26;
    }
    // carry == 1  =>  value >= p  =>  use c[] (= value - p)
    // carry == 0  =>  value <  p  =>  keep limbs[] unchanged
    uint64_t sel = 0ULL - carry; // UINT64_MAX if carry==1, 0 if carry==0
    for (size_t i = 0; i < 5; ++i)
        limbs[i] = (c[i] & sel) | (limbs[i] & ~sel);
}

// Limb layout (little-endian bit packing, 26 bits per limb):
//   l[0]: bits   0- 25  →  bytes  0-3 (bits 0-1  of byte 3)
//   l[1]: bits  26- 51  →  bytes  3-6 (bits 2-7  of byte 3, bits 0-3 of byte 6)
//   l[2]: bits  52- 77  →  bytes  6-9 (bits 4-7  of byte 6, bits 0-5 of byte 9)
//   l[3]: bits  78-103  →  bytes  9-12 (bits 6-7 of byte 9)
//   l[4]: bits 104-129  →  bytes 13-16 (bits 0-1 of byte 16)

field_1305 field_1305::from_bytes(std::array<uint8_t, 17> b)
{
    b[16] &= 0x03; // only bits 128-129 are valid in the last byte

    uint64_t l0 =  uint64_t(b[0])
                | (uint64_t(b[1]) <<  8)
                | (uint64_t(b[2]) << 16)
                | (uint64_t(b[3]) << 24);
    l0 &= MASK26;

    uint64_t l1 = (uint64_t(b[3]) >>  2)
                | (uint64_t(b[4]) <<  6)
                | (uint64_t(b[5]) << 14)
                | (uint64_t(b[6]) << 22);
    l1 &= MASK26;

    uint64_t l2 = (uint64_t(b[6]) >>  4)
                | (uint64_t(b[7]) <<  4)
                | (uint64_t(b[8]) << 12)
                | (uint64_t(b[9]) << 20);
    l2 &= MASK26;

    uint64_t l3 = (uint64_t(b[9])  >>  6)
                | (uint64_t(b[10]) <<  2)
                | (uint64_t(b[11]) << 10)
                | (uint64_t(b[12]) << 18);
    l3 &= MASK26;

    uint64_t l4 =  uint64_t(b[13])
                | (uint64_t(b[14]) <<  8)
                | (uint64_t(b[15]) << 16)
                | (uint64_t(b[16]) << 24);
    l4 &= MASK26;

    field_1305 result{{l0, l1, l2, l3, l4}};
    result.reduce_inplace();
    return result;
}

std::array<uint8_t, 17> field_1305::to_bytes() const
{
    field_1305 f = *this;
    f.reduce_inplace();
    const auto& l = f.limbs;

    std::array<uint8_t, 17> ret{};

    // l[0]: bits 0-25
    ret[0] =  uint8_t(l[0]        & 0xFF);
    ret[1] =  uint8_t(l[0] >>  8  & 0xFF);
    ret[2] =  uint8_t(l[0] >> 16  & 0xFF);
    ret[3] =  uint8_t(l[0] >> 24  & 0x03); // bits 24-25 of l[0]

    // l[1]: bits 26-51
    ret[3] |= uint8_t((l[1] <<  2) & 0xFF); // bits 0-5 of l[1] → bits 2-7 of byte 3
    ret[4]  = uint8_t( l[1] >>  6  & 0xFF);
    ret[5]  = uint8_t( l[1] >> 14  & 0xFF);
    ret[6]  = uint8_t( l[1] >> 22  & 0x0F); // bits 22-25 of l[1]

    // l[2]: bits 52-77
    ret[6] |= uint8_t((l[2] <<  4) & 0xFF); // bits 0-3 of l[2] → bits 4-7 of byte 6
    ret[7]  = uint8_t( l[2] >>  4  & 0xFF);
    ret[8]  = uint8_t( l[2] >> 12  & 0xFF);
    ret[9]  = uint8_t( l[2] >> 20  & 0x3F); // bits 20-25 of l[2]

    // l[3]: bits 78-103
    ret[9]  |= uint8_t((l[3] <<  6) & 0xFF); // bits 0-1 of l[3] → bits 6-7 of byte 9
    ret[10]  = uint8_t( l[3] >>  2  & 0xFF);
    ret[11]  = uint8_t( l[3] >> 10  & 0xFF);
    ret[12]  = uint8_t( l[3] >> 18  & 0xFF); // bits 18-25 of l[3]

    // l[4]: bits 104-129
    ret[13] = uint8_t( l[4]        & 0xFF);
    ret[14] = uint8_t( l[4] >>  8  & 0xFF);
    ret[15] = uint8_t( l[4] >> 16  & 0xFF);
    ret[16] = uint8_t( l[4] >> 24  & 0x03); // bits 24-25 of l[4]

    return ret;
}
