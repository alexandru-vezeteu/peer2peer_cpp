#pragma once

#include "domain/crypto/crypto_field.hpp"

#include "ct_optional.hpp"
#include "choice.hpp"

//aritmetica modulo 2^255 -19
//proprietati utile:
// 0.invert() trb sa fie 0
// a^(p-1) ~  1 (mod p)
// a^(-1)  ~ a^(p-2) (mod p)
// 2^255 ~ 19
// 2^256 ~ 38

//limb3 limb2 limb1 limb0 ordinea
class field_25519
{
    std::array<uint64_t, 5> limbs;
    constexpr field_25519(std::array<uint64_t, 5> aux) : limbs(aux){}
    public:
    static constexpr size_t characteristic_bits = 255;
    static constexpr size_t byte_size = 32;
    static constexpr size_t wide_byte_size = 64;

    //2^255 -1 = 5 * 51 limbs doar biti de 1... si din primul trb de scazut 18 ca sa fie 2^255-19
    static consteval field_25519 p() {
        return field_25519{{
            (static_cast<uint64_t>(1)<<51) -1-18, 
            (static_cast<uint64_t>(1)<<51) -1, 
            (static_cast<uint64_t>(1)<<51) -1, 
            (static_cast<uint64_t>(1)<<51) -1, 
            (static_cast<uint64_t>(1)<<51) -1
        }};
    };

    choice is_one() const;
    choice is_zero() const;
    
    field_25519() = default;
    ~field_25519() = default;

    field_25519(const field_25519& other) = default;
    field_25519& operator=(const field_25519& other) = default;

    field_25519(field_25519&& other) noexcept = default;
    field_25519& operator=(field_25519&& other) noexcept = default;


    field_25519 operator+(const field_25519 other) const;
    field_25519 operator-(const field_25519 other) const;
    field_25519 operator*(const field_25519 other) const;

    field_25519 operator+(const uint64_t other) const;
    field_25519 operator-(const uint64_t other) const;


    field_25519 operator-() const;
    field_25519 square() const;
    field_25519 invert() const;
    
    choice operator==(const field_25519 other) const;
    choice operator!=(const field_25519 other) const;

    static consteval field_25519 one()
    {
        return field_25519{{1,0,0,0,0}};
    }
    static consteval field_25519 zero()
    {
        return field_25519{{0,0,0,0,0}};;
    }


    //c? a : b
    static constexpr field_25519 ct_select(field_25519 a, field_25519 b, choice c)
    {
        field_25519 ret{};
        uint64_t mask = c.mask();
        for(size_t i = 0; i < 5; ++i)
        {
            ret.limbs[i] = (a.limbs[i] & mask) | (b.limbs[i] & ~mask);
        }
        return ret;
    }

    //trick ca sa pacalesti compilatorul.. ca altfel nu merge ca vede field25519 in mijlocul parsarii 25519
    template<typename T = field_25519>
    ct_optional<T> sqrt() const
    {
        return ct_optional<T>::none();
    }

    template<typename T = field_25519>
    static constexpr ct_optional<T> from_bytes(std::array<uint8_t, T::byte_size> b)
    {
        constexpr uint64_t mask51 = (static_cast<uint64_t>(1) << 51) - 1;

        //https://www.rfc-editor.org/rfc/rfc7748#section-5
        // MUST mask the most significant bit in the final byte
        b[31] &= 0x7F;

        
        field_25519 ret{};
        auto& l = ret.limbs;

        // l[0]: bytes 0..6, bits 0..50
        l[0]  =  static_cast<uint64_t>(b[0]);
        l[0] |=  static_cast<uint64_t>(b[1]) <<  8;
        l[0] |=  static_cast<uint64_t>(b[2]) << 16;
        l[0] |=  static_cast<uint64_t>(b[3]) << 24;
        l[0] |=  static_cast<uint64_t>(b[4]) << 32;
        l[0] |=  static_cast<uint64_t>(b[5]) << 40;
        l[0] |= (static_cast<uint64_t>(b[6]) & 0x07) << 48;
        l[0] &= mask51;

        // l[1]: starts at bit 3 of byte 6, bytes 6..12
        l[1]  =  static_cast<uint64_t>(b[6])  >>  3;
        l[1] |=  static_cast<uint64_t>(b[7])  <<  5;
        l[1] |=  static_cast<uint64_t>(b[8])  << 13;
        l[1] |=  static_cast<uint64_t>(b[9])  << 21;
        l[1] |=  static_cast<uint64_t>(b[10]) << 29;
        l[1] |=  static_cast<uint64_t>(b[11]) << 37;
        l[1] |= (static_cast<uint64_t>(b[12]) & 0x3F) << 45;
        l[1] &= mask51;

        // l[2]: starts at bit 6 of byte 12, bytes 12..19
        l[2]  =  static_cast<uint64_t>(b[12]) >>  6;
        l[2] |=  static_cast<uint64_t>(b[13]) <<  2;
        l[2] |=  static_cast<uint64_t>(b[14]) << 10;
        l[2] |=  static_cast<uint64_t>(b[15]) << 18;
        l[2] |=  static_cast<uint64_t>(b[16]) << 26;
        l[2] |=  static_cast<uint64_t>(b[17]) << 34;
        l[2] |=  static_cast<uint64_t>(b[18]) << 42;
        l[2] |= (static_cast<uint64_t>(b[19]) & 0x01) << 50;
        l[2] &= mask51;

        // l[3]: starts at bit 1 of byte 19, bytes 19..25
        l[3]  =  static_cast<uint64_t>(b[19]) >>  1;
        l[3] |=  static_cast<uint64_t>(b[20]) <<  7;
        l[3] |=  static_cast<uint64_t>(b[21]) << 15;
        l[3] |=  static_cast<uint64_t>(b[22]) << 23;
        l[3] |=  static_cast<uint64_t>(b[23]) << 31;
        l[3] |=  static_cast<uint64_t>(b[24]) << 39;
        l[3] |= (static_cast<uint64_t>(b[25]) & 0x0F) << 47;
        l[3] &= mask51;

        // l[4]: starts at bit 4 of byte 25, bytes 25..31
        l[4]  =  static_cast<uint64_t>(b[25]) >>  4;
        l[4] |=  static_cast<uint64_t>(b[26]) <<  4;
        l[4] |=  static_cast<uint64_t>(b[27]) << 12;
        l[4] |=  static_cast<uint64_t>(b[28]) << 20;
        l[4] |=  static_cast<uint64_t>(b[29]) << 28;
        l[4] |=  static_cast<uint64_t>(b[30]) << 36;
        l[4] |=  static_cast<uint64_t>(b[31]) << 44;
        l[4] &= mask51;

        //Implementations MUST accept non-canonical values and process them as
        //if they had been reduced modulo the field prime.  The non-canonical
        //values are 2^255 - 19 through 2^255 - 1 for X25519
        //am lasat totusi constant timp opt ca asa am scris prima data conceptul..
        ret.reduce_inplace();
        return ct_optional<T>::some(ret);
    }

    static constexpr field_25519 from_uniform_bytes(const std::array<uint8_t, field_25519::wide_byte_size> bytes)
    {
        //pe 32 de bytes valorile intre 0 si 19 apar de 2 ori.. ceea ce e un bias si nu e secure aparent deci..

        
        // hi * 2^255 + lo  (mod p)
        // = hi * 19   + lo   (mod p
        std::array<uint8_t, 32> lo_bytes{}, hi_bytes{};
        for (size_t i = 0; i < 32; ++i) lo_bytes[i] = bytes[i];
        for (size_t i = 0; i < 32; ++i) hi_bytes[i] = bytes[i + 32];

        
        auto lo = from_bytes(lo_bytes).value_or(zero());
        auto hi = from_bytes(hi_bytes).value_or(zero());

        return (hi * (one() + 18u) + lo).reduce();  // hi*19 + lo
    }

    constexpr field_25519 reduce() const
    {
        field_25519 ret = *this;
        ret.reduce_inplace();
        return ret;
    }

    constexpr void reduce_inplace()
    {
        constexpr uint64_t mask = (static_cast<uint64_t>(1) << 51) - 1;
        
        for (size_t i = 0; i < 4; ++i) {
            limbs[i+1] += limbs[i] >> 51;
            limbs[i] &= mask;
        }
        
        limbs[0] += (limbs[4] >> 51) * 19;
        limbs[4] &= mask;
        
        for (size_t i = 0; i < 4; ++i) {
            limbs[i+1] += limbs[i] >> 51;
            limbs[i] &= mask;
        }
        
        // operatorul == apeleaza asta in spate
        auto eq_raw = [](const field_25519& a, const field_25519& b)
        {
            return  choice::from_equal(a.limbs[0], b.limbs[0]) &&
                    choice::from_equal(a.limbs[1], b.limbs[1]) &&
                    choice::from_equal(a.limbs[2], b.limbs[2]) &&
                    choice::from_equal(a.limbs[3], b.limbs[3]) &&
                    choice::from_equal(a.limbs[4], b.limbs[4]);
        };


        // this e in  [0, 2^255)
        // valorile din [p, p+18] -> [0, 18]
        choice any_hit = choice::false_choice();
        field_25519 canonical{};
        for (uint64_t i = 0; i <= 18; ++i)
        {
            choice hit = eq_raw(*this, p()+ i);
            canonical = ct_select(field_25519::zero()+ i, canonical, hit);
            any_hit = any_hit || hit;
        }
        *this = ct_select(canonical, *this, any_hit);

        
        
    }


    const std::array<uint8_t, field_25519::byte_size> to_bytes() const;

private:
};

static_assert(crypto_field<field_25519, ct_optional<field_25519>, choice>);

