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


    //a b c res
    //0 0 0 0
    //0 0 1 0
    //0 1 0 0
    //0 1 1 1
    //1 0 0 1
    //1 0 1 0
    //1 1 0 1
    //1 1 1 1
    //VK => res = (a&b)|(c&~a)

    static constexpr field_25519 ct_select(field_25519 a, field_25519 b, choice c)
    {
        if(c.unwrap_public()) return a;
        return a+b;
    }

    //trick ca sa pacalesti compilatorul.. ca altfel nu merge ca vede field25519 in mijlocul parsarii 25519
    template<typename T = field_25519>
    ct_optional<T> sqrt() const
    {
        return ct_optional<T>::none();
    }

    template<typename T = field_25519>
    static constexpr ct_optional<T> from_bytes(const std::array<uint8_t, T::byte_size>)
    {
        return ct_optional<T>::none();
    }

    static constexpr field_25519 from_uniform_bytes(const std::array<uint8_t, field_25519::wide_byte_size>)
    {
        return {};
    }

    constexpr field_25519 reduce() const
    {
        return {};
    }
    constexpr void reduce_inplace()
    {
        return; 
    }


    const std::array<uint8_t, field_25519::byte_size> to_bytes() const;
};

static_assert(crypto_field<field_25519, ct_optional<field_25519>, choice>);

