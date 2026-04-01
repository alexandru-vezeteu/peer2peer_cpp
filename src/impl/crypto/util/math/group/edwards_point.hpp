#pragma once

#include "impl/crypto/util/math/field/field_25519.hpp"
#include "impl/crypto/util/math/field/field_q.hpp"
#include "impl/crypto/util/ct_optional.hpp"

#include <array>

using std::array;

class edwards_point;
edwards_point ct_select(edwards_point a, edwards_point b, choice c);

class edwards_point {
   
    field_25519 x;
    field_25519 y;
    field_25519 z;
    field_25519 t;

    constexpr edwards_point(field_25519 X, field_25519 Y, field_25519 Z, field_25519 T) : x(X), y(Y), z(Z), t(T) {}

public:
    constexpr edwards_point() : x(field_25519::zero()), y(field_25519::one()),
                                z(field_25519::one()), t(field_25519::zero()) {}

    static constexpr edwards_point identity() 
    {
        return edwards_point{}; 
    }
    static edwards_point base_point();

    // Decode from 32-byte representation (RFC 8032)
    template<typename T = edwards_point>
    static ct_optional<T> from_bytes(const array<uint8_t, 32>& b);

    // Encode to 32 bytes
    array<uint8_t, 32> to_bytes() const;

    edwards_point operator+(const edwards_point& other) const;

    edwards_point dbl() const;

	edwards_point operator*(const field_q& s) const;

	choice operator==(const edwards_point& other) const;

	friend edwards_point ct_select(edwards_point a, edwards_point b, choice c);
};
