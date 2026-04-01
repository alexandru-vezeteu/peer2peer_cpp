#pragma once

#include <array>
#include <cstdint>


// Arithmetic modulo 2^130 - 5
// 5 limbs of 26 bits each — analogous to field_25519 (5×51 bits, mod 2^255-19)
// Reduction identity: 2^130 ≡ 5 (mod p), so overflow folds back multiplied by 5
class field_1305 {
    std::array<uint64_t, 5> limbs;
    constexpr field_1305(std::array<uint64_t, 5> l) : limbs(l) {}

public:
    static constexpr std::size_t characteristic_bits = 130;

    field_1305() = default;
    ~field_1305() = default;

    field_1305(const field_1305&) = default;
    field_1305& operator=(const field_1305&) = default;

    field_1305(field_1305&&) noexcept = default;
    field_1305& operator=(field_1305&&) noexcept = default;

    static constexpr field_1305 zero() { return field_1305{{0, 0, 0, 0, 0}}; }

    field_1305 operator+(field_1305 other) const;
    field_1305 operator*(field_1305 other) const;

    void     reduce_inplace();

    // Load from 17 little-endian bytes (top 6 bits of byte[16] are masked/ignored).
    // Limb layout: l[k] holds bits [26k .. 26k+25] of the 1305-bit value.
    static field_1305 from_bytes(std::array<uint8_t, 17> b);

    // Serialize to 17 little-endian bytes after full canonical reduction mod p.
    std::array<uint8_t, 17> to_bytes() const;
};
