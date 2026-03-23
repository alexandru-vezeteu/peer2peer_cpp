#pragma once

#include <array>
#include <cstdint>

// Arithmetic modulo 2^130 - 5
// 5 limbs of 26 bits each — analogous to field_25519 (5×51 bits, mod 2^255-19)
// Reduction identity: 2^130 ≡ 5 (mod p), so overflow folds back multiplied by 5
class field_130 {
    std::array<uint64_t, 5> limbs;
    constexpr field_130(std::array<uint64_t, 5> l) : limbs(l) {}

public:
    static constexpr std::size_t characteristic_bits = 130;

    field_130() = default;
    ~field_130() = default;

    field_130(const field_130&) = default;
    field_130& operator=(const field_130&) = default;

    field_130(field_130&&) noexcept = default;
    field_130& operator=(field_130&&) noexcept = default;

    // p = 2^130 - 5 in 5×26-bit limbs:
    //   limb[0] = 2^26 - 5   (the -5 lives here)
    //   limb[1..4] = 2^26 - 1
    static consteval field_130 p() {
        return field_130{{(1ULL << 26) - 5,
                          (1ULL << 26) - 1,
                          (1ULL << 26) - 1,
                          (1ULL << 26) - 1,
                          (1ULL << 26) - 1}};
    }

    static constexpr field_130 zero() { return field_130{{0, 0, 0, 0, 0}}; }
    static constexpr field_130 one()  { return field_130{{1, 0, 0, 0, 0}}; }

    field_130 operator+(field_130 other) const;
    field_130 operator*(field_130 other) const;

    void     reduce_inplace();
    field_130 reduce() const;

    // Load from 17 little-endian bytes (top 6 bits of byte[16] are masked/ignored).
    // Limb layout: l[k] holds bits [26k .. 26k+25] of the 130-bit value.
    static field_130 from_bytes(std::array<uint8_t, 17> b);

    // Serialize to 17 little-endian bytes after full canonical reduction mod p.
    std::array<uint8_t, 17> to_bytes() const;
};
