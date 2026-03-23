#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "domain/crypto/mac.hpp"
#include "impl/crypto/util/math/field/field_130.hpp"

// Poly1305 one-time MAC — RFC 8439 §2.5
// Key layout: 32 bytes = r (16 bytes, clamped) ++ s (16 bytes)
// Tag: 16 bytes
class Poly1305 {
public:
    static constexpr std::size_t key_size = 32;
    static constexpr std::size_t tag_size = 16;

    static std::array<uint8_t, tag_size> generate(std::span<const uint8_t> key,
                                                   std::span<const uint8_t> msg);

    static bool verify(std::span<const uint8_t> key,
                       std::span<const uint8_t> msg,
                       std::span<const uint8_t> tag);
};

static_assert(mac<Poly1305>);
