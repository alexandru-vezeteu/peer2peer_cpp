#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "impl/crypto/util/math/field/field_1305.hpp"

using std::size_t;
using std::array;
using std::span;

namespace crypto {

// Poly1305 one-time MAC — RFC 8439 §2.5
// Key layout: 32 bytes = r (16 bytes, clamped) ++ s (16 bytes)
// Tag: 16 bytes
class poly_1305 {
public:
    static constexpr size_t key_size = 32;
    static constexpr size_t tag_size = 16;

    static array<uint8_t, tag_size> generate(   span<const uint8_t> key,
                                                span<const uint8_t> msg);

    static bool verify(span<const uint8_t> key,
                       span<const uint8_t> msg,
                       span<const uint8_t> tag);
};

} // namespace crypto
