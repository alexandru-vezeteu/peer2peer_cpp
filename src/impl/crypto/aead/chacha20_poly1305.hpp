#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "domain/crypto/aead.hpp"
#include "impl/crypto/stream_cipher/chacha_20.hpp"
#include "impl/crypto/mac/poly_1305.hpp"

using std::array;
using std::span;
using std::vector;

namespace crypto {

// ChaCha20-Poly1305 AEAD — RFC 8439ah

class chacha20_poly1305
{
public:
    static constexpr size_t key_size   = chacha_20::key_size;   // 32
    static constexpr size_t nonce_size = chacha_20::nonce_size; // 12
    static constexpr size_t tag_size   = poly_1305::tag_size;   // 16

    static vector<uint8_t> seal(
        array<uint8_t, key_size>         key,
        span<const uint8_t, nonce_size>  nonce,
        span<uint8_t>                    plaintext,
        span<const uint8_t>              aad = {}
    );

    static vector<uint8_t> open(
        array<uint8_t, key_size>         key,
        span<const uint8_t, nonce_size>  nonce,
        span<const uint8_t>              blob,   // ciphertext || tag
        span<const uint8_t>              aad = {}
    );

private:
    // RFC 8439: MAC input = aad || pad16(aad) || ciphertext || pad16(ct)
    //                            || uint64le(len(aad)) || uint64le(len(ct))
    static vector<uint8_t> build_mac_input(
        span<const uint8_t> aad,
        span<const uint8_t> ciphertext
    );
};

static_assert(aead<chacha20_poly1305>);

} // namespace crypto
