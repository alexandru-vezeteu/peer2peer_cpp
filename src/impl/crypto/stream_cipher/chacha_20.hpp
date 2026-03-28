#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "stream_cipher.hpp"


using std::span;
using std::array;
using std::size_t;
using std::vector;

// ChaCha20 stream cipher — IETF variant (RFC 8439)
// Key:   256 bits (32 bytes)
// Nonce:  96 bits (12 bytes)
// Counter: starts at 1 internally. Not part of the public interface.
class chacha_20 
{
public:
    static constexpr size_t key_size   = 32;
    static constexpr size_t nonce_size = 12;

    // Encrypts buffer in-place, returns ciphertext only (no nonce prepended).
    static vector<uint8_t> encrypt(
        array<uint8_t, key_size>         key,
        span<const uint8_t, nonce_size>  nonce,
        span<uint8_t>                    buffer);

    // Decrypts ciphertext, returns plaintext. Nonce provided separately.
    static vector<uint8_t> decrypt(
        array<uint8_t, key_size>         key,
        span<const uint8_t, nonce_size>  nonce,
        span<const uint8_t>              ciphertext);

    // Derives a 32-byte subkey from keystream block at counter=0.
    // Used by ChaCha20-Poly1305 (RFC 8439 §2.6) to generate the Poly1305 one-time key.
    static array<uint8_t, 32> subkey(
        array<uint8_t, key_size>         key,
        span<const uint8_t, nonce_size>  nonce);

public:
    // Raw keystream-XOR at a given starting counter.
    // Exposed for testing and special constructions.
    static void apply_keystream(
        array<uint8_t, key_size>         key,
        uint32_t                         counter,
        span<const uint8_t, nonce_size>  nonce,
        span<uint8_t>                    buffer);

private:
    static void block(span<const uint32_t, 16> state, span<uint8_t, 64> out);
};

static_assert(stream_cipher<chacha_20>);
