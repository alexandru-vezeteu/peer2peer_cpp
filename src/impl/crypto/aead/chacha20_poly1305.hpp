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

// ChaCha20-Poly1305 AEAD — RFC 8439
//
// Single 256-bit key. Internally:
//   - counter=0 + nonce → 64-byte keystream block → first 32 bytes = Poly1305 one-time key
//   - counter=1+ + nonce → keystream for message encryption
//
// seal(K, N, A, P) → ciphertext || tag (16 bytes)
// open(K, N, A, C) → P | ∅
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
        span<const uint8_t>              aad = {})
    {
        // 1. Derive the Poly1305 one-time key (RFC 8439 §2.6)
        auto auth_key = chacha_20::subkey(key, nonce);

        // 2. Encrypt the plaintext (counter starts at 1) 
        auto ciphertext = chacha_20::encrypt(key, nonce, plaintext);

        // 3. Build the MAC input: aad || pad(aad) || ciphertext || pad(ct) || len(aad) || len(ct)
        //    (RFC 8439 §2.8 padding scheme)
        auto mac_input = build_mac_input(aad, ciphertext);

        // 4. Generate and append the tag
        auto tag = poly_1305::generate(auth_key, mac_input);

        ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
        return ciphertext;
    }

    static vector<uint8_t> open(
        array<uint8_t, key_size>         key,
        span<const uint8_t, nonce_size>  nonce,
        span<const uint8_t>              blob,   // ciphertext || tag
        span<const uint8_t>              aad = {})
    {
        if (blob.size() < tag_size)
            return {};

        span<const uint8_t> ciphertext{ blob.data(), blob.size() - tag_size };
        span<const uint8_t> tag       { blob.data() + ciphertext.size(), tag_size };

        // 1. Derive the Poly1305 one-time key
        auto auth_key = chacha_20::subkey(key, nonce);

        // 2. Verify MAC before decrypting (fail fast)
        auto mac_input = build_mac_input(aad, ciphertext);
        if (!poly_1305::verify(auth_key, mac_input, tag))
            return {};

        // 3. Decrypt
        return chacha_20::decrypt(key, nonce, ciphertext);
    }

private:
    // RFC 8439 §2.8: MAC input = aad || pad16(aad) || ciphertext || pad16(ct)
    //                            || uint64le(len(aad)) || uint64le(len(ct))
    static vector<uint8_t> build_mac_input(
        span<const uint8_t> aad,
        span<const uint8_t> ciphertext)
    {
        vector<uint8_t> out;
        out.reserve(aad.size() + 16 + ciphertext.size() + 16 + 16);

        auto append_padded = [&](span<const uint8_t> data) {
            out.insert(out.end(), data.begin(), data.end());
            size_t pad = (16 - data.size() % 16) % 16;
            out.insert(out.end(), pad, 0x00);
        };

        auto append_le64 = [&](uint64_t v) {
            for (int i = 0; i < 8; ++i)
                out.push_back(uint8_t(v >> (8 * i)));
        };

        append_padded(aad);
        append_padded(ciphertext);
        append_le64(aad.size());
        append_le64(ciphertext.size());
        return out;
    }
};

static_assert(aead<chacha20_poly1305>);
