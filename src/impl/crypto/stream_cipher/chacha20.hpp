#pragma once

#include <cstdint>
#include <span>

#include "domain/crypto/stream_cipher.hpp"

// ChaCha20 stream cipher — IETF variant (RFC 8439)
// Key:   256 bits (32 bytes)
// Nonce:  96 bits (12 bytes)
// Counter: 32-bit block counter (lower 32 bits of the uint64_t parameter are used)
class ChaCha20 {
public:
    static constexpr std::size_t key_size   = 32;
    static constexpr std::size_t nonce_size = 12;

    static void process(std::span<const uint8_t> key,
                        std::span<const uint8_t> nonce,
                        uint64_t                 counter,
                        std::span<const uint8_t> input,
                        std::span<uint8_t>       output);

private:
    static void block(const uint32_t state[16], uint8_t out[64]);
};

static_assert(stream_cipher<ChaCha20>);
