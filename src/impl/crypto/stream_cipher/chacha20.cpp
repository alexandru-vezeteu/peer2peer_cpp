#include "chacha20.hpp"

#include <algorithm>
#include <cstring>

static uint32_t rotl32(uint32_t v, int n)
{
    return (v << n) | (v >> (32 - n));
}

static uint32_t load32_le(const uint8_t* p)
{
    return uint32_t(p[0])
         | uint32_t(p[1]) <<  8
         | uint32_t(p[2]) << 16
         | uint32_t(p[3]) << 24;
}

static void store32_le(uint8_t* p, uint32_t v)
{
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >>  8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

// RFC 8439 §2.1 quarter-round
#define QR(a, b, c, d)          \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = rotl32((d),  8); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b),  7);

// Produce one 64-byte keystream block from the 16-word initial state.
void ChaCha20::block(const uint32_t init[16], uint8_t out[64])
{
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = init[i];

    for (int round = 0; round < 10; ++round) {
        // column rounds
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        // diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; ++i)
        store32_le(out + 4 * i, x[i] + init[i]);
}

void ChaCha20::process(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    uint64_t                 counter,
    std::span<const uint8_t> input,
    std::span<uint8_t>       output)
{
    // "expa", "nd 3", "2-by", "te k"
    static constexpr uint32_t SIGMA[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };

    uint32_t state[16];
    state[0] = SIGMA[0]; state[1] = SIGMA[1];
    state[2] = SIGMA[2]; state[3] = SIGMA[3];
    for (int i = 0; i < 8; ++i)
        state[4 + i] = load32_le(key.data() + 4 * i);
    state[12] = uint32_t(counter);
    state[13] = load32_le(nonce.data());
    state[14] = load32_le(nonce.data() + 4);
    state[15] = load32_le(nonce.data() + 8);

    uint8_t keystream[64];
    std::size_t offset = 0;

    while (offset < input.size()) {
        block(state, keystream);
        std::size_t n = std::min(input.size() - offset, std::size_t(64));
        for (std::size_t i = 0; i < n; ++i)
            output[offset + i] = input[offset + i] ^ keystream[i];
        offset += 64;
        ++state[12]; // advance 32-bit block counter
    }
}
