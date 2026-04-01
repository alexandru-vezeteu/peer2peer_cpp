#include "chacha_20.hpp"

#include <algorithm>
#include <cstring>
using std::min;
using std::copy;

namespace crypto {

static uint32_t rotl32(uint32_t v, int n)
{
    return (v << n) | (v >> (32 - n));
}

static uint32_t load32_le(span<const uint8_t> p)
{
    return uint32_t(p[0])
         | uint32_t(p[1]) <<  8
         | uint32_t(p[2]) << 16
         | uint32_t(p[3]) << 24;
}

static void store32_le(span<uint8_t> p, uint32_t v)
{
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >>  8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

static inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d,  8);
    c += d; b ^= c; b = rotl32(b,  7);
}

void chacha_20::block(span<const uint32_t, 16> init, span<uint8_t, 64> out)
{
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = init[i];

    for (int round = 0; round < 10; ++round) 
    {
        quarter_round(x[0], x[4], x[8],  x[12]);
        quarter_round(x[1], x[5], x[9],  x[13]);
        quarter_round(x[2], x[6], x[10], x[14]);
        quarter_round(x[3], x[7], x[11], x[15]);
        quarter_round(x[0], x[5], x[10], x[15]);
        quarter_round(x[1], x[6], x[11], x[12]);
        quarter_round(x[2], x[7], x[8],  x[13]);
        quarter_round(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; ++i)
        store32_le(out.subspan(4 * i, 4), x[i] + init[i]);
}

void chacha_20::apply_keystream(
    array<uint8_t, key_size>        key,
    uint32_t                        counter,
    span<const uint8_t, nonce_size> nonce,
    span<uint8_t>                   buffer)
{
    static constexpr uint32_t SIGMA[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };

    uint32_t state[16];
    state[0] = SIGMA[0]; state[1] = SIGMA[1];
    state[2] = SIGMA[2]; state[3] = SIGMA[3];
    for (int i = 0; i < 8; ++i)
        state[4 + i] = load32_le(span<const uint8_t>(key).subspan(4 * i, 4));
    state[12] = counter;
    state[13] = load32_le(nonce.subspan(0, 4));
    state[14] = load32_le(nonce.subspan(4, 4));
    state[15] = load32_le(nonce.subspan(8, 4));

    array<uint8_t, 64> keystream_arr;
    size_t offset = 0;

    while (offset < buffer.size()) 
    {
        block(state, keystream_arr);
        size_t n = min(buffer.size() - offset, size_t(64));
        for (size_t i = 0; i < n; ++i)
            buffer[offset + i] ^= keystream_arr[i];
        offset += 64;
        ++state[12];
    }
}

// Returns ciphertext only — no nonce prepended (RFC 5116: nonce travels separately).
vector<uint8_t> chacha_20::encrypt(
    array<uint8_t, key_size>        key,
    span<const uint8_t, nonce_size> nonce,
    span<uint8_t>                   buffer)
{
    apply_keystream(key, /*counter=*/1, nonce, buffer);
    return vector<uint8_t>(buffer.begin(), buffer.end());
}

// Nonce provided separately — no blob-peeling. XOR is its own inverse.
vector<uint8_t> chacha_20::decrypt(
    array<uint8_t, key_size>        key,
    span<const uint8_t, nonce_size> nonce,
    span<const uint8_t>             ciphertext)
{
    vector<uint8_t> plaintext(ciphertext.begin(), ciphertext.end());
    apply_keystream(key, /*counter=*/1, nonce, plaintext);
    return plaintext;
}

// RFC 8439 §2.6: generate the Poly1305 one-time key.
// Produces the first 64-byte keystream block at counter=0 and returns the first 32 bytes.
array<uint8_t, 32> chacha_20::subkey(
    array<uint8_t, key_size>        key,
    span<const uint8_t, nonce_size> nonce)
{
    array<uint8_t, 64> block_out{};
    apply_keystream(key, /*counter=*/0, nonce, block_out);
    array<uint8_t, 32> result;
    copy(block_out.begin(), block_out.begin() + 32, result.begin());
    return result;
}

} // namespace crypto
